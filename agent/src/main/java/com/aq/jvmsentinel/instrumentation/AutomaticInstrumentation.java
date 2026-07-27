package com.aq.jvmsentinel.instrumentation;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.field.FieldDescription;
import net.bytebuddy.description.field.FieldList;
import net.bytebuddy.description.method.MethodList;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.pool.TypePool;
import net.bytebuddy.utility.JavaModule;

import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.Map;

import static net.bytebuddy.matcher.ElementMatchers.hasSuperType;
import static net.bytebuddy.matcher.ElementMatchers.isAbstract;
import static net.bytebuddy.matcher.ElementMatchers.isAnnotatedWith;
import static net.bytebuddy.matcher.ElementMatchers.isInterface;
import static net.bytebuddy.matcher.ElementMatchers.isMethod;
import static net.bytebuddy.matcher.ElementMatchers.nameStartsWith;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.namedOneOf;
import static net.bytebuddy.matcher.ElementMatchers.not;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Startup-only instrumentation. Bootstrap classes are deliberately not transformed; calls into selected JDK
 * APIs are observed at non-bootstrap application call sites instead.
 */
final class AutomaticInstrumentation {
    private static final String[] SPRING_MAPPING_ANNOTATIONS = {
            "org.springframework.web.bind.annotation.RequestMapping",
            "org.springframework.web.bind.annotation.GetMapping",
            "org.springframework.web.bind.annotation.PostMapping",
            "org.springframework.web.bind.annotation.PutMapping",
            "org.springframework.web.bind.annotation.DeleteMapping",
            "org.springframework.web.bind.annotation.PatchMapping"
    };

    private AutomaticInstrumentation() {
    }

    static void install(Instrumentation instrumentation, AgentConfig config, EventWriter writer) {
        // CLASS_LOAD stays classPrefix-scoped. Servlet/Filter/Interceptor HTTP capture must ignore
        // classPrefix, otherwise auth denials never produce HTTP evidence for the target controller.
        AgentBuilder.RawMatcher applicationTypes = (type, loader, module, redefining, domain) ->
                loader != null && (isHttpObservabilityType(type) || config.includes(type.getName()));

        AgentBuilder.Listener listener = new AgentBuilder.Listener.Adapter() {
            @Override
            public void onError(String typeName, ClassLoader classLoader, JavaModule module,
                                boolean loaded, Throwable throwable) {
                writer.writeObserved("INSTRUMENTATION_ERROR", typeName, "",
                        Map.of("errorType", throwable.getClass().getName()));
            }
        };

        AgentBuilder builder = new AgentBuilder.Default().with(listener);
        // BranchCoverageInstrumentation injects probe calls; that requires class-format changes.
        // Advice-only mode keeps disableClassFormatChanges for the default (coverage off) path.
        if (!config.coverageEnabled) {
            builder = builder.disableClassFormatChanges();
        }
        builder = builder
                .type(applicationTypes)
                .transform((builder0, type, loader, module, domain) -> {
                    boolean prefixed = config.includes(type.getName());
                    DynamicType.Builder<?> transformed;
                    if (!prefixed && isHttpObservabilityType(type)) {
                        transformed = instrumentHttpSurface(builder0, type);
                    } else {
                        transformed = instrumentApplicationCalls(builder0, type);
                    }
                    if (config.coverageEnabled && prefixed) {
                        transformed = transformed.visit(
                                new BranchCoverageInstrumentation(type.getName()));
                    }
                    return transformed;
                });

        builder.installOn(instrumentation);
    }

    private static boolean isHttpObservabilityType(TypeDescription type) {
        if (isInterface().matches(type)) return false;
        // Prefer hierarchy when the servlet API is visible to ByteBuddy's TypePool.
        if (hierarchyHttpSurface(type)) return true;
        // Spring Boot fat JARs often hide javax/jakarta.servlet from TypePool, so hasSuperType
        // returns false for DispatcherServlet/Filters even though they are HTTP surfaces.
        return shapedHttpServlet(type) || shapedHttpFilter(type) || shapedHttpInterceptor(type);
    }

    private static boolean hierarchyHttpSurface(TypeDescription type) {
        try {
            return hasSuperType(named("jakarta.servlet.Servlet").or(named("javax.servlet.Servlet"))).matches(type)
                    || hasSuperType(named("jakarta.servlet.Filter").or(named("javax.servlet.Filter"))).matches(type)
                    || hasSuperType(named("org.springframework.web.servlet.HandlerInterceptor")).matches(type);
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static boolean shapedHttpServlet(TypeDescription type) {
        String name = type.getName();
        // Explicit Spring MVC surfaces: service() may be inherited, so do not require a local
        // declaration (getDeclaredMethods misses FrameworkServlet.service on DispatcherServlet).
        if (name.equals("org.springframework.web.servlet.DispatcherServlet")
                || name.equals("org.springframework.web.servlet.FrameworkServlet")
                || name.endsWith(".DispatcherServlet")) {
            return true;
        }
        if (!(name.endsWith("Servlet") || name.contains("DispatcherServlet"))) return false;
        return type.getDeclaredMethods().filter(isMethod()
                .and(namedOneOf("service", "doGet", "doPost", "doPut", "doDelete", "doPatch"))
                .and(not(isAbstract()))
                .and(takesArguments(2))).size() > 0;
    }

    private static boolean shapedHttpFilter(TypeDescription type) {
        String name = type.getName();
        if (name.equals("org.springframework.web.filter.OncePerRequestFilter")
                || name.equals("org.springframework.web.filter.GenericFilterBean")
                || name.endsWith("OncePerRequestFilter")) {
            return true;
        }
        if (!(name.endsWith("Filter") || name.contains(".filter.") || name.contains(".Filter"))) {
            return false;
        }
        // Subclasses often override doFilterInternal only; parent doFilter stays on OncePerRequestFilter.
        return type.getDeclaredMethods().filter(isMethod()
                .and(namedOneOf("doFilter", "doFilterInternal"))
                .and(not(isAbstract()))).size() > 0;
    }

    private static boolean shapedHttpInterceptor(TypeDescription type) {
        String name = type.getName();
        if (!name.contains("Interceptor")) return false;
        return type.getDeclaredMethods().filter(isMethod()
                .and(named("preHandle"))
                .and(not(isAbstract()))).size() > 0;
    }

    /** HTTP-only advice for framework types outside classPrefix (no call-site flood). */
    private static DynamicType.Builder<?> instrumentHttpSurface(
            DynamicType.Builder<?> builder, TypeDescription type) {
        DynamicType.Builder<?> instrumented = builder;
        boolean servlet = false;
        boolean filter = false;
        boolean interceptor = false;
        try {
            servlet = hasSuperType(named("jakarta.servlet.Servlet")
                    .or(named("javax.servlet.Servlet"))).matches(type);
            filter = hasSuperType(named("jakarta.servlet.Filter")
                    .or(named("javax.servlet.Filter"))).matches(type);
            interceptor = hasSuperType(named("org.springframework.web.servlet.HandlerInterceptor"))
                    .matches(type);
        } catch (Throwable ignored) {
            // Fall through to shape-based advice selection.
        }
        if (servlet || shapedHttpServlet(type)) {
            instrumented = instrumented.visit(Advice.to(ServletAdvice.class).on(
                    isMethod().and(namedOneOf("service", "doGet", "doPost", "doPut",
                            "doDelete", "doPatch", "doHead", "doOptions"))
                            .and(not(isAbstract()))));
        }
        if (filter || shapedHttpFilter(type)) {
            instrumented = instrumented.visit(Advice.to(FilterAdvice.class).on(
                    isMethod().and(namedOneOf("doFilter", "doFilterInternal"))
                            .and(not(isAbstract()))));
        }
        if (interceptor || shapedHttpInterceptor(type)) {
            instrumented = instrumented.visit(Advice.to(InterceptorAdvice.class).on(
                    isMethod().and(namedOneOf("preHandle", "postHandle", "afterCompletion"))
                            .and(not(isAbstract()))));
        }
        return instrumented;
    }

    private static DynamicType.Builder<?> instrumentApplicationCalls(
            DynamicType.Builder<?> builder,
            TypeDescription type) {
        DynamicType.Builder<?> instrumented = builder
                .visit(new DependencyCallSiteVisitor(type.getName()))
                .visit(Advice.to(SpringHandlerAdvice.class).on(
                        isMethod().and(isAnnotatedWith(namedOneOf(SPRING_MAPPING_ANNOTATIONS)))
                                .and(not(isAbstract()))));
        if (hasSuperType(named("java.sql.Statement")).matches(type) && !isInterface().matches(type)) {
            instrumented = instrumented.visit(Advice.to(JdbcAdvice.class).on(
                    isMethod().and(nameStartsWith("execute")).and(not(isAbstract()))));
        }
        instrumented = instrumentHttpSurface(instrumented, type);
        return instrumented;
    }

    public static final class JdbcAdvice {
        private JdbcAdvice() {
        }

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Origin("#t") String className,
                                 @Advice.Origin("#m") String methodName,
                                 @Advice.AllArguments Object[] args) {
            // Helpers must be public: Advice is inlined into foreign classes (incl. proxies).
            String sql = extractSqlArg(args);
            if (sql.isEmpty()) {
                AgentRuntime.recordTransformedMethod(
                        "JDBC", className, methodName, "IMPLEMENTATION_METHOD");
                return;
            }
            AgentRuntime.recordTransformedDetail("JDBC", className, methodName, sqlDetail(sql));
        }

        /** Visible to inlined advice bodies running in instrumented/proxy classes. */
        public static String extractSqlArg(Object[] args) {
            if (args == null) return "";
            for (Object arg : args) {
                if (!(arg instanceof String text)) continue;
                String trimmed = text.trim();
                if (trimmed.length() < 3) continue;
                String lower = trimmed.toLowerCase(java.util.Locale.ROOT);
                if (lower.startsWith("select") || lower.startsWith("insert") || lower.startsWith("update")
                        || lower.startsWith("delete") || lower.startsWith("replace")
                        || lower.startsWith("with") || lower.startsWith("show")
                        || lower.startsWith("explain") || lower.startsWith("set ")
                        || lower.startsWith("call ") || lower.startsWith("create")
                        || lower.startsWith("alter") || lower.startsWith("drop")
                        || lower.startsWith("truncate")) {
                    return trimmed.length() <= 256 ? trimmed : trimmed.substring(0, 256);
                }
            }
            return "";
        }

        public static Map<String, String> sqlDetail(String sql) {
            String lower = sql.toLowerCase(java.util.Locale.ROOT);
            String readWrite = lower.startsWith("select") || lower.startsWith("show")
                    || lower.startsWith("explain") ? "READ"
                    : lower.startsWith("insert") || lower.startsWith("update")
                    || lower.startsWith("delete") || lower.startsWith("replace") ? "WRITE" : "UNKNOWN";
            boolean parameterized = sql.contains("?");
            return Map.of("captureMode", "JDBC_STATEMENT",
                    "sql", sql,
                    "readWrite", readWrite,
                    "parameterized", Boolean.toString(parameterized),
                    "maliciousFragmentPresent",
                    Boolean.toString(lower.contains("'\"veyrion-sqli-meta")),
                    "parameterSummary", parameterized ? "jdbc-placeholders" : "inline",
                    "outcome", "OBSERVED");
        }
    }

    public static final class ServletAdvice {
        private ServletAdvice() {
        }

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static boolean enter(@Advice.Origin("#t") String className,
                                    @Advice.Origin("#m") String methodName,
                                    @Advice.AllArguments Object[] args) {
            boolean coverageScope = AgentRuntime.beginCoverageRequest();
            String httpMethod = "";
            String route = "";
            if (args != null) {
                for (Object arg : args) {
                    if (arg == null) continue;
                    try {
                        Object methodValue = arg.getClass().getMethod("getMethod").invoke(arg);
                        Object uriValue = arg.getClass().getMethod("getRequestURI").invoke(arg);
                        if (methodValue instanceof String text) httpMethod = text;
                        if (uriValue instanceof String text) route = text;
                        if (!httpMethod.isBlank() || !route.isBlank()) break;
                    } catch (Throwable ignored) {
                        // Not a servlet request argument.
                    }
                }
            }
            AgentRuntime.recordTransformedDetail("HTTP", className, methodName,
                    Map.of("captureMode", "SERVLET_METHOD",
                            "httpMethod", truncate(httpMethod, 16),
                            "route", truncate(route, 512)));
            return coverageScope;
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
        public static void exit(@Advice.Enter boolean coverageScope) {
            AgentRuntime.endCoverageRequest(coverageScope);
        }

        private static String truncate(String value, int max) {
            if (value == null) return "";
            return value.length() <= max ? value : value.substring(0, max);
        }
    }

    public static final class FilterAdvice {
        private FilterAdvice() {
        }

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static boolean enter(@Advice.Origin("#t") String className,
                                    @Advice.Origin("#m") String methodName,
                                    @Advice.AllArguments Object[] args) {
            boolean coverageScope = AgentRuntime.beginCoverageRequest();
            String httpMethod = "";
            String route = "";
            if (args != null) {
                for (Object arg : args) {
                    if (arg == null) continue;
                    try {
                        Object methodValue = arg.getClass().getMethod("getMethod").invoke(arg);
                        Object uriValue = arg.getClass().getMethod("getRequestURI").invoke(arg);
                        if (methodValue instanceof String text) httpMethod = text;
                        if (uriValue instanceof String text) route = text;
                        if (!httpMethod.isBlank() || !route.isBlank()) break;
                    } catch (Throwable ignored) {
                        // Not a servlet request argument.
                    }
                }
            }
            AgentRuntime.recordTransformedDetail("HTTP", className, methodName,
                    Map.of("captureMode", "SERVLET_FILTER",
                            "httpMethod", truncate(httpMethod, 16),
                            "route", truncate(route, 512)));
            return coverageScope;
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
        public static void exit(@Advice.Enter boolean coverageScope) {
            AgentRuntime.endCoverageRequest(coverageScope);
        }

        private static String truncate(String value, int max) {
            if (value == null) return "";
            return value.length() <= max ? value : value.substring(0, max);
        }
    }

    public static final class InterceptorAdvice {
        private InterceptorAdvice() {
        }

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static boolean enter(@Advice.Origin("#t") String className,
                                    @Advice.Origin("#m") String methodName,
                                    @Advice.AllArguments Object[] args) {
            boolean coverageScope = AgentRuntime.beginCoverageRequest();
            String httpMethod = "";
            String route = "";
            if (args != null) {
                for (Object arg : args) {
                    if (arg == null) continue;
                    try {
                        Object methodValue = arg.getClass().getMethod("getMethod").invoke(arg);
                        Object uriValue = arg.getClass().getMethod("getRequestURI").invoke(arg);
                        if (methodValue instanceof String text) httpMethod = text;
                        if (uriValue instanceof String text) route = text;
                        if (!httpMethod.isBlank() || !route.isBlank()) break;
                    } catch (Throwable ignored) {
                        // Not a servlet request argument.
                    }
                }
            }
            AgentRuntime.recordTransformedDetail("HTTP", className, methodName,
                    Map.of("captureMode", "SPRING_INTERCEPTOR",
                            "httpMethod", truncate(httpMethod, 16),
                            "route", truncate(route, 512)));
            return coverageScope;
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
        public static void exit(@Advice.Enter boolean coverageScope) {
            AgentRuntime.endCoverageRequest(coverageScope);
        }

        private static String truncate(String value, int max) {
            if (value == null) return "";
            return value.length() <= max ? value : value.substring(0, max);
        }
    }

    public static final class SpringHandlerAdvice {
        private SpringHandlerAdvice() {
        }

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static boolean enter(@Advice.Origin("#t") String className,
                                    @Advice.Origin("#m") String methodName,
                                    @Advice.AllArguments Object[] args) {
            boolean coverageScope = AgentRuntime.beginCoverageRequest();
            String httpMethod = "";
            String route = "";
            if (args != null) {
                for (Object arg : args) {
                    if (arg == null) continue;
                    try {
                        Object methodValue = arg.getClass().getMethod("getMethod").invoke(arg);
                        Object uriValue = arg.getClass().getMethod("getRequestURI").invoke(arg);
                        if (methodValue instanceof String text) httpMethod = text;
                        if (uriValue instanceof String text) route = text;
                        if (!httpMethod.isBlank() || !route.isBlank()) break;
                    } catch (Throwable ignored) {
                        // Controller args are often domain types, not the request.
                    }
                }
            }
            if (route.isBlank()) {
                String[] fromContext = resolveRequestFromContext();
                httpMethod = fromContext[0];
                route = fromContext[1];
            }
            // Entering a Spring @*Mapping handler means argument resolution already succeeded.
            java.util.HashMap<String, String> detail = new java.util.HashMap<>();
            detail.put("captureMode", "SPRING_MAPPING_ANNOTATION");
            detail.put("entryHit", "true");
            detail.put("parameterBound", "true");
            if (!httpMethod.isBlank()) detail.put("httpMethod", truncate(httpMethod, 16));
            if (!route.isBlank()) detail.put("route", truncate(route, 512));
            AgentRuntime.recordTransformedDetail("HTTP", className, methodName, detail);
            return coverageScope;
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
        public static void exit(@Advice.Enter boolean coverageScope) {
            AgentRuntime.endCoverageRequest(coverageScope);
        }

        /** Best-effort URI from Spring RequestContextHolder when controllers omit the request arg. */
        public static String[] resolveRequestFromContext() {
            String httpMethod = "";
            String route = "";
            try {
                Class<?> holder = Class.forName(
                        "org.springframework.web.context.request.RequestContextHolder");
                Object attrs = holder.getMethod("getRequestAttributes").invoke(null);
                if (attrs == null) return new String[]{"", ""};
                Object request = attrs.getClass().getMethod("getRequest").invoke(attrs);
                if (request == null) return new String[]{"", ""};
                Object methodValue = request.getClass().getMethod("getMethod").invoke(request);
                Object uriValue = request.getClass().getMethod("getRequestURI").invoke(request);
                if (methodValue instanceof String text) httpMethod = text;
                if (uriValue instanceof String text) route = text;
            } catch (Throwable ignored) {
                // Spring not on classpath or no active request.
            }
            return new String[]{httpMethod, route};
        }

        private static String truncate(String value, int max) {
            if (value == null) return "";
            return value.length() <= max ? value : value.substring(0, max);
        }
    }

    private static final class DependencyCallSiteVisitor extends AsmVisitorWrapper.AbstractBase {
        private final String callerClass;

        private DependencyCallSiteVisitor(String callerClass) {
            this.callerClass = callerClass;
        }

        @Override
        public ClassVisitor wrap(TypeDescription instrumentedType, ClassVisitor classVisitor,
                                 Implementation.Context implementationContext, TypePool typePool,
                                 FieldList<FieldDescription.InDefinedShape> fields,
                                 MethodList<?> methods, int writerFlags, int readerFlags) {
            return new ClassVisitor(Opcodes.ASM9, classVisitor) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                 String signature, String[] exceptions) {
                    MethodVisitor delegate = super.visitMethod(access, name, descriptor, signature, exceptions);
                    return new MethodVisitor(Opcodes.ASM9, delegate) {
                        private int invocationOrdinal;

                        @Override
                        public void visitMethodInsn(int opcode, String owner, String methodName,
                                                    String methodDescriptor, boolean isInterface) {
                            String eventType = eventType(owner, methodName);
                            if (eventType != null) {
                                super.visitLdcInsn(eventType);
                                super.visitLdcInsn(callerClass);
                                super.visitLdcInsn(name + descriptor);
                                super.visitLdcInsn(owner.replace('/', '.'));
                                super.visitLdcInsn(methodName);
                                super.visitLdcInsn(Integer.toString(invocationOrdinal));
                                super.visitMethodInsn(Opcodes.INVOKESTATIC,
                                        "com/aq/jvmsentinel/instrumentation/AgentRuntime",
                                        "recordInstrumentedCall",
                                        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;"
                                                + "Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                                        false);
                            }
                            invocationOrdinal++;
                            super.visitMethodInsn(opcode, owner, methodName, methodDescriptor, isInterface);
                        }

                        @Override
                        public void visitMaxs(int maxStack, int maxLocals) {
                            super.visitMaxs(maxStack + 6, maxLocals);
                        }
                    };
                }
            };
        }

        private static String eventType(String owner, String methodName) {
            if ("java/net/http/HttpClient".equals(owner)
                    && ("send".equals(methodName) || "sendAsync".equals(methodName))) {
                return "HTTP_CLIENT";
            }
            if ("java/net/InetAddress".equals(owner)
                    && ("getByName".equals(methodName) || "getAllByName".equals(methodName)
                    || "getCanonicalHostName".equals(methodName))) {
                return "DNS_LOOKUP_ATTEMPT";
            }
            if (("java/net/Socket".equals(owner) || "java/net/DatagramSocket".equals(owner))
                    && ("connect".equals(methodName) || "send".equals(methodName))) {
                return "NETWORK_CONNECT_ATTEMPT";
            }
            if ("java/net/URL".equals(owner)
                    && ("openConnection".equals(methodName) || "openStream".equals(methodName))) {
                return "NETWORK_REQUEST_ATTEMPT";
            }
            if ("java/net/URL".equals(owner)
                    && ("hashCode".equals(methodName) || "equals".equals(methodName))) {
                return "DNS_LOOKUP_ATTEMPT";
            }
            if (("javax/naming/InitialContext".equals(owner) || "javax/naming/Context".equals(owner))
                    && "lookup".equals(methodName)) {
                return "JNDI_LOOKUP_ATTEMPT";
            }
            if ("java/lang/ProcessBuilder".equals(owner) && "start".equals(methodName)
                    || "java/lang/Runtime".equals(owner) && methodName.startsWith("exec")) {
                return "PROCESS";
            }
            if ("java/nio/file/Files".equals(owner)
                    && (methodName.startsWith("write") || "newOutputStream".equals(methodName))) {
                return "FILE";
            }
            if (("java/io/FileOutputStream".equals(owner) || "java/io/FileWriter".equals(owner))
                    && "<init>".equals(methodName)) {
                return "FILE";
            }
            return null;
        }
    }
}
