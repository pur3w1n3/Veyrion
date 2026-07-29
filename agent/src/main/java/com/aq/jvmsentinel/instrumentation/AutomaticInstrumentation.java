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
import java.util.LinkedHashMap;
import java.util.Map;

import static net.bytebuddy.matcher.ElementMatchers.hasSuperType;
import static net.bytebuddy.matcher.ElementMatchers.isAbstract;
import static net.bytebuddy.matcher.ElementMatchers.isAnnotatedWith;
import static net.bytebuddy.matcher.ElementMatchers.isConstructor;
import static net.bytebuddy.matcher.ElementMatchers.isInterface;
import static net.bytebuddy.matcher.ElementMatchers.isStatic;
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
/** Public so Byte Buddy advice inlined into foreign packages can call helpers/nested types. */
public final class AutomaticInstrumentation {
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
        // Must allow class-format changes: FilterAdvice FORCED_REACHABILITY uses
        // OnMethodEnter(skipOn=...) to short-circuit recognized auth filters. Branch coverage
        // also requires format changes when enabled. (Previously Advice-only mode called
        // disableClassFormatChanges, which silently disabled FORCED skip.)
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
        return shapedHttpServlet(type) || shapedHttpFilter(type) || shapedHttpInterceptor(type)
                || shapedAccessControlDecision(type) || shapedMethodSecurityInterceptor(type);
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
                || name.endsWith("OncePerRequestFilter")
                || name.equals("org.apache.shiro.web.servlet.AbstractShiroFilter")
                || name.contains("ShiroFilterFactoryBean$SpringShiroFilter")
                || name.equals("org.springframework.security.web.FilterChainProxy")) {
            return true;
        }
        // Shiro / Spring Security filter packages often inherit doFilter; do not require a local
        // declaration or TypePool servlet hierarchy (fat JARs hide javax/jakarta.servlet).
        if (name.startsWith("org.apache.shiro.web.filter.")
                || name.startsWith("org.apache.shiro.spring.web.")
                || name.startsWith("org.springframework.security.web.")) {
            return name.contains("Filter") || name.contains("filter");
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
            instrumented = instrumented.visit(Advice.to(AccessControlAdvice.class).on(
                    isMethod().and(named("isAccessAllowed")).and(not(isAbstract()))));
        } else if (shapedAccessControlDecision(type)) {
            instrumented = instrumented.visit(Advice.to(AccessControlAdvice.class).on(
                    isMethod().and(named("isAccessAllowed")).and(not(isAbstract()))));
        }
        if (interceptor || shapedHttpInterceptor(type)) {
            // preHandle: FORCED may skip body and force true (Blade TokenInterceptor etc.).
            instrumented = instrumented.visit(Advice.to(InterceptorPreHandleAdvice.class).on(
                    isMethod().and(named("preHandle")).and(not(isAbstract()))));
            instrumented = instrumented.visit(Advice.to(InterceptorAdvice.class).on(
                    isMethod().and(namedOneOf("postHandle", "afterCompletion"))
                            .and(not(isAbstract()))));
        }
        if (shapedMethodSecurityInterceptor(type)) {
            instrumented = instrumented.visit(Advice.to(MethodSecurityInterceptorAdvice.class).on(
                    isMethod().and(namedOneOf("invoke", "before")).and(not(isAbstract()))));
        }
        return instrumented;
    }

    private static boolean shapedMethodSecurityInterceptor(TypeDescription type) {
        String name = type.getName();
        return FrameworkBoundaryAdapter.isMethodSecurityInterceptorType(name);
    }

    private static boolean shapedAccessControlDecision(TypeDescription type) {
        String name = type.getName();
        if (!(name.contains("AccessControl") || name.contains("shiro.web.filter")
                || name.endsWith("LoginFilter") || name.endsWith("UserFilter"))) {
            return false;
        }
        return type.getDeclaredMethods().filter(isMethod()
                .and(named("isAccessAllowed"))
                .and(not(isAbstract()))).size() > 0;
    }

    private static DynamicType.Builder<?> instrumentApplicationCalls(
            DynamicType.Builder<?> builder,
            TypeDescription type) {
        DynamicType.Builder<?> instrumented = builder
                .visit(new DependencyCallSiteVisitor(type.getName()))
                .visit(Advice.to(MethodHopAdvice.class).on(
                        isMethod().and(not(isConstructor())).and(not(isStatic()))
                                .and(not(isAbstract()))
                                .and(not(namedOneOf("hashCode", "equals", "toString", "clone")))))
                .visit(Advice.to(SpringHandlerAdvice.class).on(
                        isMethod().and(isAnnotatedWith(namedOneOf(SPRING_MAPPING_ANNOTATIONS)))
                                .and(not(isAbstract()))))
                .visit(Advice.to(MethodSecurityAdvice.class).on(
                        isMethod().and(isAnnotatedWith(namedOneOf(
                                "org.springframework.security.access.prepost.PreAuthorize",
                                "org.springframework.security.access.annotation.Secured",
                                "jakarta.annotation.security.RolesAllowed",
                                "javax.annotation.security.RolesAllowed")))
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

        @Advice.OnMethodEnter
        public static void enter(@Advice.Origin("#t") String className,
                                 @Advice.Origin("#m") String methodName,
                                 @Advice.AllArguments Object[] args) throws java.sql.SQLException {
            String sql = extractSqlArg(args);
            if (sql.isEmpty()) {
                AgentRuntime.recordTransformedMethod(
                        "JDBC", className, methodName, "IMPLEMENTATION_METHOD");
                return;
            }
            if (observeFailMode()) {
                Map<String, String> failure = PathDebugDetail.merge(sqlDetail(sql),
                        PathDebugDetail.dependencyFailure("DEPENDENCY_UNAVAILABLE", sql));
                AgentRuntime.recordTransformedDetail("JDBC", className, methodName, failure);
                throw new java.sql.SQLException("veyrion OBSERVE_FAIL: dependency unavailable");
            }
            Map<String, String> detail = PathDebugDetail.merge(sqlDetail(sql),
                    PathDebugDetail.dependencyCall(sql));
            AgentRuntime.recordTransformedDetail("JDBC", className, methodName, detail);
        }

        public static boolean observeFailMode() {
            return "OBSERVE_FAIL".equalsIgnoreCase(
                    System.getProperty(AgentConfig.WORLD_PACK_DEPENDENCY_MODE_PROPERTY, "MOCK_CONTINUE"));
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
            Map<String, String> detail = new LinkedHashMap<>();
            detail.put("captureMode", "JDBC_STATEMENT");
            detail.put("sql", sql);
            detail.put("readWrite", readWrite);
            detail.put("parameterized", Boolean.toString(parameterized));
            detail.put("maliciousFragmentPresent",
                    Boolean.toString(lower.contains("'\"veyrion-sqli-meta")));
            detail.put("parameterSummary", parameterized ? "jdbc-placeholders" : "inline");
            detail.put("outcome", "OBSERVED");
            return detail;
        }
    }

    public static final class ServletAdvice {
        private ServletAdvice() {
        }

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Origin("#t") String className,
                                 @Advice.Origin("#m") String methodName,
                                 @Advice.AllArguments Object[] args) {
            HttpRequestView view = HttpRequestView.fromArgs(args);
            AgentRuntime.bindRequestCorrelation(view.correlationId);
            AgentRuntime.beginCoverageRequest();
            String posture = FrameworkBoundaryAdapter.resolvePosture(view.runtimePosture);
            FrameworkBoundaryAdapter.applyCoveragePosture(firstRequest(args), posture);
            Map<String, String> detail = httpDetail("SERVLET_METHOD", view);
            detail = PathDebugDetail.merge(detail, PathDebugDetail.methodHop("SERVLET_METHOD"));
            AgentRuntime.recordTransformedDetail("HTTP", className, methodName, detail);
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
        public static void exit() {
            AgentRuntime.endCoverageRequest();
            AgentRuntime.releaseRequestCorrelation();
        }
    }

    public static final class FilterAdvice {
        private FilterAdvice() {
        }

        /**
         * Returns {@code true} to skip the original filter body after FORCED continues the chain.
         * Non-forced paths return {@code false} (default) so the real filter runs.
         */
        @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class, suppress = Throwable.class)
        public static boolean enter(@Advice.Origin("#t") String className,
                                    @Advice.Origin("#m") String methodName,
                                    @Advice.This(optional = true) Object self,
                                    @Advice.AllArguments Object[] args) {
            // Shiro auth filters inherit doFilterInternal from AdviceFilter; Origin #t is the
            // declaring type. Prefer runtime class so LoginFilter / UserFilter are recognized.
            String runtimeType = self != null ? self.getClass().getName() : className;
            HttpRequestView view = HttpRequestView.fromArgs(args);
            AgentRuntime.bindRequestCorrelation(view.correlationId);
            AgentRuntime.beginCoverageRequest();
            String posture = FrameworkBoundaryAdapter.resolvePosture(view.runtimePosture);
            FrameworkBoundaryAdapter.applyCoveragePosture(firstRequest(args), posture);
            boolean skip = FrameworkBoundaryAdapter.forcePastRecognizedFilter(
                    posture, runtimeType, methodName, args);
            Map<String, String> detail = httpDetail("SERVLET_FILTER", view);
            detail = PathDebugDetail.merge(detail,
                    PathDebugDetail.guardDecision(skip ? "FORCED_ALLOW" : "ENTER", skip));
            if (skip) {
                detail = PathDebugDetail.merge(detail,
                        Map.of("forceMode", "SKIP_FILTER_CONTINUE_CHAIN",
                                "guardType", runtimeType));
            }
            AgentRuntime.recordTransformedDetail("HTTP", runtimeType, methodName, detail);
            return skip;
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
        public static void exit() {
            AgentRuntime.endCoverageRequest();
            AgentRuntime.releaseRequestCorrelation();
        }
    }

    /**
     * Spring HandlerInterceptor.preHandle under FORCED: skip original denial and return true.
     * Does not elevate VERIFIED; provenance remains INSTRUMENTATION_REACHABILITY.
     */
    public static final class InterceptorPreHandleAdvice {
        private InterceptorPreHandleAdvice() {
        }

        @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class, suppress = Throwable.class)
        public static boolean enter(@Advice.Origin("#t") String className,
                                    @Advice.Origin("#m") String methodName,
                                    @Advice.This(optional = true) Object self,
                                    @Advice.AllArguments Object[] args) {
            String runtimeType = self != null ? self.getClass().getName() : className;
            HttpRequestView view = HttpRequestView.fromArgs(args);
            AgentRuntime.bindRequestCorrelation(view.correlationId);
            AgentRuntime.beginCoverageRequest();
            String posture = FrameworkBoundaryAdapter.resolvePosture(view.runtimePosture);
            FrameworkBoundaryAdapter.applyCoveragePosture(firstRequest(args), posture);
            boolean force = FrameworkBoundaryAdapter.forceInterceptorPreHandle(
                    posture, runtimeType, methodName);
            Map<String, String> detail = httpDetail("SPRING_INTERCEPTOR", view);
            detail = PathDebugDetail.merge(detail,
                    PathDebugDetail.guardDecision(force ? "FORCED_ALLOW" : "ENTER", force));
            if (force) {
                detail = PathDebugDetail.merge(detail,
                        Map.of("forceMode", "INTERCEPTOR_PREHANDLE_TRUE",
                                "guardType", runtimeType));
            }
            AgentRuntime.recordTransformedDetail("HTTP", runtimeType, methodName, detail);
            return force;
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
        public static void exit(@Advice.Enter boolean forced,
                                @Advice.Return(readOnly = false) boolean allowed) {
            if (forced) {
                allowed = true;
            }
            AgentRuntime.endCoverageRequest();
            AgentRuntime.releaseRequestCorrelation();
        }
    }

    public static final class InterceptorAdvice {
        private InterceptorAdvice() {
        }

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Origin("#t") String className,
                                 @Advice.Origin("#m") String methodName,
                                 @Advice.AllArguments Object[] args) {
            HttpRequestView view = HttpRequestView.fromArgs(args);
            AgentRuntime.bindRequestCorrelation(view.correlationId);
            AgentRuntime.beginCoverageRequest();
            String posture = FrameworkBoundaryAdapter.resolvePosture(view.runtimePosture);
            FrameworkBoundaryAdapter.applyCoveragePosture(firstRequest(args), posture);
            Map<String, String> detail = httpDetail("SPRING_INTERCEPTOR", view);
            AgentRuntime.recordTransformedDetail("HTTP", className, methodName, detail);
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
        public static void exit() {
            AgentRuntime.endCoverageRequest();
            AgentRuntime.releaseRequestCorrelation();
        }
    }

    /**
     * P1: Shiro AccessControlFilter.isAccessAllowed (and app LoginFilter overrides) under FORCED.
     * Skips the original body and forces a {@code true} return; does not continue FilterChain.
     */
    public static final class AccessControlAdvice {
        private AccessControlAdvice() {
        }

        @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class, suppress = Throwable.class)
        public static boolean enter(@Advice.Origin("#t") String className,
                                    @Advice.Origin("#m") String methodName,
                                    @Advice.This(optional = true) Object self,
                                    @Advice.AllArguments Object[] args) {
            String runtimeType = self != null ? self.getClass().getName() : className;
            HttpRequestView view = HttpRequestView.fromArgs(args);
            String posture = FrameworkBoundaryAdapter.resolvePosture(view.runtimePosture);
            boolean force = FrameworkBoundaryAdapter.forceAccessAllowed(
                    posture, runtimeType, methodName);
            if (force) {
                Map<String, String> detail = httpDetail("ACCESS_CONTROL", view);
                detail = PathDebugDetail.merge(detail,
                        PathDebugDetail.guardDecision("FORCED_ALLOW", true));
                detail = PathDebugDetail.merge(detail,
                        Map.of("forceMode", "ACCESS_ALLOWED_TRUE", "guardType", runtimeType));
                AgentRuntime.recordTransformedDetail("HTTP", runtimeType, methodName, detail);
            }
            return force;
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
        public static void exit(@Advice.Enter boolean forced,
                                @Advice.Return(readOnly = false) boolean allowed) {
            if (forced) {
                allowed = true;
            }
        }
    }

    public static final class SpringHandlerAdvice {
        private SpringHandlerAdvice() {
        }

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Origin("#t") String className,
                                 @Advice.Origin("#m") String methodName,
                                 @Advice.AllArguments Object[] args) {
            HttpRequestView view = HttpRequestView.fromArgs(args);
            if (view.route.isBlank()) {
                String[] fromContext = resolveRequestFromContext();
                view = new HttpRequestView(fromContext[0], fromContext[1],
                        view.correlationId.isBlank() ? correlationFromContext() : view.correlationId);
            }
            AgentRuntime.bindRequestCorrelation(view.correlationId);
            AgentRuntime.beginCoverageRequest();
            // Entering a Spring @*Mapping handler means argument resolution already succeeded.
            Map<String, String> detail = httpDetail("SPRING_MAPPING_ANNOTATION", view);
            detail = new LinkedHashMap<>(detail);
            detail.put("entryHit", "true");
            detail.put("parameterBound", "true");
            detail = PathDebugDetail.merge(detail, PathDebugDetail.methodHop("SPRING_MAPPING_ANNOTATION"));
            AgentRuntime.recordTransformedDetail("HTTP", className, methodName, detail);
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
        public static void exit() {
            AgentRuntime.endCoverageRequest();
            AgentRuntime.releaseRequestCorrelation();
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

        public static String correlationFromContext() {
            try {
                Class<?> holder = Class.forName(
                        "org.springframework.web.context.request.RequestContextHolder");
                Object attrs = holder.getMethod("getRequestAttributes").invoke(null);
                if (attrs == null) return "";
                Object request = attrs.getClass().getMethod("getRequest").invoke(attrs);
                return HttpRequestView.header(request, "X-Veyrion-Correlation-Id");
            } catch (Throwable ignored) {
                return "";
            }
        }
    }

    public static final class MethodHopAdvice {
        private MethodHopAdvice() {
        }

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Origin("#t") String className,
                                 @Advice.Origin("#m") String methodName) {
            // Drop XSS/CGLIB flood (kvf HTMLFilter alone burned ~8k events / maxEvents)
            // so FORCED PathTraces retain Controller→Service→Repository hops.
            if (!AgentRuntime.shouldRecordMethodHop(className, methodName)) {
                return;
            }
            AgentRuntime.recordTransformedDetail("HTTP", className, methodName,
                    PathDebugDetail.methodHop("APPLICATION_METHOD"));
        }
    }

    public static final class MethodSecurityAdvice {
        private MethodSecurityAdvice() {
        }

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Origin("#t") String className,
                                 @Advice.Origin("#m") String methodName) {
            // Prefer per-request posture header via Spring RequestContextHolder; JVM -D is fallback.
            String posture = FrameworkBoundaryAdapter.resolvePosture(postureHeaderFromContext());
            if (posture.isBlank() || "UNAUTH".equals(posture)) {
                posture = FrameworkBoundaryAdapter.configuredPosture();
            }
            FrameworkBoundaryAdapter.applyCoveragePosture(null, posture);
            boolean forced = FrameworkBoundaryAdapter.forcedReachabilityActive(posture);
            Map<String, String> extra = new LinkedHashMap<>();
            extra.put("captureMode", "METHOD_SECURITY");
            if (forced) {
                // Annotation body reached under FORCED — wall was fail-opened upstream or absent.
                extra.put("forceMode", "METHOD_SECURITY_ANNOTATION_OBSERVED");
            }
            FrameworkBoundaryAdapter.recordGuardDecision(className, methodName,
                    forced ? "FORCED_ALLOW" : "CHECK", forced, extra);
        }

        public static String postureHeaderFromContext() {
            try {
                Class<?> holder = Class.forName(
                        "org.springframework.web.context.request.RequestContextHolder");
                Object attrs = holder.getMethod("getRequestAttributes").invoke(null);
                if (attrs == null) {
                    return "";
                }
                Object request = attrs.getClass().getMethod("getRequest").invoke(attrs);
                return HttpRequestView.header(request, FrameworkBoundaryAdapter.POSTURE_HEADER);
            } catch (Throwable ignored) {
                return "";
            }
        }
    }

    /**
     * FORCED fail-open for Spring {@code MethodSecurityInterceptor} /
     * {@code AuthorizationManagerBeforeMethodInterceptor}: skip the authorization check and
     * {@code proceed()} the MethodInvocation. Provenance remains INSTRUMENTATION_REACHABILITY.
     */
    public static final class MethodSecurityInterceptorAdvice {
        private MethodSecurityInterceptorAdvice() {
        }

        @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class, suppress = Throwable.class)
        public static boolean enter(@Advice.Origin("#t") String className,
                                    @Advice.Origin("#m") String methodName,
                                    @Advice.This(optional = true) Object self) {
            String runtimeType = self != null ? self.getClass().getName() : className;
            String posture = FrameworkBoundaryAdapter.resolvePosture(
                    MethodSecurityAdvice.postureHeaderFromContext());
            if (posture.isBlank() || "UNAUTH".equals(posture)) {
                posture = FrameworkBoundaryAdapter.configuredPosture();
            }
            boolean force = FrameworkBoundaryAdapter.forceMethodSecurity(
                    posture, runtimeType, methodName);
            if (force) {
                FrameworkBoundaryAdapter.recordGuardDecision(runtimeType, methodName,
                        "FORCED_ALLOW", true,
                        Map.of("captureMode", "METHOD_SECURITY",
                                "forceMode", "METHOD_SECURITY_FAIL_OPEN",
                                "guardType", runtimeType));
            }
            return force;
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
        public static void exit(@Advice.Enter boolean forced,
                                @Advice.AllArguments Object[] args,
                                @Advice.Return(readOnly = false) Object returned) {
            if (!forced || args == null || args.length == 0 || args[0] == null) {
                return;
            }
            try {
                Object invocation = args[0];
                returned = invocation.getClass().getMethod("proceed").invoke(invocation);
            } catch (Throwable ignored) {
                // Best-effort proceed; leave returned as-is on failure.
            }
        }
    }

    /** Best-effort first servlet request argument from advice args. */
    public static Object firstRequest(Object[] args) {
        if (args == null) return null;
        for (Object arg : args) {
            if (arg == null) continue;
            try {
                arg.getClass().getMethod("getMethod");
                return arg;
            } catch (Throwable ignored) {
                // not a request
            }
        }
        return null;
    }

    /** Visible to Advice bodies inlined into application / framework classes. */
    public static Map<String, String> httpDetail(String captureMode, HttpRequestView view) {
        Map<String, String> detail = new LinkedHashMap<>();
        detail.put("captureMode", captureMode);
        if (view.httpMethod != null && !view.httpMethod.isBlank()) {
            detail.put("httpMethod", truncate(view.httpMethod, 16));
        }
        if (view.route != null && !view.route.isBlank()) {
            detail.put("route", truncate(view.route, 512));
        }
        if (view.correlationId != null && !view.correlationId.isBlank()) {
            detail.put("correlationId", truncate(view.correlationId, 64));
        }
        return detail;
    }

    private static String truncate(String value, int max) {
        if (value == null) return "";
        return value.length() <= max ? value : value.substring(0, max);
    }

    /** Public so Advice-inlined bodies in foreign classes can call helpers. */
    public static final class HttpRequestView {
        public final String httpMethod;
        public final String route;
        public final String correlationId;
        public final String runtimePosture;

        public HttpRequestView(String httpMethod, String route, String correlationId, String runtimePosture) {
            this.httpMethod = httpMethod == null ? "" : httpMethod;
            this.route = route == null ? "" : route;
            this.correlationId = correlationId == null ? "" : correlationId;
            this.runtimePosture = runtimePosture == null ? "" : runtimePosture;
        }

        public HttpRequestView(String httpMethod, String route, String correlationId) {
            this(httpMethod, route, correlationId, "");
        }

        public static HttpRequestView fromArgs(Object[] args) {
            String httpMethod = "";
            String route = "";
            String correlationId = "";
            String runtimePosture = "";
            if (args != null) {
                for (Object arg : args) {
                    if (arg == null) continue;
                    try {
                        Object methodValue = arg.getClass().getMethod("getMethod").invoke(arg);
                        Object uriValue = arg.getClass().getMethod("getRequestURI").invoke(arg);
                        if (methodValue instanceof String text) httpMethod = text;
                        if (uriValue instanceof String text) route = text;
                        if (correlationId.isBlank()) {
                            correlationId = header(arg, "X-Veyrion-Correlation-Id");
                        }
                        if (runtimePosture.isBlank()) {
                            runtimePosture = header(arg, FrameworkBoundaryAdapter.POSTURE_HEADER);
                        }
                        if (!httpMethod.isBlank() || !route.isBlank()) break;
                    } catch (Throwable ignored) {
                        // Not a servlet request argument.
                    }
                }
            }
            return new HttpRequestView(httpMethod, route, correlationId, runtimePosture);
        }

        public static String header(Object request, String name) {
            if (request == null || name == null || name.isBlank()) return "";
            try {
                Object value = request.getClass().getMethod("getHeader", String.class).invoke(request, name);
                return value instanceof String text ? text.trim() : "";
            } catch (Throwable ignored) {
                return "";
            }
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

        /**
         * Top-level eventType must stay inside AgentJsonlTraceConverter whitelist.
         * Security nuance (SSRF / JNDI / DESERIALIZATION / multi-kind) goes in
         * pathDebugKind + effectKind / secondaryEffectKinds detail markers.
         */
        private static String eventType(String owner, String methodName) {
            if ("java/net/http/HttpClient".equals(owner)
                    && ("send".equals(methodName) || "sendAsync".equals(methodName))) {
                return "HTTP_CLIENT";
            }
            // Remap former NETWORK_* / DNS_* attempt labels onto HTTP_CLIENT + effectKind=SSRF.
            if ("java/net/InetAddress".equals(owner)
                    && ("getByName".equals(methodName) || "getAllByName".equals(methodName)
                    || "getCanonicalHostName".equals(methodName))) {
                return "HTTP_CLIENT";
            }
            if (("java/net/Socket".equals(owner) || "java/net/DatagramSocket".equals(owner))
                    && ("connect".equals(methodName) || "send".equals(methodName))) {
                return "HTTP_CLIENT";
            }
            if ("java/net/URL".equals(owner)
                    && ("openConnection".equals(methodName) || "openStream".equals(methodName))) {
                return "HTTP_CLIENT";
            }
            if (("javax/naming/InitialContext".equals(owner) || "javax/naming/Context".equals(owner)
                    || "javax/naming/directory/InitialDirContext".equals(owner))
                    && ("lookup".equals(methodName) || "doLookup".equals(methodName))) {
                return "JNDI";
            }
            if ("java/sql/DriverManager".equals(owner) && "getConnection".equals(methodName)) {
                return "JDBC";
            }
            if ("java/sql/Driver".equals(owner) && "connect".equals(methodName)) {
                return "JDBC";
            }
            if ("java/lang/Class".equals(owner)
                    && ("forName".equals(methodName) || "newInstance".equals(methodName))) {
                return "CLASS_LOAD";
            }
            if ("java/net/URLClassLoader".equals(owner)
                    && ("loadClass".equals(methodName) || "findClass".equals(methodName)
                    || "<init>".equals(methodName))) {
                return "CLASS_LOAD";
            }
            if ("java/io/ObjectInputStream".equals(owner)
                    && ("readObject".equals(methodName) || "readUnshared".equals(methodName))) {
                return "PROCESS";
            }
            if (("javax/script/ScriptEngine".equals(owner) || "jakarta/script/ScriptEngine".equals(owner))
                    && "eval".equals(methodName)) {
                return "PROCESS";
            }
            // QLExpress (kvf GenServiceImpl CheckCode) — expression injection sink.
            if ("com/ql/util/express/ExpressRunner".equals(owner)
                    && ("execute".equals(methodName) || "executeExt".equals(methodName))) {
                return "PROCESS";
            }
            if ("java/lang/ProcessBuilder".equals(owner) && "start".equals(methodName)
                    || "java/lang/Runtime".equals(owner) && methodName.startsWith("exec")) {
                return "PROCESS";
            }
            if ("java/nio/file/Files".equals(owner)
                    && (methodName.startsWith("write") || "newOutputStream".equals(methodName)
                    || methodName.startsWith("read") || "newInputStream".equals(methodName)
                    || "newBufferedReader".equals(methodName))) {
                return "FILE";
            }
            if (("java/io/FileOutputStream".equals(owner) || "java/io/FileWriter".equals(owner)
                    || "java/io/FileInputStream".equals(owner) || "java/io/FileReader".equals(owner))
                    && "<init>".equals(methodName)) {
                return "FILE";
            }
            return null;
        }
    }
}
