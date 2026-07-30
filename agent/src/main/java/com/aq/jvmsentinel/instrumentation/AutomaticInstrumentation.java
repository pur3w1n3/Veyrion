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
 * 仅启动期插桩。Bootstrap 类故意不转换；对选定 JDK
 * API 的调用改在非 bootstrap 应用 call site 观测。
 */
/** 公开以便内联到外部包的 Byte Buddy advice 可调用 helper/嵌套类型。 */
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
        // CLASS_LOAD 保持 classPrefix 范围。Servlet/Filter/Interceptor HTTP 捕获须忽略
        // classPrefix，否则 auth 拒绝永不为目标 controller 产生 HTTP 证据。
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
        // 须允许 class-format 变更：FilterAdvice FORCED_REACHABILITY 使用
        // 经 OnMethodEnter(skipOn=...) 短路已识别 auth filter；Branch coverage
        // 启用时亦需 format 变更。（此前仅 Advice 模式调用
        // 调用 disableClassFormatChanges 会静默禁用 FORCED skip。）
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
        // 当 servlet API 对 ByteBuddy TypePool 可见时优先 hierarchy。
        if (hierarchyHttpSurface(type)) return true;
        // Spring Boot fat JAR 常对 TypePool 隐藏 javax/jakarta.servlet，hasSuperType
        // 对 DispatcherServlet/Filter 返回 false，尽管它们是 HTTP surface。
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
        // 显式 Spring MVC surface：service() 可继承，勿要求 local
        // 声明（getDeclaredMethods 会漏 DispatcherServlet 上 FrameworkServlet.service）。
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
        // 说明：Shiro/Spring Security filter 包常继承 doFilter；勿要求 local
        // 声明或 TypePool servlet hierarchy（fat JAR 隐藏 javax/jakarta.servlet）。
        if (name.startsWith("org.apache.shiro.web.filter.")
                || name.startsWith("org.apache.shiro.spring.web.")
                || name.startsWith("org.springframework.security.web.")) {
            return name.contains("Filter") || name.contains("filter");
        }
        if (!(name.endsWith("Filter") || name.contains(".filter.") || name.contains(".Filter"))) {
            return false;
        }
        // 子类常仅 override doFilterInternal；父 doFilter 留在 OncePerRequestFilter。
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
            // 继续 shape-based advice 选择。
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
            // preHandle：FORCED 可跳过 body 并 force true（Blade TokenInterceptor 等）。
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
         * FORCED 继续 chain 后返回 {@code true} 以跳过原 filter body。
         * 非 FORCED 路径返回 {@code false}（默认），使真实 filter 运行。
         */
        @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class, suppress = Throwable.class)
        public static boolean enter(@Advice.Origin("#t") String className,
                                    @Advice.Origin("#m") String methodName,
                                    @Advice.This(optional = true) Object self,
                                    @Advice.AllArguments Object[] args) {
            // Shiro auth filter 自 AdviceFilter 继承 doFilterInternal；Origin #t 为
            // 声明类型。优先 runtime class 以识别 LoginFilter / UserFilter。
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
     * FORCED 下 Spring HandlerInterceptor.preHandle：跳过原拒绝并返回 true。
     * 不提升 VERIFIED；provenance 仍为 INSTRUMENTATION_REACHABILITY。
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
     * P1：FORCED 下 Shiro AccessControlFilter.isAccessAllowed（及 app LoginFilter override）。
     * 跳过原 body 并 force {@code true} 返回；不继续 FilterChain。
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
            // 进入 Spring @*Mapping handler 表示参数解析已成功。
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
                // classpath 无 Spring 或无 active request。
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
            // 丢弃 XSS/CGLIB 洪泛（kvf HTMLFilter 单独消耗 ~8k events / maxEvents）
            // 以便 FORCED PathTrace 保留 Controller→Service→Repository hop。
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
            // 优先经 Spring RequestContextHolder 的 per-request posture header；JVM -D 为 fallback。
            String posture = FrameworkBoundaryAdapter.resolvePosture(postureHeaderFromContext());
            if (posture.isBlank() || "UNAUTH".equals(posture)) {
                posture = FrameworkBoundaryAdapter.configuredPosture();
            }
            FrameworkBoundaryAdapter.applyCoveragePosture(null, posture);
            boolean forced = FrameworkBoundaryAdapter.forcedReachabilityActive(posture);
            Map<String, String> extra = new LinkedHashMap<>();
            extra.put("captureMode", "METHOD_SECURITY");
            if (forced) {
                // FORCED 下到达 annotation body — 上游 wall 已 fail-open 或不存在。
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
     * 说明：Spring {@code MethodSecurityInterceptor} 的 FORCED fail-open：
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
                // 尽力 proceed；失败时 returned 保持原样。
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
                // 非 request
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
                        // 非 servlet request 参数。
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
         * 顶层 eventType 须留在 AgentJsonlTraceConverter 白名单内。
         * 安全细节（SSRF / JNDI / DESERIALIZATION / multi-kind）写入
         * 细节标记：pathDebugKind + effectKind / secondaryEffectKinds。
         */
        private static String eventType(String owner, String methodName) {
            if ("java/net/http/HttpClient".equals(owner)
                    && ("send".equals(methodName) || "sendAsync".equals(methodName))) {
                return "HTTP_CLIENT";
            }
            // 将原 NETWORK_* / DNS_* attempt 标签重映射到 HTTP_CLIENT + effectKind=SSRF。
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
            // QLExpress 表达式注入 sink（kvf GenServiceImpl CheckCode）。
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
