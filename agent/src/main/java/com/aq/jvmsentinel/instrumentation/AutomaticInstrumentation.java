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
 * 仅启动期插桩。Bootstrap JDK 类故意不转换（UNSUPPORTED_FAIL_EXPLICIT）；
 * 危险原语优先在应用 call-site 观测 JDK/标准库汇聚点；框架面（Multipart/
 * RestTemplate/SpEL/DataSource）为补充。观测细、确认严——EFFECT ≠ DYNAMIC_CONFIRMED。
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
                loader != null && (isHttpObservabilityType(type) || isJdbcDataSourceEffectType(type)
                        || isMultipartFileEffectType(type)
                        || isHttpClientEffectType(type)
                        || isExpressionEffectType(type)
                        || config.includes(type.getName()));

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
                    if (!prefixed && isJdbcDataSourceEffectType(type)) {
                        transformed = instrumentJdbcDataSourceSurface(builder0);
                    } else if (!prefixed && isMultipartFileEffectType(type)) {
                        transformed = instrumentMultipartFileSurface(builder0);
                    } else if (!prefixed && isHttpClientEffectType(type)) {
                        transformed = instrumentHttpClientSurface(builder0);
                    } else if (!prefixed && isExpressionEffectType(type)) {
                        transformed = instrumentExpressionSurface(builder0);
                    } else if (!prefixed && isHttpObservabilityType(type)) {
                        transformed = instrumentHttpSurface(builder0, type);
                    } else {
                        transformed = instrumentApplicationCalls(builder0, type);
                        if (prefixed && isMultipartFileEffectType(type)) {
                            transformed = instrumentMultipartFileSurface(transformed);
                        }
                        if (prefixed && isHttpClientEffectType(type)) {
                            transformed = instrumentHttpClientSurface(transformed);
                        }
                        if (prefixed && isExpressionEffectType(type)) {
                            transformed = instrumentExpressionSurface(transformed);
                        }
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
                || shapedAccessControlDecision(type) || shapedMethodSecurityInterceptor(type)
                || shapedRememberMeManager(type);
    }

    /** Shiro rememberMe 反序列化面：classPrefix 外也要观测 DESERIALIZATION effect。 */
    private static boolean shapedRememberMeManager(TypeDescription type) {
        String name = type.getName();
        return name.equals("org.apache.shiro.mgt.AbstractRememberMeManager")
                || name.equals("org.apache.shiro.web.mgt.CookieRememberMeManager")
                || name.endsWith("RememberMeManager")
                || name.contains("shiro.mgt.AbstractRememberMeManager");
    }

    /**
     * Spring/Druid/DBCP/Hikari URL 可配置 DataSource：classPrefix 外也要观测 JDBC/SSRF。
     * kvf {@code CommonController#testDatabaseConnection} 调
     * {@code DriverManagerDataSource#setUrl/getConnection}，真正的
     * {@code DriverManager.getConnection} 在 spring-jdbc 内，仅靠应用 call site 会漏掉。
     */
    private static boolean isJdbcDataSourceEffectType(TypeDescription type) {
        String name = type.getName();
        return name.equals("org.springframework.jdbc.datasource.DriverManagerDataSource")
                || name.equals("com.alibaba.druid.pool.DruidDataSource")
                || name.equals("org.apache.commons.dbcp2.BasicDataSource")
                || name.equals("org.apache.tomcat.dbcp.dbcp2.BasicDataSource")
                || name.equals("com.zaxxer.hikari.HikariConfig")
                || name.equals("com.zaxxer.hikari.HikariDataSource");
    }

    private static DynamicType.Builder<?> instrumentJdbcDataSourceSurface(
            DynamicType.Builder<?> builder) {
        return builder.visit(Advice.to(JdbcDataSourceAdvice.class).on(
                isMethod().and(namedOneOf("setUrl", "setJdbcUrl", "getConnection"))
                        .and(not(isAbstract()))));
    }

    /**
     * RestTemplate：静态 SSRF sink 在 spring-web 内；仅靠应用 call site 时若经包装/
     * 反射调用会漏。classPrefix 外织入 exchange/getForObject 等。
     */
    private static boolean isHttpClientEffectType(TypeDescription type) {
        return "org.springframework.web.client.RestTemplate".equals(type.getName());
    }

    private static DynamicType.Builder<?> instrumentHttpClientSurface(
            DynamicType.Builder<?> builder) {
        return builder.visit(Advice.to(HttpClientSsrfAdvice.class).on(
                isMethod().and(namedOneOf(
                                "getForObject", "getForEntity", "postForObject", "postForEntity",
                                "exchange", "execute"))
                        .and(not(isAbstract()))));
    }

    /**
     * SpEL Expression#getValue：实现类在 spring-expression，classPrefix 外也要观测。
     */
    private static boolean isExpressionEffectType(TypeDescription type) {
        String name = type.getName();
        return name.equals("org.springframework.expression.spel.standard.SpelExpression")
                || name.equals("org.springframework.expression.spel.standard.SpelExpressionParser");
    }

    private static DynamicType.Builder<?> instrumentExpressionSurface(
            DynamicType.Builder<?> builder) {
        return builder.visit(Advice.to(ExpressionEvalAdvice.class).on(
                isMethod().and(namedOneOf("getValue", "getValueType", "parseExpression"))
                        .and(not(isAbstract()))));
    }

    /**
     * Spring {@code MultipartFile#transferTo}：框架补充面（非唯一策略）。
     * 优先仍靠 JDK {@code FileOutputStream}/{@code Files.write*} 应用 call-site；
     * 库内写盘不经应用字节码时本 advice 补洞。effectKind={@code FILE_WRITE}。
     */
    private static boolean isMultipartFileEffectType(TypeDescription type) {
        if (isInterface().matches(type)) {
            return false;
        }
        String name = type.getName();
        if (!(name.endsWith("MultipartFile")
                || name.endsWith("$StandardMultipartFile")
                || name.contains(".support.StandardMultipartFile")
                || name.equals("org.springframework.web.multipart.commons.CommonsMultipartFile"))) {
            return false;
        }
        return type.getDeclaredMethods()
                .filter(isMethod().and(named("transferTo")).and(not(isAbstract())))
                .size() > 0;
    }

    private static DynamicType.Builder<?> instrumentMultipartFileSurface(
            DynamicType.Builder<?> builder) {
        return builder.visit(Advice.to(MultipartFileTransferAdvice.class).on(
                isMethod().and(named("transferTo")).and(not(isAbstract()))));
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
        if (shapedRememberMeManager(type)) {
            instrumented = instrumented.visit(Advice.to(RememberMeDeserializeAdvice.class).on(
                    isMethod().and(namedOneOf("deserialize", "convertBytesToPrincipals",
                                    "getRememberedPrincipals", "getRememberedSerializedIdentity"))
                            .and(not(isAbstract()))));
        }
        return instrumented;
    }

    /**
     * Shiro rememberMe 解密/反序列化入口：记录 DESERIALIZATION effect，
     * 供 H4 动态确认（不表示 RCE 成功）。
     */
    public static final class RememberMeDeserializeAdvice {
        private RememberMeDeserializeAdvice() {
        }

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Origin("#t") String className,
                                 @Advice.Origin("#m") String methodName) {
            Map<String, String> detail = new LinkedHashMap<>();
            detail.put("captureMode", "SHIRO_REMEMBER_ME");
            detail.putAll(PathDebugDetail.effectTriggered("DESERIALIZATION"));
            detail.put("secondaryEffectKinds", "CLASS_LOADING");
            AgentRuntime.recordTransformedDetail("PROCESS", className, methodName, detail);
        }
    }

    /**
     * DataSource URL/connect 面：记录 JDBC + SSRF effect（与静态
     * {@code DriverManagerDataSource#setUrl} sink 对齐）。
     */
    public static final class JdbcDataSourceAdvice {
        private JdbcDataSourceAdvice() {
        }

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Origin("#t") String className,
                                 @Advice.Origin("#m") String methodName,
                                 @Advice.AllArguments Object[] args) {
            if (!AgentRuntime.isJdbcUrlSsrfSink(className, methodName)) {
                return;
            }
            Map<String, String> detail = new LinkedHashMap<>();
            detail.put("captureMode", "DATASOURCE_METHOD");
            detail.put("operation", methodName == null ? "" : methodName);
            detail.put("targetClass", className == null ? "" : className);
            detail.put("targetMethod", methodName == null ? "" : methodName);
            if (("setUrl".equals(methodName) || "setJdbcUrl".equals(methodName))
                    && args != null && args.length > 0
                    && args[0] instanceof String url && !url.isBlank()) {
                detail.put("url", url.length() <= 256 ? url : url.substring(0, 256));
            }
            detail.putAll(PathDebugDetail.effectTriggered("SSRF"));
            detail.put("secondaryEffectKinds", "COMMAND,CLASS_LOADING");
            AgentRuntime.recordTransformedDetail("JDBC", className, methodName, detail);
        }
    }

    /**
     * RestTemplate SSRF 面：记录 HTTP_CLIENT + EFFECT_TRIGGERED SSRF。
     */
    public static final class HttpClientSsrfAdvice {
        private HttpClientSsrfAdvice() {
        }

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Origin("#t") String className,
                                 @Advice.Origin("#m") String methodName) {
            if (!AgentRuntime.isHttpClientSsrfSink(className, methodName)) {
                return;
            }
            Map<String, String> detail = new LinkedHashMap<>();
            detail.put("captureMode", "HTTP_CLIENT_METHOD");
            detail.put("operation", methodName == null ? "" : methodName);
            detail.put("targetClass", className == null ? "" : className);
            detail.put("targetMethod", methodName == null ? "" : methodName);
            detail.putAll(PathDebugDetail.effectTriggered("SSRF"));
            AgentRuntime.recordTransformedDetail("HTTP_CLIENT", className, methodName, detail);
        }
    }

    /**
     * SpEL 表达式求值面：记录 PROCESS + EFFECT_TRIGGERED EXPRESSION。
     */
    public static final class ExpressionEvalAdvice {
        private ExpressionEvalAdvice() {
        }

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Origin("#t") String className,
                                 @Advice.Origin("#m") String methodName) {
            if (!AgentRuntime.isExpressionEvalSink(className, methodName)) {
                return;
            }
            Map<String, String> detail = new LinkedHashMap<>();
            detail.put("captureMode", "EXPRESSION_EVAL");
            detail.put("operation", methodName == null ? "" : methodName);
            detail.put("targetClass", className == null ? "" : className);
            detail.put("targetMethod", methodName == null ? "" : methodName);
            detail.putAll(PathDebugDetail.effectTriggered("EXPRESSION"));
            detail.put("secondaryEffectKinds", "COMMAND");
            AgentRuntime.recordTransformedDetail("PROCESS", className, methodName, detail);
        }
    }

    /**
     * MultipartFile 写盘面：记录 FILE_WRITE + EFFECT_TRIGGERED（框架补充）。
     */
    public static final class MultipartFileTransferAdvice {
        private MultipartFileTransferAdvice() {
        }

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Origin("#t") String className,
                                 @Advice.Origin("#m") String methodName,
                                 @Advice.AllArguments Object[] args) {
            if (!"transferTo".equals(methodName)) {
                return;
            }
            Map<String, String> detail = new LinkedHashMap<>();
            detail.put("captureMode", "MULTIPART_TRANSFER");
            detail.put("operation", "transferTo");
            detail.put("effectOp", "write");
            detail.put("targetClass", className == null ? "" : className);
            detail.put("targetMethod", "transferTo");
            detail.put("requestBound",
                    AgentRuntime.currentRequestCorrelation().isEmpty() ? "false" : "true");
            if (args != null && args.length > 0 && args[0] != null) {
                String dest = String.valueOf(args[0]);
                if (!dest.isBlank()) {
                    String path = dest.length() <= 256 ? dest : dest.substring(0, 256);
                    detail.put("path", path);
                    detail.put("pathOrUrl", path);
                }
            }
            detail.putAll(PathDebugDetail.effectTriggered("FILE_WRITE"));
            AgentRuntime.recordTransformedDetail("FILE", className, methodName, detail);
        }
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
                                emitPathCapture(opcode, owner, methodName, methodDescriptor);
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

                        /**
                         * 高 ROI：构造器首参 / URL this / Files 单 Path 参数 → pathOrUrl 摘要。
                         * 不改栈布局破坏原调用。
                         */
                        private void emitPathCapture(int opcode, String owner, String methodName,
                                                     String methodDescriptor) {
                            if (isFileCtorSinglePathArg(owner, methodName, methodDescriptor)) {
                                // stack: [uninitThis, pathArg] → DUP pathArg
                                super.visitInsn(Opcodes.DUP);
                                super.visitMethodInsn(Opcodes.INVOKESTATIC,
                                        "com/aq/jvmsentinel/instrumentation/AgentRuntime",
                                        "captureEffectArg", "(Ljava/lang/Object;)V", false);
                                return;
                            }
                            if (isFileCtorPathThenPrimitive(owner, methodName, methodDescriptor)) {
                                // stack: [uninitThis, path, int/bool] → SWAP; DUP; capture; SWAP
                                super.visitInsn(Opcodes.SWAP);
                                super.visitInsn(Opcodes.DUP);
                                super.visitMethodInsn(Opcodes.INVOKESTATIC,
                                        "com/aq/jvmsentinel/instrumentation/AgentRuntime",
                                        "captureEffectArg", "(Ljava/lang/Object;)V", false);
                                super.visitInsn(Opcodes.SWAP);
                                return;
                            }
                            if (("java/net/URL".equals(owner)
                                    && ("openConnection".equals(methodName)
                                    || "openStream".equals(methodName)))
                                    || (("java/net/HttpURLConnection".equals(owner)
                                    || owner.endsWith("/HttpURLConnection")
                                    || owner.endsWith("/HttpsURLConnection"))
                                    && ("connect".equals(methodName)
                                    || "getInputStream".equals(methodName)
                                    || "getOutputStream".equals(methodName)))) {
                                // stack: [this]
                                super.visitInsn(Opcodes.DUP);
                                super.visitMethodInsn(Opcodes.INVOKESTATIC,
                                        "com/aq/jvmsentinel/instrumentation/AgentRuntime",
                                        "captureEffectArg", "(Ljava/lang/Object;)V", false);
                                return;
                            }
                            if ("java/nio/file/Files".equals(owner)
                                    && methodDescriptor != null
                                    && methodDescriptor.startsWith("(Ljava/nio/file/Path;")) {
                                // 仅当 Path 为唯一或可廉价 DUP 的栈顶附近参数：
                                // write(Path,byte[],OpenOption[]) 等 Path 在栈底——跳过复杂重排，
                                // 依赖 correlation + effectKind；单参 Files.delete(Path) 可 DUP。
                                if ("(Ljava/nio/file/Path;)V".equals(methodDescriptor)
                                        || "(Ljava/nio/file/Path;)Ljava/nio/file/Path;".equals(methodDescriptor)
                                        || methodDescriptor.startsWith("(Ljava/nio/file/Path;)")) {
                                    int argCount = countArgs(methodDescriptor);
                                    if (argCount == 1) {
                                        super.visitInsn(Opcodes.DUP);
                                        super.visitMethodInsn(Opcodes.INVOKESTATIC,
                                                "com/aq/jvmsentinel/instrumentation/AgentRuntime",
                                                "captureEffectArg", "(Ljava/lang/Object;)V", false);
                                    }
                                }
                            }
                        }

                        @Override
                        public void visitMaxs(int maxStack, int maxLocals) {
                            super.visitMaxs(maxStack + 8, maxLocals);
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
            // DNS：可观测（门控+DNS_LOOKUP），不钩全部 Socket（过粗）。
            if ("java/net/InetAddress".equals(owner)
                    && ("getByName".equals(methodName) || "getAllByName".equals(methodName)
                    || "getCanonicalHostName".equals(methodName))) {
                return "HTTP_CLIENT";
            }
            // 故意不钩 java.net.Socket#connect / DatagramSocket——连接面过粗，洪范 JDBC/redis。
            if ("java/net/URL".equals(owner)
                    && ("openConnection".equals(methodName) || "openStream".equals(methodName))) {
                return "HTTP_CLIENT";
            }
            if (("java/net/HttpURLConnection".equals(owner)
                    || owner.endsWith("/HttpURLConnection")
                    || owner.endsWith("/HttpsURLConnection"))
                    && ("connect".equals(methodName) || "getInputStream".equals(methodName)
                    || "getOutputStream".equals(methodName))) {
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
            if (("org/springframework/jdbc/datasource/DriverManagerDataSource".equals(owner)
                    || "com/alibaba/druid/pool/DruidDataSource".equals(owner)
                    || "org/apache/commons/dbcp2/BasicDataSource".equals(owner)
                    || "org/apache/tomcat/dbcp/dbcp2/BasicDataSource".equals(owner))
                    && "setUrl".equals(methodName)) {
                return "JDBC";
            }
            if (("com/zaxxer/hikari/HikariConfig".equals(owner)
                    || "com/zaxxer/hikari/HikariDataSource".equals(owner))
                    && "setJdbcUrl".equals(methodName)) {
                return "JDBC";
            }
            if ("org/springframework/jdbc/datasource/DriverManagerDataSource".equals(owner)
                    && "getConnection".equals(methodName)) {
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
            if ("com/ql/util/express/ExpressRunner".equals(owner)
                    && ("execute".equals(methodName) || "executeExt".equals(methodName))) {
                return "PROCESS";
            }
            if (("org/springframework/expression/Expression".equals(owner)
                    || "org/springframework/expression/spel/standard/SpelExpression".equals(owner))
                    && ("getValue".equals(methodName) || "getValueType".equals(methodName))) {
                return "PROCESS";
            }
            if ("org/springframework/expression/spel/standard/SpelExpressionParser".equals(owner)
                    && "parseExpression".equals(methodName)) {
                return "PROCESS";
            }
            if ("com/googlecode/aviator/AviatorEvaluator".equals(owner)
                    && ("execute".equals(methodName) || "exec".equals(methodName))) {
                return "PROCESS";
            }
            if ("ognl/Ognl".equals(owner)
                    && ("getValue".equals(methodName) || "setValue".equals(methodName))) {
                return "PROCESS";
            }
            if ("org/mvel2/MVEL".equals(owner)
                    && ("eval".equals(methodName) || "evalToString".equals(methodName)
                    || "executeExpression".equals(methodName))) {
                return "PROCESS";
            }
            if ("freemarker/template/Template".equals(owner) && "process".equals(methodName)) {
                return "PROCESS";
            }
            if ("java/lang/ProcessBuilder".equals(owner) && "start".equals(methodName)
                    || "java/lang/Runtime".equals(owner) && methodName.startsWith("exec")) {
                return "PROCESS";
            }
            if ("org/springframework/web/client/RestTemplate".equals(owner)
                    && ("getForObject".equals(methodName) || "getForEntity".equals(methodName)
                    || "postForObject".equals(methodName) || "postForEntity".equals(methodName)
                    || "exchange".equals(methodName) || "execute".equals(methodName))) {
                return "HTTP_CLIENT";
            }
            if (("org/apache/http/client/HttpClient".equals(owner)
                    || "org/apache/http/impl/client/CloseableHttpClient".equals(owner))
                    && "execute".equals(methodName)) {
                return "HTTP_CLIENT";
            }
            if ("okhttp3/Call".equals(owner)
                    && ("execute".equals(methodName) || "enqueue".equals(methodName))) {
                return "HTTP_CLIENT";
            }
            if ("java/nio/file/Files".equals(owner)
                    && (methodName.startsWith("write") || "newOutputStream".equals(methodName)
                    || "newBufferedWriter".equals(methodName)
                    || "copy".equals(methodName) || "move".equals(methodName)
                    || methodName.startsWith("read") || "newInputStream".equals(methodName)
                    || "newBufferedReader".equals(methodName) || "lines".equals(methodName)
                    || "delete".equals(methodName) || "deleteIfExists".equals(methodName))) {
                return "FILE";
            }
            if (("java/io/FileOutputStream".equals(owner) || "java/io/FileWriter".equals(owner)
                    || "java/io/FileInputStream".equals(owner) || "java/io/FileReader".equals(owner)
                    || "java/io/RandomAccessFile".equals(owner))
                    && "<init>".equals(methodName)) {
                return "FILE";
            }
            if ("java/io/File".equals(owner)
                    && ("delete".equals(methodName) || "deleteOnExit".equals(methodName))) {
                return "FILE";
            }
            if ("java/nio/channels/FileChannel".equals(owner) && "open".equals(methodName)) {
                return "FILE";
            }
            if ("org/apache/commons/io/FileUtils".equals(owner)
                    && ("write".equals(methodName) || "writeStringToFile".equals(methodName)
                    || "writeByteArrayToFile".equals(methodName) || "copyFile".equals(methodName)
                    || "copyFileToDirectory".equals(methodName) || "copyDirectory".equals(methodName)
                    || "moveFile".equals(methodName) || "moveDirectory".equals(methodName)
                    || "readFileToString".equals(methodName) || "readFileToByteArray".equals(methodName)
                    || "openInputStream".equals(methodName)
                    || "forceDelete".equals(methodName) || "deleteDirectory".equals(methodName)
                    || "deleteQuietly".equals(methodName))) {
                return "FILE";
            }
            if (("org/springframework/web/multipart/MultipartFile".equals(owner)
                    || owner.endsWith("/MultipartFile")
                    || owner.endsWith("MultipartFile"))
                    && "transferTo".equals(methodName)) {
                return "FILE";
            }
            if (("javax/xml/parsers/DocumentBuilder".equals(owner)
                    || "javax/xml/parsers/SAXParser".equals(owner)
                    || "org/xml/sax/XMLReader".equals(owner))
                    && "parse".equals(methodName)) {
                return "PROCESS";
            }
            if ("org/dom4j/io/SAXReader".equals(owner) && "read".equals(methodName)) {
                return "PROCESS";
            }
            return null;
        }

        private static boolean isFileIoCtorOwner(String owner) {
            return "java/io/FileOutputStream".equals(owner)
                    || "java/io/FileInputStream".equals(owner)
                    || "java/io/FileWriter".equals(owner)
                    || "java/io/FileReader".equals(owner)
                    || "java/io/RandomAccessFile".equals(owner);
        }

        /** 单 path 参：栈顶即为 path。 */
        private static boolean isFileCtorSinglePathArg(String owner, String methodName,
                                                       String methodDescriptor) {
            if (!"<init>".equals(methodName) || !isFileIoCtorOwner(owner)) {
                return false;
            }
            return "(Ljava/lang/String;)V".equals(methodDescriptor)
                    || "(Ljava/io/File;)V".equals(methodDescriptor)
                    || "(Ljava/nio/file/Path;)V".equals(methodDescriptor);
        }

        /** path + boolean/int：栈顶为原始类型，需 SWAP 后捕获。 */
        private static boolean isFileCtorPathThenPrimitive(String owner, String methodName,
                                                           String methodDescriptor) {
            if (!"<init>".equals(methodName) || !isFileIoCtorOwner(owner)) {
                return false;
            }
            return "(Ljava/lang/String;Z)V".equals(methodDescriptor)
                    || "(Ljava/io/File;Z)V".equals(methodDescriptor)
                    || "(Ljava/lang/String;I)V".equals(methodDescriptor)
                    || "(Ljava/io/File;I)V".equals(methodDescriptor);
        }

        private static int countArgs(String methodDescriptor) {
            if (methodDescriptor == null || methodDescriptor.length() < 3) {
                return 0;
            }
            int count = 0;
            boolean inClass = false;
            for (int i = 1; i < methodDescriptor.length(); i++) {
                char c = methodDescriptor.charAt(i);
                if (c == ')') {
                    break;
                }
                if (inClass) {
                    if (c == ';') {
                        inClass = false;
                    }
                    continue;
                }
                if (c == 'L') {
                    inClass = true;
                    count++;
                } else if (c == '[') {
                    // array: skip to element type
                    while (i + 1 < methodDescriptor.length() && methodDescriptor.charAt(i + 1) == '[') {
                        i++;
                    }
                    if (i + 1 < methodDescriptor.length() && methodDescriptor.charAt(i + 1) == 'L') {
                        inClass = true;
                        i++;
                    }
                    count++;
                } else {
                    count++;
                }
            }
            return count;
        }
    }
}
