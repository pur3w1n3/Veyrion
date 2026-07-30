package com.aq.jvmsentinel.instrumentation;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * P0-21：COVERAGE_POSTURE 身份注入与 FORCED_REACHABILITY guard 处理。
 * 仅在已授权 Docker 沙箱内激活；永不在宿主执行。
 *
 * <p>FORCED_REACHABILITY 通过继续 {@code FilterChain} 并跳过 filter 体，
 * 或强制 AccessControl {@code isAccessAllowed} 为 true，短路<em>已识别</em>的 auth/role/permission/license
 * filter。当 {@code veyrion.sandbox.forcedGuardTypeNames} 非空时，仅强制那些 runtime 类型
 *（白名单为空时启发式仍为回退）。永不针对
 * sanitizer 或 infrastructure / container filter。
 */
public final class FrameworkBoundaryAdapter {
    static final String DOCKER_PROPERTY = "veyrion.sandbox.docker";
    static final String POSTURE_PROPERTY = "veyrion.sandbox.runtimePosture";
    static final String POSTURE_HEADER = "X-Veyrion-Runtime-Posture";
    static final String FORCED_GUARD_TYPES_PROPERTY = AgentConfig.FORCED_GUARD_TYPE_NAMES_PROPERTY;
    static final String SCAN_PRINCIPAL = "veyrion-scan-principal";
    static final String SCAN_ROLE = "ROLE_VEYRION_SCAN";
    static final String SCAN_ADMIN_ROLE = "ROLE_ADMIN";
    static final String REQUEST_ATTR_PRINCIPAL = "com.veyrion.scan.principal";
    static final String REQUEST_ATTR_POSTURE = "com.veyrion.scan.runtimePosture";
    private static final int MAX_ALLOWLIST_TYPES = 48;

    private static volatile Set<String> cachedAllowlist;
    private static volatile String cachedAllowlistRaw;

    private FrameworkBoundaryAdapter() {
    }

    public static boolean sandboxEnabled() {
        return "true".equalsIgnoreCase(System.getProperty(DOCKER_PROPERTY, "false"));
    }

    public static String configuredPosture() {
        if (!sandboxEnabled()) {
            return "";
        }
        String value = System.getProperty(POSTURE_PROPERTY, "").trim().toUpperCase(Locale.ROOT);
        return switch (value) {
            case "UNAUTH", "COVERAGE_POSTURE", "FORCED_REACHABILITY", "BYPASS" -> value;
            default -> "";
        };
    }

    public static String resolvePosture(String headerValue) {
        if (!sandboxEnabled()) {
            return "UNAUTH";
        }
        if (headerValue != null && !headerValue.isBlank()) {
            String normalized = headerValue.trim().toUpperCase(Locale.ROOT);
            if (normalized.equals("COVERAGE_POSTURE") || normalized.equals("FORCED_REACHABILITY")
                    || normalized.equals("BYPASS") || normalized.equals("UNAUTH")) {
                return normalized;
            }
        }
        String configured = configuredPosture();
        return configured.isBlank() ? "UNAUTH" : configured;
    }

    /**
     * 为 COVERAGE_POSTURE（及 FORCED 在 guard short-circuit 前的尽力 identity seed）
     * 注入 scan Principal / SecurityContext / session seed。
     */
    public static void applyCoveragePosture(Object request, String posture) {
        if (!sandboxEnabled() || request == null) {
            return;
        }
        if (!"COVERAGE_POSTURE".equals(posture) && !"FORCED_REACHABILITY".equals(posture)) {
            return;
        }
        try {
            request.getClass().getMethod("setAttribute", String.class, Object.class)
                    .invoke(request, REQUEST_ATTR_PRINCIPAL, SCAN_PRINCIPAL);
            request.getClass().getMethod("setAttribute", String.class, Object.class)
                    .invoke(request, REQUEST_ATTR_POSTURE, posture);
        } catch (Throwable ignored) {
            // Servlet API shape 各异；attribute 注入为尽力而为。
        }
        seedHttpSession(request);
        seedSpringSecurityContext();
        seedShiroSubjectBestEffort();
    }

    public static boolean forcedReachabilityActive(String posture) {
        return sandboxEnabled() && "FORCED_REACHABILITY".equals(posture);
    }

    /**
     * 与 DecisionShape 对齐的 rewrite mode。FORCED rewrite 仅通过这些 mode 返回 —
     * 永不任意 {@code Object.preHandle} 或 sanitizer filter。
     */
    public enum ForceRewriteMode {
        NONE,
        FILTER_CONTINUE_CHAIN,
        ACCESS_ALLOWED_TRUE,
        INTERCEPTOR_PREHANDLE_TRUE,
        METHOD_SECURITY_FAIL_OPEN
    }

    /**
     * FORCED 且本类型为合格 auth guard 时，继续 filter chain 并
     * 信号调用方跳过原始 filter body（{@code skipOn} 非默认）。
     *
     * @return 原始 method 应跳过时为 {@code true}
     */
    public static boolean forcePastRecognizedFilter(String posture, String className,
                                                    String methodName, Object[] args) {
        if (!forcedReachabilityActive(posture)) {
            return false;
        }
        if (rewriteMode(className, methodName) != ForceRewriteMode.FILTER_CONTINUE_CHAIN) {
            return false;
        }
        continueFilterChain(args);
        return true;
    }

    /**
     * FORCED 且本类型为合格 AccessControl decision method 时，跳过原始
     * body，以便 advice 返回 {@code true}（isAccessAllowed）。
     */
    public static boolean forceAccessAllowed(String posture, String className, String methodName) {
        if (!forcedReachabilityActive(posture)) {
            return false;
        }
        return rewriteMode(className, methodName) == ForceRewriteMode.ACCESS_ALLOWED_TRUE;
    }

    /**
     * 将 (type, method) 映射到唯一允许的 FORCED rewrite shape。
     * 先要求 eligibility（allowlist 或启发式）。
     */
    public static ForceRewriteMode rewriteMode(String className, String methodName) {
        if (className == null || methodName == null || !isForceEligibleGuard(className, methodName)) {
            return ForceRewriteMode.NONE;
        }
        if ("isAccessAllowed".equals(methodName) || "isPermissive".equals(methodName)) {
            return ForceRewriteMode.ACCESS_ALLOWED_TRUE;
        }
        if ("preHandle".equals(methodName)) {
            return isInterceptorShaped(className)
                    ? ForceRewriteMode.INTERCEPTOR_PREHANDLE_TRUE
                    : ForceRewriteMode.NONE;
        }
        if ("doFilter".equals(methodName) || "doFilterInternal".equals(methodName)) {
            return ForceRewriteMode.FILTER_CONTINUE_CHAIN;
        }
        if (isMethodSecurityInterceptorType(className)
                && ("invoke".equals(methodName) || "before".equals(methodName))) {
            return ForceRewriteMode.METHOD_SECURITY_FAIL_OPEN;
        }
        return ForceRewriteMode.NONE;
    }

    /**
     * allowlist 非空时来自 control-plane catalog；否则 name 启发式。
     * 容器/基础设施排除始终适用。
     */
    public static boolean isForceEligibleGuard(String className, String methodName) {
        if (className == null) {
            return false;
        }
        String lower = className.toLowerCase(Locale.ROOT);
        String simple = lower;
        int dot = lower.lastIndexOf('.');
        if (dot >= 0 && dot + 1 < lower.length()) {
            simple = lower.substring(dot + 1);
        }
        if (isInfrastructureFilter(simple, lower) || isAuthContainerFilter(simple, lower)
                || isSanitizerOrSqlFilter(simple)) {
            return false;
        }
        Set<String> allowlist = forcedGuardTypeAllowlist();
        if (!allowlist.isEmpty()) {
            return matchesAllowlist(className, allowlist);
        }
        return isRecognizedAuthGuard(className, methodName);
    }

    public static Set<String> forcedGuardTypeAllowlist() {
        String raw = System.getProperty(FORCED_GUARD_TYPES_PROPERTY, "");
        if (raw == null) {
            raw = "";
        }
        String normalized = raw.trim();
        Set<String> cached = cachedAllowlist;
        if (cached != null && normalized.equals(cachedAllowlistRaw)) {
            return cached;
        }
        LinkedHashSet<String> parsed = new LinkedHashSet<>();
        if (!normalized.isEmpty()) {
            for (String part : normalized.split(",")) {
                String token = part == null ? "" : part.trim();
                if (token.isEmpty() || token.length() > 200) {
                    continue;
                }
                parsed.add(token);
                if (parsed.size() >= MAX_ALLOWLIST_TYPES) {
                    break;
                }
            }
        }
        Set<String> frozen = Set.copyOf(parsed);
        cachedAllowlistRaw = normalized;
        cachedAllowlist = frozen;
        return frozen;
    }

    /** Test helper: clear allowlist property cache. */
    static void clearForcedGuardTypeAllowlistCache() {
        cachedAllowlist = null;
        cachedAllowlistRaw = null;
    }

    public static void recordGuardDecision(String className, String methodName, String decision,
                                           boolean forced, Map<String, String> extra) {
        Map<String, String> detail = PathDebugDetail.merge(extra,
                PathDebugDetail.guardDecision(decision, forced));
        AgentRuntime.recordTransformedDetail("HTTP", className, methodName, detail);
    }

    /**
     * 说明：control-plane allowlist 为空时，符合 FORCED short-circuit 的已识别
     * 说明：auth/role/permission/license/feature guard surface。刻意排除
     * 说明：infrastructure filter（CORS、encoding、…）。
     */
    public static boolean isRecognizedAuthGuard(String className, String methodName) {
        if (className == null) {
            return false;
        }
        String lower = className.toLowerCase(Locale.ROOT);
        String simple = lower;
        int dot = lower.lastIndexOf('.');
        if (dot >= 0 && dot + 1 < lower.length()) {
            simple = lower.substring(dot + 1);
        }
        if (isInfrastructureFilter(simple, lower) || isAuthContainerFilter(simple, lower)
                || isSanitizerOrSqlFilter(simple)) {
            return false;
        }
        if (methodName != null && (methodName.contains("PreAuthorize")
                || "authorize".equals(methodName)
                || "isAccessAllowed".equals(methodName)
                || "check".equals(methodName) && lower.contains("security"))) {
            // 仅 method 名 signal 对 non-guard 类型上的 PreAuthorize 不足；
            // filter 类型仍保留下方 package / simple-name gate。
            if ("isAccessAllowed".equals(methodName)
                    && (lower.contains("shiro") || simpleContainsAny(simple,
                    "accesscontrol", "loginfilter", "userfilter", "authfilter",
                    "authenticationfilter", "authorizationfilter"))) {
                return true;
            }
            if (methodName.contains("PreAuthorize")
                    || "authorize".equals(methodName)
                    || "check".equals(methodName) && lower.contains("security")) {
                return true;
            }
        }
        // Shiro：仅 authc/authz decision filter — 永不 outer AbstractShiroFilter
        // 建立 Subject / session。continueFilterChain 后跳过 container filter
        // 常导致 hang 或 request 饿死。
        if (lower.startsWith("org.apache.shiro.web.filter.authc.")
                || lower.startsWith("org.apache.shiro.web.filter.authz.")
                || (lower.contains("shiro") && simpleContainsAny(simple,
                "formauthenticationfilter", "userfilter", "anonymousfilter",
                "permissionsauthorizationfilter", "rolesauthorizationfilter",
                "portfilter", "sslfilter"))) {
            return true;
        }
        if (lower.contains("springframework.security.web")
                && (lower.contains("filter") || lower.contains("access"))) {
            return true;
        }
        if (lower.contains("cn.dev33.satoken")
                || simpleEqualsAny(simple, "sainterceptor", "saservletfilter")
                || simpleContainsAny(simple, "satokenfilter", "satokencontext")) {
            return true;
        }
        if (isMethodSecurityInterceptorType(className)) {
            return true;
        }
        return simpleContainsAny(simple,
                "authfilter", "authenticationfilter", "authorizationfilter",
                "userfilter", "loginfilter", "permissionsauthorizationfilter",
                "rolesauthorizationfilter",
                "jwtfilter", "tokenfilter", "bearertoken", "bearerfilter",
                "accesscontrol", "filterchainproxy",
                "usernamepasswordauthenticationfilter", "basicauthenticationfilter",
                "exceptiontranslationfilter", "filtersecurityinterceptor",
                "authorizationmanager", "licensefilter", "featurefilter",
                "securefilter", "preauth",
                "tokeninterceptor", "authinterceptor", "jwtinterceptor",
                "secureinterceptor", "clientinterceptor", "signinterceptor",
                "sainterceptor", "saservletfilter", "satokenfilter");
    }

    /**
     * 说明：Spring {@code HandlerInterceptor#preHandle} 的 FORCED 短路。
     * allowlist/启发式识别 interceptor 为 auth guard 时合格。
     * 拒绝 non-interceptor shape（无任意 {@code Object.preHandle}）。
     */
    public static boolean forceInterceptorPreHandle(String posture, String className,
                                                    String methodName) {
        if (!forcedReachabilityActive(posture)) {
            return false;
        }
        return rewriteMode(className, methodName) == ForceRewriteMode.INTERCEPTOR_PREHANDLE_TRUE;
    }

    /**
     * 说明：Spring method security interceptor（{@code @PreAuthorize} wall）的 FORCED fail-open。
     * 独立 {@code forceMode=METHOD_SECURITY_FAIL_OPEN}；仍为 INSTRUMENTATION_REACHABILITY。
     */
    public static boolean forceMethodSecurity(String posture, String className, String methodName) {
        if (!forcedReachabilityActive(posture)) {
            return false;
        }
        return rewriteMode(className, methodName) == ForceRewriteMode.METHOD_SECURITY_FAIL_OPEN;
    }

    public static boolean isMethodSecurityInterceptorType(String className) {
        if (className == null) {
            return false;
        }
        String lower = className.toLowerCase(Locale.ROOT);
        return lower.contains("methodsecurityinterceptor")
                || lower.contains("authorizationmanagerbeforemethodinterceptor")
                || lower.contains("authorizationmanagermethodinterceptor")
                || lower.endsWith("methodsecurityinterceptor");
    }

    private static boolean isInterceptorShaped(String className) {
        if (className == null) {
            return false;
        }
        String lower = className.toLowerCase(Locale.ROOT);
        String simple = lower;
        int dot = lower.lastIndexOf('.');
        if (dot >= 0 && dot + 1 < lower.length()) {
            simple = lower.substring(dot + 1);
        }
        return simple.contains("interceptor") || lower.contains(".interceptor.");
    }

    private static boolean simpleEqualsAny(String simple, String... needles) {
        for (String needle : needles) {
            if (simple.equals(needle)) {
                return true;
            }
        }
        return false;
    }

    private static boolean matchesAllowlist(String className, Set<String> allowlist) {
        if (allowlist.contains(className)) {
            return true;
        }
        // 接受部分 catalog 的 slash 形式 token。
        String slash = className.replace('.', '/');
        if (allowlist.contains(slash)) {
            return true;
        }
        for (String token : allowlist) {
            if (token.equalsIgnoreCase(className) || token.equalsIgnoreCase(slash)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isSanitizerOrSqlFilter(String simple) {
        return simpleContainsAny(simple,
                "xss", "sqlfilter", "sqlinjection", "sanitiz", "csrf");
    }

    /**
     * FORCED 下必须继续运行的 outer container filter，以便 framework 绑定
     * 说明：Subject/SecurityContext；仅 nested auth decision filter 被短路。
     */
    private static boolean isAuthContainerFilter(String simple, String lower) {
        return simpleContainsAny(simple,
                "abstractshirofilter", "springshirofilter", "pathmatchingfilter",
                "advicefilter", "onceperrequestfilter", "genericfilterbean")
                || lower.contains("shirofilterfactorybean$springshirofilter")
                || lower.endsWith(".abstractshirofilter");
    }

    /** args 形如 filter 调用时 invoke {@code FilterChain.doFilter(request, response)}。 */
    public static boolean continueFilterChain(Object[] args) {
        if (args == null || args.length < 3) {
            return false;
        }
        Object request = args[0];
        Object response = args[1];
        Object chain = args[2];
        if (request == null || response == null || chain == null) {
            return false;
        }
        try {
            for (Method method : chain.getClass().getMethods()) {
                if (!"doFilter".equals(method.getName()) || method.getParameterCount() != 2) {
                    continue;
                }
                method.setAccessible(true);
                method.invoke(chain, request, response);
                return true;
            }
        } catch (Throwable ignored) {
            return false;
        }
        return false;
    }

    private static void seedHttpSession(Object request) {
        try {
            Object session = request.getClass().getMethod("getSession", boolean.class)
                    .invoke(request, true);
            if (session == null) {
                return;
            }
            session.getClass().getMethod("setAttribute", String.class, Object.class)
                    .invoke(session, REQUEST_ATTR_PRINCIPAL, SCAN_PRINCIPAL);
            session.getClass().getMethod("setAttribute", String.class, Object.class)
                    .invoke(session, "veyrion.scan.authenticated", Boolean.TRUE);
        } catch (Throwable ignored) {
            // 可选
        }
    }

    private static void seedSpringSecurityContext() {
        try {
            Class<?> holder = Class.forName("org.springframework.security.core.context.SecurityContextHolder");
            Object context = holder.getMethod("createEmptyContext").invoke(null);
            Class<?> authClass = Class.forName(
                    "org.springframework.security.authentication.UsernamePasswordAuthenticationToken");
            Collection<?> authorities = springAuthorities();
            Object auth;
            try {
                Constructor<?> ctor = authClass.getConstructor(Object.class, Object.class, Collection.class);
                auth = ctor.newInstance(SCAN_PRINCIPAL, "N/A", authorities);
            } catch (NoSuchMethodException fallback) {
                auth = authClass.getConstructor(Object.class, Object.class)
                        .newInstance(SCAN_PRINCIPAL, "N/A");
                authClass.getMethod("setAuthenticated", boolean.class).invoke(auth, true);
            }
            context.getClass().getMethod("setAuthentication",
                            Class.forName("org.springframework.security.core.Authentication"))
                    .invoke(context, auth);
            holder.getMethod("setContext", context.getClass()).invoke(null, context);
        } catch (Throwable ignored) {
            // Spring Security 可选。
        }
    }

    private static Collection<?> springAuthorities() {
        List<Object> authorities = new ArrayList<>();
        try {
            Class<?> roleClass = Class.forName(
                    "org.springframework.security.core.authority.SimpleGrantedAuthority");
            Constructor<?> ctor = roleClass.getConstructor(String.class);
            authorities.add(ctor.newInstance(SCAN_ROLE));
            authorities.add(ctor.newInstance(SCAN_ADMIN_ROLE));
            authorities.add(ctor.newInstance("admin"));
            authorities.add(ctor.newInstance("administrator"));
        } catch (Throwable ignored) {
            return List.of();
        }
        return authorities;
    }

    /**
     * SecurityManager 已存在时的尽力 Shiro Subject bind。
     * 不加密 rememberMe cookie；仅 COVERAGE/FORCED 的 session seed。
     */
    private static void seedShiroSubjectBestEffort() {
        try {
            Class<?> securityUtils = Class.forName("org.apache.shiro.SecurityUtils");
            Object subject = securityUtils.getMethod("getSubject").invoke(null);
            if (subject == null) {
                return;
            }
            Boolean authenticated = (Boolean) subject.getClass().getMethod("isAuthenticated")
                    .invoke(subject);
            if (Boolean.TRUE.equals(authenticated)) {
                return;
            }
            // 可能时用 token login — 许多应用需 realm；仅尽力而为。
            try {
                Class<?> tokenClass = Class.forName(
                        "org.apache.shiro.authc.UsernamePasswordToken");
                Object token = tokenClass.getConstructor(String.class, String.class)
                        .newInstance(SCAN_PRINCIPAL, "veyrion-scan");
                subject.getClass().getMethod("login",
                                Class.forName("org.apache.shiro.authc.AuthenticationToken"))
                        .invoke(subject, token);
            } catch (Throwable ignoredLogin) {
                // Realm 可能拒绝；FORCED filter skip 仍是主路径。
            }
        } catch (Throwable ignored) {
            // Shiro 可选。
        }
    }

    private static boolean isInfrastructureFilter(String simple, String lower) {
        return simpleContainsAny(simple,
                "characterencoding", "corsfilter", "cors.", "hiddenhttpmethod",
                "requestcontextfilter", "formcontentfilter", "forwardedheader",
                "resourcerequest", "onceperrequestfilter", "serverhttprequest",
                "orderedhidden", "orderedrequest", "orderedform",
                "websitemesh", "metrictag", "httptrace")
                || lower.contains("org.springframework.web.filter.onceperrequestfilter")
                || lower.contains("org.springframework.web.filter.characterencodingfilter")
                || lower.contains("org.springframework.web.filter.corsfilter");
    }

    private static boolean simpleContainsAny(String simple, String... needles) {
        for (String needle : needles) {
            if (simple.contains(needle)) {
                return true;
            }
        }
        return false;
    }
}
