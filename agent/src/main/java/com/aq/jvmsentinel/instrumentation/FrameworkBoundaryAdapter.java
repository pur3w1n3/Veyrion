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
 * P0-21: COVERAGE_POSTURE identity injection and FORCED_REACHABILITY guard handling.
 * Only active inside authorized Docker sandboxes; never on host execution.
 *
 * <p>FORCED_REACHABILITY short-circuits <em>recognized</em> auth/role/permission/license
 * filters by continuing the {@code FilterChain} and skipping the filter body, or by forcing
 * AccessControl {@code isAccessAllowed} to true. When
 * {@code veyrion.sandbox.forcedGuardTypeNames} is non-empty, only those runtime types are
 * forced (heuristics remain the fallback when the allowlist is empty). Never targets
 * sanitizers or infrastructure / container filters.
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
     * Inject scan Principal / SecurityContext / session seed for COVERAGE_POSTURE
     * (and FORCED as a best-effort identity seed before guard short-circuit).
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
            // Servlet API shape varies; attribute injection is best-effort.
        }
        seedHttpSession(request);
        seedSpringSecurityContext();
        seedShiroSubjectBestEffort();
    }

    public static boolean forcedReachabilityActive(String posture) {
        return sandboxEnabled() && "FORCED_REACHABILITY".equals(posture);
    }

    /**
     * When FORCED and this type is an eligible auth guard, continue the filter chain and
     * signal callers to skip the original filter body ({@code skipOn} non-default).
     *
     * @return {@code true} when the original method should be skipped
     */
    public static boolean forcePastRecognizedFilter(String posture, String className,
                                                    String methodName, Object[] args) {
        if (!forcedReachabilityActive(posture) || !isForceEligibleGuard(className, methodName)) {
            return false;
        }
        continueFilterChain(args);
        return true;
    }

    /**
     * When FORCED and this type is an eligible AccessControl decision method, skip the original
     * body so advice can return {@code true} (isAccessAllowed).
     */
    public static boolean forceAccessAllowed(String posture, String className, String methodName) {
        if (!forcedReachabilityActive(posture)) {
            return false;
        }
        if (methodName == null || !("isAccessAllowed".equals(methodName)
                || "isPermissive".equals(methodName))) {
            return false;
        }
        return isForceEligibleGuard(className, methodName);
    }

    /**
     * Allowlist from control-plane catalog when non-empty; otherwise name heuristics.
     * Container / infrastructure exclusions always apply.
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
     * Recognized auth / role / permission / license / feature guard surfaces eligible for
     * FORCED short-circuit when the control-plane allowlist is empty. Intentionally excludes
     * infrastructure filters (CORS, encoding, …).
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
            // Method-name signal alone is insufficient for PreAuthorize on non-guard types;
            // keep package / simple-name gates below for filter types.
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
        // Shiro: only authc/authz decision filters — never the outer AbstractShiroFilter
        // that establishes Subject / session. Skipping the container filter after
        // continueFilterChain commonly hangs or starves the request.
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
        return simpleContainsAny(simple,
                "authfilter", "authenticationfilter", "authorizationfilter",
                "userfilter", "loginfilter", "permissionsauthorizationfilter",
                "rolesauthorizationfilter",
                "jwtfilter", "tokenfilter", "bearertoken", "bearerfilter",
                "accesscontrol", "filterchainproxy",
                "usernamepasswordauthenticationfilter", "basicauthenticationfilter",
                "exceptiontranslationfilter", "filtersecurityinterceptor",
                "authorizationmanager", "licensefilter", "featurefilter",
                "securefilter", "preauth");
    }

    private static boolean matchesAllowlist(String className, Set<String> allowlist) {
        if (allowlist.contains(className)) {
            return true;
        }
        // Accept slash-form tokens from some catalogs.
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
     * Outer container filters that must keep running under FORCED so the framework can
     * bind Subject/SecurityContext; only nested auth decision filters are short-circuited.
     */
    private static boolean isAuthContainerFilter(String simple, String lower) {
        return simpleContainsAny(simple,
                "abstractshirofilter", "springshirofilter", "pathmatchingfilter",
                "advicefilter", "onceperrequestfilter", "genericfilterbean")
                || lower.contains("shirofilterfactorybean$springshirofilter")
                || lower.endsWith(".abstractshirofilter");
    }

    /** Invoke {@code FilterChain.doFilter(request, response)} when args look like a filter call. */
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
            // optional
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
            // Spring Security optional.
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
     * Best-effort Shiro Subject bind when a SecurityManager is already present.
     * Does not encrypt rememberMe cookies; session seed for COVERAGE/FORCED only.
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
            // login with token if possible — many apps require realm; keep best-effort only.
            try {
                Class<?> tokenClass = Class.forName(
                        "org.apache.shiro.authc.UsernamePasswordToken");
                Object token = tokenClass.getConstructor(String.class, String.class)
                        .newInstance(SCAN_PRINCIPAL, "veyrion-scan");
                subject.getClass().getMethod("login",
                                Class.forName("org.apache.shiro.authc.AuthenticationToken"))
                        .invoke(subject, token);
            } catch (Throwable ignoredLogin) {
                // Realm may reject; FORCED filter skip remains the primary path.
            }
        } catch (Throwable ignored) {
            // Shiro optional.
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
