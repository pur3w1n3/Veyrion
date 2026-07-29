package com.aq.jvmsentinel.instrumentation;

/**
 * Unit-level acceptance for recognized-auth-guard heuristics, catalog allowlist,
 * DecisionShape rewrite modes, AccessControl / Interceptor / MethodSecurity force,
 * and Docker gate. Does not elevate VERIFIED; no Shiro rememberMe encryption.
 */
public final class ForcedReachabilityGuardAcceptanceTest {
    public static void main(String[] args) {
        FrameworkBoundaryAdapter.clearForcedGuardTypeAllowlistCache();
        System.clearProperty(FrameworkBoundaryAdapter.FORCED_GUARD_TYPES_PROPERTY);

        check(FrameworkBoundaryAdapter.isRecognizedAuthGuard(
                        "org.apache.shiro.web.filter.authc.FormAuthenticationFilter", "doFilterInternal"),
                "Shiro FormAuthenticationFilter recognized");
        check(FrameworkBoundaryAdapter.isRecognizedAuthGuard(
                        "org.apache.shiro.web.filter.authc.UserFilter", "isAccessAllowed"),
                "Shiro UserFilter recognized");
        check(FrameworkBoundaryAdapter.isRecognizedAuthGuard(
                        "org.springframework.security.web.FilterChainProxy", "doFilter"),
                "Spring FilterChainProxy recognized");
        check(FrameworkBoundaryAdapter.isRecognizedAuthGuard(
                        "com.example.JwtAuthFilter", "doFilterInternal"),
                "custom JwtAuthFilter recognized");
        check(FrameworkBoundaryAdapter.isRecognizedAuthGuard(
                        "com.kalvin.kvf.common.shiro.LoginFilter", "doFilterInternal"),
                "app LoginFilter recognized as auth guard");
        check(FrameworkBoundaryAdapter.isRecognizedAuthGuard(
                        "org.springblade.core.secure.interceptor.TokenInterceptor", "preHandle"),
                "Blade TokenInterceptor recognized as auth guard");
        check(FrameworkBoundaryAdapter.isRecognizedAuthGuard(
                        "org.springblade.core.secure.interceptor.AuthInterceptor", "preHandle"),
                "Blade AuthInterceptor recognized as auth guard");
        check(FrameworkBoundaryAdapter.isRecognizedAuthGuard(
                        "cn.dev33.satoken.interceptor.SaInterceptor", "preHandle"),
                "Sa-Token SaInterceptor recognized");
        check(FrameworkBoundaryAdapter.isRecognizedAuthGuard(
                        "cn.dev33.satoken.filter.SaServletFilter", "doFilter"),
                "Sa-Token SaServletFilter recognized");
        check(FrameworkBoundaryAdapter.isRecognizedAuthGuard(
                        "org.springframework.security.access.intercept.aopalliance.MethodSecurityInterceptor",
                        "invoke"),
                "MethodSecurityInterceptor recognized");
        check(!FrameworkBoundaryAdapter.isRecognizedAuthGuard(
                        "org.springframework.web.filter.CharacterEncodingFilter", "doFilterInternal"),
                "CharacterEncodingFilter not force-skipped");
        check(!FrameworkBoundaryAdapter.isRecognizedAuthGuard(
                        "org.springframework.web.filter.CorsFilter", "doFilterInternal"),
                "CorsFilter not force-skipped");
        check(!FrameworkBoundaryAdapter.isRecognizedAuthGuard(
                        "org.springframework.web.filter.OncePerRequestFilter", "doFilter"),
                "OncePerRequestFilter base not force-skipped");
        check(!FrameworkBoundaryAdapter.isRecognizedAuthGuard(
                        "org.apache.shiro.web.servlet.AbstractShiroFilter", "doFilter"),
                "AbstractShiroFilter container must not be force-skipped");
        check(!FrameworkBoundaryAdapter.isRecognizedAuthGuard(
                        "org.apache.shiro.spring.web.ShiroFilterFactoryBean$SpringShiroFilter",
                        "doFilterInternal"),
                "SpringShiroFilter container must not be force-skipped");
        check(!FrameworkBoundaryAdapter.isRecognizedAuthGuard(
                        "com.example.XssFilter", "doFilter"),
                "XssFilter must not be force-skipped");
        check(!FrameworkBoundaryAdapter.isRecognizedAuthGuard(
                        "com.example.SQLFilter", "doFilter"),
                "SQLFilter must not be force-skipped");
        check(!FrameworkBoundaryAdapter.isRecognizedAuthGuard(
                        "com.example.CsrfFilter", "doFilter"),
                "CsrfFilter must not be force-skipped");

        // Allowlist empty → heuristics
        check(FrameworkBoundaryAdapter.isForceEligibleGuard(
                        "com.kalvin.kvf.common.shiro.LoginFilter", "doFilterInternal"),
                "empty allowlist falls back to heuristics for LoginFilter");
        check(!FrameworkBoundaryAdapter.isForceEligibleGuard(
                        "org.apache.shiro.web.servlet.AbstractShiroFilter", "doFilter"),
                "empty allowlist still excludes AbstractShiroFilter");

        // Allowlist non-empty → only matching types (primary path)
        System.setProperty(FrameworkBoundaryAdapter.FORCED_GUARD_TYPES_PROPERTY,
                "com.kalvin.kvf.common.shiro.LoginFilter,org.apache.shiro.web.filter.authc.UserFilter,"
                        + "org.springblade.core.secure.interceptor.TokenInterceptor,"
                        + "cn.dev33.satoken.interceptor.SaInterceptor");
        FrameworkBoundaryAdapter.clearForcedGuardTypeAllowlistCache();
        try {
            check(FrameworkBoundaryAdapter.isForceEligibleGuard(
                            "com.kalvin.kvf.common.shiro.LoginFilter", "doFilterInternal"),
                    "allowlist matches LoginFilter");
            check(FrameworkBoundaryAdapter.isForceEligibleGuard(
                            "org.apache.shiro.web.filter.authc.UserFilter", "isAccessAllowed"),
                    "allowlist matches UserFilter");
            check(FrameworkBoundaryAdapter.isForceEligibleGuard(
                            "cn.dev33.satoken.interceptor.SaInterceptor", "preHandle"),
                    "allowlist matches SaInterceptor");
            check(!FrameworkBoundaryAdapter.isForceEligibleGuard(
                            "com.example.JwtAuthFilter", "doFilterInternal"),
                    "non-allowlisted JwtAuthFilter not forced when allowlist set");
            check(!FrameworkBoundaryAdapter.isForceEligibleGuard(
                            "org.apache.shiro.web.servlet.AbstractShiroFilter", "doFilter"),
                    "allowlist cannot force AbstractShiroFilter container");
        } finally {
            System.clearProperty(FrameworkBoundaryAdapter.FORCED_GUARD_TYPES_PROPERTY);
            FrameworkBoundaryAdapter.clearForcedGuardTypeAllowlistCache();
        }

        // DecisionShape rewrite modes (no arbitrary Object.preHandle)
        check(FrameworkBoundaryAdapter.rewriteMode(
                        "com.example.JwtAuthFilter", "doFilterInternal")
                        == FrameworkBoundaryAdapter.ForceRewriteMode.FILTER_CONTINUE_CHAIN,
                "Filter doFilter → FILTER_CONTINUE_CHAIN");
        check(FrameworkBoundaryAdapter.rewriteMode(
                        "org.apache.shiro.web.filter.authc.UserFilter", "isAccessAllowed")
                        == FrameworkBoundaryAdapter.ForceRewriteMode.ACCESS_ALLOWED_TRUE,
                "isAccessAllowed → ACCESS_ALLOWED_TRUE");
        check(FrameworkBoundaryAdapter.rewriteMode(
                        "org.springblade.core.secure.interceptor.TokenInterceptor", "preHandle")
                        == FrameworkBoundaryAdapter.ForceRewriteMode.INTERCEPTOR_PREHANDLE_TRUE,
                "Interceptor preHandle → INTERCEPTOR_PREHANDLE_TRUE");
        check(FrameworkBoundaryAdapter.rewriteMode(
                        "com.example.NotAGuard", "preHandle")
                        == FrameworkBoundaryAdapter.ForceRewriteMode.NONE,
                "arbitrary Object.preHandle not rewritten");
        check(FrameworkBoundaryAdapter.rewriteMode(
                        "com.example.XssFilter", "doFilter")
                        == FrameworkBoundaryAdapter.ForceRewriteMode.NONE,
                "sanitizer Filter not rewritten");
        check(FrameworkBoundaryAdapter.rewriteMode(
                        "org.springframework.security.access.intercept.aopalliance.MethodSecurityInterceptor",
                        "invoke")
                        == FrameworkBoundaryAdapter.ForceRewriteMode.METHOD_SECURITY_FAIL_OPEN,
                "MethodSecurityInterceptor → METHOD_SECURITY_FAIL_OPEN");

        System.setProperty(FrameworkBoundaryAdapter.DOCKER_PROPERTY, "true");
        try {
            check(FrameworkBoundaryAdapter.forcedReachabilityActive("FORCED_REACHABILITY"),
                    "forced active in docker");
            check("FORCED_REACHABILITY".equals(
                            FrameworkBoundaryAdapter.resolvePosture("FORCED_REACHABILITY")),
                    "header posture honored in docker");
            check(!FrameworkBoundaryAdapter.forcePastRecognizedFilter(
                            "COVERAGE_POSTURE",
                            "org.apache.shiro.web.filter.authc.UserFilter",
                            "doFilterInternal",
                            new Object[3]),
                    "COVERAGE does not skip filter body");
            check(FrameworkBoundaryAdapter.forceAccessAllowed(
                            "FORCED_REACHABILITY",
                            "org.apache.shiro.web.filter.authc.UserFilter",
                            "isAccessAllowed"),
                    "AccessControl isAccessAllowed forced under FORCED");
            check(FrameworkBoundaryAdapter.forceAccessAllowed(
                            "FORCED_REACHABILITY",
                            "com.kalvin.kvf.common.shiro.LoginFilter",
                            "isAccessAllowed"),
                    "LoginFilter isAccessAllowed forced under FORCED");
            check(FrameworkBoundaryAdapter.forceInterceptorPreHandle(
                            "FORCED_REACHABILITY",
                            "org.springblade.core.secure.interceptor.TokenInterceptor",
                            "preHandle"),
                    "TokenInterceptor preHandle forced under FORCED");
            check(FrameworkBoundaryAdapter.forceInterceptorPreHandle(
                            "FORCED_REACHABILITY",
                            "cn.dev33.satoken.interceptor.SaInterceptor",
                            "preHandle"),
                    "SaInterceptor preHandle forced under FORCED");
            check(!FrameworkBoundaryAdapter.forceInterceptorPreHandle(
                            "COVERAGE_POSTURE",
                            "org.springblade.core.secure.interceptor.TokenInterceptor",
                            "preHandle"),
                    "COVERAGE does not force interceptor preHandle");
            check(!FrameworkBoundaryAdapter.forceAccessAllowed(
                            "FORCED_REACHABILITY",
                            "org.apache.shiro.web.servlet.AbstractShiroFilter",
                            "isAccessAllowed"),
                    "AbstractShiroFilter isAccessAllowed not forced");
            check(!FrameworkBoundaryAdapter.forceAccessAllowed(
                            "COVERAGE_POSTURE",
                            "org.apache.shiro.web.filter.authc.UserFilter",
                            "isAccessAllowed"),
                    "COVERAGE does not force isAccessAllowed");
            check(FrameworkBoundaryAdapter.forceMethodSecurity(
                            "FORCED_REACHABILITY",
                            "org.springframework.security.access.intercept.aopalliance.MethodSecurityInterceptor",
                            "invoke"),
                    "MethodSecurityInterceptor forced under FORCED");
            check(!FrameworkBoundaryAdapter.forceMethodSecurity(
                            "COVERAGE_POSTURE",
                            "org.springframework.security.access.intercept.aopalliance.MethodSecurityInterceptor",
                            "invoke"),
                    "COVERAGE does not force MethodSecurityInterceptor");
            check(!FrameworkBoundaryAdapter.forceInterceptorPreHandle(
                            "FORCED_REACHABILITY",
                            "java.lang.Object",
                            "preHandle"),
                    "Object.preHandle never forced");
        } finally {
            System.clearProperty(FrameworkBoundaryAdapter.DOCKER_PROPERTY);
        }
        check(!FrameworkBoundaryAdapter.forcedReachabilityActive("FORCED_REACHABILITY"),
                "forced inactive without docker flag");
        System.out.println("ForcedReachabilityGuardAcceptanceTest: PASS");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
