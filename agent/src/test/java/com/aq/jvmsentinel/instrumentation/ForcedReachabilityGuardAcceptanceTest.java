package com.aq.jvmsentinel.instrumentation;

/**
 * Unit-level acceptance for recognized-auth-guard heuristics and Docker gate.
 * Does not elevate VERIFIED; no Shiro rememberMe encryption.
 */
public final class ForcedReachabilityGuardAcceptanceTest {
    public static void main(String[] args) {
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
