package com.aq.jvmsentinel.instrumentation;

import java.util.Locale;
import java.util.Map;

/**
 * P0-21: COVERAGE_POSTURE identity injection and FORCED_REACHABILITY guard recording.
 * Only active inside authorized Docker sandboxes; never on host execution.
 */
public final class FrameworkBoundaryAdapter {
    static final String DOCKER_PROPERTY = "veyrion.sandbox.docker";
    static final String POSTURE_PROPERTY = "veyrion.sandbox.runtimePosture";
    static final String POSTURE_HEADER = "X-Veyrion-Runtime-Posture";
    static final String SCAN_PRINCIPAL = "veyrion-scan-principal";
    static final String SCAN_ROLE = "ROLE_VEYRION_SCAN";

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

    /** Inject scan Principal / SecurityContext for COVERAGE_POSTURE only. */
    public static void applyCoveragePosture(Object request, String posture) {
        if (!sandboxEnabled() || request == null || !"COVERAGE_POSTURE".equals(posture)) {
            return;
        }
        try {
            request.getClass().getMethod("setAttribute", String.class, Object.class)
                    .invoke(request, "javax.servlet.request.X509Certificate", null);
            request.getClass().getMethod("setAttribute", String.class, Object.class)
                    .invoke(request, "com.veyrion.scan.principal", SCAN_PRINCIPAL);
        } catch (Throwable ignored) {
            // Servlet API shape varies; attribute injection is best-effort.
        }
        try {
            Class<?> holder = Class.forName("org.springframework.security.core.context.SecurityContextHolder");
            Object context = holder.getMethod("createEmptyContext").invoke(null);
            Class<?> authClass = Class.forName("org.springframework.security.authentication.UsernamePasswordAuthenticationToken");
            Object auth = authClass.getConstructor(Object.class, Object.class)
                    .newInstance(SCAN_PRINCIPAL, "N/A");
            authClass.getMethod("setAuthenticated", boolean.class).invoke(auth, true);
            context.getClass().getMethod("setAuthentication", Class.forName("org.springframework.security.core.Authentication"))
                    .invoke(context, auth);
            holder.getMethod("setContext", context.getClass()).invoke(null, context);
        } catch (Throwable ignored) {
            // Spring Security optional.
        }
    }

    public static boolean forcedReachabilityActive(String posture) {
        return sandboxEnabled() && "FORCED_REACHABILITY".equals(posture);
    }

    public static void recordGuardDecision(String className, String methodName, String decision,
                                           boolean forced, Map<String, String> extra) {
        Map<String, String> detail = PathDebugDetail.merge(extra,
                PathDebugDetail.guardDecision(decision, forced));
        AgentRuntime.recordTransformedDetail("HTTP", className, methodName, detail);
    }

    /** Recognized auth guard surfaces eligible for forced reachability recording. */
    public static boolean isRecognizedAuthGuard(String className, String methodName) {
        if (className == null || methodName == null) {
            return false;
        }
        String lower = className.toLowerCase(Locale.ROOT);
        return lower.contains("security") || lower.contains("auth") || lower.contains("filter")
                || lower.endsWith("interceptor") || methodName.contains("PreAuthorize")
                || methodName.contains("authorize");
    }
}
