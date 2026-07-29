package com.aq.jvmsentinel.instrumentation;

import java.util.LinkedHashMap;
import java.util.Map;

/** Detail markers for PathTrace projection (P0-21). Keeps top-level eventType whitelist stable. */
public final class PathDebugDetail {
    public static final String KIND = "pathDebugKind";
    public static final String EFFECT_KIND = "effectKind";
    public static final String FAILURE_CLASS = "failureClass";
    public static final String GUARD_DECISION = "guardDecision";
    public static final String FORCED = "forced";

    public static final String METHOD_HOP = "METHOD_HOP";
    public static final String GUARD = "GUARD_DECISION";
    public static final String EFFECT = "EFFECT_TRIGGERED";
    public static final String DEPENDENCY_CALL = "DEPENDENCY_CALL";
    public static final String DEPENDENCY_FAILURE = "DEPENDENCY_FAILURE";

    private PathDebugDetail() {
    }

    public static Map<String, String> methodHop(String captureMode) {
        Map<String, String> detail = new LinkedHashMap<>();
        detail.put(KIND, METHOD_HOP);
        if (captureMode != null && !captureMode.isBlank()) {
            detail.put("captureMode", captureMode);
        }
        return detail;
    }

    public static Map<String, String> guardDecision(String decision, boolean forced) {
        Map<String, String> detail = new LinkedHashMap<>();
        detail.put(KIND, GUARD);
        detail.put(GUARD_DECISION, decision == null ? "OBSERVED" : decision);
        detail.put(FORCED, Boolean.toString(forced));
        return detail;
    }

    public static Map<String, String> effectTriggered(String effectKind) {
        Map<String, String> detail = new LinkedHashMap<>();
        detail.put(KIND, EFFECT);
        detail.put(EFFECT_KIND, effectKind == null ? "UNKNOWN" : effectKind);
        return detail;
    }

    public static Map<String, String> dependencyCall(String summary) {
        Map<String, String> detail = new LinkedHashMap<>();
        detail.put(KIND, DEPENDENCY_CALL);
        detail.put("outcome", "OBSERVED");
        if (summary != null && !summary.isBlank()) {
            detail.put("summary", summary);
        }
        return detail;
    }

    public static Map<String, String> dependencyFailure(String failureClass, String summary) {
        Map<String, String> detail = new LinkedHashMap<>();
        detail.put(KIND, DEPENDENCY_FAILURE);
        detail.put(FAILURE_CLASS, failureClass == null ? "DEPENDENCY_UNAVAILABLE" : failureClass);
        detail.put("outcome", "FAILED");
        if (summary != null && !summary.isBlank()) {
            detail.put("summary", summary);
        }
        return detail;
    }

    public static Map<String, String> merge(Map<String, String> base, Map<String, String> markers) {
        Map<String, String> merged = new LinkedHashMap<>();
        if (base != null) merged.putAll(base);
        if (markers != null) merged.putAll(markers);
        return Map.copyOf(merged);
    }
}
