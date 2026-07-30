package com.aq.jvmsentinel.domain.pathdebug;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * path-debug contract 的可选 PathRun extension field。
 * 旧 PathRun 缺失 field 标记 LEGACY_DYNAMIC_INCOMPLETE — 永不 backfill。
 */
public record PathRunPathDebugView(
        String postureKind,
        String postureProvenance,
        List<String> forcedGuardRefs,
        String tracePlanId,
        String pathTraceId,
        String worldPackId,
        String worldPackDependencyMode,
        String exitReason,
        boolean legacyIncomplete,
        String authRequirement
) {
    public static final String LEGACY_MARKER = PathTrace.LEGACY_MARKER;

    public PathRunPathDebugView {
        postureKind = postureKind == null ? "" : postureKind;
        postureProvenance = postureProvenance == null ? "" : postureProvenance;
        forcedGuardRefs = forcedGuardRefs == null ? List.of() : List.copyOf(forcedGuardRefs);
        tracePlanId = tracePlanId == null ? "" : tracePlanId;
        pathTraceId = pathTraceId == null ? "" : pathTraceId;
        worldPackId = worldPackId == null ? "" : worldPackId;
        worldPackDependencyMode = worldPackDependencyMode == null ? "" : worldPackDependencyMode;
        exitReason = exitReason == null ? "" : exitReason;
        authRequirement = authRequirement == null ? "" : authRequirement;
        if (legacyIncomplete && exitReason.isBlank()) {
            exitReason = TraceExitReason.LEGACY_DYNAMIC_INCOMPLETE.name();
        }
        if (legacyIncomplete && postureProvenance.isBlank()) {
            postureProvenance = RuntimePosture.PROVENANCE_LEGACY;
        }
    }

    public static PathRunPathDebugView createLegacyIncomplete() {
        return new PathRunPathDebugView(
                "",
                RuntimePosture.PROVENANCE_LEGACY,
                List.of(),
                "",
                "",
                "",
                "",
                TraceExitReason.LEGACY_DYNAMIC_INCOMPLETE.name(),
                true,
                "");
    }

    public static PathRunPathDebugView fromPathTrace(PathTrace trace, String authRequirement) {
        if (trace == null) {
            return createLegacyIncomplete();
        }
        return new PathRunPathDebugView(
                trace.posture().postureKind().name(),
                trace.posture().postureProvenance(),
                trace.posture().forcedGuardRefs(),
                trace.tracePlanId(),
                trace.pathTraceId(),
                trace.worldPackId(),
                "",
                trace.exitReason().name(),
                trace.legacyIncomplete(),
                authRequirement == null ? "" : authRequirement);
    }

    /**
     * PathRun wire map 的兼容读取。缺失 posture/trace/world field → legacy incomplete。
     * 永不发明 FORCED_REACHABILITY 或 fake PathTrace event。
     */
    @SuppressWarnings("unchecked")
    public static PathRunPathDebugView fromPathRunWire(Map<String, Object> pathRunWire) {
        if (pathRunWire == null || pathRunWire.isEmpty()) {
            return createLegacyIncomplete();
        }
        String postureKind = string(pathRunWire.get("postureKind"));
        String postureProvenance = string(pathRunWire.get("postureProvenance"));
        String pathTraceId = string(pathRunWire.get("pathTraceId"));
        String tracePlanId = string(pathRunWire.get("tracePlanId"));
        String worldPackId = string(pathRunWire.get("worldPackId"));
        boolean hasDebug = !postureKind.isBlank() || !pathTraceId.isBlank()
                || !tracePlanId.isBlank() || !worldPackId.isBlank()
                || pathRunWire.get("pathTrace") instanceof Map<?, ?>;
        if (!hasDebug) {
            return createLegacyIncomplete();
        }
        List<String> forced = List.of();
        Object rawForced = pathRunWire.get("forcedGuardRefs");
        if (rawForced instanceof List<?> list) {
            forced = list.stream()
                    .filter(java.util.Objects::nonNull)
                    .map(Object::toString)
                    .filter(s -> !s.isBlank())
                    .toList();
        }
        Object pathTraceRaw = pathRunWire.get("pathTrace");
        if (pathTraceRaw instanceof Map<?, ?> nested) {
            PathTrace trace = PathTrace.fromMap((Map<String, Object>) nested);
            return fromPathTrace(trace, string(pathRunWire.get("authRequirement")));
        }
        boolean legacy = Boolean.TRUE.equals(pathRunWire.get("legacyIncomplete"))
                || LEGACY_MARKER.equals(string(pathRunWire.get("compatibilityMarker")))
                || RuntimePosture.PROVENANCE_LEGACY.equals(postureProvenance);
        return new PathRunPathDebugView(
                postureKind,
                postureProvenance.isBlank() && legacy ? RuntimePosture.PROVENANCE_LEGACY : postureProvenance,
                forced,
                tracePlanId,
                pathTraceId,
                worldPackId,
                string(pathRunWire.get("worldPackDependencyMode")),
                string(pathRunWire.get("exitReason")),
                legacy,
                string(pathRunWire.get("authRequirement")));
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        if (!postureKind.isBlank()) {
            map.put("postureKind", postureKind);
        }
        if (!postureProvenance.isBlank()) {
            map.put("postureProvenance", postureProvenance);
        }
        // 始终 emit，使 GUI wire parser 看到稳定 array shape。
        map.put("forcedGuardRefs", forcedGuardRefs);
        if (!tracePlanId.isBlank()) {
            map.put("tracePlanId", tracePlanId);
        }
        if (!pathTraceId.isBlank()) {
            map.put("pathTraceId", pathTraceId);
        }
        if (!worldPackId.isBlank()) {
            map.put("worldPackId", worldPackId);
        }
        if (!worldPackDependencyMode.isBlank()) {
            map.put("worldPackDependencyMode", worldPackDependencyMode);
        }
        if (!exitReason.isBlank()) {
            map.put("exitReason", exitReason);
        }
        map.put("legacyIncomplete", legacyIncomplete);
        if (legacyIncomplete) {
            map.put("compatibilityMarker", LEGACY_MARKER);
        }
        if (!authRequirement.isBlank()) {
            map.put("authRequirement", authRequirement);
        }
        return map;
    }

    private static String string(Object value) {
        return value == null ? "" : value.toString().trim();
    }
}
