package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.pathdebug.PathRunPathDebugView;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * P0-21: merge optional PathTrace / path-debug fields into PathRun API wire maps
 * without changing {@link ApiDtos.PathRunDto} Jackson round-trip.
 */
public final class PathDebugWireHelper {
    private PathDebugWireHelper() {
    }

    public static Map<String, Object> enrichPathRunMap(Map<String, Object> base, PathTrace pathTrace) {
        Objects.requireNonNull(base, "base");
        Map<String, Object> merged = new LinkedHashMap<>(base);
        if (pathTrace == null) {
            PathRunPathDebugView legacy = PathRunPathDebugView.createLegacyIncomplete();
            merged.putAll(legacy.toMap());
            return merged;
        }
        String authRequirement = PathTraceProjector.authRequirementFor(pathTrace, httpStatus(base));
        PathRunPathDebugView view = PathRunPathDebugView.fromPathTrace(pathTrace, authRequirement);
        merged.putAll(view.toMap());
        merged.put("pathTrace", pathTrace.toMap());
        return merged;
    }

    public static Map<String, Object> enrichPathRunMap(ApiDtos.PathRunDto dto, PathTrace pathTrace) {
        return enrichPathRunMap(basePathRunMap(dto), pathTrace);
    }

    /** Base PathRun wire map (no path-debug extensions). */
    public static Map<String, Object> basePathRunMap(ApiDtos.PathRunDto dto) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", dto.schemaVersion());
        result.put("pathRunId", dto.pathRunId());
        result.put("scanId", dto.scanId());
        result.put("entrypointRef", dto.entrypointRef());
        result.put("track", dto.track());
        result.put("attemptId", dto.attemptId());
        if (dto.experimentPlanId() != null && !dto.experimentPlanId().isBlank()) {
            result.put("experimentPlanId", dto.experimentPlanId());
        }
        String correlationId = correlationIdFromPathRun(dto);
        if (!correlationId.isBlank()) {
            result.put("correlationId", correlationId);
        }
        result.put("method", dto.method());
        result.put("contentType", dto.contentType());
        result.put("requestSummary", dto.requestSummary());
        result.put("outcomeClass", dto.outcomeClass());
        result.put("httpStatus", dto.httpStatus());
        result.put("entryHit", dto.entryHit());
        result.put("parameterBound", dto.parameterBound());
        result.put("sqlEvents", sqlEvents(dto));
        result.put("stopReason", dto.stopReason());
        result.put("verificationStatus", dto.verificationStatus());
        result.put("evidenceRefs", dto.evidenceRefs());
        result.put("identityProvenance", dto.identityProvenance());
        result.put("identityPrecondition", dto.identityPrecondition());
        result.put("branchHitMap", dto.branchHitMap());
        return result;
    }

    public static Map<String, Object> pathDebugSummary(PathTrace trace) {
        Map<String, Object> summary = new LinkedHashMap<>();
        if (trace == null) {
            summary.put("legacyIncomplete", true);
            summary.put("exitReason", "LEGACY_DYNAMIC_INCOMPLETE");
            return Map.copyOf(summary);
        }
        summary.put("entryRef", trace.entryRef());
        summary.put("track", trace.track());
        summary.put("postureKind", trace.posture().postureKind().name());
        summary.put("postureProvenance", trace.posture().postureProvenance());
        summary.put("exitReason", trace.exitReason().name());
        summary.put("lastBusinessHop", trace.lastBusinessHop());
        summary.put("effectRefs", trace.effectRefs());
        summary.put("parameterFlow", trace.parameterFlow().stream()
                .map(PathTrace.ParameterFlowStep::toMap).toList());
        summary.put("worldPackId", trace.worldPackId());
        summary.put("tracePlanId", trace.tracePlanId());
        summary.put("legacyIncomplete", trace.legacyIncomplete());
        summary.put("authRequirement", PathTraceProjector.authRequirementFor(trace, -1));
        return Map.copyOf(summary);
    }

    private static int httpStatus(Map<String, Object> map) {
        Object value = map.get("httpStatus");
        return value instanceof Number n ? n.intValue() : -1;
    }

    private static String correlationIdFromPathRun(ApiDtos.PathRunDto dto) {
        if (dto == null) return "";
        String attempt = dto.attemptId() == null ? "" : dto.attemptId().trim();
        if (attempt.startsWith("req-") && attempt.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")) {
            return attempt;
        }
        String summary = dto.requestSummary() == null ? "" : dto.requestSummary();
        int marker = summary.indexOf("correlationId=");
        if (marker < 0) return "";
        String rest = summary.substring(marker + "correlationId=".length()).trim();
        int end = rest.indexOf(' ');
        String value = end < 0 ? rest : rest.substring(0, end);
        return value.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,63}") ? value : "";
    }

    private static java.util.List<Object> sqlEvents(ApiDtos.PathRunDto dto) {
        java.util.List<Object> sqlEvents = new java.util.ArrayList<>();
        for (ApiDtos.SqlEventDto sql : dto.sqlEvents()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("sqlText", sql.sqlText());
            row.put("parameterSummary", sql.parameterSummary());
            row.put("readWrite", sql.readWrite());
            row.put("parameterized", sql.parameterized());
            row.put("maliciousFragmentPresent", sql.maliciousFragmentPresent());
            row.put("captureMode", sql.captureMode());
            sqlEvents.add(row);
        }
        return sqlEvents;
    }
}
