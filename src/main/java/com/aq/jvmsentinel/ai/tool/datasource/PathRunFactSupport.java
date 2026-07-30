package com.aq.jvmsentinel.ai.tool.datasource;

import com.aq.jvmsentinel.analysis.experiment.PathTraceGapAdvisor;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * PathRun / PathTrace / Evidence 事实序列化与 prompt 摘要辅助。
 */
public final class PathRunFactSupport {
    private static final int MAX_SQL_EVENTS_IN_FACT = 8;
    private static final int MAX_SQL_TEXT = 240;

    private PathRunFactSupport() {
    }

    /** 仅将受限 evidence 摘要与 provenance 元数据暴露给工具边界。 */
    public static JsonNode safeEvidence(ApiDtos.EvidenceDto value) {
        return DatasourceJson.JSON.createObjectNode()
                .put("evidenceId", value.evidenceId())
                .put("projectId", value.projectId())
                .put("artifactDigest", value.artifactDigest())
                .put("scanId", value.scanId())
                .put("provenanceKind", value.provenanceKind())
                .put("source", value.source())
                .put("summary", value.summary())
                .put("verificationStatus", value.verificationStatus())
                .put("dependencyMode", value.dependencyMode());
    }

    public static JsonNode pathTraceFact(PathTrace trace) {
        ObjectNode node = DatasourceJson.JSON.createObjectNode();
        node.put("kind", "PATH_TRACE");
        node.put("pathTraceId", trace.pathTraceId());
        node.put("pathRunId", trace.pathRunId());
        node.put("entryRef", trace.entryRef());
        node.put("track", trace.track());
        node.put("postureKind", trace.posture().postureKind().name());
        node.put("postureProvenance", trace.posture().postureProvenance());
        node.put("exitReason", trace.exitReason().name());
        node.put("lastBusinessHop", trace.lastBusinessHop());
        node.put("legacyIncomplete", trace.legacyIncomplete());
        node.put("authRequirement", com.aq.jvmsentinel.analysis.experiment.PathTraceProjector
                .authRequirementFor(trace, -1));
        ArrayNode effects = node.putArray("effectRefs");
        for (String ref : trace.effectRefs()) {
            effects.add(ref);
        }
        ArrayNode flow = node.putArray("parameterFlow");
        for (PathTrace.ParameterFlowStep step : trace.parameterFlow()) {
            ObjectNode row = flow.addObject();
            row.put("source", step.source());
            row.put("boundTo", step.boundTo());
            row.put("flowedTo", step.flowedTo());
            row.put("effectRef", step.effectRef());
        }
        ArrayNode suggestions = node.putArray("nextExperimentSuggestions");
        for (PathTraceGapAdvisor.Suggestion suggestion : PathTraceGapAdvisor.suggest(trace)) {
            suggestions.add(DatasourceJson.JSON.valueToTree(suggestion.toMap()));
        }
        return node;
    }

    public static JsonNode pathRunFact(ApiDtos.PathRunDto value) {
        ObjectNode node = DatasourceJson.JSON.createObjectNode();
        node.put("kind", "PATH_RUN");
        node.put("pathRunId", value.pathRunId());
        node.put("scanId", value.scanId());
        node.put("entrypointRef", value.entrypointRef());
        node.put("track", value.track());
        node.put("attemptId", value.attemptId());
        if (value.experimentPlanId() != null && !value.experimentPlanId().isBlank()) {
            node.put("experimentPlanId", value.experimentPlanId());
        }
        node.put("method", value.method());
        node.put("contentType", value.contentType());
        node.put("requestSummary", value.requestSummary());
        node.put("outcomeClass", value.outcomeClass());
        node.put("httpStatus", value.httpStatus());
        if (value.entryHit() != null) {
            node.put("entryHit", value.entryHit());
        }
        if (value.parameterBound() != null) {
            node.put("parameterBound", value.parameterBound());
        }
        node.put("stopReason", value.stopReason());
        node.put("verificationStatus", value.verificationStatus());
        node.put("identityProvenance", value.identityProvenance());
        node.put("identityPrecondition", value.identityPrecondition());
        ArrayNode evidenceRefs = node.putArray("evidenceRefs");
        for (String ref : value.evidenceRefs()) {
            evidenceRefs.add(ref);
        }
        ArrayNode sqlEvents = node.putArray("sqlEvents");
        int emitted = 0;
        for (ApiDtos.SqlEventDto sql : value.sqlEvents()) {
            if (emitted >= MAX_SQL_EVENTS_IN_FACT) {
                break;
            }
            ObjectNode row = sqlEvents.addObject();
            String sqlText = sql.sqlText() == null ? "" : sql.sqlText();
            if (sqlText.length() > MAX_SQL_TEXT) {
                sqlText = sqlText.substring(0, MAX_SQL_TEXT);
            }
            row.put("sqlText", sqlText);
            row.put("parameterSummary", sql.parameterSummary() == null ? "" : sql.parameterSummary());
            row.put("readWrite", sql.readWrite());
            row.put("parameterized", sql.parameterized());
            row.put("maliciousFragmentPresent", sql.maliciousFragmentPresent());
            row.put("captureMode", sql.captureMode());
            emitted++;
        }
        node.put("sqlEventCount", value.sqlEvents().size());
        node.put("sqlEventsTruncated", value.sqlEvents().size() > MAX_SQL_EVENTS_IN_FACT);
        return node;
    }

    /** 注入 AI prompt 时使用的紧凑 HTTP/SQL 摘要。 */
    public static Map<String, Object> pathRunPromptSummary(ApiDtos.PathRunDto value) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("pathRunId", value.pathRunId());
        row.put("entrypointRef", value.entrypointRef());
        row.put("track", value.track());
        row.put("method", value.method());
        row.put("httpStatus", value.httpStatus());
        row.put("outcomeClass", value.outcomeClass());
        row.put("verificationStatus", value.verificationStatus());
        row.put("requestSummary", truncate(value.requestSummary(), 160));
        row.put("sqlEventCount", value.sqlEvents().size());
        List<Map<String, Object>> sql = new ArrayList<>();
        int emitted = 0;
        for (ApiDtos.SqlEventDto event : value.sqlEvents()) {
            if (emitted >= 3) {
                break;
            }
            Map<String, Object> sqlRow = new LinkedHashMap<>();
            sqlRow.put("readWrite", event.readWrite());
            sqlRow.put("captureMode", event.captureMode());
            sqlRow.put("maliciousFragmentPresent", event.maliciousFragmentPresent());
            sqlRow.put("sqlText", truncate(event.sqlText(), 120));
            sql.add(sqlRow);
            emitted++;
        }
        row.put("sqlEvents", sql);
        return row;
    }

    private static String truncate(String value, int max) {
        if (value == null) {
            return "";
        }
        return value.length() <= max ? value : value.substring(0, max);
    }
}
