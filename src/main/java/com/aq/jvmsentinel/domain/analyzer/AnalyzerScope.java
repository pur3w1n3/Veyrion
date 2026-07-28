package com.aq.jvmsentinel.domain.analyzer;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/** Bound identity for an Analyzer analysis attempt. Wrong scope is fail-closed. */
public record AnalyzerScope(
        String projectId,
        String artifactDigest,
        String scanId,
        String analysisId
) {
    public AnalyzerScope {
        projectId = AnalyzerContracts.id(projectId, "projectId");
        artifactDigest = AnalyzerContracts.digest(artifactDigest, "artifactDigest");
        scanId = AnalyzerContracts.id(scanId, "scanId");
        analysisId = AnalyzerContracts.id(analysisId, "analysisId");
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("projectId", projectId);
        map.put("artifactDigest", artifactDigest);
        map.put("scanId", scanId);
        map.put("analysisId", analysisId);
        return map;
    }

    public static AnalyzerScope fromMap(Map<String, ?> map) {
        Objects.requireNonNull(map, "scope");
        return new AnalyzerScope(
                string(map, "projectId"),
                string(map, "artifactDigest"),
                string(map, "scanId"),
                string(map, "analysisId"));
    }

    private static String string(Map<String, ?> map, String key) {
        Object value = map.get(key);
        if (!(value instanceof String text) || text.isBlank()) {
            throw new IllegalArgumentException("scope." + key + " required");
        }
        return text;
    }
}
