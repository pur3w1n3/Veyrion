package com.aq.jvmsentinel.ai.context;

import com.aq.jvmsentinel.control.ApiDtos;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Prompt 摘要 JSON 与字符串截断辅助。 */
public final class AiPromptText {
    private AiPromptText() {
    }

    public static Map<String, Object> scanPromptSummary(ApiDtos.ScanDto value) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("scanId", value.scanId());
        row.put("status", value.status());
        row.put("verificationStatus", value.verificationStatus());
        row.put("dependencyMode", value.dependencyMode());
        row.put("entryCount", value.entries().size());
        row.put("dependencyCount", value.dependencies().size());
        row.put("sinkCount", value.sinks().size());
        row.put("findingCount", value.findings().size());
        row.put("pathCount", value.paths().size());
        row.put("evidenceRefCount", value.evidenceRefs().size());
        row.put("methodCounts", topCounts(value.entries().stream()
                .map(ApiDtos.EntryDto::method).toList(), 10));
        row.put("controllerCounts", topCounts(value.entries().stream()
                .map(ApiDtos.EntryDto::declaringClass).toList(), 10));
        row.put("authPreconditionCount", value.entries().stream()
                .mapToInt(entry -> authPreconditions(entry).size()).sum());
        return row;
    }

    public static Map<String, Object> entryPromptSummary(ApiDtos.EntryDto value) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("entryRef", "entry:" + value.id());
        row.put("entryId", value.id());
        row.put("protocol", value.protocol());
        row.put("method", value.method());
        row.put("route", truncatePromptValue(value.route(), 160));
        row.put("controller", truncatePromptValue(value.declaringClass(), 180));
        row.put("module", truncatePromptValue(value.module(), 120));
        row.put("parameters", limitedStrings(value.parameters(), 12, 120));
        row.put("preconditions", limitedStrings(value.preconditions(), 12, 160));
        row.put("authAnnotations", limitedStrings(authPreconditions(value), 8, 160));
        row.put("verificationStatus", value.verificationStatus());
        row.put("confidence", value.confidence());
        row.put("coverage", value.coverage());
        row.put("evidenceRefs", limitedStrings(value.evidenceRefs(), 8, 160));
        return row;
    }

    public static Map<String, Integer> topCounts(List<String> values, int max) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (String value : values) {
            String key = value == null || value.isBlank() ? "UNKNOWN" : truncatePromptValue(value, 160);
            counts.put(key, counts.getOrDefault(key, 0) + 1);
        }
        return counts.entrySet().stream()
                .sorted((left, right) -> {
                    int byCount = Integer.compare(right.getValue(), left.getValue());
                    return byCount != 0 ? byCount : left.getKey().compareTo(right.getKey());
                })
                .limit(max)
                .collect(LinkedHashMap::new,
                        (map, entry) -> map.put(entry.getKey(), entry.getValue()),
                        LinkedHashMap::putAll);
    }

    public static List<String> authPreconditions(ApiDtos.EntryDto value) {
        return value.preconditions().stream()
                .filter(AiPromptText::looksAuthRelated)
                .limit(16)
                .map(item -> truncatePromptValue(item, 160))
                .toList();
    }

    public static boolean looksAuthRelated(String value) {
        if (value == null) return false;
        String normalized = value.toLowerCase(java.util.Locale.ROOT);
        return normalized.contains("auth")
                || normalized.contains("role")
                || normalized.contains("permit")
                || normalized.contains("security")
                || normalized.contains("preauthorize")
                || normalized.contains("secured")
                || normalized.contains("anonymous")
                || normalized.contains("jwt")
                || normalized.contains("token")
                || normalized.contains("权限")
                || normalized.contains("鉴权")
                || normalized.contains("认证")
                || normalized.contains("角色");
    }

    public static List<String> limitedStrings(List<String> values, int maxItems, int maxChars) {
        return values.stream()
                .limit(maxItems)
                .map(value -> truncatePromptValue(value, maxChars))
                .toList();
    }

    public static String truncatePromptValue(String value, int max) {
        if (value == null) return "";
        return value.length() <= max ? value : value.substring(0, max);
    }
}
