package com.aq.jvmsentinel.domain.hypothesis;

import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * 一等 security hypothesis（P0-12）。source/effect 仅 DATAFLOW 必填。
 */
public record SecurityHypothesis(
        int schemaVersion,
        String hypothesisId,
        String scanId,
        String securityProperty,
        HypothesisFamily family,
        HypothesisLifecycle lifecycle,
        String detectorVersion,
        List<String> supportingEvidenceRefs,
        List<String> contradictingEvidenceRefs,
        List<String> coverageGapRefs,
        String source,
        String effect
) {
    public static final int SCHEMA_VERSION = 1;

    public SecurityHypothesis {
        if (schemaVersion < 1) {
            throw new IllegalArgumentException("schemaVersion must be >= 1");
        }
        Objects.requireNonNull(hypothesisId, "hypothesisId");
        Objects.requireNonNull(scanId, "scanId");
        Objects.requireNonNull(securityProperty, "securityProperty");
        Objects.requireNonNull(family, "family");
        Objects.requireNonNull(lifecycle, "lifecycle");
        Objects.requireNonNull(detectorVersion, "detectorVersion");
        if (hypothesisId.isBlank()) throw new IllegalArgumentException("hypothesisId must not be blank");
        if (scanId.isBlank()) throw new IllegalArgumentException("scanId must not be blank");
        if (securityProperty.isBlank()) throw new IllegalArgumentException("securityProperty must not be blank");
        if (detectorVersion.isBlank()) throw new IllegalArgumentException("detectorVersion must not be blank");
        supportingEvidenceRefs = List.copyOf(supportingEvidenceRefs == null ? List.of() : supportingEvidenceRefs);
        contradictingEvidenceRefs = List.copyOf(contradictingEvidenceRefs == null ? List.of() : contradictingEvidenceRefs);
        coverageGapRefs = List.copyOf(coverageGapRefs == null ? List.of() : coverageGapRefs);
        source = source == null ? "" : source;
        effect = effect == null ? "" : effect;
        if (family == HypothesisFamily.DATAFLOW && (source.isBlank() || effect.isBlank())) {
            throw new IllegalArgumentException("DATAFLOW hypothesis requires source and effect");
        }
    }

    /** Wire-safe map for API / SQLite JSON (unknown family stays UNKNOWN, never elevates status). */
    public java.util.Map<String, Object> toMap() {
        java.util.Map<String, Object> map = new java.util.LinkedHashMap<>();
        map.put("schemaVersion", schemaVersion);
        map.put("hypothesisId", hypothesisId);
        map.put("scanId", scanId);
        map.put("securityProperty", securityProperty);
        map.put("family", family.name());
        map.put("lifecycle", lifecycle.name());
        map.put("detectorVersion", detectorVersion);
        map.put("supportingEvidenceRefs", supportingEvidenceRefs);
        map.put("contradictingEvidenceRefs", contradictingEvidenceRefs);
        map.put("coverageGapRefs", coverageGapRefs);
        if (!source.isBlank()) map.put("source", source);
        if (!effect.isBlank()) map.put("effect", effect);
        return map;
    }

    @SuppressWarnings("unchecked")
    public static SecurityHypothesis fromMap(java.util.Map<String, Object> map) {
        Objects.requireNonNull(map, "map");
        int version = map.get("schemaVersion") instanceof Number n ? n.intValue() : SCHEMA_VERSION;
        HypothesisFamily family = HypothesisFamily.parse(string(map.get("family")));
        String source = string(map.get("source"));
        String effect = string(map.get("effect"));
        // 未知 family：保持 payload 可读，但永不发明 DATAFLOW source/effect 要求。
        if (family == HypothesisFamily.DATAFLOW && (source.isBlank() || effect.isBlank())) {
            family = HypothesisFamily.UNKNOWN;
        }
        return new SecurityHypothesis(
                version,
                require(map.get("hypothesisId"), "hypothesisId"),
                require(map.get("scanId"), "scanId"),
                require(map.get("securityProperty"), "securityProperty"),
                family,
                HypothesisLifecycle.parse(string(map.get("lifecycle"))),
                require(map.get("detectorVersion"), "detectorVersion"),
                stringList(map.get("supportingEvidenceRefs")),
                stringList(map.get("contradictingEvidenceRefs")),
                stringList(map.get("coverageGapRefs")),
                source,
                effect
        );
    }

    private static String require(Object value, String name) {
        String text = string(value);
        if (text.isBlank()) throw new IllegalArgumentException(name + " must not be blank");
        return text;
    }

    private static String string(Object value) {
        return value == null ? "" : String.valueOf(value).trim();
    }

    private static List<String> stringList(Object value) {
        if (!(value instanceof List<?> list)) return List.of();
        return list.stream()
                .filter(Objects::nonNull)
                .map(item -> String.valueOf(item).trim())
                .filter(item -> !item.isEmpty())
                .toList();
    }

    public static String normalizeProperty(String raw) {
        if (raw == null || raw.isBlank()) return "UNKNOWN";
        return raw.trim().toUpperCase(Locale.ROOT);
    }
}
