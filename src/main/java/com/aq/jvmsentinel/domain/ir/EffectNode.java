package com.aq.jvmsentinel.domain.ir;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * 敏感 effect / sink-like capability。不限于固定 API signature。
 *
 * <p>Stable id: {@code effect:{sinkDtoId}}.
 */
public record EffectNode(
        String id,
        String category,
        String symbol,
        String sourceLabel,
        List<String> evidenceRefs,
        String provenanceKind,
        String verificationStatus
) implements IrNode {
    public EffectNode {
        Objects.requireNonNull(id, "id");
        if (id.isBlank()) throw new IllegalArgumentException("id must not be blank");
        category = category == null || category.isBlank() ? "UNKNOWN" : category.trim();
        symbol = symbol == null ? "" : symbol;
        sourceLabel = sourceLabel == null ? "" : sourceLabel;
        evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
        provenanceKind = provenanceKind == null || provenanceKind.isBlank() ? "INFERENCE" : provenanceKind;
        verificationStatus = verificationStatus == null || verificationStatus.isBlank()
                ? "STATIC_INFERRED" : verificationStatus;
    }

    @Override
    public String kind() {
        return "EFFECT";
    }

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", id);
        map.put("kind", kind());
        map.put("category", category);
        map.put("symbol", symbol);
        map.put("sourceLabel", sourceLabel);
        map.put("evidenceRefs", evidenceRefs);
        map.put("provenanceKind", provenanceKind);
        map.put("verificationStatus", verificationStatus);
        return map;
    }
}
