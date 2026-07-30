package com.aq.jvmsentinel.domain.ir;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * 说明：Encoding/parameterization/whitelist/reject-branch sanitizer 或 validator。
 *
 * <p>Stable id: {@code sanitizer:{key}}. Minimal projection may leave this empty.
 */
public record SanitizerNode(
        String id,
        String sanitizerKind,
        String symbol,
        List<String> evidenceRefs,
        String provenanceKind
) implements IrNode {
    public SanitizerNode {
        Objects.requireNonNull(id, "id");
        if (id.isBlank()) throw new IllegalArgumentException("id must not be blank");
        sanitizerKind = sanitizerKind == null || sanitizerKind.isBlank() ? "UNKNOWN" : sanitizerKind.trim();
        symbol = symbol == null ? "" : symbol;
        evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
        provenanceKind = provenanceKind == null || provenanceKind.isBlank() ? "INFERENCE" : provenanceKind;
    }

    @Override
    public String kind() {
        return "SANITIZER";
    }

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", id);
        map.put("kind", kind());
        map.put("sanitizerKind", sanitizerKind);
        map.put("symbol", symbol);
        map.put("evidenceRefs", evidenceRefs);
        map.put("provenanceKind", provenanceKind);
        return map;
    }
}
