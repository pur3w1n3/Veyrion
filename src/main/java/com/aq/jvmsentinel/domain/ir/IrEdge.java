package com.aq.jvmsentinel.domain.ir;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Directed Evidence Graph edge with stable id and {@link EdgeKind}. */
public record IrEdge(
        String id,
        EdgeKind kind,
        String fromId,
        String toId,
        List<String> evidenceRefs,
        String provenanceKind
) {
    public IrEdge {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(fromId, "fromId");
        Objects.requireNonNull(toId, "toId");
        if (id.isBlank()) throw new IllegalArgumentException("id must not be blank");
        if (fromId.isBlank()) throw new IllegalArgumentException("fromId must not be blank");
        if (toId.isBlank()) throw new IllegalArgumentException("toId must not be blank");
        evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
        provenanceKind = provenanceKind == null || provenanceKind.isBlank() ? "INFERENCE" : provenanceKind;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", id);
        map.put("kind", kind.name());
        map.put("fromId", fromId);
        map.put("toId", toId);
        map.put("evidenceRefs", evidenceRefs);
        map.put("provenanceKind", provenanceKind);
        return map;
    }
}
