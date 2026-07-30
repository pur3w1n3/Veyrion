package com.aq.jvmsentinel.domain.ir;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Trust boundary / 不可信 origin（parameter、header、cookie、message、file、…）。
 *
 * <p>Stable id: {@code trust:{entryId}:{param}}.
 */
public record TrustBoundaryNode(
        String id,
        String boundaryKind,
        String name,
        String entryNodeId,
        List<String> evidenceRefs,
        String provenanceKind
) implements IrNode {
    public TrustBoundaryNode {
        Objects.requireNonNull(id, "id");
        if (id.isBlank()) throw new IllegalArgumentException("id must not be blank");
        boundaryKind = boundaryKind == null || boundaryKind.isBlank() ? "PARAMETER" : boundaryKind.trim();
        name = name == null ? "" : name;
        entryNodeId = entryNodeId == null ? "" : entryNodeId;
        evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
        provenanceKind = provenanceKind == null || provenanceKind.isBlank() ? "FACT" : provenanceKind;
    }

    @Override
    public String kind() {
        return "TRUST_BOUNDARY";
    }

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", id);
        map.put("kind", kind());
        map.put("boundaryKind", boundaryKind);
        map.put("name", name);
        map.put("entryNodeId", entryNodeId);
        map.put("evidenceRefs", evidenceRefs);
        map.put("provenanceKind", provenanceKind);
        return map;
    }
}
