package com.aq.jvmsentinel.domain.ir;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * 业务/安全 state 前置条件或 transition 主体。
 *
 * <p>Stable id: {@code state:{entryId}:{stateKey}}.
 */
public record StateNode(
        String id,
        String stateKey,
        String subjectNodeId,
        List<String> evidenceRefs,
        String provenanceKind
) implements IrNode {
    public StateNode {
        Objects.requireNonNull(id, "id");
        if (id.isBlank()) throw new IllegalArgumentException("id must not be blank");
        stateKey = stateKey == null ? "" : stateKey;
        subjectNodeId = subjectNodeId == null ? "" : subjectNodeId;
        evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
        provenanceKind = provenanceKind == null || provenanceKind.isBlank() ? "INFERENCE" : provenanceKind;
    }

    @Override
    public String kind() {
        return "STATE";
    }

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", id);
        map.put("kind", kind());
        map.put("stateKey", stateKey);
        map.put("subjectNodeId", subjectNodeId);
        map.put("evidenceRefs", evidenceRefs);
        map.put("provenanceKind", provenanceKind);
        return map;
    }
}
