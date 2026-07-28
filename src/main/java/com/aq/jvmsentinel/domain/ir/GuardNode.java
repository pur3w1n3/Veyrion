package com.aq.jvmsentinel.domain.ir;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Auth / ownership / tenant / approval guard. AUTH EntryDto rows and AUTH_GAP signals
 * project here rather than as {@link EntryNode}/{@link EffectNode} when appropriate.
 *
 * <p>Stable id: {@code guard:{key}} (or legacy {@code guard:hyp-…} sink ids reused as-is).
 */
public record GuardNode(
        String id,
        String guardKind,
        String expression,
        String subjectNodeId,
        List<String> evidenceRefs,
        String provenanceKind
) implements IrNode {
    public GuardNode {
        Objects.requireNonNull(id, "id");
        if (id.isBlank()) throw new IllegalArgumentException("id must not be blank");
        guardKind = guardKind == null || guardKind.isBlank() ? "UNKNOWN" : guardKind.trim();
        expression = expression == null ? "" : expression;
        subjectNodeId = subjectNodeId == null ? "" : subjectNodeId;
        evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
        provenanceKind = provenanceKind == null || provenanceKind.isBlank() ? "INFERENCE" : provenanceKind;
    }

    @Override
    public String kind() {
        return "GUARD";
    }

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", id);
        map.put("kind", kind());
        map.put("guardKind", guardKind);
        map.put("expression", expression);
        map.put("subjectNodeId", subjectNodeId);
        map.put("evidenceRefs", evidenceRefs);
        map.put("provenanceKind", provenanceKind);
        return map;
    }
}
