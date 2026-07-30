package com.aq.jvmsentinel.domain.ir;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * 从 PathRun / worker event 投影的 runtime observation。
 *
 * <p>Stable id: {@code runtime:{pathRunId}}.
 */
public record RuntimeObservationNode(
        String id,
        String eventKind,
        String correlation,
        String subjectNodeId,
        String outcomeClass,
        List<String> evidenceRefs,
        String provenanceKind,
        String verificationStatus
) implements IrNode {
    public RuntimeObservationNode {
        Objects.requireNonNull(id, "id");
        if (id.isBlank()) throw new IllegalArgumentException("id must not be blank");
        eventKind = eventKind == null || eventKind.isBlank() ? "PATH_RUN" : eventKind.trim();
        correlation = correlation == null ? "" : correlation;
        subjectNodeId = subjectNodeId == null ? "" : subjectNodeId;
        outcomeClass = outcomeClass == null ? "" : outcomeClass;
        evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
        provenanceKind = provenanceKind == null || provenanceKind.isBlank()
                ? "RUNTIME_OBSERVED" : provenanceKind;
        verificationStatus = verificationStatus == null || verificationStatus.isBlank()
                ? "UNREACHED" : verificationStatus;
    }

    @Override
    public String kind() {
        return "RUNTIME_OBSERVATION";
    }

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", id);
        map.put("kind", kind());
        map.put("eventKind", eventKind);
        map.put("correlation", correlation);
        map.put("subjectNodeId", subjectNodeId);
        map.put("outcomeClass", outcomeClass);
        map.put("evidenceRefs", evidenceRefs);
        map.put("provenanceKind", provenanceKind);
        map.put("verificationStatus", verificationStatus);
        return map;
    }
}
