package com.aq.jvmsentinel.domain.experiment;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * 统一 runtime observation（P1-06）：Entry/Guard/Effect/State/Dependency/Exception。
 * Provenance 保持 RUNTIME_OBSERVED；自身永不提升 verification status。
 */
public record RuntimeObservation(
        String observationId,
        String pathRunId,
        String hypothesisId,
        ExperimentPlanKind planKind,
        ObservationKind kind,
        String signalCode,
        String outcomeClass,
        boolean successfulProjection,
        List<String> evidenceRefs,
        String provenanceKind,
        List<ObservationKind> incrementalSubjects
) {
    public RuntimeObservation {
        Objects.requireNonNull(observationId, "observationId");
        Objects.requireNonNull(kind, "kind");
        if (observationId.isBlank()) {
            throw new IllegalArgumentException("observationId must not be blank");
        }
        pathRunId = pathRunId == null ? "" : pathRunId.trim();
        hypothesisId = hypothesisId == null ? "" : hypothesisId.trim();
        signalCode = signalCode == null ? "" : signalCode.trim().toUpperCase(Locale.ROOT);
        outcomeClass = outcomeClass == null ? "" : outcomeClass.trim().toUpperCase(Locale.ROOT);
        evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
        provenanceKind = provenanceKind == null || provenanceKind.isBlank()
                ? "RUNTIME_OBSERVED" : provenanceKind.trim();
        if (!"RUNTIME_OBSERVED".equals(provenanceKind)) {
            throw new IllegalArgumentException("RuntimeObservation provenance must be RUNTIME_OBSERVED");
        }
        incrementalSubjects = List.copyOf(incrementalSubjects == null ? List.of() : incrementalSubjects);
        if (!successfulProjection) {
            // 空/失败 projection 保留 identity 但不得看起来像 hit。
            if (signalCode.isBlank()) {
                signalCode = "EMPTY_OR_FAILED";
            }
        }
    }

    public boolean isEmptyOrFailed() {
        return !successfulProjection
                || pathRunId.isBlank()
                || "EMPTY_OR_FAILED".equals(signalCode)
                || evidenceRefs.isEmpty() && "UNKNOWN".equals(outcomeClass);
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("observationId", observationId);
        if (!pathRunId.isBlank()) map.put("pathRunId", pathRunId);
        if (!hypothesisId.isBlank()) map.put("hypothesisId", hypothesisId);
        if (planKind != null) map.put("planKind", planKind.name());
        map.put("kind", kind.name());
        map.put("signalCode", signalCode);
        map.put("outcomeClass", outcomeClass);
        map.put("successfulProjection", successfulProjection);
        map.put("evidenceRefs", evidenceRefs);
        map.put("provenanceKind", provenanceKind);
        map.put("incrementalSubjects", incrementalSubjects.stream().map(Enum::name).toList());
        return map;
    }
}
