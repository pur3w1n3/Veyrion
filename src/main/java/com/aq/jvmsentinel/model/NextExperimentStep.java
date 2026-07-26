package com.aq.jvmsentinel.model;

import java.util.List;
import java.util.Objects;

/**
 * Evidence-constrained next validation step produced by PATH / TRIAGE.
 * Consumable by {@code sandbox_probe}; never upgrades verification alone.
 */
public record NextExperimentStep(
        String entryRef,
        String objective,
        IdentityTrack track,
        String techniqueId,
        List<String> candidateInputs,
        List<String> pathRunRefs,
        String rationale
) {
    public NextExperimentStep {
        Objects.requireNonNull(entryRef, "entryRef");
        Objects.requireNonNull(objective, "objective");
        track = track == null ? IdentityTrack.UNAUTH : track;
        techniqueId = techniqueId == null ? "" : techniqueId.trim();
        candidateInputs = List.copyOf(candidateInputs == null ? List.of() : candidateInputs);
        pathRunRefs = List.copyOf(pathRunRefs == null ? List.of() : pathRunRefs);
        rationale = rationale == null ? "" : rationale;
        if (!entryRef.startsWith("entry:")) {
            throw new IllegalArgumentException("entryRef must be entry:*");
        }
        if (objective.isBlank() || objective.length() > 512) {
            throw new IllegalArgumentException("objective is invalid");
        }
        if (candidateInputs.size() > 8) {
            throw new IllegalArgumentException("candidateInputs exceeds bound");
        }
        for (String input : candidateInputs) {
            if (input == null || input.length() > 1024
                    || input.toLowerCase().contains("runtime.exec")
                    || input.toLowerCase().contains("memshell")) {
                throw new IllegalArgumentException("candidateInputs rejected");
            }
        }
    }
}
