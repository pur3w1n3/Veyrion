package com.aq.jvmsentinel.domain.experiment;

import java.util.Locale;
import java.util.Optional;

/**
 * Experiment plan kinds from PATH_EXPERIMENT_MODEL §6.2 (P1-06).
 * Unknown wire values stay empty — never invent a kind that elevates verification.
 */
public enum ExperimentPlanKind {
    REACHABILITY,
    DATAFLOW_DIFF,
    GUARD_DIFF,
    STATE_SEQUENCE,
    TYPESTATE_API,
    CONCURRENCY_RESOURCE;

    public static Optional<ExperimentPlanKind> tryParse(String raw) {
        if (raw == null || raw.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(ExperimentPlanKind.valueOf(raw.trim().toUpperCase(Locale.ROOT)));
        } catch (IllegalArgumentException ignored) {
            return Optional.empty();
        }
    }

    public static ExperimentPlanKind parseRequired(String raw) {
        return tryParse(raw).orElseThrow(() -> new IllegalArgumentException("UNKNOWN_PLAN_KIND"));
    }
}
