package com.aq.jvmsentinel.domain.experiment;

import java.util.Locale;
import java.util.Optional;

/**
 * 来自 PATH_EXPERIMENT_MODEL §6.2 的 experiment plan kind（P1-06）。
 * 未知 wire 值保持空 — 永不发明会提升 verification 的 kind。
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
