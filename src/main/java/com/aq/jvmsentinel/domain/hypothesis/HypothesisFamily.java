package com.aq.jvmsentinel.domain.hypothesis;

import java.util.Locale;

/**
 * SecurityHypothesis family taxonomy (ADR-0001 neutral contract).
 * Unknown wire values map to {@link #UNKNOWN} without elevating verification status.
 */
public enum HypothesisFamily {
    DATAFLOW,
    GUARD_COVERAGE,
    STATE,
    TYPESTATE,
    CONFIG,
    DEPENDENCY,
    CONCURRENCY,
    COMPOSITION,
    UNKNOWN;

    public static HypothesisFamily parse(String raw) {
        if (raw == null || raw.isBlank()) {
            return UNKNOWN;
        }
        try {
            return HypothesisFamily.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ignored) {
            return UNKNOWN;
        }
    }
}
