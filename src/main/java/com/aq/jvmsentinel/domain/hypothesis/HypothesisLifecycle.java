package com.aq.jvmsentinel.domain.hypothesis;

import java.util.Locale;

/**
 * Hypothesis lifecycle for the P0-12 vertical slice.
 * Static sink / AUTH_GAP projections start as {@link #CANDIDATE}.
 */
public enum HypothesisLifecycle {
    CANDIDATE,
    SUPPORTED,
    CONTRADICTED,
    INSUFFICIENT_EVIDENCE,
    DISMISSED;

    public static HypothesisLifecycle parse(String raw) {
        if (raw == null || raw.isBlank()) {
            return CANDIDATE;
        }
        try {
            return HypothesisLifecycle.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ignored) {
            return CANDIDATE;
        }
    }
}
