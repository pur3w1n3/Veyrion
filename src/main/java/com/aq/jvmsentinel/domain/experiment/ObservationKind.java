package com.aq.jvmsentinel.domain.experiment;

import java.util.Locale;

/**
 * 统一的 RuntimeObservation subject kind（P1-06）。
 */
public enum ObservationKind {
    ENTRY,
    GUARD,
    EFFECT,
    STATE,
    DEPENDENCY,
    EXCEPTION,
    BRANCH,
    UNKNOWN;

    public static ObservationKind parse(String raw) {
        if (raw == null || raw.isBlank()) {
            return UNKNOWN;
        }
        try {
            return ObservationKind.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ignored) {
            return UNKNOWN;
        }
    }
}
