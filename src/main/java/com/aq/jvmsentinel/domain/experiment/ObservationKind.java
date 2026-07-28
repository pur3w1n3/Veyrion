package com.aq.jvmsentinel.domain.experiment;

import java.util.Locale;

/**
 * Unified RuntimeObservation subject kinds (P1-06).
 */
public enum ObservationKind {
    ENTRY,
    GUARD,
    EFFECT,
    STATE,
    DEPENDENCY,
    EXCEPTION,
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
