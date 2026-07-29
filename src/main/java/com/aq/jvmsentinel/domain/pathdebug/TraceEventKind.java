package com.aq.jvmsentinel.domain.pathdebug;

import java.util.Locale;
import java.util.Optional;

/** Ordered PathTrace event kinds (P0-21). */
public enum TraceEventKind {
    ENTRY_HIT,
    PARAMETER_BOUND,
    METHOD_HOP,
    GUARD_DECISION,
    EFFECT_TRIGGERED,
    DEPENDENCY_CALL,
    DEPENDENCY_FAILURE,
    EXCEPTION_THROWN,
    RETURN_EXIT,
    TRACE_TRUNCATED;

    public static Optional<TraceEventKind> tryParse(String raw) {
        if (raw == null || raw.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(valueOf(raw.trim().toUpperCase(Locale.ROOT)));
        } catch (IllegalArgumentException ignored) {
            return Optional.empty();
        }
    }
}
