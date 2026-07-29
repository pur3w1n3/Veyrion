package com.aq.jvmsentinel.domain.pathdebug;

import java.util.Locale;
import java.util.Optional;

/** Authoritative PathTrace termination reasons (P0-21). */
public enum TraceExitReason {
    COMPLETED,
    AUTH_CHALLENGE,
    GUARD_BLOCKED,
    FORCED_PAST_GUARD,
    PARAMETER_BINDING_GAP,
    WORLD_STATE_GAP,
    DEPENDENCY_UNAVAILABLE,
    DEPENDENCY_DATA_GAP,
    LICENSE_UNAVAILABLE,
    AUTH_POSTURE_GAP,
    BUSINESS_TIMEOUT,
    TRACE_TRUNCATED,
    RUNTIME_CRASH,
    LEGACY_DYNAMIC_INCOMPLETE,
    UNKNOWN;

    public static Optional<TraceExitReason> tryParse(String raw) {
        if (raw == null || raw.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(valueOf(raw.trim().toUpperCase(Locale.ROOT)));
        } catch (IllegalArgumentException ignored) {
            return Optional.empty();
        }
    }

    public static TraceExitReason parseOrUnknown(String raw) {
        return tryParse(raw).orElse(UNKNOWN);
    }
}
