package com.aq.jvmsentinel.domain.pathdebug;

import java.util.Locale;
import java.util.Optional;

/**
 * 说明：P0-21 runtime posture kind；Wire IdentityTrack 仍为 UNAUTH/USER/ADMIN/BYPASS_CANDIDATE；
 * postureKind 为产品用途维度。
 */
public enum RuntimePostureKind {
    UNAUTH,
    COVERAGE_POSTURE,
    FORCED_REACHABILITY,
    BYPASS;

    public static Optional<RuntimePostureKind> tryParse(String raw) {
        if (raw == null || raw.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(valueOf(raw.trim().toUpperCase(Locale.ROOT)));
        } catch (IllegalArgumentException ignored) {
            return Optional.empty();
        }
    }

    public static RuntimePostureKind parseRequired(String raw) {
        return tryParse(raw).orElseThrow(() -> new IllegalArgumentException("UNKNOWN_POSTURE_KIND"));
    }
}
