package com.aq.jvmsentinel.domain.pathdebug;

import java.util.Locale;
import java.util.Optional;

/**
 * World Pack dependency strategy.
 * OBSERVE_FAIL: real failure, keep prior path.
 * MOCK_CONTINUE: stub/seed continues deeper exploration with MOCK provenance.
 */
public enum WorldPackDependencyMode {
    OBSERVE_FAIL,
    MOCK_CONTINUE;

    public static Optional<WorldPackDependencyMode> tryParse(String raw) {
        if (raw == null || raw.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(valueOf(raw.trim().toUpperCase(Locale.ROOT)));
        } catch (IllegalArgumentException ignored) {
            return Optional.empty();
        }
    }

    public static WorldPackDependencyMode parseOrDefault(String raw) {
        return tryParse(raw).orElse(MOCK_CONTINUE);
    }
}
