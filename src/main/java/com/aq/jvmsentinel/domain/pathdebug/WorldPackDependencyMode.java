package com.aq.jvmsentinel.domain.pathdebug;

import java.util.Locale;
import java.util.Optional;

/**
 * World Pack dependency 策略。
 * OBSERVE_FAIL：真实 failure，保留 prior path。
 * 说明：MOCK_CONTINUE：stub/seed 以 MOCK provenance 继续更深探索。
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
