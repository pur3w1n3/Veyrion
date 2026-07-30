package com.aq.jvmsentinel.domain.pathdebug;

import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * 符合 FORCED_REACHABILITY 的 guard kind。Sanitizer / SQL parameterization /
 * 说明：file-type/business state-machine invariant 永不可 force。
 */
public enum ForcedGuardKind {
    AUTH,
    ROLE,
    PERMISSION,
    LICENSE,
    FEATURE;

    private static final Set<String> FORBIDDEN = Set.of(
            "SANITIZER",
            "SQL_PARAMETERIZATION",
            "FILE_TYPE_VALIDATION",
            "BUSINESS_STATE_MACHINE",
            "AMOUNT_INVARIANT",
            "APPROVAL_INVARIANT"
    );

    public static Optional<ForcedGuardKind> tryParse(String raw) {
        if (raw == null || raw.isBlank()) {
            return Optional.empty();
        }
        String normalized = raw.trim().toUpperCase(Locale.ROOT);
        if (FORBIDDEN.contains(normalized) || normalized.contains("SANITIZER")
                || normalized.contains("PARAMETERIZ") || normalized.contains("STATE_MACHINE")) {
            return Optional.empty();
        }
        try {
            return Optional.of(valueOf(normalized));
        } catch (IllegalArgumentException ignored) {
            return Optional.empty();
        }
    }

    public static boolean isForbiddenForceTarget(String raw) {
        if (raw == null || raw.isBlank()) {
            return false;
        }
        String normalized = raw.trim().toUpperCase(Locale.ROOT);
        if (FORBIDDEN.contains(normalized)) {
            return true;
        }
        return normalized.contains("SANITIZER")
                || normalized.contains("PARAMETERIZ")
                || normalized.contains("FILE_TYPE")
                || normalized.contains("STATE_MACHINE")
                || normalized.contains("AMOUNT_INVARIANT")
                || normalized.contains("APPROVAL");
    }
}
