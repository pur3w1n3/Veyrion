package com.aq.jvmsentinel.domain.pathdebug;

import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Static catalog entry for a FORCED_REACHABILITY-eligible guard surface.
 * Refs are server-owned ({@code GUARD:AUTH:<simpleName>}); AI/frontend cannot supply them.
 */
public record GuardSurface(
        String ref,
        ForcedGuardKind kind,
        List<String> typeNames,
        DecisionShape decisionShape
) {
    public enum DecisionShape {
        FILTER_CHAIN,
        ACCESS_CONTROL,
        HEURISTIC
    }

    public GuardSurface {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(decisionShape, "decisionShape");
        if (ref == null || ref.isBlank()) {
            throw new IllegalArgumentException("ref must not be blank");
        }
        ref = ref.trim();
        typeNames = List.copyOf(typeNames == null ? List.of() : typeNames);
        if (typeNames.isEmpty()) {
            throw new IllegalArgumentException("typeNames must not be empty");
        }
        if (ForcedGuardKind.isForbiddenForceTarget(ref)) {
            throw new IllegalArgumentException("FORBIDDEN_FORCE_TARGET:" + ref);
        }
    }

    public static String refFor(ForcedGuardKind kind, String simpleName) {
        Objects.requireNonNull(kind, "kind");
        String simple = simpleName == null ? "" : simpleName.trim();
        if (simple.isBlank()) {
            throw new IllegalArgumentException("simpleName must not be blank");
        }
        return "GUARD:" + kind.name() + ":" + simple;
    }

    public static DecisionShape parseShape(String raw) {
        if (raw == null || raw.isBlank()) {
            return DecisionShape.HEURISTIC;
        }
        try {
            return DecisionShape.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ignored) {
            return DecisionShape.HEURISTIC;
        }
    }
}
