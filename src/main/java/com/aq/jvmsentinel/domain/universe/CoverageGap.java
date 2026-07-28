package com.aq.jvmsentinel.domain.universe;

import java.util.Locale;
import java.util.Objects;

/**
 * Explicit analysis / artifact coverage gap. Gaps are never counted as covered.
 */
public record CoverageGap(
        String id,
        String kind,
        String detail,
        UniverseScope scope,
        String stopReason,
        String evidenceRef
) {
    public static final String KIND_UNEXPANDED_DEPENDENCY = "UNEXPANDED_DEPENDENCY";
    public static final String KIND_REFLECTION = "REFLECTION";
    public static final String KIND_PROXY = "PROXY";
    public static final String KIND_INVOKEDYNAMIC = "INVOKEDYNAMIC";
    public static final String KIND_UNRESOLVED_CALL = "UNRESOLVED_CALL";
    public static final String KIND_UNKNOWN_PROTOCOL = "UNKNOWN_PROTOCOL";
    public static final String KIND_BUDGET_TRUNCATED = "BUDGET_TRUNCATED";
    public static final String KIND_RUNTIME_ONLY_CLASS = "RUNTIME_ONLY_CLASS";
    public static final String KIND_STATIC_NOT_LOADED = "STATIC_NOT_LOADED";
    public static final String KIND_UNKNOWN_RESOURCE = "UNKNOWN_RESOURCE";
    /** Same class binary name appears under multiple archive paths / versions. */
    public static final String KIND_MULTI_VERSION_CLASS = "MULTI_VERSION_CLASS";

    public CoverageGap {
        Objects.requireNonNull(id, "id");
        if (id.isBlank()) throw new IllegalArgumentException("id must not be blank");
        kind = normalizeKind(kind);
        detail = detail == null ? "" : detail;
        scope = scope == null ? UniverseScope.UNKNOWN : scope;
        stopReason = stopReason == null ? "" : stopReason;
        evidenceRef = evidenceRef == null ? "" : evidenceRef;
    }

    private static String normalizeKind(String kind) {
        if (kind == null || kind.isBlank()) {
            throw new IllegalArgumentException("kind must not be blank");
        }
        return kind.trim().toUpperCase(Locale.ROOT);
    }
}
