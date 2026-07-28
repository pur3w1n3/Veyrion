package com.aq.jvmsentinel.domain.ir;

/**
 * Evidence Graph edge kinds (P1-02). Language-neutral; JVM call descriptors stay in extensions.
 */
public enum EdgeKind {
    CALL,
    CONTROL,
    DATA,
    ALIAS,
    GUARD,
    STATE,
    OWNERSHIP,
    HAPPENS_BEFORE,
    OBSERVED;

    public static EdgeKind parse(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException("edge kind must not be blank");
        }
        return EdgeKind.valueOf(raw.trim().toUpperCase(java.util.Locale.ROOT));
    }
}
