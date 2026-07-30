package com.aq.jvmsentinel.domain.ir;

/**
 * 说明：Evidence Graph edge kind（P1-02）；语言中立，JVM call descriptor 留在 extension。
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
