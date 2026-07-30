package com.aq.jvmsentinel.domain.hypothesis;

import java.util.Locale;

/**
 * 说明：SecurityHypothesis family 分类（ADR-0001 中立 contract）。
 * 未知 wire 值映射为 {@link #UNKNOWN}，不提升 verification status。
 */
public enum HypothesisFamily {
    DATAFLOW,
    GUARD_COVERAGE,
    STATE,
    TYPESTATE,
    CONFIG,
    DEPENDENCY,
    CONCURRENCY,
    COMPOSITION,
    UNKNOWN;

    public static HypothesisFamily parse(String raw) {
        if (raw == null || raw.isBlank()) {
            return UNKNOWN;
        }
        try {
            return HypothesisFamily.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ignored) {
            return UNKNOWN;
        }
    }
}
