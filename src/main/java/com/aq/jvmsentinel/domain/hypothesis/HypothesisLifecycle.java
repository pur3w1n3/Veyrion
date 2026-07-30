package com.aq.jvmsentinel.domain.hypothesis;

import java.util.Locale;

/**
 * P0-12 垂直切片的 hypothesis lifecycle。
 * 静态 sink / AUTH_GAP 投影起始于 {@link #CANDIDATE}。
 */
public enum HypothesisLifecycle {
    CANDIDATE,
    SUPPORTED,
    CONTRADICTED,
    INSUFFICIENT_EVIDENCE,
    DISMISSED;

    public static HypothesisLifecycle parse(String raw) {
        if (raw == null || raw.isBlank()) {
            return CANDIDATE;
        }
        try {
            return HypothesisLifecycle.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ignored) {
            return CANDIDATE;
        }
    }
}
