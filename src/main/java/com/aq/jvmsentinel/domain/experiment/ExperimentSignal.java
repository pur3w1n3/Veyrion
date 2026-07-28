package com.aq.jvmsentinel.domain.experiment;

import java.util.Locale;
import java.util.Objects;

/**
 * Expected or counter signal declared on a hypothesis-bound experiment plan.
 */
public record ExperimentSignal(String code, String detail) {
    public ExperimentSignal {
        code = normalize(code);
        if (code.isBlank()) {
            throw new IllegalArgumentException("signal code must not be blank");
        }
        detail = detail == null ? "" : detail.trim();
        if (code.length() > 128) {
            throw new IllegalArgumentException("signal code exceeds bound");
        }
        if (detail.length() > 512) {
            throw new IllegalArgumentException("signal detail exceeds bound");
        }
    }

    public static ExperimentSignal of(String code) {
        return new ExperimentSignal(code, "");
    }

    public boolean matches(String observedCode) {
        return code.equals(normalize(observedCode));
    }

    private static String normalize(String raw) {
        return raw == null ? "" : raw.trim().toUpperCase(Locale.ROOT);
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (!(other instanceof ExperimentSignal signal)) return false;
        return code.equals(signal.code);
    }

    @Override
    public int hashCode() {
        return Objects.hash(code);
    }
}
