package com.aq.jvmsentinel.domain.analyzer;

import java.util.Locale;

/** Deterministic Analyzer terminal states. Partial output is never SUCCESS. */
public enum AnalyzerTerminalState {
    SUCCESS,
    FAILED,
    CANCELLED,
    TIMED_OUT,
    PROTOCOL_INCOMPATIBLE;

    public static AnalyzerTerminalState require(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException("terminalState required");
        }
        try {
            return AnalyzerTerminalState.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.INVALID_TERMINAL_STATE,
                    "unknown terminalState: " + raw);
        }
    }
}
