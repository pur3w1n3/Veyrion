package com.aq.jvmsentinel.domain.analyzer;

import java.util.Locale;
import java.util.Optional;

/**
 * Negotiated Analyzer capabilities. Unknown values are rejected during negotiation
 * (closed for authorization of what may be published).
 */
public enum AnalyzerCapability {
    PROGRAM_IR,
    ENTRY_SURFACE,
    COVERAGE_GAP,
    DIAGNOSTIC;

    public static Optional<AnalyzerCapability> tryParse(String raw) {
        if (raw == null || raw.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(AnalyzerCapability.valueOf(raw.trim().toUpperCase(Locale.ROOT)));
        } catch (IllegalArgumentException ignored) {
            return Optional.empty();
        }
    }

    public static AnalyzerCapability require(String raw) {
        return tryParse(raw).orElseThrow(() ->
                new AnalyzerRejectException(AnalyzerRejectReason.UNKNOWN_CAPABILITY,
                        "unknown capability: " + raw));
    }
}
