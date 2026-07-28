package com.aq.jvmsentinel.domain.analyzer;

import java.util.Locale;
import java.util.Objects;

public record AnalyzerDiagnostic(Severity severity, String code, String message) {
    public enum Severity {
        INFO, WARN, ERROR
    }

    public AnalyzerDiagnostic {
        Objects.requireNonNull(severity, "severity");
        code = AnalyzerContracts.id(code, "code");
        message = message == null ? "" : message;
    }

    public static AnalyzerDiagnostic info(String code, String message) {
        return new AnalyzerDiagnostic(Severity.INFO, code, message);
    }

    public static Severity severity(String raw) {
        return Severity.valueOf(raw.trim().toUpperCase(Locale.ROOT));
    }
}
