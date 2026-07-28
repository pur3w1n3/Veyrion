package com.aq.jvmsentinel.domain.analyzer;

/** Inclusive schema version range accepted for an Analyzer session. */
public record AnalyzerSchemaRange(int minSchemaVersion, int maxSchemaVersion) {
    public static AnalyzerSchemaRange v1Only() {
        return new AnalyzerSchemaRange(1, 1);
    }

    public AnalyzerSchemaRange {
        if (minSchemaVersion < 1 || maxSchemaVersion < minSchemaVersion) {
            throw new IllegalArgumentException("invalid schema range");
        }
    }

    public boolean accepts(int schemaVersion) {
        return schemaVersion >= minSchemaVersion && schemaVersion <= maxSchemaVersion;
    }
}
