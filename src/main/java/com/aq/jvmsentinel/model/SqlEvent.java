package com.aq.jvmsentinel.model;

import java.util.Objects;

/** D1 SQL observation attached to a PathRun. */
public record SqlEvent(
        String sqlText,
        String parameterSummary,
        String readWrite,
        boolean parameterized,
        boolean maliciousFragmentPresent,
        String captureMode
) {
    public SqlEvent {
        sqlText = truncate(Objects.requireNonNullElse(sqlText, ""), 2048);
        parameterSummary = truncate(Objects.requireNonNullElse(parameterSummary, ""), 512);
        readWrite = Objects.requireNonNullElse(readWrite, "UNKNOWN");
        captureMode = Objects.requireNonNullElse(captureMode, "MOCK");
    }

    private static String truncate(String value, int max) {
        return value.length() <= max ? value : value.substring(0, max);
    }
}
