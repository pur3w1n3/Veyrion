package com.aq.jvmsentinel.domain.analyzer;

/** Reported Analyzer resource consumption; compared against session budget. */
public record AnalyzerResourceUsage(
        int chunkCount,
        long totalPayloadBytes,
        long wallClockMillis,
        int nodeCount
) {
    public AnalyzerResourceUsage {
        if (chunkCount < 0 || totalPayloadBytes < 0 || wallClockMillis < 0 || nodeCount < 0) {
            throw new IllegalArgumentException("resource usage cannot be negative");
        }
    }
}
