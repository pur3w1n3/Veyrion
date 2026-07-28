package com.aq.jvmsentinel.domain.analyzer;

/** Server-supplied Analyzer budget. Analyzer cannot raise these ceilings. */
public record AnalyzerBudget(
        int maxChunks,
        int maxChunkBytes,
        int maxTotalBytes,
        int maxNodes,
        long maxWallClockMillis
) {
    public static AnalyzerBudget defaults() {
        return new AnalyzerBudget(
                AnalyzerContracts.MAX_CHUNKS,
                AnalyzerContracts.MAX_CHUNK_BYTES,
                AnalyzerContracts.MAX_TOTAL_BYTES,
                256,
                60_000L);
    }

    public AnalyzerBudget {
        if (maxChunks < 1 || maxChunks > AnalyzerContracts.MAX_CHUNKS) {
            throw new IllegalArgumentException("maxChunks out of range");
        }
        if (maxChunkBytes < 1 || maxChunkBytes > AnalyzerContracts.MAX_CHUNK_BYTES) {
            throw new IllegalArgumentException("maxChunkBytes out of range");
        }
        if (maxTotalBytes < 1 || maxTotalBytes > AnalyzerContracts.MAX_TOTAL_BYTES) {
            throw new IllegalArgumentException("maxTotalBytes out of range");
        }
        if (maxNodes < 1) {
            throw new IllegalArgumentException("maxNodes must be positive");
        }
        if (maxWallClockMillis < 1) {
            throw new IllegalArgumentException("maxWallClockMillis must be positive");
        }
    }
}
