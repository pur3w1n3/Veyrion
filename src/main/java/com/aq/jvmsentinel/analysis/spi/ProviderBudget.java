package com.aq.jvmsentinel.analysis.spi;

/**
 * {@link ProviderOutputGate} 在 accept contribution 前应用 hard cap。
 */
public record ProviderBudget(
        int maxEntries,
        int maxTrustBoundaries,
        int maxEffects,
        int maxGuards,
        int maxSanitizers,
        int maxMethodSummaries,
        int maxDetectors,
        int maxProbes,
        int maxArtifactNodes
) {
    public static final ProviderBudget DEFAULT = new ProviderBudget(
            2_000, 8_000, 4_000, 4_000, 2_000, 4_000, 2_000, 512, 4_000);

    public ProviderBudget {
        if (maxEntries < 0 || maxTrustBoundaries < 0 || maxEffects < 0 || maxGuards < 0
                || maxSanitizers < 0 || maxMethodSummaries < 0 || maxDetectors < 0
                || maxProbes < 0 || maxArtifactNodes < 0) {
            throw new IllegalArgumentException("budget caps must be non-negative");
        }
    }
}
