package com.aq.jvmsentinel.domain.analyzer;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;

/** Control-plane opened Analyzer session expectations. */
public record AnalyzerSessionSpec(
        AnalyzerScope scope,
        String artifactDigest,
        String policyDigest,
        Set<AnalyzerCapability> acceptedCapabilities,
        AnalyzerSchemaRange schemaRange,
        AnalyzerBudget budget,
        Instant deadline
) {
    public AnalyzerSessionSpec {
        Objects.requireNonNull(scope, "scope");
        artifactDigest = AnalyzerContracts.digest(artifactDigest, "artifactDigest");
        policyDigest = AnalyzerContracts.digest(policyDigest, "policyDigest");
        if (!artifactDigest.equals(scope.artifactDigest())) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.ARTIFACT_DIGEST_MISMATCH,
                    "session artifactDigest mismatch");
        }
        Objects.requireNonNull(acceptedCapabilities, "acceptedCapabilities");
        if (acceptedCapabilities.isEmpty()) {
            throw new IllegalArgumentException("acceptedCapabilities required");
        }
        acceptedCapabilities = Set.copyOf(acceptedCapabilities);
        Objects.requireNonNull(schemaRange, "schemaRange");
        Objects.requireNonNull(budget, "budget");
        Objects.requireNonNull(deadline, "deadline");
    }
}
