package com.aq.jvmsentinel.domain.analyzer;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Analyzer 提供 capability；Control Plane 接受子集。
 * 未知 capability fail-closed — 永不静默忽略。
 */
public record CapabilityNegotiation(
        int schemaVersion,
        String analyzerId,
        String analyzerVersion,
        List<String> languages,
        List<String> mediaTypes,
        Set<AnalyzerCapability> offeredCapabilities,
        AnalyzerSchemaRange schemaRange,
        String artifactDigest,
        String policyDigest,
        AnalyzerScope scope,
        List<String> requestedAnalysisKinds
) {
    public CapabilityNegotiation {
        AnalyzerContracts.schemaVersion(schemaVersion);
        analyzerId = AnalyzerContracts.id(analyzerId, "analyzerId");
        analyzerVersion = AnalyzerContracts.id(analyzerVersion, "analyzerVersion");
        languages = AnalyzerContracts.boundedCopy(languages, "languages", AnalyzerContracts.MAX_COLLECTION);
        mediaTypes = AnalyzerContracts.boundedCopy(mediaTypes, "mediaTypes", AnalyzerContracts.MAX_COLLECTION);
        if (languages.isEmpty() || mediaTypes.isEmpty()) {
            throw new IllegalArgumentException("languages/mediaTypes required");
        }
        Objects.requireNonNull(offeredCapabilities, "offeredCapabilities");
        if (offeredCapabilities.isEmpty()) {
            throw new IllegalArgumentException("offeredCapabilities required");
        }
        offeredCapabilities = Set.copyOf(offeredCapabilities);
        Objects.requireNonNull(schemaRange, "schemaRange");
        artifactDigest = AnalyzerContracts.digest(artifactDigest, "artifactDigest");
        policyDigest = AnalyzerContracts.digest(policyDigest, "policyDigest");
        Objects.requireNonNull(scope, "scope");
        if (!artifactDigest.equals(scope.artifactDigest())) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.ARTIFACT_DIGEST_MISMATCH,
                    "artifactDigest does not match scope");
        }
        requestedAnalysisKinds = AnalyzerContracts.boundedCopy(
                requestedAnalysisKinds == null ? List.of() : requestedAnalysisKinds,
                "requestedAnalysisKinds",
                AnalyzerContracts.MAX_COLLECTION);
    }

    /**
     * 仅接受 offer 包含且服务端允许的已知 capability。
     */
    public Set<AnalyzerCapability> accept(Set<AnalyzerCapability> serverAllowed) {
        Objects.requireNonNull(serverAllowed, "serverAllowed");
        Set<AnalyzerCapability> accepted = new LinkedHashSet<>();
        for (AnalyzerCapability offered : offeredCapabilities) {
            if (!serverAllowed.contains(offered)) {
                throw new AnalyzerRejectException(AnalyzerRejectReason.UNKNOWN_CAPABILITY,
                        "capability not allowed by control plane: " + offered);
            }
            accepted.add(offered);
        }
        if (accepted.isEmpty()) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.UNKNOWN_CAPABILITY,
                    "no capabilities accepted");
        }
        return Set.copyOf(accepted);
    }

    /** Parse offered capability strings; unknown tokens fail closed. */
    public static Set<AnalyzerCapability> parseOffered(List<String> raw) {
        Set<AnalyzerCapability> offered = new LinkedHashSet<>();
        for (String token : raw) {
            offered.add(AnalyzerCapability.require(token));
        }
        return Set.copyOf(offered);
    }
}
