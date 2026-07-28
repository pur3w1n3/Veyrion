package com.aq.jvmsentinel.domain.analyzer;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** Final Analyzer result envelope committed after staging validation. */
public record AnalyzerSubmission(
        int schemaVersion,
        String submissionId,
        AnalyzerScope scope,
        String artifactDigest,
        String policyDigest,
        Set<AnalyzerCapability> acceptedCapabilities,
        IrChunkManifest chunkManifest,
        List<AnalyzerDiagnostic> diagnostics,
        List<AnalyzerCoverageGapDto> coverageGaps,
        AnalyzerResourceUsage resourceUsage,
        AnalyzerTerminalState terminalState,
        String stopReason,
        String fingerprint
) {
    public AnalyzerSubmission {
        AnalyzerContracts.schemaVersion(schemaVersion);
        submissionId = AnalyzerContracts.id(submissionId, "submissionId");
        Objects.requireNonNull(scope, "scope");
        artifactDigest = AnalyzerContracts.digest(artifactDigest, "artifactDigest");
        policyDigest = AnalyzerContracts.digest(policyDigest, "policyDigest");
        if (!artifactDigest.equals(scope.artifactDigest())) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.ARTIFACT_DIGEST_MISMATCH,
                    "submission artifactDigest mismatch");
        }
        Objects.requireNonNull(acceptedCapabilities, "acceptedCapabilities");
        acceptedCapabilities = Set.copyOf(acceptedCapabilities);
        Objects.requireNonNull(chunkManifest, "chunkManifest");
        diagnostics = AnalyzerContracts.boundedCopy(
                diagnostics == null ? List.of() : diagnostics,
                "diagnostics",
                AnalyzerContracts.MAX_COLLECTION);
        coverageGaps = AnalyzerContracts.boundedCopy(
                coverageGaps == null ? List.of() : coverageGaps,
                "coverageGaps",
                AnalyzerContracts.MAX_COLLECTION);
        Objects.requireNonNull(resourceUsage, "resourceUsage");
        Objects.requireNonNull(terminalState, "terminalState");
        stopReason = stopReason == null ? "" : stopReason;
        String calculated = calculateFingerprint(scope, artifactDigest, policyDigest,
                acceptedCapabilities, chunkManifest, terminalState, stopReason);
        if (fingerprint == null || fingerprint.isBlank()) {
            fingerprint = calculated;
        } else {
            AnalyzerContracts.digest(fingerprint, "fingerprint");
            if (!fingerprint.equals(calculated)) {
                throw new AnalyzerRejectException(AnalyzerRejectReason.INVALID_MANIFEST,
                        "fingerprint mismatch");
            }
        }
    }

    public static String calculateFingerprint(
            AnalyzerScope scope,
            String artifactDigest,
            String policyDigest,
            Set<AnalyzerCapability> capabilities,
            IrChunkManifest manifest,
            AnalyzerTerminalState terminalState,
            String stopReason
    ) {
        ByteArrayOutputStream canonical = new ByteArrayOutputStream();
        AnalyzerContracts.putCanonical(canonical, scope.projectId());
        AnalyzerContracts.putCanonical(canonical, scope.artifactDigest());
        AnalyzerContracts.putCanonical(canonical, scope.scanId());
        AnalyzerContracts.putCanonical(canonical, scope.analysisId());
        AnalyzerContracts.putCanonical(canonical, artifactDigest);
        AnalyzerContracts.putCanonical(canonical, policyDigest);
        capabilities.stream().map(Enum::name).sorted().forEach(name ->
                AnalyzerContracts.putCanonical(canonical, name));
        for (IrChunkManifest.ChunkRef chunk : manifest.chunks()) {
            canonical.writeBytes(ByteBuffer.allocate(Long.BYTES).putLong(chunk.sequence()).array());
            AnalyzerContracts.putCanonical(canonical, chunk.kind());
            AnalyzerContracts.putCanonical(canonical, chunk.payloadDigest());
            canonical.writeBytes(ByteBuffer.allocate(Integer.BYTES).putInt(chunk.payloadBytes()).array());
        }
        AnalyzerContracts.putCanonical(canonical, terminalState.name());
        AnalyzerContracts.putCanonical(canonical, stopReason == null ? "" : stopReason);
        return AnalyzerContracts.sha256(canonical.toByteArray());
    }

    public Set<String> capabilityNames() {
        Set<String> names = new LinkedHashSet<>();
        for (AnalyzerCapability capability : acceptedCapabilities) {
            names.add(capability.name());
        }
        return Set.copyOf(names);
    }
}
