package com.aq.jvmsentinel.verification;

import com.aq.jvmsentinel.worker.WorkerCapability;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Fail-closed comparison of two independently completed executions of the original artifact.
 *
 * <p>A successful comparison creates a replayable candidate only. It never upgrades Agent or
 * substituted-dependency observations to VERIFIED.</p>
 */
public final class ReplayEvidenceGate {
    private static final Set<String> DEPENDENCY_MODES =
            Set.of("MOCK", "RECORDED_REPLAY", "REAL");

    public ReplayDecision compare(ReplayAttempt first, ReplayAttempt replay) {
        Objects.requireNonNull(first, "first");
        Objects.requireNonNull(replay, "replay");
        requireHardened(first);
        requireHardened(replay);
        if (first.taskId().equals(replay.taskId())) {
            throw new SecurityException("replay must use a distinct task");
        }
        if (!first.identity().equals(replay.identity())) {
            throw new SecurityException("replay execution identity mismatch");
        }
        if (!first.outcomeDigest().equals(replay.outcomeDigest())) {
            return new ReplayDecision(false, "DYNAMIC_SUSPECTED", "REPLAY_OUTCOME_DIVERGED",
                    first.replayFingerprint(), List.of(first.traceHeadDigest(), replay.traceHeadDigest()));
        }
        if (first.observedEvents() <= 0 || replay.observedEvents() <= 0) {
            throw new SecurityException("replay contains no runtime observations");
        }
        return new ReplayDecision(true, "DYNAMIC_SUSPECTED", "ORIGINAL_ARTIFACT_REPLAY_MATCHED",
                first.replayFingerprint(), List.of(first.traceHeadDigest(), replay.traceHeadDigest()));
    }

    private static void requireHardened(ReplayAttempt value) {
        if (!value.completed() || !value.agentIntegrityVerified() || value.fixtureOnly()) {
            throw new SecurityException("replay attempt is not eligible");
        }
        if (value.capability() != WorkerCapability.HARDENED_GVISOR
                && value.capability() != WorkerCapability.HARDENED_KATA) {
            throw new SecurityException("external replay requires a hardened runtime");
        }
    }

    public record ReplayAttempt(
            int schemaVersion,
            String projectId,
            String scanId,
            String taskId,
            String targetEntryId,
            String artifactDigest,
            String originalJarDigest,
            String agentDigest,
            String runtimeImageDigest,
            String harnessPlanDigest,
            String substitutionTranscriptDigest,
            String dependencyMode,
            WorkerCapability capability,
            boolean fixtureOnly,
            boolean completed,
            boolean agentIntegrityVerified,
            long observedEvents,
            String outcomeDigest,
            String traceHeadDigest) {
        public ReplayAttempt {
            requireSchemaVersion(schemaVersion);
            projectId = id(projectId, "projectId");
            scanId = id(scanId, "scanId");
            taskId = id(taskId, "taskId");
            targetEntryId = id(targetEntryId, "targetEntryId");
            artifactDigest = digest(artifactDigest, "artifactDigest");
            originalJarDigest = digest(originalJarDigest, "originalJarDigest");
            agentDigest = digest(agentDigest, "agentDigest");
            runtimeImageDigest = digest(runtimeImageDigest, "runtimeImageDigest");
            harnessPlanDigest = digest(harnessPlanDigest, "harnessPlanDigest");
            substitutionTranscriptDigest =
                    digest(substitutionTranscriptDigest, "substitutionTranscriptDigest");
            if (!artifactDigest.equals(originalJarDigest)) {
                throw new SecurityException("registered artifact and original JAR digest mismatch");
            }
            Objects.requireNonNull(dependencyMode, "dependencyMode");
            if (!DEPENDENCY_MODES.contains(dependencyMode)) {
                throw new IllegalArgumentException("unsupported dependencyMode");
            }
            Objects.requireNonNull(capability, "capability");
            if (observedEvents < 0 || observedEvents > 10_000_000L) {
                throw new IllegalArgumentException("observedEvents is outside policy");
            }
            outcomeDigest = digest(outcomeDigest, "outcomeDigest");
            traceHeadDigest = digest(traceHeadDigest, "traceHeadDigest");
        }

        public ReplayIdentity identity() {
            return new ReplayIdentity(projectId, scanId, targetEntryId, artifactDigest,
                    originalJarDigest, agentDigest, runtimeImageDigest, harnessPlanDigest,
                    substitutionTranscriptDigest, dependencyMode, capability);
        }

        public String replayFingerprint() {
            ReplayIdentity value = identity();
            String canonical = String.join("\n", value.projectId(), value.scanId(),
                    value.targetEntryId(), value.artifactDigest(), value.originalJarDigest(),
                    value.agentDigest(), value.runtimeImageDigest(), value.harnessPlanDigest(),
                    value.substitutionTranscriptDigest(), value.dependencyMode(),
                    value.capability().name());
            return sha256(canonical.getBytes(StandardCharsets.UTF_8));
        }
    }

    public record ReplayIdentity(
            String projectId,
            String scanId,
            String targetEntryId,
            String artifactDigest,
            String originalJarDigest,
            String agentDigest,
            String runtimeImageDigest,
            String harnessPlanDigest,
            String substitutionTranscriptDigest,
            String dependencyMode,
            WorkerCapability capability) { }

    public record ReplayDecision(
            boolean eligible,
            String verificationStatus,
            String reasonCode,
            String replayFingerprint,
            List<String> traceHeadDigests) {
        public ReplayDecision {
            if (!"DYNAMIC_SUSPECTED".equals(verificationStatus)) {
                throw new IllegalArgumentException("replay gate cannot issue VERIFIED");
            }
            reasonCode = id(reasonCode, "reasonCode");
            replayFingerprint = digest(replayFingerprint, "replayFingerprint");
            traceHeadDigests = List.copyOf(Objects.requireNonNull(traceHeadDigests, "traceHeadDigests"));
            if (traceHeadDigests.size() != 2) {
                throw new IllegalArgumentException("replay decision requires two trace heads");
            }
            traceHeadDigests.forEach(value -> digest(value, "traceHeadDigest"));
        }
    }

    private static void requireSchemaVersion(int value) {
        if (value != 1) throw new IllegalArgumentException("unsupported schemaVersion");
    }

    private static String id(String value, String name) {
        Objects.requireNonNull(value, name);
        if (!value.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")) {
            throw new IllegalArgumentException(name + " contains invalid characters");
        }
        return value;
    }

    private static String digest(String value, String name) {
        Objects.requireNonNull(value, name);
        if (!value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException(name + " must be a lowercase SHA-256");
        }
        return value;
    }

    private static String sha256(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }
}
