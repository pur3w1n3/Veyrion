package com.aq.jvmsentinel.verification;

import com.aq.jvmsentinel.worker.WorkerCapability;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * 启用外部制品执行的部署侧 P0 门禁。
 *
 * <p>本类校验证据清单；不运行 escape 测试，也不信任
 * 浏览器/目标提供的 assertion。</p>
 */
public final class SandboxReleaseGate {
    private static final Duration MAX_EVIDENCE_AGE = Duration.ofDays(30);
    private static final Set<Requirement> REQUIRED = Set.of(Requirement.values());

    public ReleaseDecision evaluate(ReleaseAttestation attestation, Instant now) {
        Objects.requireNonNull(attestation, "attestation");
        Objects.requireNonNull(now, "now");
        if (attestation.capability() != WorkerCapability.HARDENED_GVISOR
                && attestation.capability() != WorkerCapability.HARDENED_KATA) {
            throw new SecurityException("external release requires a hardened runtime");
        }
        if (!attestation.evidence().keySet().equals(REQUIRED)) {
            throw new SecurityException("sandbox release evidence is incomplete");
        }
        for (Map.Entry<Requirement, VerificationEvidence> entry : attestation.evidence().entrySet()) {
            VerificationEvidence evidence = entry.getValue();
            if (!evidence.passed() || !evidence.signatureVerified()) {
                throw new SecurityException("sandbox release evidence did not pass trusted verification");
            }
            if (evidence.observedAt().isAfter(now)
                    || evidence.observedAt().isBefore(now.minus(MAX_EVIDENCE_AGE))) {
                throw new SecurityException("sandbox release evidence is stale or future-dated");
            }
        }
        String canonical = attestation.evidence().entrySet().stream()
                .sorted(Map.Entry.comparingByKey(Comparator.comparing(Enum::name)))
                .map(entry -> entry.getKey().name() + ":" + entry.getValue().evidenceDigest())
                .reduce((left, right) -> left + "\n" + right)
                .orElseThrow();
        String evidenceSetDigest = sha256((attestation.deploymentId() + "\n"
                + attestation.capability().name() + "\n" + attestation.runtimeImageDigest()
                + "\n" + canonical).getBytes(StandardCharsets.UTF_8));
        return new ReleaseDecision(true, "EXTERNAL_ARTIFACT_ENABLED",
                attestation.deploymentId(), attestation.capability(),
                attestation.runtimeImageDigest(), evidenceSetDigest);
    }

    public enum Requirement {
        NETWORK_EGRESS_DENIED,
        DNS_EGRESS_DENIED,
        CLOUD_METADATA_DENIED,
        HOST_MOUNT_DENIED,
        DOCKER_SOCKET_DENIED,
        NON_ROOT_ENFORCED,
        READ_ONLY_ROOT_ENFORCED,
        CAPABILITIES_DROPPED,
        RESOURCE_EXHAUSTION_STOPPED,
        TRACE_TAMPER_REJECTED,
        AGENT_ABSENCE_REJECTED,
        SANDBOX_ESCAPE_SUITE_PASSED
    }

    public record ReleaseAttestation(
            int schemaVersion,
            String deploymentId,
            WorkerCapability capability,
            String runtimeImageDigest,
            Map<Requirement, VerificationEvidence> evidence) {
        public ReleaseAttestation {
            if (schemaVersion != 1) throw new IllegalArgumentException("unsupported schemaVersion");
            deploymentId = id(deploymentId, "deploymentId");
            Objects.requireNonNull(capability, "capability");
            runtimeImageDigest = digest(runtimeImageDigest, "runtimeImageDigest");
            evidence = Map.copyOf(Objects.requireNonNull(evidence, "evidence"));
            if (evidence.size() > REQUIRED.size() || evidence.values().stream().anyMatch(Objects::isNull)) {
                throw new IllegalArgumentException("release evidence is outside policy");
            }
        }
    }

    public record VerificationEvidence(
            String evidenceDigest,
            String verifierKeyId,
            Instant observedAt,
            boolean passed,
            boolean signatureVerified) {
        public VerificationEvidence {
            evidenceDigest = digest(evidenceDigest, "evidenceDigest");
            verifierKeyId = id(verifierKeyId, "verifierKeyId");
            Objects.requireNonNull(observedAt, "observedAt");
        }
    }

    public record ReleaseDecision(
            boolean enabled,
            String mode,
            String deploymentId,
            WorkerCapability capability,
            String runtimeImageDigest,
            String evidenceSetDigest) {
        public ReleaseDecision {
            if (!enabled || !"EXTERNAL_ARTIFACT_ENABLED".equals(mode)) {
                throw new IllegalArgumentException("release decision must be enabled");
            }
            deploymentId = id(deploymentId, "deploymentId");
            Objects.requireNonNull(capability, "capability");
            runtimeImageDigest = digest(runtimeImageDigest, "runtimeImageDigest");
            evidenceSetDigest = digest(evidenceSetDigest, "evidenceSetDigest");
        }
    }

    private static String id(String value, String name) {
        Objects.requireNonNull(value, name);
        if (!value.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")) {
            throw new IllegalArgumentException(name + " is invalid");
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
