package com.aq.jvmsentinel.sandbox;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.policy.NetworkMode;
import com.aq.jvmsentinel.verification.SandboxReleaseGate;
import com.aq.jvmsentinel.worker.NetworkPolicy;
import com.aq.jvmsentinel.worker.ResourceBudget;
import com.aq.jvmsentinel.worker.WorkerCapability;
import com.aq.jvmsentinel.worker.WorkerTaskSpec;

import java.time.Duration;
import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * P2 SCAFFOLDING：每条 hardening 要求有 fail-closed 拒绝断言
 * (release evidence checklist + existing Worker deny-network / attestation paths).
 */
public final class SandboxHardeningAcceptanceTest {
    private static final Instant NOW = Instant.parse("2026-07-28T00:00:00Z");
    private static final String IMAGE = "a".repeat(64);
    private static final ResourceBudget BUDGET = new ResourceBudget(
            120, 30_000, 256L * 1024 * 1024, 64L * 1024 * 1024, 1024L * 1024);

    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        checklistCoversAllHardeningItems();
        eachRequirementMissingIsRejected();
        eachRequirementFailedIsRejected();
        workerDenyNetworkAndAttestationPaths();
        trustedDockerCannotSatisfyHardenedRelease();
        System.out.println("SandboxHardeningAcceptanceTest: PASS");
    }

    private static void checklistCoversAllHardeningItems() {
        Set<String> required = Set.of(
                "NETWORK_EGRESS_DENIED",
                "DNS_EGRESS_DENIED",
                "CLOUD_METADATA_DENIED",
                "HOST_MOUNT_DENIED",
                "DOCKER_SOCKET_DENIED",
                "NON_ROOT_ENFORCED",
                "READ_ONLY_ROOT_ENFORCED",
                "CAPABILITIES_DROPPED",
                "RESOURCE_EXHAUSTION_STOPPED",
                "TRACE_TAMPER_REJECTED",
                "AGENT_ABSENCE_REJECTED",
                "SANDBOX_ESCAPE_SUITE_PASSED");
        for (SandboxReleaseGate.Requirement requirement : SandboxReleaseGate.Requirement.values()) {
            check(required.contains(requirement.name()),
                    "policy checklist includes " + requirement.name());
        }
        check(SandboxReleaseGate.Requirement.values().length == required.size(),
                "checklist size matches Requirement enum");
    }

    private static void eachRequirementMissingIsRejected() {
        SandboxReleaseGate gate = new SandboxReleaseGate();
        for (SandboxReleaseGate.Requirement requirement : SandboxReleaseGate.Requirement.values()) {
            EnumMap<SandboxReleaseGate.Requirement, SandboxReleaseGate.VerificationEvidence> evidence =
                    fullEvidence(NOW.minusSeconds(60));
            evidence.remove(requirement);
            reject(() -> gate.evaluate(attestation(WorkerCapability.HARDENED_GVISOR, evidence), NOW),
                    "missing " + requirement.name());
        }
    }

    private static void eachRequirementFailedIsRejected() {
        SandboxReleaseGate gate = new SandboxReleaseGate();
        for (SandboxReleaseGate.Requirement requirement : SandboxReleaseGate.Requirement.values()) {
            EnumMap<SandboxReleaseGate.Requirement, SandboxReleaseGate.VerificationEvidence> evidence =
                    fullEvidence(NOW.minusSeconds(60));
            evidence.put(requirement, new SandboxReleaseGate.VerificationEvidence(
                    "b".repeat(64), "release-key-1", NOW.minusSeconds(60), false, true));
            reject(() -> gate.evaluate(attestation(WorkerCapability.HARDENED_KATA, evidence), NOW),
                    "failed " + requirement.name());
        }
    }

    private static void workerDenyNetworkAndAttestationPaths() {
        WorkerTaskSpec trusted = new WorkerTaskSpec(
                1, "project-1", IMAGE, "scan-1", "task-1", "entry-1",
                true, BUDGET, NetworkPolicy.denyAll(), WorkerCapability.TRUSTED_DOCKER);
        check(trusted.networkPolicy().mode() == NetworkMode.DENY,
                "Worker task network mode DENY");
        check(trusted.networkPolicy().allowlist().isEmpty(),
                "Worker task allowlist empty");
        reject(() -> new WorkerTaskSpec(
                        1, "project-1", IMAGE, "scan-1", "task-net", "entry-1",
                        true, BUDGET,
                        new NetworkPolicy(NetworkMode.ALLOWLIST, List.of("example.invalid")),
                        WorkerCapability.TRUSTED_DOCKER),
                "TRUSTED_DOCKER with allowlist network rejected");

        Set<String> caps = Set.of(
                "lifecycle-v1", "execd-command-v1", "network-deny-v1",
                "resource-budget-v1", "non-root-v1", "read-only-rootfs-v1",
                "writable-tmp-v1", "controlled-tmpfs-v1",
                "digest-pinned-readonly-artifact-v1");
        RuntimeAttestation weakEgress = new RuntimeAttestation(
                "v1", WorkerCapability.HARDENED_GVISOR, "runsc",
                false, true, true, caps);
        OpenSandboxConfig config = new OpenSandboxConfig(
                java.net.URI.create("http://127.0.0.1:9"),
                "api-key-hardening-test",
                "execd-token-hardening-test",
                Duration.ofSeconds(5),
                "v1",
                new RuntimeAttestation("v1", WorkerCapability.HARDENED_GVISOR, "runsc",
                        true, true, true, caps));
        reject(() -> weakEgress.require(config, requestWithMount()),
                "egressDefaultDeny=false rejected by RuntimeAttestation");

        RuntimeAttestation rootUser = new RuntimeAttestation(
                "v1", WorkerCapability.HARDENED_GVISOR, "runsc",
                true, false, true, caps);
        reject(() -> rootUser.require(config, requestWithMount()),
                "nonRoot=false rejected by RuntimeAttestation");

        RuntimeAttestation writableRoot = new RuntimeAttestation(
                "v1", WorkerCapability.HARDENED_GVISOR, "runsc",
                true, true, false, caps);
        reject(() -> writableRoot.require(config, requestWithMount()),
                "readOnlyRootFilesystem=false rejected by RuntimeAttestation");
    }

    private static SandboxRequest requestWithMount() {
        try {
            java.nio.file.Path jar = java.nio.file.Files.createTempFile("veyrion-harden-", ".jar");
            java.nio.file.Files.write(jar, new byte[]{'P', 'K', 3, 4});
            String digest = java.util.HexFormat.of().formatHex(
                    java.security.MessageDigest.getInstance("SHA-256")
                            .digest(java.nio.file.Files.readAllBytes(jar)));
            ReadOnlyArtifactMount mount = new ReadOnlyArtifactMount(
                    jar, "/opt/veyrion/artifact/application.jar", digest,
                    java.nio.file.Files.size(jar));
            return new SandboxRequest(
                    "registry.example/veyrion/runtime@sha256:" + IMAGE,
                    List.of("/bin/sleep", "infinity"),
                    60,
                    BUDGET,
                    WorkerCapability.HARDENED_GVISOR,
                    List.of(mount),
                    BUDGET.maxDiskBytes());
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static void trustedDockerCannotSatisfyHardenedRelease() {
        SandboxReleaseGate gate = new SandboxReleaseGate();
        reject(() -> gate.evaluate(
                        attestation(WorkerCapability.TRUSTED_DOCKER, fullEvidence(NOW.minusSeconds(60))),
                        NOW),
                "TRUSTED_DOCKER cannot pass hardened release inventory");
    }

    private static SandboxReleaseGate.ReleaseAttestation attestation(
            WorkerCapability capability,
            Map<SandboxReleaseGate.Requirement, SandboxReleaseGate.VerificationEvidence> evidence) {
        return new SandboxReleaseGate.ReleaseAttestation(
                1, "deployment-hardening-1", capability, IMAGE, evidence);
    }

    private static EnumMap<SandboxReleaseGate.Requirement, SandboxReleaseGate.VerificationEvidence>
    fullEvidence(Instant observedAt) {
        EnumMap<SandboxReleaseGate.Requirement, SandboxReleaseGate.VerificationEvidence> result =
                new EnumMap<>(SandboxReleaseGate.Requirement.class);
        int index = 1;
        for (SandboxReleaseGate.Requirement requirement : SandboxReleaseGate.Requirement.values()) {
            result.put(requirement, new SandboxReleaseGate.VerificationEvidence(
                    String.format("%064x", index++), "release-key-1", observedAt, true, true));
        }
        return result;
    }

    private static void reject(Runnable action, String message) {
        try {
            action.run();
        } catch (RuntimeException expected) {
            // 说明：OpenSandboxException/IllegalArgumentException/SecurityException。
            AcceptanceAssertions.record();
            return;
        }
        throw new AssertionError("expected rejection: " + message);
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        AcceptanceAssertions.record();
    }
}
