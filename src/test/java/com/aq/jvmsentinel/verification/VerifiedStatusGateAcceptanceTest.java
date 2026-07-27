package com.aq.jvmsentinel.verification;

import com.aq.jvmsentinel.model.VerificationStatus;
import com.aq.jvmsentinel.worker.WorkerCapability;

import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/** P2-02: VERIFIED stays closed for TRUSTED_DOCKER; hardened path still scaffolding-closed. */
public final class VerifiedStatusGateAcceptanceTest {
    private static final Instant NOW = Instant.parse("2026-07-27T00:00:00Z");
    private static final String DIGEST = "a".repeat(64);

    public static void main(String[] args) {
        VerifiedStatusGate.Decision health = VerifiedStatusGate.forTrustedDockerHealth();
        check(!health.allowed(), "health gate denies VERIFIED");
        check("TRUSTED_DOCKER_NEVER_VERIFIED".equals(health.reasonCode()), "trusted docker reason");
        check("DYNAMIC_DISABLED".equals(health.dynamicExecutionMode()), "health mode DYNAMIC_DISABLED");
        check(!VerificationStatus.VERIFIED.name().equals(health.verificationStatus()),
                "health must not claim VERIFIED");

        SandboxReleaseGate.ReleaseDecision release = new SandboxReleaseGate().evaluate(
                new SandboxReleaseGate.ReleaseAttestation(
                        1, "deployment-1", WorkerCapability.HARDENED_GVISOR, DIGEST, evidence()),
                NOW);
        ReplayEvidenceGate.ReplayDecision replay = new ReplayEvidenceGate.ReplayDecision(
                true, "DYNAMIC_SUSPECTED", "ORIGINAL_ARTIFACT_REPLAY_MATCHED",
                DIGEST, List.of(DIGEST, "b".repeat(64)));

        VerifiedStatusGate.Decision trusted = VerifiedStatusGate.evaluate(
                WorkerCapability.TRUSTED_DOCKER, release, replay);
        check(!trusted.allowed(), "TRUSTED_DOCKER never VERIFIED even with release+replay");
        check("TRUSTED_DOCKER_NEVER_VERIFIED".equals(trusted.reasonCode()), "trusted reason");

        VerifiedStatusGate.Decision hardened = VerifiedStatusGate.evaluate(
                WorkerCapability.HARDENED_GVISOR, release, replay);
        check(!hardened.allowed(), "VERIFIED gate remains scaffolding-closed");
        check("ATTESTATION_PATH_UNSET".equals(hardened.reasonCode())
                        || "VERIFIED_GATE_NOT_OPEN".equals(hardened.reasonCode())
                        || "ESCAPE_ATTESTATION_REQUIRED".equals(hardened.reasonCode()),
                "not-open / attestation-required reason, got " + hardened.reasonCode());
        check(VerificationStatus.DYNAMIC_SUSPECTED.name().equals(hardened.verificationStatus()),
                "hardened pending stays DYNAMIC_SUSPECTED");

        // Even with a synthetic "present" attestation view, VERIFIED stays closed.
        EscapeSuiteAttestation.AttestationView present = new EscapeSuiteAttestation.AttestationView(
                true, true, WorkerCapability.HARDENED_GVISOR, "file:escape.txt",
                "ATTESTATION_PRESENT_BUT_GATE_CLOSED");
        VerifiedStatusGate.Decision withAttestation = VerifiedStatusGate.evaluate(
                WorkerCapability.HARDENED_GVISOR, release, replay, present);
        check(!withAttestation.allowed(), "attestation present still fail-closed");
        check("VERIFIED_GATE_NOT_OPEN".equals(withAttestation.reasonCode()),
                "scaffold reason VERIFIED_GATE_NOT_OPEN");

        VerifiedStatusGate.Decision noRelease = VerifiedStatusGate.evaluate(
                WorkerCapability.HARDENED_GVISOR, null, replay);
        check(!noRelease.allowed() && "SANDBOX_RELEASE_NOT_ENABLED".equals(noRelease.reasonCode()),
                "missing release denied");

        System.out.println("VerifiedStatusGateAcceptanceTest: PASS");
    }

    private static Map<SandboxReleaseGate.Requirement, SandboxReleaseGate.VerificationEvidence> evidence() {
        EnumMap<SandboxReleaseGate.Requirement, SandboxReleaseGate.VerificationEvidence> result =
                new EnumMap<>(SandboxReleaseGate.Requirement.class);
        int index = 1;
        for (SandboxReleaseGate.Requirement requirement : SandboxReleaseGate.Requirement.values()) {
            result.put(requirement, new SandboxReleaseGate.VerificationEvidence(
                    String.format("%064x", index++), "release-key-1", NOW.minusSeconds(60), true, true));
        }
        return result;
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
