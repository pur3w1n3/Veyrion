package com.aq.jvmsentinel;

import com.aq.jvmsentinel.verification.SandboxReleaseGate;
import com.aq.jvmsentinel.worker.WorkerCapability;

import java.time.Instant;
import java.util.EnumMap;
import java.util.Map;

/** Fail-closed release inventory for external-artifact sandbox capabilities. */
public final class SandboxReleaseGateAcceptanceTest {
    private static final Instant NOW = Instant.parse("2026-07-24T09:00:00Z");
    private static final String IMAGE = "a".repeat(64);

    public static void main(String[] args) {
        SandboxReleaseGate gate = new SandboxReleaseGate();
        SandboxReleaseGate.ReleaseDecision accepted = gate.evaluate(attestation(
                WorkerCapability.HARDENED_GVISOR, evidence(NOW.minusSeconds(60))), NOW);
        check(accepted.enabled()
                        && "EXTERNAL_ARTIFACT_ENABLED".equals(accepted.mode())
                        && accepted.evidenceSetDigest().matches("[0-9a-f]{64}"),
                "complete trusted release evidence was rejected");

        EnumMap<SandboxReleaseGate.Requirement, SandboxReleaseGate.VerificationEvidence> missing =
                evidence(NOW.minusSeconds(60));
        missing.remove(SandboxReleaseGate.Requirement.DNS_EGRESS_DENIED);
        reject(() -> gate.evaluate(attestation(WorkerCapability.HARDENED_GVISOR, missing), NOW),
                "missing DNS evidence");

        EnumMap<SandboxReleaseGate.Requirement, SandboxReleaseGate.VerificationEvidence> unsigned =
                evidence(NOW.minusSeconds(60));
        unsigned.put(SandboxReleaseGate.Requirement.SANDBOX_ESCAPE_SUITE_PASSED,
                new SandboxReleaseGate.VerificationEvidence(
                        "b".repeat(64), "release-key-1", NOW.minusSeconds(60), true, false));
        reject(() -> gate.evaluate(attestation(WorkerCapability.HARDENED_GVISOR, unsigned), NOW),
                "unsigned escape evidence");

        reject(() -> gate.evaluate(attestation(WorkerCapability.HARDENED_GVISOR,
                        evidence(NOW.minusSeconds(31L * 24 * 60 * 60))), NOW),
                "stale evidence");
        reject(() -> gate.evaluate(attestation(WorkerCapability.FIXTURE_RUNC,
                        evidence(NOW.minusSeconds(60))), NOW),
                "ordinary runc");

        System.out.println("SandboxReleaseGateAcceptanceTest: PASS");
    }

    private static SandboxReleaseGate.ReleaseAttestation attestation(
            WorkerCapability capability,
            Map<SandboxReleaseGate.Requirement, SandboxReleaseGate.VerificationEvidence> evidence) {
        return new SandboxReleaseGate.ReleaseAttestation(
                1, "deployment-1", capability, IMAGE, evidence);
    }

    private static EnumMap<SandboxReleaseGate.Requirement, SandboxReleaseGate.VerificationEvidence>
    evidence(Instant observedAt) {
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
        } catch (IllegalArgumentException | SecurityException expected) {
            return;
        }
        throw new AssertionError("expected rejection: " + message);
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
