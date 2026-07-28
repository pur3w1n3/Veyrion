package com.aq.jvmsentinel.verification;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.worker.WorkerCapability;

import java.time.Instant;
import java.util.EnumMap;
import java.util.Map;

/**
 * P2: dual replay + release evidence still cannot open VERIFIED; TRUSTED_DOCKER never elevates.
 */
public final class VerifiedGateAcceptanceTest {
    private static final Instant NOW = Instant.parse("2026-07-28T12:00:00Z");
    private static final String A = "a".repeat(64);
    private static final String B = "b".repeat(64);
    private static final String C = "c".repeat(64);
    private static final String D = "d".repeat(64);
    private static final String E = "e".repeat(64);
    private static final String F = "f".repeat(64);
    private static final String OUTCOME = "1".repeat(64);

    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        dualReplayPlusReleaseStillClosed();
        trustedDockerNeverElevates();
        replayGateItselfNeverIssuesVerified();
        System.out.println("VerifiedGateAcceptanceTest: PASS");
    }

    private static void dualReplayPlusReleaseStillClosed() {
        SandboxReleaseGate.ReleaseDecision release = new SandboxReleaseGate().evaluate(
                new SandboxReleaseGate.ReleaseAttestation(
                        1, "deployment-verified-gate", WorkerCapability.HARDENED_GVISOR, A, evidence()),
                NOW);

        ReplayEvidenceGate.ReplayAttempt first = attempt("task-first", WorkerCapability.HARDENED_GVISOR);
        ReplayEvidenceGate.ReplayAttempt second = attempt("task-replay", WorkerCapability.HARDENED_GVISOR);
        ReplayEvidenceGate.ReplayDecision replay = new ReplayEvidenceGate().compare(first, second);
        check(replay.eligible(), "dual replay matched");
        check("DYNAMIC_SUSPECTED".equals(replay.verificationStatus()),
                "dual replay status stays DYNAMIC_SUSPECTED");
        check(replay.traceHeadDigests().size() == 2, "dual replay has two trace heads");

        EscapeSuiteAttestation.AttestationView present =
                new EscapeSuiteAttestation.AttestationView(
                        true, true, WorkerCapability.HARDENED_GVISOR, "file:escape.txt",
                        "ATTESTATION_PRESENT_BUT_GATE_CLOSED");

        VerifiedStatusGate.Decision decision = VerifiedStatusGate.evaluate(
                WorkerCapability.HARDENED_GVISOR, release, replay, present);
        check(!decision.allowed(), "VERIFIED remains closed with release+dual-replay+attestation");
        check(!"VERIFIED".equals(decision.verificationStatus()),
                "denied decision must not claim VERIFIED");
        check("VERIFIED_GATE_NOT_OPEN".equals(decision.reasonCode()),
                "scaffolding reason VERIFIED_GATE_NOT_OPEN");

        VerifiedStatusGate.Decision kata = VerifiedStatusGate.evaluate(
                WorkerCapability.HARDENED_KATA,
                new SandboxReleaseGate().evaluate(
                        new SandboxReleaseGate.ReleaseAttestation(
                                1, "deployment-kata", WorkerCapability.HARDENED_KATA, A, evidence()),
                        NOW),
                replay,
                new EscapeSuiteAttestation.AttestationView(
                        true, true, WorkerCapability.HARDENED_KATA, "file:escape-kata.txt",
                        "ATTESTATION_PRESENT_BUT_GATE_CLOSED"));
        check(!kata.allowed(), "KATA path also keeps VERIFIED closed");
    }

    private static void trustedDockerNeverElevates() {
        SandboxReleaseGate.ReleaseDecision release = new SandboxReleaseGate().evaluate(
                new SandboxReleaseGate.ReleaseAttestation(
                        1, "deployment-gvisor", WorkerCapability.HARDENED_GVISOR, A, evidence()),
                NOW);
        ReplayEvidenceGate.ReplayDecision replay = new ReplayEvidenceGate.ReplayDecision(
                true, "DYNAMIC_SUSPECTED", "ORIGINAL_ARTIFACT_REPLAY_MATCHED",
                A, java.util.List.of(A, B));

        VerifiedStatusGate.Decision trusted = VerifiedStatusGate.evaluate(
                WorkerCapability.TRUSTED_DOCKER, release, replay);
        check(!trusted.allowed(), "TRUSTED_DOCKER never VERIFIED even with release+replay");
        check("TRUSTED_DOCKER_NEVER_VERIFIED".equals(trusted.reasonCode()),
                "trusted docker reason");

        VerifiedStatusGate.Decision health = VerifiedStatusGate.forTrustedDockerHealth();
        check(!health.allowed(), "health path denies VERIFIED");
        check("TRUSTED_DOCKER_NEVER_VERIFIED".equals(health.reasonCode()),
                "health reason TRUSTED_DOCKER_NEVER_VERIFIED");
    }

    private static void replayGateItselfNeverIssuesVerified() {
        ReplayEvidenceGate.ReplayDecision accepted = new ReplayEvidenceGate().compare(
                attempt("task-a", WorkerCapability.HARDENED_GVISOR),
                attempt("task-b", WorkerCapability.HARDENED_GVISOR));
        check(!"VERIFIED".equals(accepted.verificationStatus()),
                "ReplayEvidenceGate cannot issue VERIFIED");
        reject(() -> new ReplayEvidenceGate.ReplayDecision(
                        true, "VERIFIED", "SHOULD_FAIL", A, java.util.List.of(A, B)),
                "ReplayDecision constructor rejects VERIFIED status");
    }

    private static ReplayEvidenceGate.ReplayAttempt attempt(String taskId, WorkerCapability capability) {
        return new ReplayEvidenceGate.ReplayAttempt(
                1, "project-1", "scan-1", taskId, "entry-1",
                A, A, B, C, D, E, "MOCK", capability,
                false, true, true, 12, OUTCOME, F);
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

    private static void reject(Runnable action, String message) {
        try {
            action.run();
        } catch (IllegalArgumentException | SecurityException expected) {
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
