package com.aq.jvmsentinel;

import com.aq.jvmsentinel.verification.ReplayEvidenceGate;
import com.aq.jvmsentinel.worker.WorkerCapability;

/** Security gates for replaying the digest-verified original artifact. */
public final class ReplayEvidenceGateAcceptanceTest {
    private static final String A = "a".repeat(64);
    private static final String B = "b".repeat(64);
    private static final String C = "c".repeat(64);
    private static final String D = "d".repeat(64);
    private static final String E = "e".repeat(64);
    private static final String F = "f".repeat(64);

    public static void main(String[] args) {
        ReplayEvidenceGate gate = new ReplayEvidenceGate();
        ReplayEvidenceGate.ReplayAttempt first = attempt(
                "task-first", WorkerCapability.HARDENED_GVISOR, A, true, 12);
        ReplayEvidenceGate.ReplayAttempt replay = attempt(
                "task-replay", WorkerCapability.HARDENED_GVISOR, A, true, 12);

        ReplayEvidenceGate.ReplayDecision accepted = gate.compare(first, replay);
        check(accepted.eligible(), "matching original-artifact replay was rejected");
        check("DYNAMIC_SUSPECTED".equals(accepted.verificationStatus()),
                "replay must not fabricate VERIFIED");
        check("ORIGINAL_ARTIFACT_REPLAY_MATCHED".equals(accepted.reasonCode()),
                "replay reason is missing");

        ReplayEvidenceGate.ReplayDecision divergent = gate.compare(first,
                attempt("task-diverged", WorkerCapability.HARDENED_GVISOR, B, true, 12));
        check(!divergent.eligible() && "REPLAY_OUTCOME_DIVERGED".equals(divergent.reasonCode()),
                "divergent outcome was accepted");

        reject(() -> gate.compare(first, attempt(
                "task-runc", WorkerCapability.FIXTURE_RUNC, A, true, 12)), "runc");
        reject(() -> gate.compare(first, attempt(
                "task-no-agent", WorkerCapability.HARDENED_GVISOR, A, false, 12)), "agent integrity");
        reject(() -> gate.compare(first, attempt(
                "task-empty", WorkerCapability.HARDENED_GVISOR, A, true, 0)), "empty observations");
        reject(() -> gate.compare(first, new ReplayEvidenceGate.ReplayAttempt(
                1, "project-1", "scan-1", "task-other-artifact", "entry-1",
                B, B, B, C, D, E, "MOCK", WorkerCapability.HARDENED_GVISOR,
                false, true, true, 12, A, F)), "identity mismatch");
        reject(() -> gate.compare(first, first), "same task");

        System.out.println("ReplayEvidenceGateAcceptanceTest: PASS");
    }

    private static ReplayEvidenceGate.ReplayAttempt attempt(
            String taskId, WorkerCapability capability, String outcome,
            boolean agentIntegrity, long events) {
        return new ReplayEvidenceGate.ReplayAttempt(
                1, "project-1", "scan-1", taskId, "entry-1",
                A, A, B, C, D, E, "MOCK", capability,
                false, true, agentIntegrity, events, outcome, F);
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
