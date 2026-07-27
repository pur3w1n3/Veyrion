package com.aq.jvmsentinel.verification;

import com.aq.jvmsentinel.worker.WorkerCapability;

/** MVP-6 acceptance: VERIFIED remains fail-closed even with hardened scaffolding. */
public final class VerifiedGateScaffoldingAcceptanceTest {
    public static void main(String[] args) {
        hardenedWithoutAttestationStaysClosed();
        trustedDockerNeverVerified();
        System.out.println("VerifiedGateScaffoldingAcceptanceTest: PASS");
    }

    private static void hardenedWithoutAttestationStaysClosed() {
        VerifiedStatusGate.Decision decision = VerifiedStatusGate.forHardenedRuntime(
                WorkerCapability.HARDENED_GVISOR);
        check(!decision.allowed(), "hardened without attestation must not allow VERIFIED");
        check(!"VERIFIED".equals(decision.verificationStatus()), "status not VERIFIED");
    }

    private static void trustedDockerNeverVerified() {
        VerifiedStatusGate.Decision decision = VerifiedStatusGate.forTrustedDockerHealth();
        check(!decision.allowed(), "trusted docker denied");
        check("TRUSTED_DOCKER_NEVER_VERIFIED".equals(decision.reasonCode()),
                "trusted docker reason");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
