package com.aq.jvmsentinel.verification;

import com.aq.jvmsentinel.model.VerificationStatus;
import com.aq.jvmsentinel.worker.WorkerCapability;

import java.time.Instant;
import java.util.Objects;

/**
 * Fail-closed gate before any path may claim {@link VerificationStatus#VERIFIED}.
 * Ordinary {@link WorkerCapability#TRUSTED_DOCKER} never qualifies; health without
 * hardened release evidence keeps dynamic verification disabled for VERIFIED.
 *
 * <p>MVP-6 scaffolding: escape-suite attestation may be inspected, but VERIFIED
 * remains closed until a future deployment wires escape-suite attestation end-to-end
 * (reason {@code VERIFIED_GATE_NOT_OPEN}).</p>
 */
public final class VerifiedStatusGate {
    private VerifiedStatusGate() { }

    public record Decision(boolean allowed, String verificationStatus, String reasonCode,
                           String dynamicExecutionMode) {
        public Decision {
            verificationStatus = verificationStatus == null ? "" : verificationStatus;
            reasonCode = reasonCode == null ? "" : reasonCode;
            dynamicExecutionMode = dynamicExecutionMode == null ? "DYNAMIC_DISABLED" : dynamicExecutionMode;
            if (allowed && !VerificationStatus.VERIFIED.name().equals(verificationStatus)) {
                throw new IllegalArgumentException("allowed decision must carry VERIFIED");
            }
            if (!allowed && VerificationStatus.VERIFIED.name().equals(verificationStatus)) {
                throw new IllegalArgumentException("denied decision must not claim VERIFIED");
            }
        }
    }

    /**
     * Evaluates whether VERIFIED may be issued. Requires hardened capability,
     * an enabled sandbox release decision, and an eligible replay match.
     * Never upgrades MOCK / TRUSTED_DOCKER observations alone.
     */
    public static Decision evaluate(WorkerCapability capability,
                                    SandboxReleaseGate.ReleaseDecision release,
                                    ReplayEvidenceGate.ReplayDecision replay) {
        return evaluate(capability, release, replay, EscapeSuiteAttestation.load(Instant.now()));
    }

    public static Decision evaluate(WorkerCapability capability,
                                    SandboxReleaseGate.ReleaseDecision release,
                                    ReplayEvidenceGate.ReplayDecision replay,
                                    EscapeSuiteAttestation.AttestationView attestation) {
        Objects.requireNonNull(capability, "capability");
        if (capability == WorkerCapability.TRUSTED_DOCKER
                || capability == WorkerCapability.STATIC_ONLY) {
            return denied(capability, "TRUSTED_DOCKER_NEVER_VERIFIED");
        }
        if (capability != WorkerCapability.HARDENED_GVISOR
                && capability != WorkerCapability.HARDENED_KATA) {
            return denied(capability, "HARDENED_RUNTIME_REQUIRED");
        }
        if (release == null || !release.enabled()) {
            return denied(capability, "SANDBOX_RELEASE_NOT_ENABLED");
        }
        if (replay == null || !replay.eligible()) {
            return denied(capability, "REPLAY_EVIDENCE_INELIGIBLE");
        }
        if (!"DYNAMIC_SUSPECTED".equals(replay.verificationStatus())) {
            // Replay gate itself never issues VERIFIED; keep belt-and-suspenders.
            return denied(capability, "REPLAY_STATUS_NOT_PROMOTABLE");
        }
        if (attestation == null || !attestation.present() || !attestation.fresh()
                || attestation.capability() != capability
                || !"ATTESTATION_PRESENT_BUT_GATE_CLOSED".equals(attestation.reasonCode())) {
            String reason = attestation == null || attestation.reasonCode().isBlank()
                    ? "ESCAPE_ATTESTATION_REQUIRED"
                    : attestation.reasonCode();
            return denied(capability, reason);
        }
        // Honest scaffolding: even with all inputs + attestation file, VERIFIED stays
        // closed until a future deployment wires escape-suite attestation end-to-end.
        return new Decision(false, VerificationStatus.DYNAMIC_SUSPECTED.name(),
                "VERIFIED_GATE_NOT_OPEN", "HARDENED_PENDING_VERIFIED");
    }

    public static Decision forTrustedDockerHealth() {
        return denied(WorkerCapability.TRUSTED_DOCKER, "TRUSTED_DOCKER_NEVER_VERIFIED");
    }

    /** Hardened runtime path used by health / capability probes (never opens VERIFIED alone). */
    public static Decision forHardenedRuntime(WorkerCapability capability) {
        if (capability != WorkerCapability.HARDENED_GVISOR
                && capability != WorkerCapability.HARDENED_KATA) {
            return denied(capability, "HARDENED_RUNTIME_REQUIRED");
        }
        EscapeSuiteAttestation.AttestationView attestation =
                EscapeSuiteAttestation.load(Instant.now());
        if (!attestation.present() || !attestation.fresh()
                || attestation.capability() != capability) {
            return denied(capability, attestation.reasonCode().isBlank()
                    ? "HARDENED_RUNTIME_NOT_VERIFIED" : attestation.reasonCode());
        }
        return new Decision(false, VerificationStatus.DYNAMIC_SUSPECTED.name(),
                "VERIFIED_GATE_NOT_OPEN", "HARDENED_PENDING_VERIFIED");
    }

    private static Decision denied(WorkerCapability capability, String reason) {
        String mode = capability == WorkerCapability.HARDENED_GVISOR
                || capability == WorkerCapability.HARDENED_KATA
                ? "HARDENED_PENDING_VERIFIED"
                : "DYNAMIC_DISABLED";
        return new Decision(false, VerificationStatus.DYNAMIC_SUSPECTED.name(), reason, mode);
    }
}
