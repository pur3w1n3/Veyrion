package com.aq.jvmsentinel.verification;

import com.aq.jvmsentinel.model.VerificationStatus;
import com.aq.jvmsentinel.worker.WorkerCapability;

import java.time.Instant;
import java.util.Objects;

/**
 * 任一路径声称 {@link VerificationStatus#VERIFIED} 前的 fail-closed 门禁。
 * 普通 {@link WorkerCapability#TRUSTED_DOCKER} 永不符合；无加固 release 证据的 health
 * 对 VERIFIED 保持动态验证禁用。
 *
 * <p>MVP-6 脚手架：可检查 escape-suite attestation，但 VERIFIED
 * 在未来部署端到端接入 escape-suite attestation 前保持关闭
 *（原因 {@code VERIFIED_GATE_NOT_OPEN}）。</p>
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
     * 评估是否可签发 VERIFIED。需要 hardened capability、
     * 已启用的 sandbox release 决策，以及合格的 replay 匹配。
     * 永不单独将 MOCK / TRUSTED_DOCKER 观测升级。
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
            // Replay 门禁本身永不签发 VERIFIED；双重保险。
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
        // 诚实脚手架：即使具备全部输入 + attestation 文件，VERIFIED 仍
        // 在未来部署端到端接入 escape-suite attestation 前保持关闭。
        return new Decision(false, VerificationStatus.DYNAMIC_SUSPECTED.name(),
                "VERIFIED_GATE_NOT_OPEN", "HARDENED_PENDING_VERIFIED");
    }

    public static Decision forTrustedDockerHealth() {
        return denied(WorkerCapability.TRUSTED_DOCKER, "TRUSTED_DOCKER_NEVER_VERIFIED");
    }

    /** health / capability 探针使用的 hardened runtime 路径（永不单独打开 VERIFIED）。 */
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
