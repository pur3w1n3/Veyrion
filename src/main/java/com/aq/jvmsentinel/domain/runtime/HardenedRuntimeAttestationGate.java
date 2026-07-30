package com.aq.jvmsentinel.domain.runtime;

import java.util.Objects;

/**
 * 说明：gVisor/Kata RuntimeAdapter fail-closed 启用 gate（P2 SCAFFOLDING）。
 *
 * <p>Without a fresh, capability-matching attestation that marks the escape suite passed,
 * hardened capability 不得启用。即使有 present attestation view，本
 * gate 永不声称 production isolation 或打开 VERIFIED。
 */
public final class HardenedRuntimeAttestationGate {
    private HardenedRuntimeAttestationGate() {
    }

    public record AttestationSnapshot(
            boolean present,
            boolean fresh,
            RuntimeCapability capability,
            boolean escapeSuitePassed,
            String reasonCode
    ) {
        public AttestationSnapshot {
            reasonCode = reasonCode == null ? "" : reasonCode;
        }

        public static AttestationSnapshot unset() {
            return new AttestationSnapshot(false, false, null, false, "ATTESTATION_PATH_UNSET");
        }

        public static AttestationSnapshot missing() {
            return new AttestationSnapshot(false, false, null, false, "ATTESTATION_FILE_MISSING");
        }
    }

    public record EnablementDecision(
            boolean enabled,
            RuntimeCapability capability,
            String reasonCode
    ) {
        public EnablementDecision {
            Objects.requireNonNull(capability, "capability");
            reasonCode = reasonCode == null ? "" : reasonCode;
            if (enabled && !capability.isHardened()) {
                throw new IllegalArgumentException("only hardened capabilities may be enabled");
            }
        }
    }

    /**
     * 尝试启用 hardened capability。无 attestation 时始终 fail-closed。
     * 说明：TRUSTED_DOCKER/STATIC_ONLY 被拒绝（非 hardened 启用目标）。
     */
    public static EnablementDecision tryEnable(
            RuntimeCapability requested,
            AttestationSnapshot attestation
    ) {
        Objects.requireNonNull(requested, "requested");
        Objects.requireNonNull(attestation, "attestation");
        if (!requested.isHardened()) {
            return new EnablementDecision(false, requested, "HARDENED_RUNTIME_REQUIRED");
        }
        if (!attestation.present()) {
            return new EnablementDecision(false, requested,
                    blankOr(attestation.reasonCode(), "ESCAPE_ATTESTATION_REQUIRED"));
        }
        if (!attestation.fresh()) {
            return new EnablementDecision(false, requested,
                    blankOr(attestation.reasonCode(), "ATTESTATION_STALE"));
        }
        if (attestation.capability() != requested) {
            return new EnablementDecision(false, requested, "ATTESTATION_CAPABILITY_MISMATCH");
        }
        if (!attestation.escapeSuitePassed()) {
            return new EnablementDecision(false, requested,
                    blankOr(attestation.reasonCode(), "ESCAPE_SUITE_NOT_MARKED_PASSED"));
        }
        // 诚实 scaffolding：attestation inventory 可能存在，但启用保持关闭，
        // 直至未来审计过的 deployment 端到端接入 gVisor/Kata。
        return new EnablementDecision(false, requested, "HARDENED_ENABLEMENT_NOT_OPEN");
    }

    private static String blankOr(String reason, String fallback) {
        return reason == null || reason.isBlank() ? fallback : reason;
    }
}
