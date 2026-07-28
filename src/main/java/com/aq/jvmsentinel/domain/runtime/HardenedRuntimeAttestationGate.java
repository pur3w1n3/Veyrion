package com.aq.jvmsentinel.domain.runtime;

import java.util.Objects;

/**
 * Fail-closed enablement gate for gVisor/Kata RuntimeAdapters (P2 SCAFFOLDING).
 *
 * <p>Without a fresh, capability-matching attestation that marks the escape suite passed,
 * hardened capabilities must not be enabled. Even with a present attestation view this
 * gate never claims production isolation or opens VERIFIED.
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
     * Attempts to enable a hardened capability. Always fail-closed without attestation.
     * TRUSTED_DOCKER / STATIC_ONLY are rejected (not hardened enablement targets).
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
        // Honest scaffolding: attestation inventory may be present, but enablement stays closed
        // until a future audited deployment wires gVisor/Kata end-to-end.
        return new EnablementDecision(false, requested, "HARDENED_ENABLEMENT_NOT_OPEN");
    }

    private static String blankOr(String reason, String fallback) {
        return reason == null || reason.isBlank() ? fallback : reason;
    }
}
