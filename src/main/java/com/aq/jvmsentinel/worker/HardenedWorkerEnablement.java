package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.domain.runtime.HardenedRuntimeAttestationGate;
import com.aq.jvmsentinel.domain.runtime.RuntimeCapability;
import com.aq.jvmsentinel.verification.EscapeSuiteAttestation;

import java.time.Instant;
import java.util.Objects;

/**
 * Worker 侧桥接：将 {@link WorkerCapability} HARDENED_GVISOR/KATA 映射到
 * {@link RuntimeCapability#GVISOR}/{@link RuntimeCapability#KATA}，无 escape-suite attestation 则拒绝启用
 *（P2 SCAFFOLDING，始终 fail-closed）。
 */
public final class HardenedWorkerEnablement {
    private HardenedWorkerEnablement() {
    }

    public record Decision(boolean enabled, WorkerCapability capability, String reasonCode) {
        public Decision {
            Objects.requireNonNull(capability, "capability");
            reasonCode = reasonCode == null ? "" : reasonCode;
            if (enabled) {
                throw new IllegalArgumentException("hardened Worker enablement must stay fail-closed");
            }
        }
    }

    public static Decision tryEnable(WorkerCapability capability) {
        return tryEnable(capability, EscapeSuiteAttestation.load(Instant.now()));
    }

    public static Decision tryEnable(
            WorkerCapability capability,
            EscapeSuiteAttestation.AttestationView attestation
    ) {
        Objects.requireNonNull(capability, "capability");
        Objects.requireNonNull(attestation, "attestation");
        RuntimeCapability runtime = toRuntime(capability);
        boolean escapePassed = "ATTESTATION_PRESENT_BUT_GATE_CLOSED".equals(attestation.reasonCode());
        HardenedRuntimeAttestationGate.AttestationSnapshot snapshot =
                new HardenedRuntimeAttestationGate.AttestationSnapshot(
                        attestation.present(),
                        attestation.fresh(),
                        attestation.capability() == null
                                ? null
                                : toRuntime(attestation.capability()),
                        escapePassed,
                        attestation.reasonCode());
        HardenedRuntimeAttestationGate.EnablementDecision decision =
                HardenedRuntimeAttestationGate.tryEnable(runtime, snapshot);
        return new Decision(false, capability, decision.reasonCode());
    }

    public static RuntimeCapability toRuntime(WorkerCapability capability) {
        Objects.requireNonNull(capability, "capability");
        return switch (capability) {
            case STATIC_ONLY -> RuntimeCapability.STATIC_ONLY;
            case TRUSTED_DOCKER -> RuntimeCapability.TRUSTED_DOCKER;
            case HARDENED_GVISOR -> RuntimeCapability.GVISOR;
            case HARDENED_KATA -> RuntimeCapability.KATA;
        };
    }

    public static WorkerCapability toWorker(RuntimeCapability capability) {
        Objects.requireNonNull(capability, "capability");
        return switch (capability) {
            case STATIC_ONLY -> WorkerCapability.STATIC_ONLY;
            case TRUSTED_DOCKER -> WorkerCapability.TRUSTED_DOCKER;
            case GVISOR -> WorkerCapability.HARDENED_GVISOR;
            case KATA -> WorkerCapability.HARDENED_KATA;
        };
    }
}
