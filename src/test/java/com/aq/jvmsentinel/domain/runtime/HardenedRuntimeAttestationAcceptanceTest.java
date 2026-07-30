package com.aq.jvmsentinel.domain.runtime;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.verification.EscapeSuiteAttestation;
import com.aq.jvmsentinel.worker.HardenedWorkerEnablement;
import com.aq.jvmsentinel.worker.WorkerCapability;

/**
 * 说明：P2 SCAFFOLDING：GVISOR/KATA capability 词汇+无 attestation fail-closed 启用。
 */
public final class HardenedRuntimeAttestationAcceptanceTest {
    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        capabilityVocabulary();
        rejectWithoutAttestation();
        rejectTrustedDockerEnablement();
        presentAttestationStillClosed();
        workerBridgeAlwaysFailClosed();
        System.out.println("HardenedRuntimeAttestationAcceptanceTest: PASS");
    }

    private static void capabilityVocabulary() {
        check(RuntimeCapability.GVISOR.isHardened(), "GVISOR is hardened");
        check(RuntimeCapability.KATA.isHardened(), "KATA is hardened");
        check(!RuntimeCapability.TRUSTED_DOCKER.isHardened(), "TRUSTED_DOCKER is not hardened");
        check("HARDENED_GVISOR".equals(RuntimeCapability.GVISOR.workerWireName()),
                "GVISOR maps to HARDENED_GVISOR wire");
        check("HARDENED_KATA".equals(RuntimeCapability.KATA.workerWireName()),
                "KATA maps to HARDENED_KATA wire");
        check(RuntimeCapability.fromWorkerWireName("GVISOR") == RuntimeCapability.GVISOR,
                "GVISOR alias parses");
        check(RuntimeCapability.fromWorkerWireName("HARDENED_KATA") == RuntimeCapability.KATA,
                "HARDENED_KATA parses to KATA");
        check(WorkerCapability.HARDENED_GVISOR.name().contains("GVISOR"),
                "WorkerCapability contains GVISOR wire");
        check(WorkerCapability.HARDENED_KATA.name().contains("KATA"),
                "WorkerCapability contains KATA wire");
    }

    private static void rejectWithoutAttestation() {
        HardenedRuntimeAttestationGate.EnablementDecision gvisor =
                HardenedRuntimeAttestationGate.tryEnable(
                        RuntimeCapability.GVISOR,
                        HardenedRuntimeAttestationGate.AttestationSnapshot.unset());
        check(!gvisor.enabled(), "GVISOR without attestation not enabled");
        check("ATTESTATION_PATH_UNSET".equals(gvisor.reasonCode())
                        || "ESCAPE_ATTESTATION_REQUIRED".equals(gvisor.reasonCode()),
                "missing attestation reason");

        HardenedRuntimeAttestationGate.EnablementDecision kata =
                HardenedRuntimeAttestationGate.tryEnable(
                        RuntimeCapability.KATA,
                        HardenedRuntimeAttestationGate.AttestationSnapshot.missing());
        check(!kata.enabled(), "KATA without attestation not enabled");
    }

    private static void rejectTrustedDockerEnablement() {
        HardenedRuntimeAttestationGate.EnablementDecision trusted =
                HardenedRuntimeAttestationGate.tryEnable(
                        RuntimeCapability.TRUSTED_DOCKER,
                        new HardenedRuntimeAttestationGate.AttestationSnapshot(
                                true, true, RuntimeCapability.GVISOR, true,
                                "ATTESTATION_PRESENT_BUT_GATE_CLOSED"));
        check(!trusted.enabled(), "TRUSTED_DOCKER cannot be hardened-enabled");
        check("HARDENED_RUNTIME_REQUIRED".equals(trusted.reasonCode()),
                "trusted docker rejected as non-hardened");
    }

    private static void presentAttestationStillClosed() {
        HardenedRuntimeAttestationGate.EnablementDecision decision =
                HardenedRuntimeAttestationGate.tryEnable(
                        RuntimeCapability.GVISOR,
                        new HardenedRuntimeAttestationGate.AttestationSnapshot(
                                true, true, RuntimeCapability.GVISOR, true,
                                "ATTESTATION_PRESENT_BUT_GATE_CLOSED"));
        check(!decision.enabled(), "present attestation still fail-closed");
        check("HARDENED_ENABLEMENT_NOT_OPEN".equals(decision.reasonCode()),
                "scaffolding enablement not open");
    }

    private static void workerBridgeAlwaysFailClosed() {
        EscapeSuiteAttestation.AttestationView unset =
                new EscapeSuiteAttestation.AttestationView(
                        false, false, null, "", "ATTESTATION_PATH_UNSET");
        HardenedWorkerEnablement.Decision denied =
                HardenedWorkerEnablement.tryEnable(WorkerCapability.HARDENED_GVISOR, unset);
        check(!denied.enabled(), "Worker gVisor enablement denied without attestation");

        EscapeSuiteAttestation.AttestationView present =
                new EscapeSuiteAttestation.AttestationView(
                        true, true, WorkerCapability.HARDENED_KATA, "file:escape.txt",
                        "ATTESTATION_PRESENT_BUT_GATE_CLOSED");
        HardenedWorkerEnablement.Decision stillClosed =
                HardenedWorkerEnablement.tryEnable(WorkerCapability.HARDENED_KATA, present);
        check(!stillClosed.enabled(), "Worker Kata enablement stays scaffolding-closed");
        check("HARDENED_ENABLEMENT_NOT_OPEN".equals(stillClosed.reasonCode()),
                "Worker bridge scaffolding reason");
        check(HardenedWorkerEnablement.toRuntime(WorkerCapability.HARDENED_GVISOR)
                        == RuntimeCapability.GVISOR,
                "Worker→domain GVISOR map");
        check(HardenedWorkerEnablement.toWorker(RuntimeCapability.KATA)
                        == WorkerCapability.HARDENED_KATA,
                "domain→Worker KATA map");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        AcceptanceAssertions.record();
    }
}
