package com.aq.jvmsentinel.sandbox;

import com.aq.jvmsentinel.worker.WorkerCapability;

import java.util.Objects;
import java.util.Set;

/**
 * Deployment-operator attestation for the OpenSandbox server configuration.
 * The standard lifecycle API does not report secure_runtime, so untrusted response data must not grant capability.
 */
public record RuntimeAttestation(String protocolVersion, WorkerCapability capability, String runtime,
                                 boolean egressDefaultDeny, boolean nonRoot, boolean readOnlyRootFilesystem,
                                 Set<String> serverCapabilities) {
    private static final Set<String> REQUIRED = Set.of(
            "lifecycle-v1", "execd-command-v1", "network-deny-v1",
            "resource-budget-v1", "non-root-v1", "read-only-rootfs-v1",
            "writable-tmp-v1");

    public RuntimeAttestation {
        protocolVersion = SandboxContracts.text(protocolVersion, "protocolVersion", 32);
        Objects.requireNonNull(capability, "capability");
        runtime = SandboxContracts.text(runtime, "runtime", 128);
        Objects.requireNonNull(serverCapabilities, "serverCapabilities");
        if (serverCapabilities.size() > 64 || serverCapabilities.stream().anyMatch(Objects::isNull)) {
            throw new IllegalArgumentException("invalid serverCapabilities");
        }
        serverCapabilities = Set.copyOf(serverCapabilities);
    }

    public void require(OpenSandboxConfig config, SandboxRequest request) {
        Objects.requireNonNull(config, "config");
        Objects.requireNonNull(request, "request");
        if (!protocolVersion.equals(config.requiredProtocolVersion())) {
            throw OpenSandboxException.capability("protocol version mismatch");
        }
        if (capability != request.requiredCapability()) {
            throw OpenSandboxException.capability("runtime capability downgrade");
        }
        if (!request.fixtureOnly() && capability != WorkerCapability.HARDENED_GVISOR
                && capability != WorkerCapability.HARDENED_KATA) {
            throw OpenSandboxException.capability("external artifact runtime is not hardened");
        }
        if (!egressDefaultDeny || !nonRoot || !readOnlyRootFilesystem || !serverCapabilities.containsAll(REQUIRED)) {
            throw OpenSandboxException.capability("required isolation capability is absent");
        }
        String normalized = runtime.toLowerCase(java.util.Locale.ROOT);
        if (capability == WorkerCapability.HARDENED_GVISOR && !normalized.contains("gvisor")
                && !normalized.contains("runsc")) {
            throw OpenSandboxException.capability("gVisor runtime attestation mismatch");
        }
        if (capability == WorkerCapability.HARDENED_KATA && !normalized.contains("kata")) {
            throw OpenSandboxException.capability("Kata runtime attestation mismatch");
        }
        if (capability == WorkerCapability.FIXTURE_RUNC && !request.fixtureOnly()) {
            throw OpenSandboxException.capability("runc is restricted to fixtures");
        }
    }
}
