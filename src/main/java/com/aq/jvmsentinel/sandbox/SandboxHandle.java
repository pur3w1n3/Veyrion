package com.aq.jvmsentinel.sandbox;

import java.util.Objects;

public record SandboxHandle(String id, SandboxStatus status, RuntimeAttestation runtimeAttestation) {
    public SandboxHandle {
        id = SandboxContracts.id(id, "sandbox id");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(runtimeAttestation, "runtimeAttestation");
    }
}
