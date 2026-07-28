package com.aq.jvmsentinel.domain.runtime;

/**
 * Neutral RuntimeAdapter capability vocabulary (P2 scaffolding).
 *
 * <p>{@link #GVISOR} / {@link #KATA} name the hardened Worker runtimes. Presence in this
 * enum does not enable production isolation — enablement requires signed attestation and
 * remains fail-closed via {@link HardenedRuntimeAttestationGate}.
 */
public enum RuntimeCapability {
    STATIC_ONLY,
    /** Local trusted Boot JAR debugging only — never qualifies for VERIFIED. */
    TRUSTED_DOCKER,
    /** Hardened gVisor Worker (scaffolding; attestation required to enable). */
    GVISOR,
    /** Hardened Kata Worker (scaffolding; attestation required to enable). */
    KATA;

    public boolean isHardened() {
        return this == GVISOR || this == KATA;
    }

    /**
     * Wire-compatible names used by WorkerCapability ({@code HARDENED_GVISOR}/{@code HARDENED_KATA}).
     */
    public String workerWireName() {
        return switch (this) {
            case STATIC_ONLY -> "STATIC_ONLY";
            case TRUSTED_DOCKER -> "TRUSTED_DOCKER";
            case GVISOR -> "HARDENED_GVISOR";
            case KATA -> "HARDENED_KATA";
        };
    }

    public static RuntimeCapability fromWorkerWireName(String name) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("capability required");
        }
        return switch (name.trim()) {
            case "STATIC_ONLY" -> STATIC_ONLY;
            case "TRUSTED_DOCKER" -> TRUSTED_DOCKER;
            case "GVISOR", "HARDENED_GVISOR" -> GVISOR;
            case "KATA", "HARDENED_KATA" -> KATA;
            default -> throw new IllegalArgumentException("unsupported runtime capability: " + name);
        };
    }
}
