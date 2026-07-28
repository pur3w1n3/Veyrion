package com.aq.jvmsentinel.worker;

/**
 * Host capabilities configured out-of-band. A task may require one value but cannot grant it.
 *
 * <p>{@link #HARDENED_GVISOR} / {@link #HARDENED_KATA} are the Worker wire names for the
 * domain {@code GVISOR}/{@code KATA} capabilities. Enablement without attestation is rejected
 * by {@link HardenedWorkerEnablement}; VERIFIED remains closed.
 */
public enum WorkerCapability {
    STATIC_ONLY,
    /** Explicit operator authorization for internal JARs on the local Docker backend. */
    TRUSTED_DOCKER,
    /** gVisor hardened Worker (wire alias of domain RuntimeCapability.GVISOR). */
    HARDENED_GVISOR,
    /** Kata hardened Worker (wire alias of domain RuntimeCapability.KATA). */
    HARDENED_KATA
}
