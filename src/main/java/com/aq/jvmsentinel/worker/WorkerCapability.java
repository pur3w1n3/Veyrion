package com.aq.jvmsentinel.worker;

/** Host capabilities configured out-of-band. A task may require one value but cannot grant it. */
public enum WorkerCapability {
    STATIC_ONLY,
    /** Explicit operator authorization for internal JARs on the local Docker backend. */
    TRUSTED_DOCKER,
    HARDENED_GVISOR,
    HARDENED_KATA
}
