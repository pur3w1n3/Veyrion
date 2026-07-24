package com.aq.jvmsentinel.worker;

/** Host capabilities configured out-of-band. A task may require one value but cannot grant it. */
public enum WorkerCapability {
    STATIC_ONLY,
    FIXTURE_RUNC,
    HARDENED_GVISOR,
    HARDENED_KATA
}
