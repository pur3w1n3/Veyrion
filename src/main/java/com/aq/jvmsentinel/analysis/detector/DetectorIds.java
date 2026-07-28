package com.aq.jvmsentinel.analysis.detector;

/** Stable detector identifiers for P1-05 first batch and P2 scaffolding. */
public final class DetectorIds {
    public static final String GUARD_CONSISTENCY = "guard-consistency";
    public static final String OWNERSHIP_IDOR = "ownership-idor";
    public static final String DANGEROUS_CONFIG = "dangerous-config";
    public static final String DESERIALIZATION_CONFIG = "deserialization-config";
    public static final String DEPENDENCY_VERSION = "dependency-version";
    public static final String RESOURCE_LIFECYCLE = "resource-lifecycle";
    /** P2 scaffolding — cross-request state / repeat-submit / quota. */
    public static final String STATE_SEQUENCE = "state-sequence";
    /** P2 scaffolding — TOCTOU / race / lock-window. */
    public static final String CONCURRENCY_RESOURCE = "concurrency-resource";

    private DetectorIds() {
    }
}
