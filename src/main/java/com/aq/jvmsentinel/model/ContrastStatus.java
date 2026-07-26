package com.aq.jvmsentinel.model;

/**
 * Static↔dynamic contrast for a sink/entry row. Never upgrades verification:
 * MATCHED is still at most {@code DYNAMIC_SUSPECTED}.
 */
public enum ContrastStatus {
    /** Static candidate aligns with a pass-gate PathRun on the same entry×track. */
    MATCHED,
    /** PathRun exists for the entry×track but bind/sink touch is incomplete. */
    PARTIAL,
    /** Static reachability/gap with no usable pass-gate PathRun (e.g. all 401). */
    STATIC_ONLY,
    /** PathRun without a matching static sink row. */
    DYNAMIC_ONLY,
    /** Insufficient data to classify. */
    UNKNOWN
}
