package com.aq.jvmsentinel.model;

/**
 * Probe/Agent outcome taxonomy. AI may only cite these codes; it cannot invent new ones.
 */
public enum PathOutcomeClass {
    COLD_START,
    AUTH_CHALLENGE,
    REACHED_NO_BIND,
    BUSINESS_TIMEOUT,
    ENGINE_BUSY,
    DEPENDENCY_MOCK_GAP,
    TRANSPORT_ERROR,
    PROBE_BUDGET,
    UNKNOWN,
    /** Identity could not be synthesized for this track. */
    IDENTITY_UNAVAILABLE,
    /** Probe received an HTTP response that is not otherwise classified. */
    HTTP_OBSERVED
}
