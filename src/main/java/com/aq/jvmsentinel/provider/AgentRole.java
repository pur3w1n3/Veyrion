package com.aq.jvmsentinel.provider;

/** Fixed model responsibilities. Roles describe work, not operator authorization. */
public enum AgentRole {
    PRE_ANALYSIS,
    /**
     * Static auth model, synthetic-identity strategy, track set, and experiment-plan drafts.
     * May also run a second pass to confirm bypass only after dynamic 401/pass-gate evidence.
     */
    AUTH_ANALYSIS,
    /** Interpret sandbox/runtime records and propose replayable checks; never alone claim VERIFIED. */
    DYNAMIC_VERIFICATION,
    PATH_EXPLORATION,
    VULNERABILITY_TRIAGE,
    REPORT_GENERATION
}
