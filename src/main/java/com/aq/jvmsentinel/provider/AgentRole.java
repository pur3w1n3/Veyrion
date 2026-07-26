package com.aq.jvmsentinel.provider;

/** Fixed model responsibilities. Roles describe work, not operator authorization. */
public enum AgentRole {
    PRE_ANALYSIS,
    /** Interpret sandbox/runtime records and propose replayable checks; never alone claim VERIFIED. */
    DYNAMIC_VERIFICATION,
    PATH_EXPLORATION,
    VULNERABILITY_TRIAGE,
    REPORT_GENERATION
}
