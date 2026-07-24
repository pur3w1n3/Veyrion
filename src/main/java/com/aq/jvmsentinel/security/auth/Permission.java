package com.aq.jvmsentinel.security.auth;

/** Explicit operator permissions; absence from a role mapping means deny. */
public enum Permission {
    READ_SECURITY_CONFIGURATION,
    MANAGE_PROVIDERS,
    MANAGE_MODELS,
    ASSIGN_AGENT_ROLES,
    ROTATE_PROVIDER_SECRETS,
    RUN_AI_JOBS,
    MANAGE_OPERATOR_ACCESS,
    MANAGE_PROJECTS,
    RUN_SCANS,
    READ_AUDIT
}
