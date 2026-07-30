package com.aq.jvmsentinel.security.auth;

/** 显式 operator permission；role 映射中缺失即 deny。 */
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
