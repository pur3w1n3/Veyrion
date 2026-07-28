package com.aq.jvmsentinel.domain.security;

/**
 * Fail-closed production session / tenancy feature flags (P2 scaffolding).
 *
 * <p>All flags remain {@link #DISABLED}. Enabling any requires an ACCEPTED ADR and audited
 * implementation — see {@code docs/adr/0003-production-session-deferred.md}.
 */
public final class ProductionFeatures {
    /** Sentinel constant: production session stack is not enabled. */
    public static final boolean DISABLED = true;

    public static final boolean SESSION_AUTH = false;
    public static final boolean CSRF_PROTECTION = false;
    public static final boolean SSO_OIDC = false;
    public static final boolean MULTI_TENANT_ISOLATION = false;
    public static final boolean DATA_RETENTION_POLICY = false;

    private ProductionFeatures() {
    }

    /** True only when the local PAT / loopback model remains the sole auth path. */
    public static boolean productionSessionStackEnabled() {
        return SESSION_AUTH || CSRF_PROTECTION || SSO_OIDC
                || MULTI_TENANT_ISOLATION || DATA_RETENTION_POLICY;
    }

    public static void requireDisabled() {
        if (productionSessionStackEnabled() || !DISABLED) {
            throw new SecurityException(
                    "PRODUCTION_FEATURES_MUST_REMAIN_DISABLED: session/CSRF/SSO/tenancy/retention "
                            + "are scaffolding only until ADR-0003 is accepted and audited");
        }
    }
}
