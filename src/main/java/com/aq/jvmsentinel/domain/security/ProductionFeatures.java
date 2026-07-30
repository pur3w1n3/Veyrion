package com.aq.jvmsentinel.domain.security;

/**
 * fail-closed 的 production session / tenancy feature flag（P2 scaffolding）。
 *
 * <p>所有 flag 保持 {@link #DISABLED}。启用任一需 ACCEPTED ADR 与审计过的
 * 实现 — 见 {@code docs/adr/0003-production-session-deferred.md}。
 */
public final class ProductionFeatures {
    /** 哨兵常量：production session 栈未启用。 */
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
