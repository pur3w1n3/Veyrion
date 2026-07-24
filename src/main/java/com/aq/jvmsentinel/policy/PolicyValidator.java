package com.aq.jvmsentinel.policy;

public final class PolicyValidator {
    private PolicyValidator() { }

    public static void requireStartAllowed(ScanPolicy policy) {
        if (policy == null) throw new PolicyViolationException("scan policy is required");
        if (!policy.authorized()) throw new PolicyViolationException("scan authorization is required");
        if (policy.networkMode() != NetworkMode.DENY && policy.networkAllowlist().isEmpty()) {
            throw new PolicyViolationException("network mode requires an explicit allowlist");
        }
        if (policy.dangerousActionMode() == DangerousActionMode.APPROVED) {
            throw new PolicyViolationException("destructive actions require a separate approval workflow");
        }
    }
}
