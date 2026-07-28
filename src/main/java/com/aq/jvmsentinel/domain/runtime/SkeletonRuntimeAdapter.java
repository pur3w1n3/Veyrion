package com.aq.jvmsentinel.domain.runtime;

import java.util.Objects;
import java.util.Set;

/**
 * Minimal RuntimeAdapter skeleton: binds only server-fixed profiles and rejects overrides.
 * Does not launch containers or grant Analyzer dynamic execution rights.
 */
public final class SkeletonRuntimeAdapter implements RuntimeAdapter {
    private final String runtimeKind;
    private final String runtimeVersion;
    private final Set<String> capabilities;

    public SkeletonRuntimeAdapter(String runtimeKind, String runtimeVersion, Set<String> capabilities) {
        this.runtimeKind = Objects.requireNonNull(runtimeKind, "runtimeKind");
        this.runtimeVersion = Objects.requireNonNull(runtimeVersion, "runtimeVersion");
        this.capabilities = Set.copyOf(Objects.requireNonNull(capabilities, "capabilities"));
    }

    @Override
    public String runtimeKind() {
        return runtimeKind;
    }

    @Override
    public String runtimeVersion() {
        return runtimeVersion;
    }

    @Override
    public Set<String> declaredCapabilities() {
        return capabilities;
    }

    @Override
    public RuntimeRunProfile bindProfile(RuntimeRunProfile profile) {
        return bindProfile(profile, RuntimeAdapterOverrideAttempt.none());
    }

    public RuntimeRunProfile bindProfile(
            RuntimeRunProfile profile,
            RuntimeAdapterOverrideAttempt untrustedAttempt
    ) {
        Objects.requireNonNull(profile, "profile");
        if (!runtimeKind.equals(profile.runtimeKind())) {
            throw new IllegalArgumentException("runtimeKind mismatch");
        }
        return RuntimeAdapterGuard.requireServerFixed(profile, untrustedAttempt);
    }
}
