package com.aq.jvmsentinel.domain.runtime;

import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * Second-language RuntimeAdapter skeleton for JavaScript / Node.
 *
 * <p>Static LanguageAnalyzer support does <strong>not</strong> imply dynamic capability.
 * Default construction declares no observe/probe/launch capabilities; dynamic profiles are
 * rejected until an independently audited capability set is supplied (ADR-0001).
 */
public final class JsRuntimeAdapter implements RuntimeAdapter {
    public static final String RUNTIME_KIND = "NODE_JS";
    public static final String RUNTIME_VERSION = "20";

    /** Capabilities that would enable dynamic observation / probing. */
    public static final Set<String> DYNAMIC_CAPABILITIES = Set.of(
            "OBSERVE", "HTTP_PROBE", "LAUNCH", "TRACE_CAPTURE");

    private final String runtimeVersion;
    private final Set<String> capabilities;

    /** Fail-closed default: static language support only — no dynamic capabilities. */
    public JsRuntimeAdapter() {
        this(RUNTIME_VERSION, Set.of());
    }

    public JsRuntimeAdapter(String runtimeVersion, Set<String> capabilities) {
        this.runtimeVersion = Objects.requireNonNull(runtimeVersion, "runtimeVersion");
        this.capabilities = Set.copyOf(Objects.requireNonNull(capabilities, "capabilities"));
    }

    @Override
    public String runtimeKind() {
        return RUNTIME_KIND;
    }

    @Override
    public String runtimeVersion() {
        return runtimeVersion;
    }

    @Override
    public Set<String> declaredCapabilities() {
        return capabilities;
    }

    public boolean supportsDynamicExecution() {
        for (String capability : capabilities) {
            if (DYNAMIC_CAPABILITIES.contains(normalize(capability))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Bind a server-fixed profile only when this adapter actually declares a matching
     * dynamic capability. Static-only adapters reject all dynamic bind attempts.
     */
    @Override
    public RuntimeRunProfile bindProfile(RuntimeRunProfile profile) {
        return bindProfile(profile, RuntimeAdapterOverrideAttempt.none());
    }

    public RuntimeRunProfile bindProfile(
            RuntimeRunProfile profile,
            RuntimeAdapterOverrideAttempt untrustedAttempt
    ) {
        Objects.requireNonNull(profile, "profile");
        if (!RUNTIME_KIND.equals(profile.runtimeKind())) {
            throw new IllegalArgumentException("runtimeKind mismatch: expected " + RUNTIME_KIND);
        }
        if (!supportsDynamicExecution()) {
            throw new SecurityException(
                    "RUNTIME_CAPABILITY_DENIED: static LanguageAnalyzer support does not grant "
                            + "dynamic RuntimeAdapter capabilities");
        }
        for (String observation : profile.allowedObservationKinds()) {
            String required = normalize(observation);
            if (DYNAMIC_CAPABILITIES.contains(required) && !capabilities.contains(required)) {
                throw new SecurityException("RUNTIME_CAPABILITY_DENIED:" + required);
            }
        }
        return RuntimeAdapterGuard.requireServerFixed(profile, untrustedAttempt);
    }

    private static String normalize(String raw) {
        return raw == null ? "" : raw.trim().toUpperCase(Locale.ROOT);
    }
}
