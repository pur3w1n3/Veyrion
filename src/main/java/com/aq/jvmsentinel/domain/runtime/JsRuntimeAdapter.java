package com.aq.jvmsentinel.domain.runtime;

import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * JavaScript / Node 的第二语言 RuntimeAdapter 骨架。
 *
 * <p>Static LanguageAnalyzer support does <strong>not</strong> imply dynamic capability.
 * 默认构造不声明 observe/probe/launch capability；dynamic profile
 * 在提供独立审计过的 capability set 前拒绝（ADR-0001）。
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
     * 仅当本 adapter 实际声明匹配
     * dynamic capability 时绑定服务端固定 profile。仅 static adapter 拒绝所有 dynamic bind 尝试。
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
