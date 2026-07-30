package com.aq.jvmsentinel.analysis.framework;

import com.aq.jvmsentinel.analysis.executor.ExecutorEntryAdapterRegistry;
import com.aq.jvmsentinel.analysis.identity.AuthCodeQueryService;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * {@link FrameworkAdapter} 实现的 registry。
 * {@link SpringMvcAdapter} is the default always-match baseline; optional adapters
 * ({@link SpringBladeAdapter}, {@link ServletFrameworkAdapter}, {@link WarFrameworkAdapter})
 * 匹配时贡献相同 SPI signal。可注入仅 test adapter。
 */
public final class FrameworkAdapterRegistry {
    private static final CopyOnWriteArrayList<FrameworkAdapter> ADAPTERS = new CopyOnWriteArrayList<>(
            List.of(
                    new SpringMvcAdapter(),
                    new SpringBladeAdapter(),
                    new ServletFrameworkAdapter(),
                    new WarFrameworkAdapter()));

    private FrameworkAdapterRegistry() {
    }

    public static List<FrameworkAdapter> matching(Path artifactPath, List<String> routes) {
        List<FrameworkAdapter> matched = new ArrayList<>();
        for (FrameworkAdapter adapter : ADAPTERS) {
            if (adapter.matches(artifactPath, routes)) matched.add(adapter);
        }
        return List.copyOf(matched);
    }

    /** Union of adapter-owned known-weak-key dictionaries (detection only, never silent mint). */
    public static List<AuthCodeQueryService.WellKnownKey> wellKnownSecretDictionaries() {
        List<AuthCodeQueryService.WellKnownKey> keys = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (FrameworkAdapter adapter : ADAPTERS) {
            for (AuthCodeQueryService.WellKnownKey key : adapter.wellKnownSecretHints()) {
                if (key != null && seen.add(key.alias() + "|" + key.value() + "|" + key.usage())) {
                    keys.add(key);
                }
            }
        }
        // 说明：Platform rememberMe cipher dictionary（非 JWT mint 材料）。
        for (AuthCodeQueryService.WellKnownKey key
                : com.aq.jvmsentinel.analysis.identity.RememberMeCipherHarvester.dictionary()) {
            if (key != null && seen.add(key.alias() + "|" + key.value() + "|" + key.usage())) {
                keys.add(key);
            }
        }
        return List.copyOf(keys);
    }

    /** JWT-signing subset only — never includes rememberMe cipher keys. */
    public static List<AuthCodeQueryService.WellKnownKey> wellKnownJwtSigningDictionaries() {
        List<AuthCodeQueryService.WellKnownKey> keys = new ArrayList<>();
        for (AuthCodeQueryService.WellKnownKey key : wellKnownSecretDictionaries()) {
            if (key != null && key.jwtSigning()) {
                keys.add(key);
            }
        }
        return List.copyOf(keys);
    }

    /** Union of adapter auth class-path fragments for generic code_query scans. */
    public static Set<String> authClassPathSignals() {
        Set<String> signals = new LinkedHashSet<>();
        for (FrameworkAdapter adapter : ADAPTERS) {
            signals.addAll(adapter.authClassPathSignals());
        }
        return Set.copyOf(signals);
    }

    /**
     * 来自首个 prefer 的 matched adapter 的次要 auth header 名；
     * 无则为空。
     */
    public static String secondaryAuthHeaderName(Path artifactPath, List<String> routes) {
        for (FrameworkAdapter adapter : matching(artifactPath, routes)) {
            if (adapter.preferSecondaryAuthHeader(null)) {
                String name = adapter.secondaryAuthHeaderName();
                if (name != null && !name.isBlank()) return name.trim();
            }
        }
        return "";
    }

    public static boolean containsHighValueSignal(String value) {
        String lower = value == null ? "" : value.toLowerCase(Locale.ROOT);
        for (FrameworkAdapter adapter : ADAPTERS) {
            for (String signal : adapter.highValueRouteSignals()) {
                if (lower.contains(signal.toLowerCase(Locale.ROOT))) return true;
            }
            for (String signal : adapter.highValueClassSignals()) {
                if (lower.contains(signal.toLowerCase(Locale.ROOT))) return true;
            }
        }
        // Executor / runtime-callback 高价值信号（/run /beat /actuator …）。
        if (ExecutorEntryAdapterRegistry.containsHighValueSignal(lower)) {
            return true;
        }
        // 保留 ProbePlanService 先前使用的 generic 高价值 token。
        return lower.contains("admin") || lower.contains("upload") || lower.contains("deploy")
                || lower.contains("token") || lower.contains("exec") || lower.contains("flowable")
                || lower.contains("bpmn") || lower.contains("oauth")
                || lower.contains("sink") || lower.contains("sql") || lower.contains("jndi")
                || lower.contains("ssrf") || lower.contains("deserial");
    }

    /** Test-only injection. Production code must not call this. */
    public static void registerForTests(FrameworkAdapter adapter) {
        Objects.requireNonNull(adapter, "adapter");
        ADAPTERS.addIfAbsent(adapter);
    }

    /** Test-only cleanup. */
    public static void unregisterForTests(FrameworkAdapter adapter) {
        ADAPTERS.remove(adapter);
    }

    public static List<FrameworkAdapter> all() {
        return List.copyOf(ADAPTERS);
    }
}
