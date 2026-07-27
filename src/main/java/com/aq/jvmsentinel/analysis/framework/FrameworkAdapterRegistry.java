package com.aq.jvmsentinel.analysis.framework;

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
 * Registry of {@link FrameworkAdapter} implementations.
 * {@link SpringMvcAdapter} is the default always-match baseline; optional adapters
 * (e.g. {@link SpringBladeAdapter}) contribute the same SPI signals when they match.
 * Test-only adapters may be injected.
 */
public final class FrameworkAdapterRegistry {
    private static final CopyOnWriteArrayList<FrameworkAdapter> ADAPTERS = new CopyOnWriteArrayList<>(
            List.of(new SpringMvcAdapter(), new SpringBladeAdapter()));

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
                if (key != null && seen.add(key.alias() + "|" + key.value())) {
                    keys.add(key);
                }
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
     * Secondary auth header name from the first matched adapter that prefers one;
     * empty when none.
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
        // Preserve prior generic high-value tokens used by ProbePlanService.
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
