package com.aq.jvmsentinel.analysis.framework;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;

/** Registry of {@link FrameworkAdapter} implementations. Test-only adapters may be injected. */
public final class FrameworkAdapterRegistry {
    private static final CopyOnWriteArrayList<FrameworkAdapter> ADAPTERS = new CopyOnWriteArrayList<>(
            List.of(new SpringBladeAdapter(), new SpringMvcAdapter()));

    private FrameworkAdapterRegistry() {
    }

    public static List<FrameworkAdapter> matching(Path artifactPath, List<String> routes) {
        List<FrameworkAdapter> matched = new ArrayList<>();
        for (FrameworkAdapter adapter : ADAPTERS) {
            if (adapter.matches(artifactPath, routes)) matched.add(adapter);
        }
        return List.copyOf(matched);
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
                || lower.contains("bpmn") || lower.contains("oauth") || lower.contains("blade-")
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
