package com.aq.jvmsentinel.analysis.executor;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * {@link ExecutorEntryAdapter} 注册表（对齐 {@code FrameworkAdapterRegistry}）。
 * 默认安装 XXL-JOB、Actuator、ElasticJob、Netty/gRPC reflection。
 */
public final class ExecutorEntryAdapterRegistry {
    private static final CopyOnWriteArrayList<ExecutorEntryAdapter> ADAPTERS =
            new CopyOnWriteArrayList<>(List.of(
                    new XxlJobExecutorEntryAdapter(),
                    new SpringActuatorEntryAdapter(),
                    new ElasticJobHttpEntryAdapter(),
                    new NettyGrpcExecutorEntryAdapter()));

    private ExecutorEntryAdapterRegistry() {
    }

    public static List<ExecutorEntryAdapter> all() {
        return List.copyOf(ADAPTERS);
    }

    public static List<ExecutorEntryAdapter> matching(ExecutorEntryContext context) {
        List<ExecutorEntryAdapter> matched = new ArrayList<>();
        for (ExecutorEntryAdapter adapter : ADAPTERS) {
            if (adapter.matches(context)) {
                matched.add(adapter);
            }
        }
        return List.copyOf(matched);
    }

    public static List<RuntimeCallbackEntry> discoverAll(ExecutorEntryContext context) {
        Objects.requireNonNull(context, "context");
        List<RuntimeCallbackEntry> out = new ArrayList<>();
        LinkedHashSet<String> seen = new LinkedHashSet<>();
        for (ExecutorEntryAdapter adapter : matching(context)) {
            for (RuntimeCallbackEntry entry : adapter.discover(context)) {
                if (entry == null) {
                    continue;
                }
                String key = entry.adapterId() + "|" + entry.protocol() + "|" + entry.operation()
                        + "|" + entry.address() + "|" + entry.declaringSymbol()
                        + "|" + entry.preconditions();
                if (seen.add(key)) {
                    out.add(entry);
                }
            }
        }
        return List.copyOf(out);
    }

    public static boolean containsHighValueSignal(String value) {
        String lower = value == null ? "" : value.toLowerCase(Locale.ROOT);
        for (ExecutorEntryAdapter adapter : ADAPTERS) {
            for (String signal : adapter.highValueRouteSignals()) {
                if (signal != null && lower.contains(signal.toLowerCase(Locale.ROOT))) {
                    return true;
                }
            }
            for (String signal : adapter.highValueClassSignals()) {
                if (signal != null && lower.contains(signal.toLowerCase(Locale.ROOT))) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Test-only injection. */
    public static void registerForTests(ExecutorEntryAdapter adapter) {
        Objects.requireNonNull(adapter, "adapter");
        ADAPTERS.addIfAbsent(adapter);
    }

    /** Test-only cleanup. */
    public static void unregisterForTests(ExecutorEntryAdapter adapter) {
        ADAPTERS.remove(adapter);
    }

    public static Set<String> registeredIds() {
        LinkedHashSet<String> ids = new LinkedHashSet<>();
        for (ExecutorEntryAdapter adapter : ADAPTERS) {
            ids.add(adapter.id());
        }
        return Set.copyOf(ids);
    }
}
