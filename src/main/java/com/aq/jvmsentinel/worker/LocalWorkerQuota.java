package com.aq.jvmsentinel.worker;

import java.util.Objects;

/**
 * 本地 Docker worker / 保留沙箱的 per-project 与全局配额。
 *
 * <p>UI 工作区 = {@code projectId}。跨 project 动态任务不得互堵；
 * 保留沙箱不得被别的 project 的全局 LRU 误杀。</p>
 */
public record LocalWorkerQuota(
        int maxGlobalConcurrency,
        int maxPerProjectConcurrency,
        int maxGlobalRetainedSessions,
        int maxPerProjectRetainedSessions
) {
    public static final String GLOBAL_CONCURRENCY_ENV = "VEYRION_WORKER_GLOBAL_CONCURRENCY";
    public static final String GLOBAL_CONCURRENCY_PROP = "veyrion.worker.globalConcurrency";
    public static final String PER_PROJECT_CONCURRENCY_ENV = "VEYRION_WORKER_PER_PROJECT_CONCURRENCY";
    public static final String PER_PROJECT_CONCURRENCY_PROP = "veyrion.worker.perProjectConcurrency";
    public static final String RETAINED_GLOBAL_ENV = "VEYRION_RETAINED_SANDBOX_GLOBAL_MAX";
    public static final String RETAINED_GLOBAL_PROP = "veyrion.sandbox.retainedGlobalMax";
    public static final String RETAINED_PER_PROJECT_ENV = "VEYRION_RETAINED_SANDBOX_PER_PROJECT_MAX";
    public static final String RETAINED_PER_PROJECT_PROP = "veyrion.sandbox.retainedPerProjectMax";

    public static final int DEFAULT_GLOBAL_CONCURRENCY = 3;
    public static final int DEFAULT_PER_PROJECT_CONCURRENCY = 1;
    public static final int DEFAULT_GLOBAL_RETAINED = 8;
    public static final int DEFAULT_PER_PROJECT_RETAINED = 2;

    private static final int HARD_GLOBAL_CONCURRENCY = 8;
    private static final int HARD_PER_PROJECT_CONCURRENCY = 4;
    private static final int HARD_GLOBAL_RETAINED = 32;
    private static final int HARD_PER_PROJECT_RETAINED = 8;

    public LocalWorkerQuota {
        if (maxGlobalConcurrency < 1 || maxGlobalConcurrency > HARD_GLOBAL_CONCURRENCY) {
            throw new IllegalArgumentException("maxGlobalConcurrency out of range");
        }
        if (maxPerProjectConcurrency < 1
                || maxPerProjectConcurrency > HARD_PER_PROJECT_CONCURRENCY
                || maxPerProjectConcurrency > maxGlobalConcurrency) {
            throw new IllegalArgumentException("maxPerProjectConcurrency out of range");
        }
        if (maxGlobalRetainedSessions < 1 || maxGlobalRetainedSessions > HARD_GLOBAL_RETAINED) {
            throw new IllegalArgumentException("maxGlobalRetainedSessions out of range");
        }
        if (maxPerProjectRetainedSessions < 1
                || maxPerProjectRetainedSessions > HARD_PER_PROJECT_RETAINED
                || maxPerProjectRetainedSessions > maxGlobalRetainedSessions) {
            throw new IllegalArgumentException("maxPerProjectRetainedSessions out of range");
        }
    }

    public static LocalWorkerQuota defaults() {
        return new LocalWorkerQuota(
                DEFAULT_GLOBAL_CONCURRENCY,
                DEFAULT_PER_PROJECT_CONCURRENCY,
                DEFAULT_GLOBAL_RETAINED,
                DEFAULT_PER_PROJECT_RETAINED);
    }

    public static LocalWorkerQuota fromEnvironment() {
        int globalConcurrency = readInt(GLOBAL_CONCURRENCY_ENV, GLOBAL_CONCURRENCY_PROP,
                DEFAULT_GLOBAL_CONCURRENCY, 1, HARD_GLOBAL_CONCURRENCY);
        int perProjectConcurrency = Math.min(globalConcurrency,
                readInt(PER_PROJECT_CONCURRENCY_ENV, PER_PROJECT_CONCURRENCY_PROP,
                        DEFAULT_PER_PROJECT_CONCURRENCY, 1, HARD_PER_PROJECT_CONCURRENCY));
        int globalRetained = readInt(RETAINED_GLOBAL_ENV, RETAINED_GLOBAL_PROP,
                DEFAULT_GLOBAL_RETAINED, 1, HARD_GLOBAL_RETAINED);
        int perProjectRetained = Math.min(globalRetained,
                readInt(RETAINED_PER_PROJECT_ENV, RETAINED_PER_PROJECT_PROP,
                        DEFAULT_PER_PROJECT_RETAINED, 1, HARD_PER_PROJECT_RETAINED));
        return new LocalWorkerQuota(
                globalConcurrency, perProjectConcurrency, globalRetained, perProjectRetained);
    }

    private static int readInt(String env, String prop, int defaultValue, int min, int max) {
        Objects.requireNonNull(env, "env");
        Objects.requireNonNull(prop, "prop");
        String raw = System.getenv(env);
        if (raw == null || raw.isBlank()) {
            raw = System.getProperty(prop, String.valueOf(defaultValue));
        }
        try {
            int value = Integer.parseInt(raw.trim());
            if (value < min) {
                return defaultValue;
            }
            return Math.min(value, max);
        } catch (NumberFormatException ignored) {
            return defaultValue;
        }
    }
}
