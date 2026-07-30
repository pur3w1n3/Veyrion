package com.aq.jvmsentinel.control.http;

/** Control Plane HTTP 与运行时常量。 */
public final class ControlPlaneHttpLimits {
    private ControlPlaneHttpLimits() {}

    public static final String API_PREFIX = "/api/v1";
    public static final int MAX_BODY_BYTES = 1 * 1024 * 1024;
    public static final int MAX_LIST_ITEMS = 10_000;
    public static final int MAX_IDEMPOTENCY_KEYS = 50_000;
    public static final int MAX_AI_JOB_EVENTS = 128;
    /** 无 Worker 认领的 QUEUED 动态任务超时后标记 DYNAMIC_DISABLED。 */
    public static final java.time.Duration DYNAMIC_QUEUE_TIMEOUT = java.time.Duration.ofMinutes(10);
    public static final long DEFAULT_WALL_CLOCK_SECONDS = 900;
    public static final long DEFAULT_MEMORY_BYTES = 2L * 1024 * 1024 * 1024;
    public static final long DEFAULT_DISK_BYTES = 2L * 1024 * 1024 * 1024;
}
