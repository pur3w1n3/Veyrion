package com.aq.jvmsentinel.worker;

/**
 * 外部制品沙箱执行器的固定路径与资源上限常量。
 */
public final class ExternalArtifactPaths {
    public static final String AGENT_PATH = "/opt/veyrion/agent/veyrion-agent.jar";
    public static final String ARTIFACT_PATH = "/opt/veyrion/artifact/application.jar";
    public static final String WORKING_DIRECTORY = "/sandbox";
    public static final String TRACE_DIRECTORY = "/tmp/veyrion-trace";
    public static final String TRACE_FILE = TRACE_DIRECTORY + "/agent-events.jsonl";
    public static final String PROBE_TRACE_FILE = TRACE_DIRECTORY + "/probe-events.jsonl";
    public static final String PROBE_STATUS_FILE = TRACE_DIRECTORY + "/probe-status.txt";
    /** 可信 Docker 以容器默认 root 运行，以便 JAR 绑定特权端口（如 80）。 */
    public static final int SANDBOX_UID = 0;
    public static final int SANDBOX_GID = 0;

    /** 单次动态任务的产品级洪水上限；须与 {@code ProbePlanService.MAX_DYNAMIC_PROBES} 及 agent {@code LoopbackHttpProbe} 批量行对齐。 */
    public static final int MAX_PROBE_PLAN_ENTRIES = 512;
    /**
     * 每个 {@link ExternalArtifactTaskExecutor.ProbeTarget} 的最坏 UTF-8 TSV 行预算
     *（method + 1024 route + 256 query + track + 双 2048 auth 头 + tab/换行）。
     */
    public static final int MAX_PROBE_PLAN_LINE_BYTES = 6 * 1024;
    /** 有界 host→sandbox 探针计划上传预算（{@link #MAX_PROBE_PLAN_ENTRIES} × {@link #MAX_PROBE_PLAN_LINE_BYTES} = 3 MiB）；非通用大文件通道。 */
    public static final int MAX_PROBE_PLAN_UPLOAD_BYTES =
            MAX_PROBE_PLAN_ENTRIES * MAX_PROBE_PLAN_LINE_BYTES;
    /** 有界 Base64 下载命令的原始字节块；编码输出保持在 1 MiB 以下。 */
    public static final int TRACE_READ_BLOCK_BYTES = 512 * 1024;
    public static final long MIN_PROBE_TRACE_RESERVE_BYTES = 64L * 1024;
    public static final long PROBE_TRACE_BYTES_PER_ENTRY = 2_048L;

    public static final long MAX_WALL_SECONDS = 3_600;
    public static final long MAX_CPU_MILLIS = 3_600_000;
    public static final long MAX_MEMORY_BYTES = 4L * 1024 * 1024 * 1024;
    public static final long MAX_DISK_BYTES = 1024L * 1024 * 1024;
    public static final long MAX_TRACE_BYTES = 64L * 1024 * 1024;
    public static final long MAX_ARTIFACT_BYTES = 2L * 1024 * 1024 * 1024;
    /**
     * 轨迹 tmpfs 相对 {@link #MAX_TRACE_BYTES}/{@code maxTraceBytes} 的固定余量。
     * 覆盖同挂载上的 application.log、progress、probe-plan（≤3MiB）、http-context-path、
     * WaitHttpReady stderr 与并发刷盘；避免轨迹写满后再写日志即 ENOSPC。取 32MiB（非百分比）：
     * 小预算时也有绝对地板，大探针满额时余量仍可预期。
     */
    public static final long TMPFS_TRACE_HEADROOM_BYTES = 32L * 1024 * 1024;
    /**
     * 轨迹侧 tmpfs 上限：跟随 maxTrace 动态计算后的天花板（不再死卡 64MiB）。
     * {@code MAX_TRACE_BYTES + TMPFS_TRACE_HEADROOM_BYTES} = 96MiB。
     */
    public static final long MAX_TMPFS_BYTES =
            MAX_TRACE_BYTES + TMPFS_TRACE_HEADROOM_BYTES;
    /**
     * {@code /tmp}（{@code java.io.tmpdir}）独立下限。与轨迹挂载分离时，不得比轨迹侧
     * 更小到立刻顶满；至少 128MiB，并与轨迹 tmpfs 取较大值。
     */
    public static final long MIN_TMP_TMPFS_BYTES = 128L * 1024 * 1024;

    private ExternalArtifactPaths() { }
}
