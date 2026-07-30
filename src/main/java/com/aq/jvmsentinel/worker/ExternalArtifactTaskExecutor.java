package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.sandbox.CommandRequest;
import com.aq.jvmsentinel.sandbox.CommandResult;
import com.aq.jvmsentinel.sandbox.ReadOnlyArtifactMount;
import com.aq.jvmsentinel.sandbox.SandboxHandle;
import com.aq.jvmsentinel.sandbox.SandboxRequest;
import com.aq.jvmsentinel.sandbox.SandboxRuntimeClient;
import com.aq.jvmsentinel.verification.SandboxReleaseGate;
import com.aq.jvmsentinel.worker.agent.AgentTraceMerger;
import com.aq.jvmsentinel.worker.agent.AgentTraceReader;
import com.aq.jvmsentinel.worker.docker.ArtifactJarInspection;
import com.aq.jvmsentinel.worker.docker.ExternalArtifactDiagnostics;
import com.aq.jvmsentinel.worker.docker.SandboxLaunchCommandBuilder;
import com.aq.jvmsentinel.worker.probe.ProbeCommandBuilder;
import com.aq.jvmsentinel.worker.probe.ProbeEvidenceValidator;
import com.aq.jvmsentinel.worker.probe.ProbePlanCodec;
import com.aq.jvmsentinel.worker.session.RetainedSandboxSessions;
import com.aq.jvmsentinel.worker.session.RetainedSandboxSessions.RetainedSandboxSession;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * 仅在全新摘要校验通过后执行 catalog 拥有的可执行 JAR。
 * 无宿主进程回退，不向调用方暴露可控制的 command、镜像、路径或能力。
 */
public final class ExternalArtifactTaskExecutor {
    static final String AGENT_PATH = ExternalArtifactPaths.AGENT_PATH;
    static final String ARTIFACT_PATH = ExternalArtifactPaths.ARTIFACT_PATH;
    static final String WORKING_DIRECTORY = ExternalArtifactPaths.WORKING_DIRECTORY;
    static final String TRACE_DIRECTORY = ExternalArtifactPaths.TRACE_DIRECTORY;
    static final String TRACE_FILE = ExternalArtifactPaths.TRACE_FILE;
    static final String PROBE_TRACE_FILE = ExternalArtifactPaths.PROBE_TRACE_FILE;
    static final String PROBE_STATUS_FILE = ExternalArtifactPaths.PROBE_STATUS_FILE;
    static final int SANDBOX_UID = ExternalArtifactPaths.SANDBOX_UID;
    static final int SANDBOX_GID = ExternalArtifactPaths.SANDBOX_GID;

    /**
     * 单次动态任务的产品级洪水上限；须与 {@code ProbePlanService.MAX_DYNAMIC_PROBES}
     * 及 agent {@code LoopbackHttpProbe} 批量行对齐。
     */
    public static final int MAX_PROBE_PLAN_ENTRIES = ExternalArtifactPaths.MAX_PROBE_PLAN_ENTRIES;
    /**
     * 每个 {@link ProbeTarget} 的最坏 UTF-8 TSV 行预算
     *（method + 1024 route + 256 query + track + 双 2048 auth 头 + tab/换行）。
     */
    public static final int MAX_PROBE_PLAN_LINE_BYTES = ExternalArtifactPaths.MAX_PROBE_PLAN_LINE_BYTES;
    /**
     * 有界 host→sandbox 探针计划上传预算（{@link #MAX_PROBE_PLAN_ENTRIES} ×
     * {@link #MAX_PROBE_PLAN_LINE_BYTES} = 3 MiB）；非通用大文件通道。
     */
    public static final int MAX_PROBE_PLAN_UPLOAD_BYTES = ExternalArtifactPaths.MAX_PROBE_PLAN_UPLOAD_BYTES;
    /** 有界 Base64 下载命令的原始字节块；编码输出保持在 1 MiB 以下。 */
    static final int TRACE_READ_BLOCK_BYTES = ExternalArtifactPaths.TRACE_READ_BLOCK_BYTES;

    private final WorkerControlPlaneClient control;
    private final SandboxRuntimeClient sandbox;
    private final ArtifactCatalog catalog;
    private final RuntimePolicy runtimePolicy;
    private final AgentJsonlTraceConverter converter;
    private final RetainedSandboxSessions retainedSessions;
    private final String workerId;

    public ExternalArtifactTaskExecutor(WorkerControlPlaneClient control, SandboxRuntimeClient sandbox,
                                        ArtifactCatalog catalog, RuntimePolicy runtimePolicy,
                                        String workerId) {
        this(control, sandbox, catalog, runtimePolicy,
                new AgentJsonlTraceConverter(Clock.systemUTC(), ExternalArtifactPaths.MAX_TRACE_BYTES,
                        64 * 1024, 500_000, WorkerContracts.MAX_TRACE_PAYLOAD_BYTES),
                workerId, LocalWorkerQuota.defaults());
    }

    public ExternalArtifactTaskExecutor(WorkerControlPlaneClient control, SandboxRuntimeClient sandbox,
                                        ArtifactCatalog catalog, RuntimePolicy runtimePolicy,
                                        AgentJsonlTraceConverter converter, String workerId) {
        this(control, sandbox, catalog, runtimePolicy, converter, workerId, LocalWorkerQuota.defaults());
    }

    public ExternalArtifactTaskExecutor(WorkerControlPlaneClient control, SandboxRuntimeClient sandbox,
                                        ArtifactCatalog catalog, RuntimePolicy runtimePolicy,
                                        AgentJsonlTraceConverter converter, String workerId,
                                        LocalWorkerQuota quota) {
        this.control = Objects.requireNonNull(control, "control");
        this.sandbox = Objects.requireNonNull(sandbox, "sandbox");
        this.catalog = Objects.requireNonNull(catalog, "catalog");
        this.runtimePolicy = Objects.requireNonNull(runtimePolicy, "runtimePolicy");
        this.converter = Objects.requireNonNull(converter, "converter");
        this.retainedSessions = new RetainedSandboxSessions(Duration.ofMinutes(20),
                Objects.requireNonNull(quota, "quota"));
        this.workerId = ExternalArtifactIds.requireId(workerId, "workerId");
    }

    /** 执行一条内部 scoped 任务；请求 intentionally 仅含不可变 scope。 */
    public ExecutionResult execute(ExecutionRequest request) {
        Objects.requireNonNull(request, "request");
        WorkerControlPlaneClient.TaskDescriptor descriptor = control.get(request.scope());
        ExternalArtifactTaskValidator.validateDescriptor(descriptor, request.scope(), TaskLifecycle.QUEUED);
        ArtifactRegistration registration = catalog.require(request.scope());
        ExternalArtifactTaskValidator.validateRegistration(registration, request.scope());
        ExternalArtifactTaskValidator.validateBudget(descriptor.resourceBudget());
        runtimePolicy.requireCapability(descriptor.requiredCapability());

        WorkerLease lease = null;
        String sandboxId = null;
        RuntimeException primary = null;
        ExecutorService commandExecutor = null;
        try {
            ResourceBudget budget = descriptor.resourceBudget();
            // 租约须长于 Docker 命令超时；长运行期间 heartbeat 续租。
            Duration leaseDuration = Duration.ofSeconds(Math.min(3_600,
                    budget.maxWallClockSeconds() + 120));
            Duration heartbeatExtension = Duration.ofSeconds(Math.min(3_600,
                    budget.maxWallClockSeconds() + 60));
            lease = control.lease(request.scope(), workerId, Set.of(descriptor.requiredCapability()),
                    leaseDuration);
            requireLease(lease, request.scope(), descriptor.requiredCapability());
            WorkerControlPlaneClient.TaskDescriptor started =
                    control.start(request.scope(), lease.leaseId(), workerId);
            ExternalArtifactTaskValidator.validateDescriptor(started, request.scope(), TaskLifecycle.RUNNING);
            ExternalArtifactTaskValidator.requireStableDescriptor(descriptor, started);
            pulse(request.scope(), lease, heartbeatExtension, "复核制品摘要");

            // 故意放在 lease/start 转换之后、沙箱使用之前。
            ExternalArtifactTaskValidator.recheckDigest(registration);
            retainedSessions.releaseExpired(sandbox);
            RetainedSandboxSession retained = retainedSessions.get(request.scope(), registration.sha256());
            if (retained != null) {
                pulse(request.scope(), lease, heartbeatExtension,
                        "复用断网沙箱会话并执行研判探针");
                return executeRetainedProbe(request, descriptor, registration, lease,
                        heartbeatExtension, retained);
            }
            pulse(request.scope(), lease, heartbeatExtension, "创建断网沙箱容器");
            ReadOnlyArtifactMount mount = new ReadOnlyArtifactMount(
                    registration.path(), ARTIFACT_PATH, registration.sha256(), registration.sizeBytes());
            SandboxTmpfsAllocation tmpfs = SandboxTmpfsAllocation.forBudget(budget);
            SandboxHandle handle = sandbox.create(new SandboxRequest(
                    runtimePolicy.imageUri(), List.of("/bin/sleep", "infinity"), timeoutSeconds(budget),
                    tmpfs.resourceBudget(), descriptor.requiredCapability(), List.of(mount),
                    tmpfs.traceTmpfsBytes()));
            sandboxId = handle.id();

            pulse(request.scope(), lease, heartbeatExtension, "准备 Agent 轨迹目录");
            CommandResult prepareTrace = sandbox.command(sandboxId, new CommandRequest(
                    "umask 077 && rm -f " + TRACE_FILE + " " + PROBE_TRACE_FILE + " " + PROBE_STATUS_FILE
                            + " " + TRACE_DIRECTORY + "/progress.txt",
                    WORKING_DIRECTORY,
                    Duration.ofSeconds(10), SANDBOX_UID, SANDBOX_GID));
            if (prepareTrace.exitCode() != 0) {
                throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                        "TRACE_DIRECTORY_FAILED", "Agent trace directory could not be prepared", null);
            }
            pulse(request.scope(), lease, heartbeatExtension,
                    "上传批量探针计划（" + registration.probePlan().size() + " 入口）");
            Path probePlanHost = ProbePlanCodec.writeHostProbePlan(registration.probePlan());
            try {
                sandbox.uploadFile(sandboxId, probePlanHost, TRACE_DIRECTORY + "/probe-plan.txt");
            } finally {
                try {
                    Files.deleteIfExists(probePlanHost);
                } catch (IOException ignored) {
                    // 尽力清理 host 侧计划文件。
                }
            }
            pulse(request.scope(), lease, heartbeatExtension,
                    "启动应用 JAR（javaagent hook 出网/IO + 依赖替身）");
            commandExecutor = Executors.newSingleThreadExecutor(runnable -> {
                Thread thread = new Thread(runnable, "veyrion-sandbox-command");
                thread.setDaemon(true);
                return thread;
            });
            String activeSandboxId = sandboxId;
            Future<CommandResult> runFuture = commandExecutor.submit(() -> sandbox.command(
                    activeSandboxId, new CommandRequest(
                            SandboxLaunchCommandBuilder.fixedCommand(budget, registration),
                            WORKING_DIRECTORY, commandTimeout(budget),
                            SANDBOX_UID, SANDBOX_GID)));
            CommandResult run = awaitCommandWithHeartbeat(
                    request.scope(), lease, heartbeatExtension, activeSandboxId, runFuture);
            if (run.exitCode() != 0) {
                CommandResult applicationLog = sandbox.command(sandboxId, new CommandRequest(
                        "tail -c 4096 " + TRACE_DIRECTORY + "/application.log 2>/dev/null; "
                                + "printf '%s\\n' 'probe diagnostics:'; tail -c 512 "
                                + PROBE_STATUS_FILE + " 2>/dev/null || true",
                        WORKING_DIRECTORY, Duration.ofSeconds(10), SANDBOX_UID, SANDBOX_GID));
                String detail = ExternalArtifactDiagnostics.diagnostic(run.stdout(), run.stderr(),
                        applicationLog.stdout() + "\n" + applicationLog.stderr());
                throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                        "EXTERNAL_ARTIFACT_EXIT_NONZERO",
                        ExternalArtifactDiagnostics.exitDiagnostic(run.exitCode(), detail), null);
            }

            pulse(request.scope(), lease, heartbeatExtension, "读取 Agent 轨迹");
            byte[] agentBytes = AgentTraceReader.readTraceFile(
                    sandbox, sandboxId, TRACE_FILE, budget.maxTraceBytes(), true);
            byte[] probeBytes = AgentTraceReader.readTraceFile(
                    sandbox, sandboxId, PROBE_TRACE_FILE,
                    budget.maxTraceBytes() - agentBytes.length, false);
            // 覆盖校验只看 probe-events：避免与 agent HTTP 合并后淹没 truncatedTail 信号。
            requireHttpProbeEvidence(registration, probeBytes);
            byte[] jsonl = AgentTraceMerger.mergeProbeEvents(agentBytes, probeBytes);
            if (jsonl.length > budget.maxTraceBytes()) {
                throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                        "TRACE_TOO_LARGE", "Agent trace exceeds the task budget", null);
            }
            List<TraceChunk> chunks = converter.convert(jsonl, request.scope(), budget);
            pulse(request.scope(), lease, heartbeatExtension,
                    "提交轨迹（" + chunks.size() + " 段）");
            for (TraceChunk chunk : chunks) {
                control.commitTrace(request.scope(), lease.leaseId(), workerId, chunk);
            }
            int httpPort = readSandboxHttpPort(sandboxId);
            pulse(request.scope(), lease, heartbeatExtension,
                    "保留断网沙箱会话供 PATH/TRIAGE 复用");
            if (retainedSessions.retain(request.scope(), registration.sha256(),
                    sandboxId, httpPort, sandbox)) {
                sandboxId = null;
                pulse(request.scope(), lease, heartbeatExtension,
                        "任务完成；断网沙箱保留至 TRIAGE 动态校验结束");
            } else {
                pulse(request.scope(), lease, heartbeatExtension,
                        "任务完成；全局保留沙箱硬顶已满且无法同工作区腾挪，容器将释放");
            }
            WorkerControlPlaneClient.TaskDescriptor completed =
                    control.complete(request.scope(), lease.leaseId(), workerId);
            ExternalArtifactTaskValidator.requireCompletedDescriptor(completed, request.scope(), descriptor);
            return new ExecutionResult(request.scope(), registration.sha256(), chunks.size(),
                    chunks.get(chunks.size() - 1).digest(), TaskLifecycle.COMPLETED);
        } catch (RuntimeException failure) {
            primary = failure;
            if (lease != null) {
                try {
                    control.fail(request.scope(), lease.leaseId(), workerId,
                            StopReason.WORKER_FAILURE, ExternalArtifactDiagnostics.failureCode(failure),
                            ExternalArtifactDiagnostics.failureDiagnostic(failure));
                } catch (RuntimeException failFailure) {
                    failure.addSuppressed(failFailure);
                    tryMarkTerminalFailure(request.scope(), failure);
                }
            } else {
                tryMarkTerminalFailure(request.scope(), failure);
            }
            throw failure;
        } finally {
            if (commandExecutor != null) {
                commandExecutor.shutdownNow();
            }
            if (sandboxId != null) {
                try {
                    sandbox.delete(sandboxId);
                } catch (RuntimeException cleanupFailure) {
                    if (primary != null) primary.addSuppressed(cleanupFailure);
                    else throw cleanupFailure;
                }
            }
        }
    }

    private ExecutionResult executeRetainedProbe(ExecutionRequest request,
                                                 WorkerControlPlaneClient.TaskDescriptor descriptor,
                                                 ArtifactRegistration registration,
                                                 WorkerLease lease,
                                                 Duration heartbeatExtension,
                                                 RetainedSandboxSession session) {
        ResourceBudget budget = descriptor.resourceBudget();
        pulse(request.scope(), lease, heartbeatExtension,
                "清理上次探针输出并上传本轮计划（复用沙箱）");
        // 回收 trace tmpfs：首轮 agent-events / application.log 常占满 maxTrace+headroom，
        // 复用探针再写 probe-events 会中途 ENOSPC → truncatedTail 假 COVERAGE_INCOMPLETE。
        // agent 轨迹块已在首轮 commit，磁盘副本可截断。
        CommandResult prepareProbe = sandbox.command(session.sandboxId(), new CommandRequest(
                "rm -f " + PROBE_TRACE_FILE + " " + PROBE_STATUS_FILE
                        + "; : > " + TRACE_FILE
                        + "; : > " + TRACE_DIRECTORY + "/application.log"
                        + "; printf '%s\\n' '复用已启动应用，准备本轮探针' > "
                        + TRACE_DIRECTORY + "/progress.txt",
                WORKING_DIRECTORY, Duration.ofSeconds(10), SANDBOX_UID, SANDBOX_GID));
        if (prepareProbe.exitCode() != 0) {
            retainedSessions.release(session, sandbox);
            throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                    "RETAINED_SANDBOX_PREPARE_FAILED",
                    "retained sandbox could not prepare a probe", null);
        }
        Path probePlanHost = ProbePlanCodec.writeHostProbePlan(registration.probePlan());
        try {
            sandbox.uploadFile(session.sandboxId(), probePlanHost, TRACE_DIRECTORY + "/probe-plan.txt");
        } finally {
            try {
                Files.deleteIfExists(probePlanHost);
            } catch (IOException ignored) {
                // 尽力清理 host 侧计划文件。
            }
        }
        pulse(request.scope(), lease, heartbeatExtension,
                "在保留沙箱内执行本轮 loopback 探针");
        String command = "HTTP_PORT=" + session.httpPort()
                + "; probe_jvm_status=not-run; PROBE_JVM_OK=0; "
                + ProbeCommandBuilder.batchProbeStep(registration.probePlan())
                + "; if [ \"$PROBE_JVM_OK\" -ne 1 ]; then exit 71; else exit 0; fi";
        CommandResult run = sandbox.command(session.sandboxId(), new CommandRequest(
                command, WORKING_DIRECTORY, commandTimeout(budget), SANDBOX_UID, SANDBOX_GID));
        if (run.exitCode() != 0) {
            retainedSessions.release(session, sandbox);
            throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                    "RETAINED_SANDBOX_PROBE_FAILED",
                    ExternalArtifactDiagnostics.exitDiagnostic(run.exitCode(),
                            ExternalArtifactDiagnostics.diagnostic(run.stdout(), run.stderr(), "")),
                    null);
        }
        pulse(request.scope(), lease, heartbeatExtension, "读取复用沙箱探针轨迹");
        byte[] probeBytes = AgentTraceReader.readTraceFile(
                sandbox, session.sandboxId(), PROBE_TRACE_FILE, budget.maxTraceBytes(), true);
        requireHttpProbeEvidence(registration, probeBytes);
        List<TraceChunk> chunks = converter.convert(probeBytes, request.scope(), budget);
        pulse(request.scope(), lease, heartbeatExtension,
                "提交复用沙箱轨迹（" + chunks.size() + " 段）");
        for (TraceChunk chunk : chunks) {
            control.commitTrace(request.scope(), lease.leaseId(), workerId, chunk);
        }
        retainedSessions.touch(session);
        pulse(request.scope(), lease, heartbeatExtension,
                "复用沙箱探针完成；会话继续保留至 TRIAGE 结束");
        WorkerControlPlaneClient.TaskDescriptor completed =
                control.complete(request.scope(), lease.leaseId(), workerId);
        ExternalArtifactTaskValidator.requireCompletedDescriptor(completed, request.scope(), descriptor);
        return new ExecutionResult(request.scope(), registration.sha256(), chunks.size(),
                chunks.get(chunks.size() - 1).digest(), TaskLifecycle.COMPLETED);
    }

    private int readSandboxHttpPort(String sandboxId) {
        CommandResult result = sandbox.command(sandboxId, new CommandRequest(
                "cat " + TRACE_DIRECTORY + "/http-port.txt 2>/dev/null | tr -d '\\r\\n'",
                WORKING_DIRECTORY, Duration.ofSeconds(5), SANDBOX_UID, SANDBOX_GID));
        if (result.exitCode() != 0 || result.stdout() == null
                || !result.stdout().strip().matches("[0-9]{1,5}")) {
            throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                    "HTTP_PORT_NOT_RETAINABLE",
                    "completed sandbox did not expose a reusable HTTP port", null);
        }
        int port = Integer.parseInt(result.stdout().strip());
        if (port < 1 || port > 65_535) {
            throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                    "HTTP_PORT_NOT_RETAINABLE",
                    "completed sandbox HTTP port is outside TCP range", null);
        }
        return port;
    }

    private void pulse(TaskScope scope, WorkerLease lease, Duration extension, String progressDetail) {
        WorkerLease renewed = control.heartbeat(scope, lease.leaseId(), workerId, extension, progressDetail);
        requireLease(renewed, scope, lease.capability());
    }

    private CommandResult awaitCommandWithHeartbeat(TaskScope scope, WorkerLease lease, Duration extension,
                                                    String sandboxId, Future<CommandResult> future) {
        String fallback = "容器内执行中（启动 JAR / hook / 探测）";
        while (true) {
            try {
                return future.get(2, TimeUnit.SECONDS);
            } catch (TimeoutException waiting) {
                String step = readContainerProgress(sandboxId);
                pulse(scope, lease, extension, step == null ? fallback : step);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                future.cancel(true);
                throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                        "EXTERNAL_ARTIFACT_INTERRUPTED", "external artifact execution interrupted", interrupted);
            } catch (ExecutionException failed) {
                Throwable cause = failed.getCause() == null ? failed : failed.getCause();
                if (cause instanceof RuntimeException runtime) throw runtime;
                throw ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.of(
                        "EXTERNAL_ARTIFACT_EXECUTION_FAILED",
                        cause.getMessage() == null ? "sandbox command failed" : cause.getMessage(),
                        cause instanceof Exception exception ? exception : failed);
            }
        }
    }

    private String readContainerProgress(String sandboxId) {
        try {
            CommandResult result = sandbox.command(sandboxId, new CommandRequest(
                    "tail -c 512 " + TRACE_DIRECTORY + "/progress.txt 2>/dev/null || true",
                    WORKING_DIRECTORY, Duration.ofSeconds(5), SANDBOX_UID, SANDBOX_GID));
            if (result.exitCode() != 0 || result.stdout() == null || result.stdout().isBlank()) {
                return null;
            }
            String[] lines = result.stdout().strip().split("\\R");
            String last = lines[lines.length - 1].strip();
            if (last.isEmpty()) return null;
            return last.length() <= 240 ? last : last.substring(0, 240);
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    static long agentTraceBudget(ResourceBudget budget, int probeCount) {
        return AgentTraceReader.agentTraceBudget(budget, probeCount);
    }

    static byte[] readTraceFile(SandboxRuntimeClient sandbox, String sandboxId, String path,
                                long maxBytes, boolean required) {
        return AgentTraceReader.readTraceFile(sandbox, sandboxId, path, maxBytes, required);
    }

    static byte[] mergeProbeEvents(byte[] agentJsonl, byte[] probeJsonl) {
        return AgentTraceMerger.mergeProbeEvents(agentJsonl, probeJsonl);
    }

    public static byte[] encodeProbePlan(List<ProbeTarget> targets) {
        return ProbePlanCodec.encodeProbePlan(targets);
    }

    public static int probePlanUtf8Bytes(List<ProbeTarget> targets) {
        return ProbePlanCodec.probePlanUtf8Bytes(targets);
    }

    static boolean containsMysqlConnector(Path artifact) {
        return ArtifactJarInspection.containsMysqlConnector(artifact);
    }

    /** 服务端拥有的 GuardSurface typeNames，供 agent FORCED 白名单；catalog 无结果时为空。 */
    public static String forcedGuardTypeNamesProperty(Path artifactPath) {
        return forcedGuardAllowlist(artifactPath).typeNamesCsv();
    }

    /** FORCED catalog 采集的白名单 CSV 与截断 gap 可见性。 */
    public record ForcedGuardAllowlist(String typeNamesCsv, boolean truncated, String gapCode) {
        public ForcedGuardAllowlist {
            typeNamesCsv = typeNamesCsv == null ? "" : typeNamesCsv;
            gapCode = gapCode == null ? "" : gapCode.trim();
        }
    }

    public static ForcedGuardAllowlist forcedGuardAllowlist(Path artifactPath) {
        return ArtifactJarInspection.forcedGuardAllowlist(artifactPath);
    }

    static void requireHttpProbeEvidence(ArtifactRegistration registration, byte[] mergedJsonl) {
        ProbeEvidenceValidator.requireHttpProbeEvidence(registration, mergedJsonl);
    }

    static int countHttpEvents(byte[] jsonl) {
        return ProbeEvidenceValidator.countHttpEvents(jsonl);
    }

    static String diagnostic(String probeStdout, String probeStderr, String applicationLog) {
        return ExternalArtifactDiagnostics.diagnostic(probeStdout, probeStderr, applicationLog);
    }

    private static int timeoutSeconds(ResourceBudget budget) {
        return Math.toIntExact(budget.maxWallClockSeconds());
    }

    private static Duration commandTimeout(ResourceBudget budget) {
        // Docker 进程在容器内 wall clock 结束后的 teardown 宽限。
        return Duration.ofSeconds(Math.min(3_600, budget.maxWallClockSeconds() + 45));
    }

    /**
     * lease 绑定 fail 不可用时的尽力终态化（租约前拒绝或租约回收竞态）。
     * 置 FAILED 以免 stage 重试被僵尸 QUEUED 任务阻塞。
     */
    private void tryMarkTerminalFailure(TaskScope scope, RuntimeException failure) {
        try {
            WorkerControlPlaneClient.TaskDescriptor current = control.get(scope);
            if (current.lifecycle() == TaskLifecycle.QUEUED) {
                control.failQueued(scope, StopReason.WORKER_FAILURE,
                        ExternalArtifactDiagnostics.failureCode(failure),
                        ExternalArtifactDiagnostics.failureDiagnostic(failure));
            } else if (current.lease() != null
                    && (current.lifecycle() == TaskLifecycle.LEASED
                    || current.lifecycle() == TaskLifecycle.RUNNING
                    || current.lifecycle() == TaskLifecycle.PAUSED)) {
                control.fail(scope, current.lease().leaseId(), workerId,
                        StopReason.WORKER_FAILURE, ExternalArtifactDiagnostics.failureCode(failure),
                        ExternalArtifactDiagnostics.failureDiagnostic(failure));
            }
        } catch (RuntimeException ignored) {
            // stage 重试可 supersede 遗留 active 任务；不掩盖主失败。
        }
    }

    private void requireLease(WorkerLease lease, TaskScope scope, WorkerCapability capability) {
        ExternalArtifactTaskValidator.requireLease(lease, scope, capability, workerId);
    }

    public void closeRetainedSessions() {
        retainedSessions.releaseAll(sandbox);
    }

    /** TRIAGE 或流水线放弃后释放某 scan 的断网保留沙箱。 */
    public void releaseRetainedForScan(String projectId, String artifactDigest, String scanId) {
        retainedSessions.releaseForScan(
                ExternalArtifactIds.requireId(projectId, "projectId"),
                ExternalArtifactIds.requireId(artifactDigest, "artifactDigest"),
                ExternalArtifactIds.requireId(scanId, "scanId"),
                sandbox);
    }

    @FunctionalInterface
    public interface ArtifactCatalog {
        ArtifactRegistration require(TaskScope scope);
    }

    /** deny-all 容器内的一条有界 HTTP 刺激。 */
    public record ProbeTarget(String method, String route, String query, String track,
                              String authHeader, String bladeAuthHeader, String experimentPlanId,
                              String cookieHeader) {
        public ProbeTarget(String method, String route) {
            this(method, route, "", "UNAUTH", "", "", "", "");
        }

        public ProbeTarget(String method, String route, String query) {
            this(method, route, query, "UNAUTH", "", "", "", "");
        }

        /** 仅 Auth 构造；Blade-Auth / Cookie 保持空（通道独立）。 */
        public ProbeTarget(String method, String route, String query, String track, String authHeader) {
            this(method, route, query, track, authHeader, "", "", "");
        }

        public ProbeTarget(String method, String route, String query, String track,
                           String authHeader, String bladeAuthHeader) {
            this(method, route, query, track, authHeader, bladeAuthHeader, "", "");
        }

        public ProbeTarget(String method, String route, String query, String track,
                           String authHeader, String bladeAuthHeader, String experimentPlanId) {
            this(method, route, query, track, authHeader, bladeAuthHeader, experimentPlanId, "");
        }

        public ProbeTarget {
            method = Objects.requireNonNull(method, "method").toUpperCase(java.util.Locale.ROOT);
            query = query == null ? "" : query;
            track = track == null || track.isBlank() ? "UNAUTH" : track;
            authHeader = authHeader == null ? "" : authHeader;
            bladeAuthHeader = bladeAuthHeader == null ? "" : bladeAuthHeader;
            experimentPlanId = experimentPlanId == null ? "" : experimentPlanId.trim();
            cookieHeader = cookieHeader == null ? "" : cookieHeader;
            if (!Set.of("GET", "POST", "PUT", "PATCH", "DELETE").contains(method)
                    || route == null
                    || !route.matches("/[A-Za-z0-9_./{}:-]{0,1023}")
                    || (!query.isEmpty() && !query.matches("[A-Za-z0-9_=&%./{}:-]{1,256}"))
                    || !track.matches("[A-Z_]{1,32}")
                    || authHeader.length() > 2048
                    || authHeader.chars().anyMatch(c -> c < 0x20 || c == 0x7f)
                    || bladeAuthHeader.length() > 2048
                    || bladeAuthHeader.chars().anyMatch(c -> c < 0x20 || c == 0x7f)
                    || cookieHeader.length() > 2048
                    || cookieHeader.chars().anyMatch(c -> c < 0x20 || c == 0x7f)
                    || experimentPlanId.length() > 128
                    || (!experimentPlanId.isEmpty()
                    && !experimentPlanId.matches("[A-Za-z0-9_.:/-]{1,128}"))) {
                throw new IllegalArgumentException("artifact probe target is invalid");
            }
        }
    }

    public record ArtifactRegistration(String projectId, String sha256, Path path, long sizeBytes,
                                       boolean executableSpringBootJar, String probeMethod,
                                       String probeRoute, String classPrefix,
                                       List<ProbeTarget> probePlan, String worldPackDependencyMode) {
        public ArtifactRegistration(String projectId, String sha256, Path path, long sizeBytes,
                                    boolean executableSpringBootJar) {
            this(projectId, sha256, path, sizeBytes, executableSpringBootJar, "GET", "/", "",
                    List.of(new ProbeTarget("GET", "/")), "MOCK_CONTINUE");
        }

        public ArtifactRegistration(String projectId, String sha256, Path path, long sizeBytes,
                                    boolean executableSpringBootJar, String probeMethod,
                                    String probeRoute) {
            this(projectId, sha256, path, sizeBytes, executableSpringBootJar,
                    probeMethod, probeRoute, "", List.of(new ProbeTarget(probeMethod, probeRoute)),
                    "MOCK_CONTINUE");
        }

        public ArtifactRegistration(String projectId, String sha256, Path path, long sizeBytes,
                                    boolean executableSpringBootJar, String probeMethod,
                                    String probeRoute, String classPrefix) {
            this(projectId, sha256, path, sizeBytes, executableSpringBootJar,
                    probeMethod, probeRoute, classPrefix,
                    List.of(new ProbeTarget(probeMethod, probeRoute)), "MOCK_CONTINUE");
        }

        public ArtifactRegistration(String projectId, String sha256, Path path, long sizeBytes,
                                    boolean executableSpringBootJar, String probeMethod,
                                    String probeRoute, String classPrefix,
                                    List<ProbeTarget> probePlan) {
            this(projectId, sha256, path, sizeBytes, executableSpringBootJar,
                    probeMethod, probeRoute, classPrefix, probePlan, "MOCK_CONTINUE");
        }

        public ArtifactRegistration {
            projectId = ExternalArtifactIds.requireId(projectId, "projectId");
            if (sha256 == null || !sha256.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("sha256 must be a lowercase SHA-256 digest");
            }
            Objects.requireNonNull(path, "path");
            path = path.toAbsolutePath().normalize();
            if (sizeBytes <= 0 || sizeBytes > ExternalArtifactPaths.MAX_ARTIFACT_BYTES) {
                throw new IllegalArgumentException("registered artifact size is outside limits");
            }
            probeMethod = Objects.requireNonNull(probeMethod, "probeMethod")
                    .toUpperCase(java.util.Locale.ROOT);
            if (!Set.of("GET", "POST", "PUT", "PATCH", "DELETE").contains(probeMethod)
                    || probeRoute == null
                    || !probeRoute.matches("/[A-Za-z0-9_./{}:-]{0,1023}")) {
                throw new IllegalArgumentException("artifact probe target is invalid");
            }
            classPrefix = Objects.requireNonNull(classPrefix, "classPrefix");
            if (!classPrefix.isEmpty()
                    && !classPrefix.matches("[A-Za-z_$][A-Za-z0-9_$.]{0,254}")) {
                throw new IllegalArgumentException("artifact class prefix is invalid");
            }
            if (probePlan == null || probePlan.isEmpty()) {
                probePlan = List.of(new ProbeTarget(probeMethod, probeRoute));
            } else {
                if (probePlan.size() > MAX_PROBE_PLAN_ENTRIES) {
                    throw new IllegalArgumentException("probe plan exceeds limit");
                }
                probePlan = List.copyOf(probePlan);
            }
            worldPackDependencyMode = worldPackDependencyMode == null || worldPackDependencyMode.isBlank()
                    ? "MOCK_CONTINUE" : worldPackDependencyMode.trim().toUpperCase(java.util.Locale.ROOT);
            if (!worldPackDependencyMode.equals("MOCK_CONTINUE")
                    && !worldPackDependencyMode.equals("OBSERVE_FAIL")) {
                throw new IllegalArgumentException("worldPackDependencyMode must be MOCK_CONTINUE or OBSERVE_FAIL");
            }
        }
    }

    /** 部署拥有的 runtime 镜像，可信 Agent 位于固定路径。 */
    public static final class RuntimePolicy {
        private final String imageUri;
        private final SandboxReleaseGate.ReleaseDecision releaseDecision;
        private final boolean trustedLocalDocker;

        /** 加固 gVisor/Kata 部署的 release-gated 策略。 */
        public RuntimePolicy(String imageUri, SandboxReleaseGate.ReleaseDecision releaseDecision) {
            this(imageUri, releaseDecision, false);
        }

        private RuntimePolicy(String imageUri, SandboxReleaseGate.ReleaseDecision releaseDecision,
                              boolean trustedLocalDocker) {
            this.imageUri = Objects.requireNonNull(imageUri, "imageUri");
            this.releaseDecision = releaseDecision;
            this.trustedLocalDocker = trustedLocalDocker;
            if (imageUri.length() > 512
                    || !imageUri.matches("[a-z0-9.-]+(?::[0-9]{1,5})?"
                    + "(?:/[A-Za-z0-9._-]+)+@sha256:[0-9a-f]{64}")) {
                throw new IllegalArgumentException("external runtime image must be digest-pinned");
            }
            if (trustedLocalDocker) {
                if (releaseDecision != null) {
                    throw new IllegalArgumentException("trusted-local policy cannot carry a release decision");
                }
                return;
            }
            Objects.requireNonNull(releaseDecision, "releaseDecision");
            if (!releaseDecision.enabled()
                    || !imageUri.endsWith("@sha256:" + releaseDecision.runtimeImageDigest())) {
                throw new SecurityException("runtime image is not covered by the sandbox release decision");
            }
        }

        /** 显式本地策略；永不授权 fixture 或 hardened 能力。 */
        public static RuntimePolicy trustedLocalDocker(String imageUri) {
            return new RuntimePolicy(imageUri, null, true);
        }

        public String imageUri() {
            return imageUri;
        }

        public SandboxReleaseGate.ReleaseDecision releaseDecision() {
            return releaseDecision;
        }

        void requireCapability(WorkerCapability capability) {
            if (trustedLocalDocker) {
                if (capability != WorkerCapability.TRUSTED_DOCKER) {
                    throw new SecurityException("trusted-local policy only covers TRUSTED_DOCKER");
                }
            } else if (releaseDecision.capability() != capability) {
                throw new SecurityException("task capability is not covered by the sandbox release decision");
            }
        }
    }

    public record ExecutionRequest(TaskScope scope) {
        public ExecutionRequest {
            Objects.requireNonNull(scope, "scope");
        }
    }

    public record ExecutionResult(TaskScope scope, String executedDigest, int traceChunks,
                                  String traceHeadDigest, TaskLifecycle lifecycle) {
        public ExecutionResult {
            Objects.requireNonNull(scope, "scope");
            if (executedDigest == null || !executedDigest.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("executedDigest is invalid");
            }
            if (traceChunks <= 0) throw new IllegalArgumentException("traceChunks must be positive");
            if (traceHeadDigest == null || !traceHeadDigest.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("traceHeadDigest is invalid");
            }
            if (lifecycle != TaskLifecycle.COMPLETED) {
                throw new IllegalArgumentException("execution result must be completed");
            }
        }
    }

    public static final class ExternalArtifactExecutionException extends RuntimeException {
        private final String code;

        private ExternalArtifactExecutionException(String code, String message, Throwable cause) {
            super(message, cause);
            this.code = ExternalArtifactIds.requireId(code, "code");
        }

        /** 供 worker 子包 helper 构造 fail-closed 执行异常；已是本类型时不再二次套娃。 */
        public static ExternalArtifactExecutionException of(String code, String message, Throwable cause) {
            if (cause instanceof ExternalArtifactExecutionException existing) {
                return existing;
            }
            return new ExternalArtifactExecutionException(code, message, cause);
        }

        public String code() {
            return code;
        }
    }
}
