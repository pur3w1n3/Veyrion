package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.analysis.experiment.GuardSurfaceCatalog;
import com.aq.jvmsentinel.policy.NetworkMode;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.sandbox.CommandRequest;
import com.aq.jvmsentinel.sandbox.CommandResult;
import com.aq.jvmsentinel.sandbox.ReadOnlyArtifactMount;
import com.aq.jvmsentinel.sandbox.SandboxHandle;
import com.aq.jvmsentinel.sandbox.SandboxRequest;
import com.aq.jvmsentinel.sandbox.SandboxRuntimeClient;
import com.aq.jvmsentinel.verification.SandboxReleaseGate;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Executes a catalog-owned executable JAR only after a fresh digest check.
 * It has no host-process fallback and exposes no caller-controlled command, image, path, or capability.
 */
public final class ExternalArtifactTaskExecutor {
    static final String AGENT_PATH = "/opt/veyrion/agent/veyrion-agent.jar";
    static final String ARTIFACT_PATH = "/opt/veyrion/artifact/application.jar";
    static final String WORKING_DIRECTORY = "/sandbox";
    static final String TRACE_DIRECTORY = "/tmp/veyrion-trace";
    static final String TRACE_FILE = TRACE_DIRECTORY + "/agent-events.jsonl";
    static final String PROBE_TRACE_FILE = TRACE_DIRECTORY + "/probe-events.jsonl";
    static final String PROBE_STATUS_FILE = TRACE_DIRECTORY + "/probe-status.txt";
    /** Trusted Docker runs as container-default root so JARs may bind privileged ports (e.g. 80). */
    static final int SANDBOX_UID = 0;
    static final int SANDBOX_GID = 0;

    /**
     * Product flood ceiling for one dynamic task. Must stay aligned with
     * {@code ProbePlanService.MAX_DYNAMIC_PROBES} and agent {@code LoopbackHttpProbe} batch lines.
     */
    public static final int MAX_PROBE_PLAN_ENTRIES = 512;
    /**
     * Worst-case UTF-8 TSV line budget per {@link ProbeTarget}
     * (method + 1024 route + 256 query + track + dual 2048 auth headers + tabs/newline).
     */
    public static final int MAX_PROBE_PLAN_LINE_BYTES = 6 * 1024;
    /**
     * Bounded host→sandbox probe-plan upload budget ({@link #MAX_PROBE_PLAN_ENTRIES} ×
     * {@link #MAX_PROBE_PLAN_LINE_BYTES} = 3 MiB). Not a general large-file channel.
     */
    public static final int MAX_PROBE_PLAN_UPLOAD_BYTES =
            MAX_PROBE_PLAN_ENTRIES * MAX_PROBE_PLAN_LINE_BYTES;
    /** Raw bytes per bounded Base64 download command; encoded output stays below 1 MiB. */
    static final int TRACE_READ_BLOCK_BYTES = 512 * 1024;
    private static final long MIN_PROBE_TRACE_RESERVE_BYTES = 64L * 1024;
    private static final long PROBE_TRACE_BYTES_PER_ENTRY = 2_048L;

    private static final long MAX_WALL_SECONDS = 3_600;
    private static final long MAX_CPU_MILLIS = 3_600_000;
    private static final long MAX_MEMORY_BYTES = 4L * 1024 * 1024 * 1024;
    private static final long MAX_DISK_BYTES = 1024L * 1024 * 1024;
    private static final long MAX_TRACE_BYTES = 64L * 1024 * 1024;
    private static final long MAX_ARTIFACT_BYTES = 2L * 1024 * 1024 * 1024;
    private static final long MAX_TMPFS_BYTES = 64L * 1024 * 1024;

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
                new AgentJsonlTraceConverter(Clock.systemUTC(), MAX_TRACE_BYTES,
                        64 * 1024, 100_000, WorkerContracts.MAX_TRACE_PAYLOAD_BYTES),
                workerId);
    }

    public ExternalArtifactTaskExecutor(WorkerControlPlaneClient control, SandboxRuntimeClient sandbox,
                                        ArtifactCatalog catalog, RuntimePolicy runtimePolicy,
                                        AgentJsonlTraceConverter converter, String workerId) {
        this.control = Objects.requireNonNull(control, "control");
        this.sandbox = Objects.requireNonNull(sandbox, "sandbox");
        this.catalog = Objects.requireNonNull(catalog, "catalog");
        this.runtimePolicy = Objects.requireNonNull(runtimePolicy, "runtimePolicy");
        this.converter = Objects.requireNonNull(converter, "converter");
        this.retainedSessions = new RetainedSandboxSessions(Duration.ofMinutes(20));
        this.workerId = requireId(workerId, "workerId");
    }

    /** Executes one internally scoped task; the request intentionally contains only its immutable scope. */
    public ExecutionResult execute(ExecutionRequest request) {
        Objects.requireNonNull(request, "request");
        WorkerControlPlaneClient.TaskDescriptor descriptor = control.get(request.scope());
        validateDescriptor(descriptor, request.scope(), TaskLifecycle.QUEUED);
        ArtifactRegistration registration = catalog.require(request.scope());
        validateRegistration(registration, request.scope());
        validateBudget(descriptor.resourceBudget());
        runtimePolicy.requireCapability(descriptor.requiredCapability());

        WorkerLease lease = null;
        String sandboxId = null;
        RuntimeException primary = null;
        ExecutorService commandExecutor = null;
        try {
            ResourceBudget budget = descriptor.resourceBudget();
            // Lease must outlive the Docker command timeout; heartbeat renews during the long run.
            Duration leaseDuration = Duration.ofSeconds(Math.min(3_600,
                    budget.maxWallClockSeconds() + 120));
            Duration heartbeatExtension = Duration.ofSeconds(Math.min(3_600,
                    budget.maxWallClockSeconds() + 60));
            lease = control.lease(request.scope(), workerId, Set.of(descriptor.requiredCapability()),
                    leaseDuration);
            requireLease(lease, request.scope(), descriptor.requiredCapability());
            WorkerControlPlaneClient.TaskDescriptor started =
                    control.start(request.scope(), lease.leaseId(), workerId);
            validateDescriptor(started, request.scope(), TaskLifecycle.RUNNING);
            requireStableDescriptor(descriptor, started);
            pulse(request.scope(), lease, heartbeatExtension, "复核制品摘要");

            // This is deliberately after the lease/start transition and immediately before sandbox use.
            recheckDigest(registration);
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
            SandboxHandle handle = sandbox.create(new SandboxRequest(
                    runtimePolicy.imageUri(), List.of("/bin/sleep", "infinity"), timeoutSeconds(budget),
                    budget, descriptor.requiredCapability(), List.of(mount),
                    Math.min(MAX_TMPFS_BYTES, budget.maxDiskBytes())));
            sandboxId = handle.id();

            pulse(request.scope(), lease, heartbeatExtension, "准备 Agent 轨迹目录");
            CommandResult prepareTrace = sandbox.command(sandboxId, new CommandRequest(
                    "umask 077 && rm -f " + TRACE_FILE + " " + PROBE_TRACE_FILE + " " + PROBE_STATUS_FILE
                            + " " + TRACE_DIRECTORY + "/progress.txt",
                    WORKING_DIRECTORY,
                    Duration.ofSeconds(10), SANDBOX_UID, SANDBOX_GID));
            if (prepareTrace.exitCode() != 0) {
                throw new ExternalArtifactExecutionException(
                        "TRACE_DIRECTORY_FAILED", "Agent trace directory could not be prepared", null);
            }
            pulse(request.scope(), lease, heartbeatExtension,
                    "上传批量探针计划（" + registration.probePlan().size() + " 入口）");
            Path probePlanHost = writeHostProbePlan(registration.probePlan());
            try {
                sandbox.uploadFile(sandboxId, probePlanHost, TRACE_DIRECTORY + "/probe-plan.txt");
            } finally {
                try {
                    Files.deleteIfExists(probePlanHost);
                } catch (IOException ignored) {
                    // Best-effort cleanup of the host-side plan file.
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
                            fixedCommand(budget, registration), WORKING_DIRECTORY, commandTimeout(budget),
                            SANDBOX_UID, SANDBOX_GID)));
            CommandResult run = awaitCommandWithHeartbeat(
                    request.scope(), lease, heartbeatExtension, activeSandboxId, runFuture);
            if (run.exitCode() != 0) {
                CommandResult applicationLog = sandbox.command(sandboxId, new CommandRequest(
                        "tail -c 4096 " + TRACE_DIRECTORY + "/application.log 2>/dev/null; "
                                + "printf '%s\\n' 'probe diagnostics:'; tail -c 512 "
                                + PROBE_STATUS_FILE + " 2>/dev/null || true",
                        WORKING_DIRECTORY, Duration.ofSeconds(10), SANDBOX_UID, SANDBOX_GID));
                String detail = diagnostic(run.stdout(), run.stderr(),
                        applicationLog.stdout() + "\n" + applicationLog.stderr());
                throw new ExternalArtifactExecutionException(
                        "EXTERNAL_ARTIFACT_EXIT_NONZERO",
                        exitDiagnostic(run.exitCode(), detail), null);
            }

            pulse(request.scope(), lease, heartbeatExtension, "读取 Agent 轨迹");
            byte[] agentBytes = readTraceFile(
                    sandbox, sandboxId, TRACE_FILE, budget.maxTraceBytes(), true);
            byte[] probeBytes = readTraceFile(
                    sandbox, sandboxId, PROBE_TRACE_FILE,
                    budget.maxTraceBytes() - agentBytes.length, false);
            byte[] jsonl = mergeProbeEvents(agentBytes, probeBytes);
            if (jsonl.length > budget.maxTraceBytes()) {
                throw new ExternalArtifactExecutionException(
                        "TRACE_TOO_LARGE", "Agent trace exceeds the task budget", null);
            }
            requireHttpProbeEvidence(registration, jsonl);
            List<TraceChunk> chunks = converter.convert(jsonl, request.scope(), budget);
            pulse(request.scope(), lease, heartbeatExtension,
                    "提交轨迹（" + chunks.size() + " 段）");
            for (TraceChunk chunk : chunks) {
                control.commitTrace(request.scope(), lease.leaseId(), workerId, chunk);
            }
            int httpPort = readSandboxHttpPort(sandboxId);
            pulse(request.scope(), lease, heartbeatExtension,
                    "保留断网沙箱会话供 PATH/TRIAGE 复用");
            retainedSessions.retain(request.scope(), registration.sha256(), sandboxId, httpPort, sandbox);
            sandboxId = null;
            pulse(request.scope(), lease, heartbeatExtension,
                    "任务完成；断网沙箱保留至 TRIAGE 动态校验结束");
            WorkerControlPlaneClient.TaskDescriptor completed =
                    control.complete(request.scope(), lease.leaseId(), workerId);
            requireCompletedDescriptor(completed, request.scope(), descriptor);
            return new ExecutionResult(request.scope(), registration.sha256(), chunks.size(),
                    chunks.get(chunks.size() - 1).digest(), TaskLifecycle.COMPLETED);
        } catch (RuntimeException failure) {
            primary = failure;
            if (lease != null) {
                try {
                    control.fail(request.scope(), lease.leaseId(), workerId,
                            StopReason.WORKER_FAILURE, failureCode(failure),
                            failureDiagnostic(failure));
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
        try {
            pulse(request.scope(), lease, heartbeatExtension,
                    "清理上次探针输出并上传本轮计划（复用沙箱）");
            CommandResult prepareProbe = sandbox.command(session.sandboxId(), new CommandRequest(
                    "rm -f " + PROBE_TRACE_FILE + " " + PROBE_STATUS_FILE
                            + "; printf '%s\\n' '复用已启动应用，准备本轮探针' > "
                            + TRACE_DIRECTORY + "/progress.txt",
                    WORKING_DIRECTORY, Duration.ofSeconds(10), SANDBOX_UID, SANDBOX_GID));
            if (prepareProbe.exitCode() != 0) {
                retainedSessions.release(session, sandbox);
                throw new ExternalArtifactExecutionException(
                        "RETAINED_SANDBOX_PREPARE_FAILED",
                        "retained sandbox could not prepare a probe", null);
            }
            Path probePlanHost = writeHostProbePlan(registration.probePlan());
            try {
                sandbox.uploadFile(session.sandboxId(), probePlanHost, TRACE_DIRECTORY + "/probe-plan.txt");
            } finally {
                try {
                    Files.deleteIfExists(probePlanHost);
                } catch (IOException ignored) {
                    // Best-effort cleanup of the host-side plan file.
                }
            }
            pulse(request.scope(), lease, heartbeatExtension,
                    "在保留沙箱内执行本轮 loopback 探针");
            String command = "HTTP_PORT=" + session.httpPort()
                    + "; probe_jvm_status=not-run; PROBE_JVM_OK=0; "
                    + batchProbeStep(registration.probePlan())
                    + "; if [ \"$PROBE_JVM_OK\" -ne 1 ]; then exit 71; else exit 0; fi";
            CommandResult run = sandbox.command(session.sandboxId(), new CommandRequest(
                    command, WORKING_DIRECTORY, commandTimeout(budget), SANDBOX_UID, SANDBOX_GID));
            if (run.exitCode() != 0) {
                retainedSessions.release(session, sandbox);
                throw new ExternalArtifactExecutionException(
                        "RETAINED_SANDBOX_PROBE_FAILED",
                        exitDiagnostic(run.exitCode(), diagnostic(run.stdout(), run.stderr(), "")), null);
            }
            pulse(request.scope(), lease, heartbeatExtension, "读取复用沙箱探针轨迹");
            byte[] probeBytes = readTraceFile(
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
            requireCompletedDescriptor(completed, request.scope(), descriptor);
            return new ExecutionResult(request.scope(), registration.sha256(), chunks.size(),
                    chunks.get(chunks.size() - 1).digest(), TaskLifecycle.COMPLETED);
        } catch (RuntimeException failure) {
            throw failure;
        }
    }

    private int readSandboxHttpPort(String sandboxId) {
        CommandResult result = sandbox.command(sandboxId, new CommandRequest(
                "cat " + TRACE_DIRECTORY + "/http-port.txt 2>/dev/null | tr -d '\\r\\n'",
                WORKING_DIRECTORY, Duration.ofSeconds(5), SANDBOX_UID, SANDBOX_GID));
        if (result.exitCode() != 0 || result.stdout() == null
                || !result.stdout().strip().matches("[0-9]{1,5}")) {
            throw new ExternalArtifactExecutionException(
                    "HTTP_PORT_NOT_RETAINABLE",
                    "completed sandbox did not expose a reusable HTTP port", null);
        }
        int port = Integer.parseInt(result.stdout().strip());
        if (port < 1 || port > 65_535) {
            throw new ExternalArtifactExecutionException(
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
                throw new ExternalArtifactExecutionException(
                        "EXTERNAL_ARTIFACT_INTERRUPTED", "external artifact execution interrupted", interrupted);
            } catch (ExecutionException failed) {
                Throwable cause = failed.getCause() == null ? failed : failed.getCause();
                if (cause instanceof RuntimeException runtime) throw runtime;
                throw new ExternalArtifactExecutionException(
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

    private static void validateDescriptor(WorkerControlPlaneClient.TaskDescriptor value,
                                           TaskScope expectedScope, TaskLifecycle expectedLifecycle) {
        if (!value.scope().equals(expectedScope) || value.lifecycle() != expectedLifecycle) {
            throw new SecurityException("task response changed execution identity or lifecycle");
        }
        if (!value.authorized()) {
            throw new SecurityException("external artifact execution requires an authorized task");
        }
        if (value.requiredCapability() != WorkerCapability.TRUSTED_DOCKER
                && value.requiredCapability() != WorkerCapability.HARDENED_GVISOR
                && value.requiredCapability() != WorkerCapability.HARDENED_KATA) {
            throw new SecurityException("external artifact execution requires an approved artifact runtime");
        }
        if (value.networkPolicy().mode() != NetworkMode.DENY
                || !value.networkPolicy().allowlist().isEmpty()) {
            throw new SecurityException("external artifact execution requires deny-all network policy");
        }
    }

    /**
     * Completing may fail-closed into FAILED (e.g. PROJECTION_FAILED) while keeping scope stable.
     * Surface that distinctly so callers do not misread it as a lease/start identity mismatch.
     */
    private static void requireCompletedDescriptor(WorkerControlPlaneClient.TaskDescriptor value,
                                                   TaskScope expectedScope,
                                                   WorkerControlPlaneClient.TaskDescriptor baseline) {
        if (!value.scope().equals(expectedScope)) {
            throw new SecurityException("task response changed execution identity or lifecycle");
        }
        if (value.lifecycle() == TaskLifecycle.FAILED) {
            throw new ExternalArtifactExecutionException(
                    "PROJECTION_OR_COMPLETE_FAILED",
                    "control plane rejected task completion (lifecycle=FAILED); "
                            + "inspect /scans/{scanId}/dynamic-tasks failureDiagnostic",
                    null);
        }
        validateDescriptor(value, expectedScope, TaskLifecycle.COMPLETED);
        requireStableDescriptor(baseline, value);
    }

    private static void validateRegistration(ArtifactRegistration value, TaskScope scope) {
        Objects.requireNonNull(value, "artifact registration");
        if (!value.projectId().equals(scope.projectId()) || !value.sha256().equals(scope.artifactDigest())) {
            throw new SecurityException("artifact registration is not bound to the task scope");
        }
        if (!value.executableSpringBootJar()) {
            throw new SecurityException("registered artifact is not an executable Spring Boot JAR");
        }
        if (!value.path().getFileName().toString().toLowerCase(java.util.Locale.ROOT).endsWith(".jar")) {
            throw new SecurityException("registered external artifact is not a JAR");
        }
    }

    private static void requireStableDescriptor(WorkerControlPlaneClient.TaskDescriptor expected,
                                                WorkerControlPlaneClient.TaskDescriptor actual) {
        if (!expected.scope().equals(actual.scope())
                || !expected.targetEntryId().equals(actual.targetEntryId())
                || expected.authorized() != actual.authorized()
                || expected.requiredCapability() != actual.requiredCapability()
                || !expected.resourceBudget().equals(actual.resourceBudget())
                || !expected.networkPolicy().equals(actual.networkPolicy())) {
            throw new SecurityException("task response changed the immutable execution policy");
        }
    }

    private static void validateBudget(ResourceBudget budget) {
        if (budget.maxWallClockSeconds() < 60 || budget.maxWallClockSeconds() > MAX_WALL_SECONDS
                || budget.maxCpuMillis() > MAX_CPU_MILLIS
                || budget.maxCpuMillis() > budget.maxWallClockSeconds() * 1_000
                || budget.maxMemoryBytes() < 64L * 1024 * 1024
                || budget.maxMemoryBytes() > MAX_MEMORY_BYTES
                || budget.maxDiskBytes() < 1024L * 1024 || budget.maxDiskBytes() > MAX_DISK_BYTES
                || budget.maxTraceBytes() < 256 || budget.maxTraceBytes() > MAX_TRACE_BYTES) {
            throw new SecurityException("external artifact resource budget is outside hardened limits");
        }
    }

    private static void recheckDigest(ArtifactRegistration registration) {
        Path path = registration.path();
        try {
            BasicFileAttributes before = Files.readAttributes(
                    path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!before.isRegularFile() || Files.isSymbolicLink(path)
                    || before.size() <= 0 || before.size() > MAX_ARTIFACT_BYTES
                    || before.size() != registration.sizeBytes()) {
                throw new SecurityException("registered artifact file identity or size changed");
            }
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] signature = new byte[4];
            int signatureLength = 0;
            try (FileChannel channel = FileChannel.open(
                    path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
                ByteBuffer buffer = ByteBuffer.allocate(64 * 1024);
                while (channel.read(buffer) >= 0) {
                    buffer.flip();
                    while (buffer.hasRemaining()) {
                        byte value = buffer.get();
                        if (signatureLength < signature.length) signature[signatureLength++] = value;
                        digest.update(value);
                    }
                    buffer.clear();
                }
            }
            BasicFileAttributes after = Files.readAttributes(
                    path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (signatureLength != 4 || signature[0] != 'P' || signature[1] != 'K'
                    || !sameFile(before, after) || after.size() != registration.sizeBytes()) {
                throw new SecurityException("registered JAR changed during digest verification");
            }
            String actual = HexFormat.of().formatHex(digest.digest());
            if (!MessageDigest.isEqual(actual.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                    registration.sha256().getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
                throw new SecurityException("registered artifact digest no longer matches");
            }
        } catch (IOException exception) {
            throw new ExternalArtifactExecutionException(
                    "ARTIFACT_DIGEST_RECHECK_FAILED", "registered artifact could not be reverified", exception);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static boolean sameFile(BasicFileAttributes before, BasicFileAttributes after) {
        if (!after.isRegularFile() || before.size() != after.size()
                || !before.lastModifiedTime().equals(after.lastModifiedTime())) return false;
        return before.fileKey() == null || after.fileKey() == null || before.fileKey().equals(after.fileKey());
    }

    private void requireLease(WorkerLease lease, TaskScope scope, WorkerCapability capability) {
        if (!lease.scope().equals(scope) || !lease.workerId().equals(workerId)
                || lease.capability() != capability) {
            throw new SecurityException("lease binding does not match external artifact execution");
        }
    }

    static long agentTraceBudget(ResourceBudget budget, int probeCount) {
        Objects.requireNonNull(budget, "budget");
        long total = Math.min(MAX_TRACE_BYTES, budget.maxTraceBytes());
        int probes = Math.max(1, Math.min(MAX_PROBE_PLAN_ENTRIES, probeCount));
        long desiredReserve = MIN_PROBE_TRACE_RESERVE_BYTES
                + probes * PROBE_TRACE_BYTES_PER_ENTRY;
        long reserve = Math.min(desiredReserve, Math.max(0L, total - 256L));
        return total - reserve;
    }

    /**
     * Reads only fixed trace paths through bounded Base64 blocks. The live Agent may still
     * append to the source while the sandbox is retained, so this copies to a stable
     * {@code *.snapshot} first, then length-checks every block against that frozen size.
     */
    static byte[] readTraceFile(SandboxRuntimeClient sandbox, String sandboxId, String path,
                                long maxBytes, boolean required) {
        Objects.requireNonNull(sandbox, "sandbox");
        if (!TRACE_FILE.equals(path) && !PROBE_TRACE_FILE.equals(path)) {
            throw new SecurityException("trace read path is not allowlisted");
        }
        if (maxBytes < 0 || maxBytes > MAX_TRACE_BYTES) {
            throw new SecurityException("trace read budget is outside limits");
        }
        String snapshot = path + ".snapshot";
        try {
            // Freeze the JSONL before sizing/reading: retained apps keep writing via FileChannel.
            String sizeCommand = required
                    ? "cp -f " + path + " " + snapshot + " && wc -c < " + snapshot
                    : "if [ -f " + path + " ]; then cp -f " + path + " " + snapshot
                            + " && wc -c < " + snapshot + "; else printf '0\\n'; fi";
            CommandResult sizeResult = sandbox.command(sandboxId, new CommandRequest(
                    sizeCommand, WORKING_DIRECTORY, Duration.ofSeconds(20),
                    SANDBOX_UID, SANDBOX_GID));
            String sizeText = sizeResult.stdout().strip();
            if (sizeResult.exitCode() != 0 || !sizeText.matches("[0-9]{1,10}")) {
                throw new ExternalArtifactExecutionException(
                        "TRACE_READ_FAILED", "trace size could not be read", null);
            }
            long size = Long.parseLong(sizeText);
            if (size == 0) {
                if (required) {
                    throw new ExternalArtifactExecutionException(
                            "TRACE_READ_FAILED", "required Agent trace is empty", null);
                }
                return new byte[0];
            }
            if (size > maxBytes) {
                throw new ExternalArtifactExecutionException(
                        "TRACE_TOO_LARGE", "Agent and probe trace exceed the task budget", null);
            }

            ByteArrayOutputStream output = new ByteArrayOutputStream(Math.toIntExact(size));
            int blocks = Math.toIntExact((size + TRACE_READ_BLOCK_BYTES - 1)
                    / TRACE_READ_BLOCK_BYTES);
            for (int block = 0; block < blocks; block++) {
                String command = "dd if=" + snapshot + " bs=" + TRACE_READ_BLOCK_BYTES
                        + " skip=" + block + " count=1 2>/dev/null"
                        + " | base64 | tr -d '\\r\\n'";
                CommandResult chunk = sandbox.command(sandboxId, new CommandRequest(
                        command, WORKING_DIRECTORY, Duration.ofSeconds(15),
                        SANDBOX_UID, SANDBOX_GID));
                if (chunk.exitCode() != 0) {
                    throw new ExternalArtifactExecutionException(
                            "TRACE_READ_FAILED", "trace block command failed", null);
                }
                String encoded = chunk.stdout() == null ? "" : chunk.stdout().replaceAll("\\s+", "");
                byte[] decoded;
                try {
                    decoded = Base64.getDecoder().decode(encoded);
                } catch (IllegalArgumentException malformed) {
                    throw new ExternalArtifactExecutionException(
                            "TRACE_READ_FAILED", "trace block is not valid Base64", malformed);
                }
                int expected = (int) Math.min(TRACE_READ_BLOCK_BYTES,
                        size - (long) block * TRACE_READ_BLOCK_BYTES);
                if (decoded.length != expected) {
                    throw new ExternalArtifactExecutionException(
                            "TRACE_READ_FAILED",
                            "trace block length mismatch (block=" + block
                                    + " expected=" + expected
                                    + " actual=" + decoded.length + ")",
                            null);
                }
                output.write(decoded, 0, decoded.length);
            }
            byte[] result = output.toByteArray();
            if (result.length != size) {
                throw new ExternalArtifactExecutionException(
                        "TRACE_READ_FAILED", "trace length changed during read", null);
            }
            return result;
        } catch (ExternalArtifactExecutionException failure) {
            throw failure;
        } catch (RuntimeException failure) {
            throw new ExternalArtifactExecutionException(
                    "TRACE_READ_FAILED", "trace could not be read safely", failure);
        } finally {
            try {
                sandbox.command(sandboxId, new CommandRequest(
                        "rm -f " + snapshot,
                        WORKING_DIRECTORY, Duration.ofSeconds(5), SANDBOX_UID, SANDBOX_GID));
            } catch (RuntimeException ignored) {
                // Best-effort snapshot cleanup on the trace tmpfs.
            }
        }
    }

    private static String fixedCommand(ResourceBudget budget, ArtifactRegistration registration) {
        long maxBytes = agentTraceBudget(budget, registration.probePlan().size());
        long maxEvents = Math.max(1, Math.min(100_000, maxBytes / 256));
        long runSeconds = Math.max(1, budget.maxWallClockSeconds() - 15);
        String worldPackMode = registration.worldPackDependencyMode();
        boolean mockDependencies = !"OBSERVE_FAIL".equalsIgnoreCase(worldPackMode);
        // Keep application readiness separate from the full task wall clock. The remaining
        // budget is for probes and trace collection after HTTP is ready.
        long startupLimitSeconds = registration.sizeBytes() >= 80L * 1024 * 1024 ? 180
                : registration.sizeBytes() >= 20L * 1024 * 1024 ? 120 : 90;
        long startupSeconds = Math.min(runSeconds, startupLimitSeconds);
        String businessProbes = batchProbeStep(registration.probePlan());
        if (businessProbes.isBlank()) {
            businessProbes = batchProbeStep(List.of(
                    new ProbeTarget(registration.probeMethod(), registration.probeRoute())));
        }
        // Do not force server.port/address: the JAR keeps its own listen config.
        // Readiness uses WaitHttpReady (process LISTEN -> HTTP classify) to avoid fragile shell quoting.
        boolean mysqlConnector = containsMysqlConnector(registration.path());
        // Quote JDBC URLs for /bin/sh: unquoted '&' in query strings backgrounds the java process
        // and makes later --spring.* flags execute as separate shell commands (exit 70).
        String datasource = mysqlConnector
                ? shellSingleQuoted(
                        "jdbc:mysql://127.0.0.1:3306/veyrion?connectTimeout=1000&socketTimeout=1000&useSSL=false")
                : "jdbc:veyrion-mock:mem:veyrion";
        String driver = mysqlConnector ? "" : " --spring.datasource.driver-class-name="
                + "com.aq.jvmsentinel.instrumentation.mock.VeyrionMockDriver";
        String forcedGuardTypes = forcedGuardTypeNamesProperty(registration.path());
        return writeProgress("启动应用 JAR（保留制品自身端口；javaagent hook + 协议级依赖替身；容器断网）")
                + "; java"
                + " -Dveyrion.sandbox.traceDir=" + TRACE_DIRECTORY
                + " -Dveyrion.sandbox.traceDir.authorized=true"
                + " -Dveyrion.sandbox.docker=true"
                + " -Dveyrion.worldPack.dependencyMode=" + worldPackMode
                + " -Dveyrion.sandbox.dependencyMock=" + mockDependencies
                + " -Dveyrion.coverage.enabled=true"
                + (forcedGuardTypes.isEmpty()
                ? "" : " -Dveyrion.sandbox.forcedGuardTypeNames="
                + shellSingleQuoted(forcedGuardTypes))
                // Keep app temps off the tiny trace tmpfs so probe-events.jsonl can still be written.
                + " -Djava.io.tmpdir=/tmp"
                // Quartz AUTO uses hostname; deny-all Docker often cannot resolve it
                // ("Couldn't get host name" -> "Cannot run without an instance id").
                // Use a fixed literal id (not AUTO / SYS_PROP).
                + " -Dorg.quartz.scheduler.instanceName=veyrion-sandbox"
                + " -Dorg.quartz.scheduler.instanceId=veyrion-sandbox"
                // World Pack mode is -D only so older digest-pinned runtime Agent jars stay compatible.
                + " -javaagent:" + AGENT_PATH + "=maxBytes=" + maxBytes + ",maxEvents=" + maxEvents
                + ",dependencyMock=" + mockDependencies
                + ",veyrion.coverage.enabled=true"
                + (registration.classPrefix().isEmpty()
                ? "" : ",classPrefix=" + registration.classPrefix())
                + " -jar " + ARTIFACT_PATH
                // Fail-open pools + protocol mock URL so deny-all jars can bind loopback for probes.
                + " --spring.main.lazy-initialization=true"
                + (mockDependencies
                ? " --spring.datasource.url=" + datasource
                + driver
                + " --spring.datasource.hikari.initialization-fail-timeout=-1"
                + " --spring.datasource.hikari.connection-timeout=1000"
                + " --spring.datasource.druid.initial-size=0"
                + " --spring.datasource.druid.min-idle=0"
                + " --spring.datasource.druid.max-wait=1000"
                + " --spring.datasource.druid.fail-fast=false"
                + " --spring.datasource.druid.connection-error-retry-attempts=0"
                + " --spring.datasource.druid.break-after-acquire-failure=true"
                + " --spring.datasource.druid.test-while-idle=false"
                + " --spring.redis.host=127.0.0.1"
                + " --spring.redis.port=6379"
                + " --spring.redis.timeout=500ms"
                + " --spring.data.redis.timeout=500ms"
                + " --management.health.redis.enabled=false"
                : "")
                + " --spring.flyway.enabled=false"
                + " --spring.liquibase.enabled=false"
                + " --spring.sql.init.mode=never"
                + " --spring.jpa.hibernate.ddl-auto=none"
                + " --spring.data.redis.repositories.enabled=false"
                + " --spring.quartz.auto-startup=false"
                + " --spring.quartz.job-store-type=memory"
                + " --spring.quartz.overwrite-existing-jobs=false"
                + " --spring.quartz.properties.org.quartz.scheduler.instanceName=veyrion-sandbox"
                + " --spring.quartz.properties.org.quartz.scheduler.instanceId=veyrion-sandbox"
                + " --spring.quartz.properties.org.quartz.jobStore.class="
                + "org.quartz.simpl.RAMJobStore"
                + " --spring.quartz.properties.org.quartz.jobStore.isClustered=false"
                + " > " + TRACE_DIRECTORY + "/application.log 2>&1"
                + " & APP_PID=$!; elapsed=0; probe_status=1; probe_jvm_status=not-run; PROBE_JVM_OK=0; HTTP_PORT="
                + "; rm -f " + TRACE_DIRECTORY + "/http-port.txt " + TRACE_DIRECTORY
                + "/listen-ports.txt " + TRACE_DIRECTORY + "/http-port.stdout "
                + TRACE_DIRECTORY + "/wait-http-ready.err " + PROBE_TRACE_FILE + " " + PROBE_STATUS_FILE
                + "; " + writeProgress("等待应用就绪（分析进程 LISTEN 端口）")
                + "; while kill -0 \"$APP_PID\" 2>/dev/null"
                + " && [ \"$elapsed\" -lt " + startupSeconds + " ]"
                + "; do"
                + " if java -Xmx64m -XX:MaxMetaspaceSize=64m -Dveyrion.sandbox.traceDir=" + TRACE_DIRECTORY
                + " -cp " + AGENT_PATH
                + " com.aq.jvmsentinel.agent.WaitHttpReady \"$APP_PID\" " + TRACE_DIRECTORY
                + " > " + TRACE_DIRECTORY + "/http-port.stdout 2>> " + TRACE_DIRECTORY + "/wait-http-ready.err"
                + "; then HTTP_PORT=$(cat " + TRACE_DIRECTORY + "/http-port.stdout 2>/dev/null | tr -d '\\r\\n');"
                + " break; fi"
                + "; sleep 2; elapsed=$((elapsed+2)); done"
                + "; if [ -z \"$HTTP_PORT\" ] && [ -f " + TRACE_DIRECTORY + "/http-port.txt ]"
                + "; then HTTP_PORT=$(cat " + TRACE_DIRECTORY + "/http-port.txt | tr -d '\\r\\n'); fi"
                + "; case \"$HTTP_PORT\" in ''|*[!0-9]*|3306|6379|5432|27017|11211|9200|5672|61616|9092) HTTP_PORT= ;; esac"
                + "; if kill -0 \"$APP_PID\" 2>/dev/null && [ -n \"$HTTP_PORT\" ]"
                + "; then probe_status=0"
                + "; printf '应用已就绪，HTTP 端口 %s，开始业务入口探测\\n' \"$HTTP_PORT\" > "
                + TRACE_DIRECTORY + "/progress.txt"
                + "; " + businessProbes
                + "; fi"
                + "; if [ \"$probe_status\" -eq 0 ] && [ \"$PROBE_JVM_OK\" -eq 1 ]; then "
                + "printf '%s\\n' \"$HTTP_PORT\" > " + TRACE_DIRECTORY + "/http-port.txt"
                + "; " + writeProgress("探测完成，保留应用进程供 PATH/TRIAGE 复用")
                + "; exit 0"
                + "; elif [ \"$probe_status\" -eq 0 ]; then "
                + "printf 'HTTP 端口已就绪但批量探针失败（退出码 %s），停止应用进程\\n' "
                + "\"$probe_jvm_status\" > " + TRACE_DIRECTORY + "/progress.txt"
                + "; else " + writeProgress("就绪超时，停止应用进程")
                + "; fi"
                + "; if kill -0 \"$APP_PID\" 2>/dev/null; then "
                + "kill -TERM \"$APP_PID\""
                + "; grace=0; while kill -0 \"$APP_PID\" 2>/dev/null && [ \"$grace\" -lt 10 ]"
                + "; do sleep 1; grace=$((grace+1)); done"
                + "; if kill -0 \"$APP_PID\" 2>/dev/null; then kill -KILL \"$APP_PID\"; fi"
                + "; wait \"$APP_PID\" 2>/dev/null || true"
                + "; if [ \"$probe_status\" -ne 0 ]; then exit 70"
                + "; elif [ \"$PROBE_JVM_OK\" -ne 1 ]; then exit 71"
                + "; else exit 0; fi"
                + "; else wait \"$APP_PID\"; app_status=$?"
                + "; if [ \"$probe_status\" -ne 0 ]; then exit 70"
                + "; elif [ \"$PROBE_JVM_OK\" -ne 1 ]; then exit 71"
                + "; else exit \"$app_status\"; fi; fi";
    }

    /** Select protocol-level MySQL only when Connector/J is present in the catalog JAR. */
    static boolean containsMysqlConnector(Path artifact) {
        int entries = 0;
        try (ZipFile zip = new ZipFile(artifact.toFile())) {
            var iterator = zip.entries();
            while (iterator.hasMoreElements() && entries++ < 100_000) {
                ZipEntry entry = iterator.nextElement();
                if (entry.isDirectory()) continue;
                String name = entry.getName().toLowerCase(java.util.Locale.ROOT);
                if (name.contains("mysql-connector")
                        && (name.endsWith(".jar") || name.endsWith(".zip"))) return true;
            }
            return false;
        } catch (IOException ignored) {
            // Digest/signature validation rejects malformed artifacts before command construction.
            return false;
        }
    }

    /** One JVM probes the whole plan file so hundreds of entries stay inside the wall clock. */
    private static String batchProbeStep(List<ProbeTarget> targets) {
        int count = targets == null ? 0 : targets.size();
        // Bounded heap so the probe can start beside a large Blade app; do not swallow JVM death.
        return writeProgress("开始批量探测 " + count + " 个 HTTP 入口（单 JVM）")
                + "; printf 'probe selected http port: %s\\n' \"$HTTP_PORT\" >&2"
                + "; case \"$HTTP_PORT\" in ''|*[!0-9]*|3306|6379|5432|27017|11211|9200|5672|61616|9092)"
                + " probe_jvm_status=64;"
                + " printf 'invalid or dependency HTTP_PORT for probe: %s\\n' \"$HTTP_PORT\" >&2 ;;"
                + " *) java -Xmx64m -XX:MaxMetaspaceSize=64m -Dveyrion.sandbox.traceDir=" + TRACE_DIRECTORY
                + " -Dveyrion.loopbackProbe.port=\"$HTTP_PORT\""
                + " -cp " + AGENT_PATH
                + " com.aq.jvmsentinel.agent.LoopbackHttpProbe --batch "
                + TRACE_DIRECTORY + "/probe-plan.txt \"$HTTP_PORT\""
                + "; probe_jvm_status=$? ;; esac"
                + "; printf 'probe_jvm_status=%s\\n' \"$probe_jvm_status\" > " + PROBE_STATUS_FILE
                + "; if [ \"$probe_jvm_status\" -eq 0 ] || [ \"$probe_jvm_status\" -eq 2 ]"
                + "; then PROBE_JVM_OK=1; fi";
    }

    private static Path writeHostProbePlan(List<ProbeTarget> targets) {
        try {
            Path file = Files.createTempFile("veyrion-probe-plan-", ".txt");
            Files.write(file, encodeProbePlan(targets));
            return file;
        } catch (IllegalArgumentException invalid) {
            throw new ExternalArtifactExecutionException(
                    "PROBE_PLAN_TOO_LARGE", invalid.getMessage(), invalid);
        } catch (IOException failure) {
            throw new ExternalArtifactExecutionException(
                    "PROBE_PLAN_WRITE_FAILED", "probe plan could not be written on the host", failure);
        }
    }

    /**
     * Serializes a flood/probe plan to the agent TSV format and enforces the trusted-sandbox
     * upload budget before any worker upload begins.
     */
    public static byte[] encodeProbePlan(List<ProbeTarget> targets) {
        List<ProbeTarget> plan = targets == null ? List.of() : targets;
        if (plan.size() > MAX_PROBE_PLAN_ENTRIES) {
            throw new IllegalArgumentException("probe plan exceeds entry limit ("
                    + plan.size() + " > " + MAX_PROBE_PLAN_ENTRIES + ")");
        }
        StringBuilder text = new StringBuilder(Math.min(64 * 1024, plan.size() * 64 + 16));
        for (ProbeTarget target : plan) {
            text.append(target.method()).append('\t').append(target.route()).append('\t')
                    .append(target.query() == null ? "" : target.query()).append('\t')
                    .append(target.track() == null ? "UNAUTH" : target.track()).append('\t')
                    .append(target.authHeader() == null ? "" : target.authHeader()).append('\t')
                    .append(target.bladeAuthHeader() == null ? "" : target.bladeAuthHeader());
            boolean hasCookie = target.cookieHeader() != null && !target.cookieHeader().isBlank();
            boolean hasPlan = target.experimentPlanId() != null && !target.experimentPlanId().isBlank();
            if (hasPlan || hasCookie) {
                text.append('\t').append(hasPlan ? target.experimentPlanId() : "");
            }
            if (hasCookie) {
                text.append('\t').append(target.cookieHeader());
            }
            text.append('\n');
        }
        byte[] bytes = text.toString().getBytes(StandardCharsets.UTF_8);
        if (bytes.length == 0 || bytes.length > MAX_PROBE_PLAN_UPLOAD_BYTES) {
            throw new IllegalArgumentException(
                    "probe plan host file size exceeds trusted sandbox upload budget ("
                            + bytes.length + " > " + MAX_PROBE_PLAN_UPLOAD_BYTES + ")");
        }
        return bytes;
    }

    /** UTF-8 size of the serialized probe plan, or 0 when empty. */
    public static int probePlanUtf8Bytes(List<ProbeTarget> targets) {
        List<ProbeTarget> plan = targets == null ? List.of() : targets;
        if (plan.isEmpty()) return 0;
        int total = 0;
        for (ProbeTarget target : plan) {
            total += target.method().getBytes(StandardCharsets.UTF_8).length + 1;
            total += target.route().getBytes(StandardCharsets.UTF_8).length + 1;
            String query = target.query() == null ? "" : target.query();
            total += query.getBytes(StandardCharsets.UTF_8).length + 1;
            String track = target.track() == null || target.track().isBlank() ? "UNAUTH" : target.track();
            total += track.getBytes(StandardCharsets.UTF_8).length + 1;
            String auth = target.authHeader() == null ? "" : target.authHeader();
            total += auth.getBytes(StandardCharsets.UTF_8).length + 1;
            String blade = target.bladeAuthHeader() == null ? "" : target.bladeAuthHeader();
            total += blade.getBytes(StandardCharsets.UTF_8).length + 1;
            boolean hasCookie = target.cookieHeader() != null && !target.cookieHeader().isBlank();
            boolean hasPlan = target.experimentPlanId() != null && !target.experimentPlanId().isBlank();
            if (hasPlan || hasCookie) {
                String planId = hasPlan ? target.experimentPlanId() : "";
                total += planId.getBytes(StandardCharsets.UTF_8).length + 1;
            }
            if (hasCookie) {
                total += target.cookieHeader().getBytes(StandardCharsets.UTF_8).length + 1;
            }
        }
        return total;
    }

    private static String writeProgress(String message) {
        return "printf '%s\\n' " + shellSingleQuoted(message) + " > " + TRACE_DIRECTORY + "/progress.txt";
    }

    /**
     * Appends out-of-process loopback probe events after the in-app agent JSONL, renumbering
     * sequences so {@link AgentJsonlTraceConverter} sees one contiguous stream.
     */
    static byte[] mergeProbeEvents(byte[] agentJsonl, byte[] probeJsonl) {
        Objects.requireNonNull(agentJsonl, "agentJsonl");
        if (probeJsonl == null || probeJsonl.length == 0) return agentJsonl;
        String agentText = new String(agentJsonl, java.nio.charset.StandardCharsets.UTF_8);
        String probeText = new String(probeJsonl, java.nio.charset.StandardCharsets.UTF_8).trim();
        if (probeText.isEmpty()) return agentJsonl;
        long nextSequence = 0;
        for (String line : agentText.split("\n", -1)) {
            if (line.isBlank()) continue;
            int marker = line.indexOf("\"sequence\":");
            if (marker < 0) continue;
            int start = marker + "\"sequence\":".length();
            int end = start;
            while (end < line.length() && Character.isDigit(line.charAt(end))) end++;
            if (end > start) {
                nextSequence = Math.max(nextSequence, Long.parseLong(line.substring(start, end)) + 1);
            }
        }
        StringBuilder merged = new StringBuilder(agentText);
        if (!agentText.isEmpty() && !agentText.endsWith("\n")) merged.append('\n');
        for (String line : probeText.split("\n", -1)) {
            if (line.isBlank()) continue;
            int marker = line.indexOf("\"sequence\":");
            if (marker < 0) continue;
            int start = marker + "\"sequence\":".length();
            int end = start;
            while (end < line.length() && Character.isDigit(line.charAt(end))) end++;
            if (end <= start) continue;
            merged.append(line, 0, start).append(nextSequence++).append(line, end, line.length());
            if (!line.endsWith("\n")) merged.append('\n');
        }
        return merged.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private static String shellSingleQuoted(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }

    /**
     * Server-owned GuardSurface typeNames for the agent FORCED allowlist.
     * Empty when the catalog finds nothing — agent then keeps name heuristics.
     */
    public static String forcedGuardTypeNamesProperty(Path artifactPath) {
        return GuardSurfaceCatalog.formatTypeNamesProperty(
                GuardSurfaceCatalog.typeNames(GuardSurfaceCatalog.harvest(artifactPath)));
    }

    private static int timeoutSeconds(ResourceBudget budget) {
        return Math.toIntExact(budget.maxWallClockSeconds());
    }

    private static Duration commandTimeout(ResourceBudget budget) {
        // Grace for Docker process teardown after the in-container wall clock ends.
        return Duration.ofSeconds(Math.min(3_600, budget.maxWallClockSeconds() + 45));
    }

    /**
     * Best-effort terminalization when lease-bound fail is unavailable (pre-lease reject or
     * lease reclaim race). Leaves FAILED so stage retry is not blocked by a zombie QUEUED task.
     */
    private void tryMarkTerminalFailure(TaskScope scope, RuntimeException failure) {
        try {
            WorkerControlPlaneClient.TaskDescriptor current = control.get(scope);
            if (current.lifecycle() == TaskLifecycle.QUEUED) {
                control.failQueued(scope, StopReason.WORKER_FAILURE, failureCode(failure),
                        failureDiagnostic(failure));
            } else if (current.lease() != null
                    && (current.lifecycle() == TaskLifecycle.LEASED
                    || current.lifecycle() == TaskLifecycle.RUNNING
                    || current.lifecycle() == TaskLifecycle.PAUSED)) {
                control.fail(scope, current.lease().leaseId(), workerId,
                        StopReason.WORKER_FAILURE, failureCode(failure), failureDiagnostic(failure));
            }
        } catch (RuntimeException ignored) {
            // Stage retry can supersede leftover active tasks; do not mask the primary failure.
        }
    }

    private static String failureCode(RuntimeException failure) {
        if (failure instanceof ExternalArtifactExecutionException external) {
            String code = external.code();
            if (code != null && !code.isBlank() && !"EXTERNAL_ARTIFACT_EXECUTION_FAILED".equals(code)) {
                return code;
            }
            SandboxStartupDiagnostics.Diagnosis diagnosis =
                    SandboxStartupDiagnostics.classify(extractExitCode(external.getMessage()),
                            external.getMessage());
            return diagnosis.code();
        }
        if (failure instanceof SecurityException || failure instanceof IllegalArgumentException) {
            return "EXTERNAL_ARTIFACT_REJECTED";
        }
        SandboxStartupDiagnostics.Diagnosis diagnosis =
                SandboxStartupDiagnostics.classify(-1, failure.getMessage());
        return diagnosis.code();
    }

    private static String failureDiagnostic(RuntimeException failure) {
        String value = failure.getMessage();
        if (value == null || value.isBlank()) return failureCode(failure);
        value = value.replaceAll("(?i)(password|passwd|secret|token|api[_-]?key)(\\s*[:=]\\s*)\\S+",
                        "$1$2[REDACTED]")
                .replaceAll("(?i)bearer\\s+[A-Za-z0-9._~+/-]{4,}", "Bearer [REDACTED]")
                .replaceAll("\\bsk-[A-Za-z0-9_-]{4,}\\b", "[REDACTED]")
                .replaceAll("[\\p{Cntrl}&&[^\\n\\t]]", " ").strip();
        SandboxStartupDiagnostics.Diagnosis diagnosis =
                SandboxStartupDiagnostics.classify(extractExitCode(value), value);
        String classified = "[" + diagnosis.failureClass().name() + "] " + diagnosis.summary()
                + " | " + value;
        return classified.length() <= 2048 ? classified : classified.substring(0, 2048);
    }

    private static int extractExitCode(String message) {
        if (message == null) return -1;
        java.util.regex.Matcher matcher = java.util.regex.Pattern
                .compile("exit (\\d{1,3})")
                .matcher(message);
        if (matcher.find()) {
            try {
                return Integer.parseInt(matcher.group(1));
            } catch (NumberFormatException ignored) {
                return -1;
            }
        }
        return -1;
    }

    static String diagnostic(String probeStdout, String probeStderr, String applicationLog) {
        String stderr = cleanDiagnostic(probeStderr);
        String stdout = cleanDiagnostic(probeStdout);
        String application = cleanDiagnostic(applicationLog);
        stderr = compactDiagnostic(stderr, 650, "probe stack");
        if (stdout.length() > 120) stdout = stdout.substring(stdout.length() - 120);
        application = compactDiagnostic(application, 650, "application log");
        String value = "probe stderr:\n" + (stderr.isBlank() ? "(empty)" : stderr)
                + "\nprobe stdout tail:\n" + (stdout.isBlank() ? "(empty)" : stdout)
                + "\napplication log tail:\n" + (application.isBlank() ? "(empty)" : application);
        return value.length() <= 1_600 ? value : value.substring(0, 1_600);
    }

    private static String cleanDiagnostic(String value) {
        return (value == null ? "" : value)
                .replaceAll("[\\p{Cntrl}&&[^\\r\\n\\t]]", "?").strip();
    }

    private static String compactDiagnostic(String value, int limit, String label) {
        if (value == null || value.length() <= limit) return value == null ? "" : value;
        int anchor = diagnosticAnchor(value);
        if (anchor < 0) return value.substring(value.length() - limit);
        int start = Math.max(0, anchor - 160);
        int end = Math.min(value.length(), start + limit);
        String slice = value.substring(start, end);
        if (start > 0) slice = "...[" + label + " omitted before]...\n" + slice;
        if (end < value.length()) slice = slice + "\n...[" + label + " omitted after]...";
        return slice.length() <= limit ? slice : slice.substring(0, limit);
    }

    private static int diagnosticAnchor(String value) {
        int best = -1;
        for (String marker : List.of("Exception in thread", "Caused by", "ERROR", "java.lang.")) {
            int index = value.indexOf(marker);
            if (index >= 0 && (best < 0 || index < best)) best = index;
        }
        return best;
    }

    private static String exitDiagnostic(int exitCode, String detail) {
        SandboxStartupDiagnostics.Diagnosis diagnosis =
                SandboxStartupDiagnostics.classify(exitCode, detail);
        String prefix = "external artifact returned exit " + exitCode
                + " [" + diagnosis.failureClass().name() + "] " + diagnosis.summary();
        if (exitCode == 70) {
            prefix += " (loopback HTTP listen never classified as ready; application likely failed to bind"
                    + " an HTTP port under deny-all - often blocked by unavailable DB/external deps)";
        } else if (exitCode == 71) {
            prefix += " (HTTP port was ready but LoopbackHttpProbe failed; probe_jvm_status=3 means"
                    + " zero writable events, while other nonzero values indicate probe startup, plan,"
                    + " or runtime failure; the recorded status follows below)";
        }
        if (detail == null || detail.isBlank()) return prefix;
        return prefix + ": " + detail;
    }

    /**
     * Flood/sandbox plans must produce at least one HTTP probe event. Per-target timeouts remain
     * success with evidence; zero events after a non-empty plan is fail-closed.
     */
    static void requireHttpProbeEvidence(ArtifactRegistration registration, byte[] mergedJsonl) {
        Objects.requireNonNull(registration, "registration");
        Objects.requireNonNull(mergedJsonl, "mergedJsonl");
        if (registration.probePlan() == null || registration.probePlan().isEmpty()) return;

        Set<String> expected = registration.probePlan().stream()
                .map(target -> probeIdentity(target.method(), target.route(),
                        target.query().isBlank() ? target.route() : target.route() + "?" + target.query(),
                        target.track()))
                .collect(Collectors.toSet());
        Set<String> observed = new java.util.HashSet<>();
        int httpEvents = 0;
        try {
            for (String line : new String(mergedJsonl, StandardCharsets.UTF_8).split("\n", -1)) {
                if (line.isBlank()) continue;
                Map<String, Object> event = JsonCodec.parseObject(line);
                if (!"HTTP".equals(event.get("eventType"))) continue;
                httpEvents++;
                if (!"com.aq.jvmsentinel.agent.LoopbackHttpProbe".equals(event.get("class"))
                        || !(event.get("detail") instanceof Map<?, ?> detail)) {
                    continue;
                }
                observed.add(probeIdentity(
                        Objects.toString(detail.get("httpMethod"), ""),
                        Objects.toString(detail.get("route"), ""),
                        Objects.toString(detail.get("requestTarget"), ""),
                        Objects.toString(detail.get("track"), "")));
            }
        } catch (RuntimeException malformed) {
            throw new ExternalArtifactExecutionException(
                    "MALFORMED_PROBE_EVENTS", "loopback HTTP probe events are not valid JSONL", malformed);
        }
        if (observed.containsAll(expected)) return;
        String code = httpEvents == 0 ? "EMPTY_PROBE_EVENTS" : "PROBE_EVENT_COVERAGE_INCOMPLETE";
        throw new ExternalArtifactExecutionException(code,
                "loopback HTTP probe evidence does not cover the submitted plan (expected="
                        + expected.size() + ", observed=" + observed.size()
                        + ", httpEvents=" + httpEvents + ")",
                null);
    }

    private static String probeIdentity(String method, String route, String requestTarget, String track) {
        return method.toUpperCase(java.util.Locale.ROOT) + '\u0000' + route + '\u0000'
                + requestTarget + '\u0000' + track;
    }

    static int countHttpEvents(byte[] jsonl) {
        if (jsonl == null || jsonl.length == 0) return 0;
        int count = 0;
        for (String line : new String(jsonl, java.nio.charset.StandardCharsets.UTF_8).split("\n", -1)) {
            if (line.contains("\"eventType\":\"HTTP\"")) count++;
        }
        return count;
    }

    private static String requireId(String value, String name) {
        Objects.requireNonNull(value, name);
        if (!value.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")) {
            throw new IllegalArgumentException(name + " is invalid");
        }
        return value;
    }

    private record SessionKey(String projectId, String artifactDigest, String scanId) {
        private static SessionKey from(TaskScope scope) {
            return new SessionKey(scope.projectId(), scope.artifactDigest(), scope.scanId());
        }
    }

    private record RetainedSandboxSession(SessionKey key, String sha256, String sandboxId,
                                          int httpPort, long expiresAtNanos) { }

    private static final class RetainedSandboxSessions {
        private static final int MAX_RETAINED_SESSIONS = 8;
        private final Duration ttl;
        private final Map<SessionKey, RetainedSandboxSession> sessions = new ConcurrentHashMap<>();

        private RetainedSandboxSessions(Duration ttl) {
            this.ttl = Objects.requireNonNull(ttl, "ttl");
        }

        RetainedSandboxSession get(TaskScope scope, String sha256) {
            SessionKey key = SessionKey.from(scope);
            RetainedSandboxSession session = sessions.get(key);
            if (session == null || !session.sha256().equals(sha256)
                    || session.expiresAtNanos() < System.nanoTime()) {
                return null;
            }
            return session;
        }

        void retain(TaskScope scope, String sha256, String sandboxId, int httpPort,
                    SandboxRuntimeClient sandbox) {
            SessionKey key = SessionKey.from(scope);
            RetainedSandboxSession prior = sessions.put(key,
                    new RetainedSandboxSession(key, sha256, sandboxId, httpPort, deadlineNanos()));
            if (prior != null && !prior.sandboxId().equals(sandboxId)) {
                deleteQuietly(sandbox, prior.sandboxId());
            }
            if (sessions.size() > MAX_RETAINED_SESSIONS) {
                RetainedSandboxSession oldest = sessions.values().stream()
                        .min(java.util.Comparator.comparingLong(RetainedSandboxSession::expiresAtNanos))
                        .orElse(null);
                if (oldest != null && sessions.remove(oldest.key(), oldest)
                        && !oldest.sandboxId().equals(sandboxId)) {
                    deleteQuietly(sandbox, oldest.sandboxId());
                }
            }
        }

        void touch(RetainedSandboxSession session) {
            if (session == null) return;
            sessions.computeIfPresent(session.key(), (ignored, existing) ->
                    existing.sandboxId().equals(session.sandboxId())
                            ? new RetainedSandboxSession(existing.key(), existing.sha256(),
                            existing.sandboxId(), existing.httpPort(), deadlineNanos())
                            : existing);
        }

        void release(RetainedSandboxSession session, SandboxRuntimeClient sandbox) {
            if (session == null) return;
            if (sessions.remove(session.key(), session)) {
                deleteQuietly(sandbox, session.sandboxId());
            }
        }

        void releaseExpired(SandboxRuntimeClient sandbox) {
            long now = System.nanoTime();
            for (RetainedSandboxSession session : List.copyOf(sessions.values())) {
                if (session.expiresAtNanos() < now && sessions.remove(session.key(), session)) {
                    deleteQuietly(sandbox, session.sandboxId());
                }
            }
        }

        void releaseAll(SandboxRuntimeClient sandbox) {
            for (RetainedSandboxSession session : List.copyOf(sessions.values())) {
                if (sessions.remove(session.key(), session)) {
                    deleteQuietly(sandbox, session.sandboxId());
                }
            }
        }

        void releaseForScan(String projectId, String artifactDigest, String scanId,
                            SandboxRuntimeClient sandbox) {
            SessionKey key = new SessionKey(projectId, artifactDigest, scanId);
            RetainedSandboxSession session = sessions.remove(key);
            if (session != null) {
                deleteQuietly(sandbox, session.sandboxId());
            }
        }

        private static void deleteQuietly(SandboxRuntimeClient sandbox, String sandboxId) {
            try {
                sandbox.delete(sandboxId);
            } catch (RuntimeException ignored) {
                // Best-effort cleanup; the sandbox backend may also own process-exit cleanup.
            }
        }

        private long deadlineNanos() {
            long now = System.nanoTime();
            long ttlNanos = ttl.toNanos();
            if (ttlNanos <= 0 || Long.MAX_VALUE - now < ttlNanos) return Long.MAX_VALUE;
            return now + ttlNanos;
        }
    }

    public void closeRetainedSessions() {
        retainedSessions.releaseAll(sandbox);
    }

    /** Releases the retained deny-all sandbox for one scan after TRIAGE or pipeline abandon. */
    public void releaseRetainedForScan(String projectId, String artifactDigest, String scanId) {
        retainedSessions.releaseForScan(
                requireId(projectId, "projectId"),
                requireId(artifactDigest, "artifactDigest"),
                requireId(scanId, "scanId"),
                sandbox);
    }
    @FunctionalInterface
    public interface ArtifactCatalog {
        ArtifactRegistration require(TaskScope scope);
    }

    /** One bounded HTTP stimulus inside the deny-all container. */
    public record ProbeTarget(String method, String route, String query, String track,
                              String authHeader, String bladeAuthHeader, String experimentPlanId,
                              String cookieHeader) {
        public ProbeTarget(String method, String route) {
            this(method, route, "", "UNAUTH", "", "", "", "");
        }

        public ProbeTarget(String method, String route, String query) {
            this(method, route, query, "UNAUTH", "", "", "", "");
        }

        /** Auth-only constructor; Blade-Auth / Cookie stay empty (channels are independent). */
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
            projectId = requireId(projectId, "projectId");
            if (sha256 == null || !sha256.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("sha256 must be a lowercase SHA-256 digest");
            }
            Objects.requireNonNull(path, "path");
            path = path.toAbsolutePath().normalize();
            if (sizeBytes <= 0 || sizeBytes > MAX_ARTIFACT_BYTES) {
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

    /** Deployment-owned runtime image containing the trusted Agent at the fixed path. */
    public static final class RuntimePolicy {
        private final String imageUri;
        private final SandboxReleaseGate.ReleaseDecision releaseDecision;
        private final boolean trustedLocalDocker;

        /** Release-gated policy for hardened gVisor/Kata deployments. */
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

        /** Explicit local policy; it never authorizes fixture or hardened capabilities. */
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
            this.code = requireId(code, "code");
        }

        public String code() {
            return code;
        }
    }
}
