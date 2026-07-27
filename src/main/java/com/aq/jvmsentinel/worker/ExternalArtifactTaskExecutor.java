package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.policy.NetworkMode;
import com.aq.jvmsentinel.sandbox.CommandRequest;
import com.aq.jvmsentinel.sandbox.CommandResult;
import com.aq.jvmsentinel.sandbox.ReadOnlyArtifactMount;
import com.aq.jvmsentinel.sandbox.SandboxHandle;
import com.aq.jvmsentinel.sandbox.SandboxRequest;
import com.aq.jvmsentinel.sandbox.SandboxRuntimeClient;
import com.aq.jvmsentinel.verification.SandboxReleaseGate;

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
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Set;
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

            // This is deliberately after the lease/start transition and immediately before sandbox creation.
            recheckDigest(registration);
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
                    "umask 077 && rm -f " + TRACE_FILE + " " + PROBE_TRACE_FILE
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
                        "tail -c 2048 " + TRACE_DIRECTORY + "/application.log 2>/dev/null || true",
                        WORKING_DIRECTORY, Duration.ofSeconds(10), SANDBOX_UID, SANDBOX_GID));
                String detail = diagnostic(run.stdout() + "\n" + applicationLog.stdout(),
                        run.stderr() + "\n" + applicationLog.stderr());
                throw new ExternalArtifactExecutionException(
                        "EXTERNAL_ARTIFACT_EXIT_NONZERO",
                        exitDiagnostic(run.exitCode(), detail), null);
            }

            pulse(request.scope(), lease, heartbeatExtension, "读取 Agent 轨迹");
            CommandResult traceRead = sandbox.command(sandboxId, new CommandRequest(
                    "/bin/cat " + TRACE_FILE, WORKING_DIRECTORY, Duration.ofSeconds(10),
                    SANDBOX_UID, SANDBOX_GID));
            if (traceRead.exitCode() != 0) {
                throw new ExternalArtifactExecutionException(
                        "TRACE_READ_FAILED", "Agent trace could not be read", null);
            }
            CommandResult probeRead = sandbox.command(sandboxId, new CommandRequest(
                    "/bin/cat " + PROBE_TRACE_FILE + " 2>/dev/null || true",
                    WORKING_DIRECTORY, Duration.ofSeconds(10), SANDBOX_UID, SANDBOX_GID));
            byte[] probeBytes = probeRead.stdout().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] jsonl = mergeProbeEvents(
                    traceRead.stdout().getBytes(java.nio.charset.StandardCharsets.UTF_8),
                    probeBytes);
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
            pulse(request.scope(), lease, heartbeatExtension, "销毁沙箱并完成任务");
            sandbox.delete(sandboxId);
            sandboxId = null;
            WorkerControlPlaneClient.TaskDescriptor completed =
                    control.complete(request.scope(), lease.leaseId(), workerId);
            validateDescriptor(completed, request.scope(), TaskLifecycle.COMPLETED);
            requireStableDescriptor(descriptor, completed);
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

    private static String fixedCommand(ResourceBudget budget, ArtifactRegistration registration) {
        long maxBytes = Math.min(MAX_TRACE_BYTES, budget.maxTraceBytes());
        long maxEvents = Math.max(1, Math.min(100_000, maxBytes / 256));
        long runSeconds = Math.max(1, budget.maxWallClockSeconds() - 15);
        // Large Blade JARs need ~45–90s cold start; do not consume half the wall on readiness.
        long startupSeconds = Math.min(runSeconds, Math.max(120, Math.min(180, budget.maxWallClockSeconds() / 6)));
        String businessProbes = batchProbeStep(registration.probePlan());
        if (businessProbes.isBlank()) {
            businessProbes = batchProbeStep(List.of(
                    new ProbeTarget(registration.probeMethod(), registration.probeRoute())));
        }
        // Do not force server.port/address: the JAR keeps its own listen config.
        // Readiness uses WaitHttpReady (process LISTEN → HTTP classify) to avoid fragile shell quoting.
        boolean mysqlConnector = containsMysqlConnector(registration.path());
        // Quote JDBC URLs for /bin/sh: unquoted '&' in query strings backgrounds the java process
        // and makes later --spring.* flags execute as separate shell commands (exit 70).
        String datasource = mysqlConnector
                ? shellSingleQuoted(
                        "jdbc:mysql://127.0.0.1:3306/veyrion?connectTimeout=1000&socketTimeout=1000&useSSL=false")
                : "jdbc:veyrion-mock:mem:veyrion";
        String driver = mysqlConnector ? "" : " --spring.datasource.driver-class-name="
                + "com.aq.jvmsentinel.instrumentation.mock.VeyrionMockDriver";
        return writeProgress("启动应用 JAR（保留制品自身端口；javaagent hook + 协议级依赖替身；容器断网）")
                + "; java"
                + " -Dveyrion.sandbox.traceDir=" + TRACE_DIRECTORY
                + " -Dveyrion.sandbox.traceDir.authorized=true"
                + " -Dveyrion.sandbox.dependencyMock=true"
                + " -Dveyrion.coverage.enabled=true"
                // Keep app temps off the tiny trace tmpfs so probe-events.jsonl can still be written.
                + " -Djava.io.tmpdir=/tmp"
                + " -javaagent:" + AGENT_PATH + "=maxBytes=" + maxBytes + ",maxEvents=" + maxEvents
                + ",dependencyMock=true,veyrion.coverage.enabled=true"
                + (registration.classPrefix().isEmpty()
                ? "" : ",classPrefix=" + registration.classPrefix())
                + " -jar " + ARTIFACT_PATH
                // Fail-open pools + protocol mock URL so deny-all jars can bind loopback for probes.
                + " --spring.main.lazy-initialization=true"
                + " --spring.datasource.url=" + datasource
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
                + " --spring.flyway.enabled=false"
                + " --spring.liquibase.enabled=false"
                + " --spring.sql.init.mode=never"
                + " --spring.jpa.hibernate.ddl-auto=none"
                + " --spring.data.redis.repositories.enabled=false"
                + " --spring.redis.host=127.0.0.1"
                + " --spring.redis.port=6379"
                + " --spring.redis.timeout=500ms"
                + " --spring.data.redis.timeout=500ms"
                + " --management.health.redis.enabled=false"
                + " > " + TRACE_DIRECTORY + "/application.log 2>&1"
                + " & APP_PID=$!; elapsed=0; probe_status=1; PROBE_JVM_OK=0; HTTP_PORT="
                + "; rm -f " + TRACE_DIRECTORY + "/http-port.txt " + TRACE_DIRECTORY
                + "/listen-ports.txt " + PROBE_TRACE_FILE
                + "; " + writeProgress("等待应用就绪（分析进程 LISTEN 端口）")
                + "; while kill -0 \"$APP_PID\" 2>/dev/null"
                + " && [ \"$elapsed\" -lt " + startupSeconds + " ]"
                + "; do"
                + " if java -Xmx64m -XX:MaxMetaspaceSize=64m -Dveyrion.sandbox.traceDir=" + TRACE_DIRECTORY
                + " -cp " + AGENT_PATH
                + " com.aq.jvmsentinel.agent.WaitHttpReady \"$APP_PID\" " + TRACE_DIRECTORY
                + "; then HTTP_PORT=$(cat " + TRACE_DIRECTORY + "/http-port.txt 2>/dev/null | tr -d '\\r\\n');"
                + " break; fi"
                + "; sleep 2; elapsed=$((elapsed+2)); done"
                + "; if [ -z \"$HTTP_PORT\" ] && [ -f " + TRACE_DIRECTORY + "/http-port.txt ]"
                + "; then HTTP_PORT=$(cat " + TRACE_DIRECTORY + "/http-port.txt | tr -d '\\r\\n'); fi"
                + "; if kill -0 \"$APP_PID\" 2>/dev/null && [ -n \"$HTTP_PORT\" ]"
                + "; then probe_status=0"
                + "; printf '应用已就绪，HTTP 端口 %s，开始业务入口探测\\n' \"$HTTP_PORT\" > "
                + TRACE_DIRECTORY + "/progress.txt"
                + "; " + businessProbes
                + "; else"
                + " while kill -0 \"$APP_PID\" 2>/dev/null && [ \"$probe_status\" -ne 0 ]"
                + " && [ \"$elapsed\" -lt " + runSeconds + " ]"
                + "; do sleep 3; elapsed=$((elapsed+3))"
                + "; " + writeProgress("仍在等待应用就绪（分析进程 LISTEN 端口）")
                + "; if java -Xmx64m -XX:MaxMetaspaceSize=64m -Dveyrion.sandbox.traceDir=" + TRACE_DIRECTORY
                + " -cp " + AGENT_PATH
                + " com.aq.jvmsentinel.agent.WaitHttpReady \"$APP_PID\" " + TRACE_DIRECTORY
                + "; then HTTP_PORT=$(cat " + TRACE_DIRECTORY + "/http-port.txt 2>/dev/null | tr -d '\\r\\n');"
                + " probe_status=0"
                + "; printf '应用已就绪，HTTP 端口 %s，开始业务入口探测\\n' \"$HTTP_PORT\" > "
                + TRACE_DIRECTORY + "/progress.txt"
                + "; " + businessProbes
                + "; fi; done; fi"
                + "; if [ \"$probe_status\" -eq 0 ] && [ \"$PROBE_JVM_OK\" -eq 1 ]; then "
                + writeProgress("探测完成，停止应用进程")
                + "; elif [ \"$probe_status\" -eq 0 ]; then "
                + writeProgress("HTTP 端口已就绪但批量探针未写入事件，停止应用进程")
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
                + "; java -Xmx64m -XX:MaxMetaspaceSize=64m -Dveyrion.sandbox.traceDir=" + TRACE_DIRECTORY
                + " -cp " + AGENT_PATH
                + " com.aq.jvmsentinel.agent.LoopbackHttpProbe @"
                + TRACE_DIRECTORY + "/probe-plan.txt \"$HTTP_PORT\""
                + "; probe_jvm_status=$?"
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
                    .append(target.bladeAuthHeader() == null ? "" : target.bladeAuthHeader())
                    .append('\n');
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
        if (failure instanceof ExternalArtifactExecutionException external) return external.code();
        if (failure instanceof SecurityException || failure instanceof IllegalArgumentException) {
            return "EXTERNAL_ARTIFACT_REJECTED";
        }
        return "EXTERNAL_ARTIFACT_EXECUTION_FAILED";
    }

    private static String failureDiagnostic(RuntimeException failure) {
        String value = failure.getMessage();
        if (value == null || value.isBlank()) return failureCode(failure);
        value = value.replaceAll("(?i)(password|passwd|secret|token|api[_-]?key)(\\s*[:=]\\s*)\\S+",
                        "$1$2[REDACTED]")
                .replaceAll("(?i)bearer\\s+[A-Za-z0-9._~+/-]{4,}", "Bearer [REDACTED]")
                .replaceAll("\\bsk-[A-Za-z0-9_-]{4,}\\b", "[REDACTED]")
                .replaceAll("[\\p{Cntrl}&&[^\\n\\t]]", " ").strip();
        return value.length() <= 2048 ? value : value.substring(0, 2048);
    }

    private static String diagnostic(String stdout, String stderr) {
        String value = ((stderr == null ? "" : stderr) + "\n"
                + (stdout == null ? "" : stdout))
                .replaceAll("[\\p{Cntrl}&&[^\\r\\n\\t]]", "?").strip();
        return value.length() <= 2048 ? value : value.substring(value.length() - 2048);
    }

    private static String exitDiagnostic(int exitCode, String detail) {
        String prefix = "external artifact returned exit " + exitCode;
        if (exitCode == 70) {
            prefix += " (loopback HTTP listen never classified as ready; application likely failed to bind"
                    + " an HTTP port under deny-all — often blocked by unavailable DB/external deps)";
        } else if (exitCode == 71) {
            prefix += " (HTTP port looked ready but LoopbackHttpProbe wrote no usable probe events"
                    + " — probe JVM may have OOM'd, crashed, or failed to write probe-events.jsonl)";
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
        if (countHttpEvents(mergedJsonl) > 0) return;
        throw new ExternalArtifactExecutionException(
                "EMPTY_PROBE_EVENTS",
                "loopback HTTP probe produced no HTTP events despite a non-empty probe plan ("
                        + registration.probePlan().size() + " targets)",
                null);
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

    @FunctionalInterface
    public interface ArtifactCatalog {
        ArtifactRegistration require(TaskScope scope);
    }

    /** One bounded HTTP stimulus inside the deny-all container. */
    public record ProbeTarget(String method, String route, String query, String track,
                              String authHeader, String bladeAuthHeader) {
        public ProbeTarget(String method, String route) {
            this(method, route, "", "UNAUTH", "", "");
        }

        public ProbeTarget(String method, String route, String query) {
            this(method, route, query, "UNAUTH", "", "");
        }

        /** Auth-only constructor; Blade-Auth stays empty (channels are independent). */
        public ProbeTarget(String method, String route, String query, String track, String authHeader) {
            this(method, route, query, track, authHeader, "");
        }

        public ProbeTarget {
            method = Objects.requireNonNull(method, "method").toUpperCase(java.util.Locale.ROOT);
            query = query == null ? "" : query;
            track = track == null || track.isBlank() ? "UNAUTH" : track;
            authHeader = authHeader == null ? "" : authHeader;
            bladeAuthHeader = bladeAuthHeader == null ? "" : bladeAuthHeader;
            if (!Set.of("GET", "POST", "PUT", "PATCH", "DELETE").contains(method)
                    || route == null
                    || !route.matches("/[A-Za-z0-9_./{}:-]{0,1023}")
                    || (!query.isEmpty() && !query.matches("[A-Za-z0-9_=&%./{}:-]{1,256}"))
                    || !track.matches("[A-Z_]{1,32}")
                    || authHeader.length() > 2048
                    || authHeader.chars().anyMatch(c -> c < 0x20 || c == 0x7f)
                    || bladeAuthHeader.length() > 2048
                    || bladeAuthHeader.chars().anyMatch(c -> c < 0x20 || c == 0x7f)) {
                throw new IllegalArgumentException("artifact probe target is invalid");
            }
        }
    }

    public record ArtifactRegistration(String projectId, String sha256, Path path, long sizeBytes,
                                       boolean executableSpringBootJar, String probeMethod,
                                       String probeRoute, String classPrefix,
                                       List<ProbeTarget> probePlan) {
        public ArtifactRegistration(String projectId, String sha256, Path path, long sizeBytes,
                                    boolean executableSpringBootJar) {
            this(projectId, sha256, path, sizeBytes, executableSpringBootJar, "GET", "/", "",
                    List.of(new ProbeTarget("GET", "/")));
        }

        public ArtifactRegistration(String projectId, String sha256, Path path, long sizeBytes,
                                    boolean executableSpringBootJar, String probeMethod,
                                    String probeRoute) {
            this(projectId, sha256, path, sizeBytes, executableSpringBootJar,
                    probeMethod, probeRoute, "", List.of(new ProbeTarget(probeMethod, probeRoute)));
        }

        public ArtifactRegistration(String projectId, String sha256, Path path, long sizeBytes,
                                    boolean executableSpringBootJar, String probeMethod,
                                    String probeRoute, String classPrefix) {
            this(projectId, sha256, path, sizeBytes, executableSpringBootJar,
                    probeMethod, probeRoute, classPrefix,
                    List.of(new ProbeTarget(probeMethod, probeRoute)));
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
