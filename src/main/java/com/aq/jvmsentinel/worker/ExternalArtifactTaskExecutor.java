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
    static final int SANDBOX_UID = 65532;
    static final int SANDBOX_GID = 65532;

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
        try {
            lease = control.lease(request.scope(), workerId, Set.of(descriptor.requiredCapability()),
                    Duration.ofSeconds(Math.min(3_600, descriptor.resourceBudget().maxWallClockSeconds() + 30)));
            requireLease(lease, request.scope(), descriptor.requiredCapability());
            WorkerControlPlaneClient.TaskDescriptor started =
                    control.start(request.scope(), lease.leaseId(), workerId);
            validateDescriptor(started, request.scope(), TaskLifecycle.RUNNING);
            requireStableDescriptor(descriptor, started);

            // This is deliberately after the lease/start transition and immediately before sandbox creation.
            recheckDigest(registration);
            ResourceBudget budget = descriptor.resourceBudget();
            ReadOnlyArtifactMount mount = new ReadOnlyArtifactMount(
                    registration.path(), ARTIFACT_PATH, registration.sha256(), registration.sizeBytes());
            SandboxHandle handle = sandbox.create(new SandboxRequest(
                    runtimePolicy.imageUri(), List.of("/bin/sleep", "infinity"), timeoutSeconds(budget),
                    budget, descriptor.requiredCapability(), List.of(mount),
                    Math.min(MAX_TMPFS_BYTES, budget.maxDiskBytes())));
            sandboxId = handle.id();

            CommandResult prepareTrace = sandbox.command(sandboxId, new CommandRequest(
                    "umask 077 && rm -f " + TRACE_FILE, WORKING_DIRECTORY,
                    Duration.ofSeconds(10), SANDBOX_UID, SANDBOX_GID));
            if (prepareTrace.exitCode() != 0) {
                throw new ExternalArtifactExecutionException(
                        "TRACE_DIRECTORY_FAILED", "Agent trace directory could not be prepared", null);
            }
            CommandResult run = sandbox.command(sandboxId, new CommandRequest(
                    fixedCommand(budget, registration), WORKING_DIRECTORY, commandTimeout(budget),
                    SANDBOX_UID, SANDBOX_GID));
            if (run.exitCode() != 0) {
                CommandResult applicationLog = sandbox.command(sandboxId, new CommandRequest(
                        "tail -c 2048 " + TRACE_DIRECTORY + "/application.log 2>/dev/null || true",
                        WORKING_DIRECTORY, Duration.ofSeconds(10), SANDBOX_UID, SANDBOX_GID));
                throw new ExternalArtifactExecutionException(
                        "EXTERNAL_ARTIFACT_EXIT_NONZERO",
                        "external artifact returned exit " + run.exitCode() + ": "
                                + diagnostic(run.stdout() + "\n" + applicationLog.stdout(),
                                run.stderr() + "\n" + applicationLog.stderr()), null);
            }

            CommandResult traceRead = sandbox.command(sandboxId, new CommandRequest(
                    "/bin/cat " + TRACE_FILE, WORKING_DIRECTORY, Duration.ofSeconds(10),
                    SANDBOX_UID, SANDBOX_GID));
            if (traceRead.exitCode() != 0) {
                throw new ExternalArtifactExecutionException(
                        "TRACE_READ_FAILED", "Agent trace could not be read", null);
            }
            byte[] jsonl = traceRead.stdout().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            if (jsonl.length > budget.maxTraceBytes()) {
                throw new ExternalArtifactExecutionException(
                        "TRACE_TOO_LARGE", "Agent trace exceeds the task budget", null);
            }
            List<TraceChunk> chunks = converter.convert(jsonl, request.scope(), budget);
            for (TraceChunk chunk : chunks) {
                control.commitTrace(request.scope(), lease.leaseId(), workerId, chunk);
            }
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
                }
            }
            throw failure;
        } finally {
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
        long startupSeconds = Math.min(30, Math.max(10, runSeconds / 2));
        return "java"
                + " -Dveyrion.sandbox.traceDir=" + TRACE_DIRECTORY
                + " -Dveyrion.sandbox.traceDir.authorized=true"
                + " -Djava.io.tmpdir=" + TRACE_DIRECTORY
                + " -javaagent:" + AGENT_PATH + "=maxBytes=" + maxBytes + ",maxEvents=" + maxEvents
                + (registration.classPrefix().isEmpty()
                ? "" : ",classPrefix=" + registration.classPrefix())
                + " -jar " + ARTIFACT_PATH
                + " > " + TRACE_DIRECTORY + "/application.log 2>&1"
                + " & pid=$!; elapsed=0; probe_status=1"
                + "; while kill -0 \"$pid\" 2>/dev/null"
                + " && [ \"$elapsed\" -lt " + startupSeconds + " ]"
                + "; do sleep 1; elapsed=$((elapsed+1)); done"
                + "; if kill -0 \"$pid\" 2>/dev/null && java -cp " + AGENT_PATH
                + " com.aq.jvmsentinel.agent.LoopbackHttpProbe "
                + registration.probeMethod() + " '" + registration.probeRoute() + "'"
                + "; then probe_status=0; fi"
                + "; while kill -0 \"$pid\" 2>/dev/null && [ \"$probe_status\" -ne 0 ]"
                + " && [ \"$elapsed\" -lt " + runSeconds + " ]"
                + "; do sleep 3; elapsed=$((elapsed+3))"
                + "; if java -cp " + AGENT_PATH
                + " com.aq.jvmsentinel.agent.LoopbackHttpProbe "
                + registration.probeMethod() + " '" + registration.probeRoute() + "'"
                + "; then probe_status=0; fi; done"
                + "; while kill -0 \"$pid\" 2>/dev/null && [ \"$elapsed\" -lt " + runSeconds + " ]"
                + "; do sleep 1; elapsed=$((elapsed+1)); done"
                + "; if kill -0 \"$pid\" 2>/dev/null; then kill -TERM \"$pid\""
                + "; grace=0; while kill -0 \"$pid\" 2>/dev/null && [ \"$grace\" -lt 10 ]"
                + "; do sleep 1; grace=$((grace+1)); done"
                + "; if kill -0 \"$pid\" 2>/dev/null; then kill -KILL \"$pid\"; fi"
                + "; wait \"$pid\" 2>/dev/null || true"
                + "; if [ \"$probe_status\" -eq 0 ]; then exit 0; else exit 70; fi"
                + "; else wait \"$pid\"; app_status=$?"
                + "; if [ \"$probe_status\" -ne 0 ]; then exit 70; else exit \"$app_status\"; fi; fi";
    }

    private static int timeoutSeconds(ResourceBudget budget) {
        return Math.toIntExact(budget.maxWallClockSeconds());
    }

    private static Duration commandTimeout(ResourceBudget budget) {
        return Duration.ofSeconds(Math.min(3_600, budget.maxWallClockSeconds()));
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

    public record ArtifactRegistration(String projectId, String sha256, Path path, long sizeBytes,
                                       boolean executableSpringBootJar, String probeMethod,
                                       String probeRoute, String classPrefix) {
        public ArtifactRegistration(String projectId, String sha256, Path path, long sizeBytes,
                                    boolean executableSpringBootJar) {
            this(projectId, sha256, path, sizeBytes, executableSpringBootJar, "GET", "/", "");
        }

        public ArtifactRegistration(String projectId, String sha256, Path path, long sizeBytes,
                                    boolean executableSpringBootJar, String probeMethod,
                                    String probeRoute) {
            this(projectId, sha256, path, sizeBytes, executableSpringBootJar,
                    probeMethod, probeRoute, "");
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
