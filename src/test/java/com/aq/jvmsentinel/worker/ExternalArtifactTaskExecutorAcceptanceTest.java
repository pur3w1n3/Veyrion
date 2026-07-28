package com.aq.jvmsentinel.worker;
import com.aq.jvmsentinel.AcceptanceAssertions;

import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.sandbox.CommandRequest;
import com.aq.jvmsentinel.sandbox.CommandResult;
import com.aq.jvmsentinel.sandbox.OpenSandboxClient;
import com.aq.jvmsentinel.sandbox.OpenSandboxConfig;
import com.aq.jvmsentinel.sandbox.RuntimeAttestation;
import com.aq.jvmsentinel.sandbox.SandboxHandle;
import com.aq.jvmsentinel.sandbox.SandboxRequest;
import com.aq.jvmsentinel.sandbox.SandboxRuntimeClient;
import com.aq.jvmsentinel.sandbox.SandboxStatus;
import com.aq.jvmsentinel.verification.SandboxReleaseGate;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Main-style acceptance checks for digest-pinned external executable JAR execution. */
public final class ExternalArtifactTaskExecutorAcceptanceTest {
    private static final String IMAGE =
            "registry.example/veyrion/external-runtime@sha256:" + "c".repeat(64);
    private static final String FEATURES = String.join(",",
            "lifecycle-v1", "execd-command-v1", "network-deny-v1", "resource-budget-v1",
            // OpenSandbox hardened attestation still requires non-root-v1; TRUSTED_DOCKER local
            // Docker uses container-root-v1 separately in LocalDockerTrustedSandboxClient.
            "non-root-v1", "read-only-rootfs-v1", "writable-tmp-v1",
            "controlled-tmpfs-v1", "digest-pinned-readonly-artifact-v1");

    private ExternalArtifactTaskExecutorAcceptanceTest() { }

    public static void main(String[] args) throws Exception {
        Path directory = Files.createTempDirectory("veyrion-external-acceptance-");
        Path jar = directory.resolve("application.jar");
        createJar(jar, "original");
        Path mysqlJar = directory.resolve("mysql-application.jar");
        createJar(mysqlJar, "mysql-connector-j-8.4.0.jar", "original");
        check(!ExternalArtifactTaskExecutor.containsMysqlConnector(jar),
                "plain application must keep in-JVM JDBC substitute");
        check(ExternalArtifactTaskExecutor.containsMysqlConnector(mysqlJar),
                "Connector/J catalog entry must select protocol substitute");
        byte[] original = Files.readAllBytes(jar);
        String digest = sha256(original);

        MockServices mock = new MockServices(digest);
        mock.start();
        try {
            ExternalArtifactTaskExecutor.ArtifactRegistration registration =
                    new ExternalArtifactTaskExecutor.ArtifactRegistration(
                            "project-1", digest, jar, Files.size(jar), true,
                            "POST", "/sample/http-entry");
            ExternalArtifactTaskExecutor.ArtifactRegistration legacyRegistration =
                    new ExternalArtifactTaskExecutor.ArtifactRegistration(
                            "project-1", digest, jar, Files.size(jar), true);
            check(legacyRegistration.probeMethod().equals("GET")
                            && legacyRegistration.probeRoute().equals("/"),
                    "legacy artifact registration constructor");
            expect(IllegalArgumentException.class,
                    () -> new ExternalArtifactTaskExecutor.ArtifactRegistration(
                            "project-1", digest, jar, Files.size(jar), true,
                            "POST", "/sample/http-entry;touch-/tmp/escape"),
                    "probe route command expansion rejection");
            ExternalArtifactTaskExecutor executor = executor(mock, scope(digest, "task-success"), registration);
            ExternalArtifactTaskExecutor.ExecutionResult result =
                    executor.execute(new ExternalArtifactTaskExecutor.ExecutionRequest(
                            scope(digest, "task-success")));
            check(result.lifecycle() == TaskLifecycle.COMPLETED
                    && result.executedDigest().equals(digest)
                    && result.traceChunks() == 1, "successful execution");
            mock.assertSecureCreateAndCommand(digest);
            check(mock.deleted == 0, "successful sandbox is retained for PATH/TRIAGE probes");

            int createsAfterInitialProbe = mock.creates;
            ExternalArtifactTaskExecutor.ExecutionResult followup =
                    executor.execute(new ExternalArtifactTaskExecutor.ExecutionRequest(
                            scope(digest, "task-followup")));
            check(followup.lifecycle() == TaskLifecycle.COMPLETED
                            && followup.traceChunks() == 1
                            && mock.creates == createsAfterInitialProbe,
                    "follow-up probe reuses retained sandbox");
            mock.assertRetainedProbeReused();
            executor.closeRetainedSessions();
            check(mock.deleted == 1, "retained sandbox cleanup");

            ExternalArtifactTaskExecutor trusted = executor(
                    mock, scope(digest, "task-trusted-local"), registration);
            ExternalArtifactTaskExecutor.ExecutionResult trustedResult = trusted.execute(
                    new ExternalArtifactTaskExecutor.ExecutionRequest(
                            scope(digest, "task-trusted-local")));
            check(trustedResult.lifecycle() == TaskLifecycle.COMPLETED,
                    "explicit trusted-local execution");
            mock.assertSecureCreateAndCommand(digest);

            int createsBeforeTamper = mock.creates;
            Files.writeString(jar, "tampered", StandardCharsets.UTF_8);
            ExternalArtifactTaskExecutor tampered = executor(
                    mock, scope(digest, "task-tampered"), registration);
            expect(SecurityException.class, () -> tampered.execute(
                    new ExternalArtifactTaskExecutor.ExecutionRequest(scope(digest, "task-tampered"))),
                    "digest mismatch");
            check(mock.creates == createsBeforeTamper, "tampered artifact must not create a sandbox");
            check(mock.failedTasks.contains("task-tampered"), "tampered task must be failed");

            Files.write(jar, original);
            mock.failCommand = true;
            int deletesBeforeFailure = mock.deleted;
            ExternalArtifactTaskExecutor failing = executor(
                    mock, scope(digest, "task-command-failure"), registration);
            expect(ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.class,
                    () -> failing.execute(new ExternalArtifactTaskExecutor.ExecutionRequest(
                            scope(digest, "task-command-failure"))), "non-zero artifact exit");
            check(mock.deleted == deletesBeforeFailure + 1, "failed sandbox must be deleted");
            check(mock.failedTasks.contains("task-command-failure"), "failed execution state");
            mock.failCommand = false;

            expect(IllegalArgumentException.class,
                    () -> new ExternalArtifactTaskExecutor.RuntimePolicy("runtime:latest", releaseDecision()),
                    "unpinned runtime image");

            check(ExternalArtifactTaskExecutor.countHttpEvents(
                    MockServices.probeJsonl().getBytes(StandardCharsets.UTF_8)) == 1,
                    "HTTP probe event counter");
            expect(ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.class,
                    () -> ExternalArtifactTaskExecutor.requireHttpProbeEvidence(
                            registration, MockServices.agentJsonl().getBytes(StandardCharsets.UTF_8)),
                    "empty probe events fail closed");
            ExternalArtifactTaskExecutor.requireHttpProbeEvidence(
                    registration, MockServices.probeJsonl().getBytes(StandardCharsets.UTF_8));
            expect(ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.class,
                    () -> ExternalArtifactTaskExecutor.requireHttpProbeEvidence(registration,
                            MockServices.probeJsonl()
                                    .replace("/sample/http-entry", "/tmp/veyrion-trace/probe-plan.txt")
                                    .getBytes(StandardCharsets.UTF_8)),
                    "mismatched probe target must fail closed");
            chunkedTraceReadContract();
            String prioritized = ExternalArtifactTaskExecutor.diagnostic(
                    "probe-out", "Exception in thread main: probe failed\nstack-frame",
                    "application-noise-".repeat(300));
            check(prioritized.startsWith("probe stderr:\nException in thread main: probe failed")
                            && prioritized.contains("application log tail:")
                            && prioritized.length() <= 1_600,
                    "failure diagnostic prioritizes the probe exception within the public limit");

            System.out.println("ExternalArtifactTaskExecutorAcceptanceTest: PASS");
        } finally {
            mock.close();
            Files.deleteIfExists(jar);
            Files.deleteIfExists(mysqlJar);
            Files.deleteIfExists(directory);
        }
    }

    private static void chunkedTraceReadContract() throws Exception {
        byte[] large = new byte[ExternalArtifactTaskExecutor.TRACE_READ_BLOCK_BYTES * 2 + 137];
        for (int i = 0; i < large.length; i++) large[i] = (byte) (i * 31);

        TraceFileRuntimeClient runtime = new TraceFileRuntimeClient(large);
        byte[] read = ExternalArtifactTaskExecutor.readTraceFile(
                runtime, "sandbox-1", ExternalArtifactTaskExecutor.TRACE_FILE,
                large.length, true);
        check(Arrays.equals(large, read) && runtime.blockReads == 3,
                "trace larger than command response is read in bounded blocks");

        ResourceBudget fourMiB = new ResourceBudget(
                60, 60_000, 256L * 1024 * 1024, 64L * 1024 * 1024, 4L * 1024 * 1024);
        check(ExternalArtifactTaskExecutor.agentTraceBudget(fourMiB, 512)
                        == 4L * 1024 * 1024 - 64L * 1024 - 512L * 2_048,
                "Agent trace budget reserves bounded room for 512 probe events");

        TraceFileRuntimeClient oversized = new TraceFileRuntimeClient(large);
        var tooLarge = expect(ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.class,
                () -> ExternalArtifactTaskExecutor.readTraceFile(
                        oversized, "sandbox-1", ExternalArtifactTaskExecutor.TRACE_FILE,
                        large.length - 1L, true),
                "trace over task budget");
        check("TRACE_TOO_LARGE".equals(tooLarge.code()) && oversized.blockReads == 0,
                "oversized trace rejected before any block download");

        TraceFileRuntimeClient malformed = new TraceFileRuntimeClient(large);
        malformed.malformedBlock = 1;
        var badBase64 = expect(ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.class,
                () -> ExternalArtifactTaskExecutor.readTraceFile(
                        malformed, "sandbox-1", ExternalArtifactTaskExecutor.TRACE_FILE,
                        large.length, true),
                "malformed Base64 trace block");
        check("TRACE_READ_FAILED".equals(badBase64.code()),
                "malformed trace block fails closed");

        TraceFileRuntimeClient shortRead = new TraceFileRuntimeClient(large);
        shortRead.shortBlock = 2;
        var shortFailure = expect(ExternalArtifactTaskExecutor.ExternalArtifactExecutionException.class,
                () -> ExternalArtifactTaskExecutor.readTraceFile(
                        shortRead, "sandbox-1", ExternalArtifactTaskExecutor.TRACE_FILE,
                        large.length, true),
                "short trace block");
        check("TRACE_READ_FAILED".equals(shortFailure.code()),
                "short trace block fails closed");

        TraceFileRuntimeClient missing = new TraceFileRuntimeClient(null);
        byte[] optional = ExternalArtifactTaskExecutor.readTraceFile(
                missing, "sandbox-1", ExternalArtifactTaskExecutor.PROBE_TRACE_FILE,
                1024, false);
        check(optional.length == 0, "missing optional probe trace is empty");
        expect(SecurityException.class,
                () -> ExternalArtifactTaskExecutor.readTraceFile(
                        runtime, "sandbox-1", "/tmp/not-allowlisted", large.length, true),
                "trace path allowlist");
    }

    private static ExternalArtifactTaskExecutor executor(
            MockServices mock, TaskScope scope,
            ExternalArtifactTaskExecutor.ArtifactRegistration registration) {
        URI origin = URI.create("http://127.0.0.1:" + mock.port() + "/");
        WorkerControlPlaneClient control = new WorkerControlPlaneClient(
                origin.resolve("internal/worker/v1/"), "worker-token", Duration.ofSeconds(5));
        WorkerCapability capability = scope.taskId().equals("task-trusted-local")
                ? WorkerCapability.TRUSTED_DOCKER : WorkerCapability.HARDENED_GVISOR;
        RuntimeAttestation attestation = new RuntimeAttestation(
                "0.1.0", capability,
                capability == WorkerCapability.TRUSTED_DOCKER ? "docker-desktop-runc" : "runsc-gvisor",
                true, true, true, Set.of(FEATURES.split(",")));
        SandboxRuntimeClient sandbox = capability == WorkerCapability.TRUSTED_DOCKER
                ? new TrustedRuntimeClient(attestation)
                : new OpenSandboxClient(new OpenSandboxConfig(
                        origin.resolve("v1/"), "sandbox-key", "execd-token",
                        Duration.ofSeconds(5), "0.1.0", attestation));
        ExternalArtifactTaskExecutor.RuntimePolicy policy =
                capability == WorkerCapability.TRUSTED_DOCKER
                        ? ExternalArtifactTaskExecutor.RuntimePolicy.trustedLocalDocker(IMAGE)
                        : new ExternalArtifactTaskExecutor.RuntimePolicy(IMAGE, releaseDecision());
        return new ExternalArtifactTaskExecutor(control, sandbox, requested -> {
            check(requested.projectId().equals(scope.projectId())
                            && requested.artifactDigest().equals(scope.artifactDigest())
                            && requested.scanId().equals(scope.scanId()),
                    "catalog scope");
            return registration;
        }, policy, "worker-1");
    }

    private static SandboxReleaseGate.ReleaseDecision releaseDecision() {
        return new SandboxReleaseGate.ReleaseDecision(
                true, "EXTERNAL_ARTIFACT_ENABLED", "deployment-1",
                WorkerCapability.HARDENED_GVISOR, "c".repeat(64), "d".repeat(64));
    }

    private static TaskScope scope(String digest, String taskId) {
        return new TaskScope("project-1", digest, "scan-1", taskId);
    }

    private static void createJar(Path path, String value) throws IOException {
        createJar(path, null, value);
    }

    private static void createJar(Path path, String libraryName, String value) throws IOException {
        try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(path))) {
            output.putNextEntry(new ZipEntry("BOOT-INF/classes/example.txt"));
            output.write(value.getBytes(StandardCharsets.UTF_8));
            output.closeEntry();
            if (libraryName != null) {
                output.putNextEntry(new ZipEntry("BOOT-INF/lib/" + libraryName));
                output.write(new byte[]{0x50, 0x4b, 0x03, 0x04});
                output.closeEntry();
            }
        }
    }

    private static String sha256(byte[] value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        AcceptanceAssertions.record();
    }

    private static <T extends Throwable> T expect(
            Class<T> type, ThrowingRunnable runnable, String message) throws Exception {
        try {
            runnable.run();
        } catch (Throwable actual) {
            if (type.isInstance(actual)) return type.cast(actual);
            throw actual;
        }
        throw new AssertionError("expected " + type.getSimpleName() + ": " + message);
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    private static String traceReadOutput(String command) {
        byte[] source;
        String path;
        if (command.startsWith("wc -c < " + ExternalArtifactTaskExecutor.TRACE_FILE)) {
            return Integer.toString(MockServices.agentJsonl().getBytes(StandardCharsets.UTF_8).length);
        }
        if (command.startsWith("wc -c < " + ExternalArtifactTaskExecutor.PROBE_TRACE_FILE)) {
            return Integer.toString(MockServices.probeJsonl().getBytes(StandardCharsets.UTF_8).length);
        }
        if (command.startsWith("if [ -f " + ExternalArtifactTaskExecutor.PROBE_TRACE_FILE)) {
            return Integer.toString(MockServices.probeJsonl().getBytes(StandardCharsets.UTF_8).length);
        }
        if (command.startsWith("cat " + ExternalArtifactTaskExecutor.TRACE_DIRECTORY + "/http-port.txt")) {
            return "8080\n";
        }
        if (command.startsWith("dd if=" + ExternalArtifactTaskExecutor.TRACE_FILE)) {
            source = MockServices.agentJsonl().getBytes(StandardCharsets.UTF_8);
            path = ExternalArtifactTaskExecutor.TRACE_FILE;
        } else if (command.startsWith("dd if=" + ExternalArtifactTaskExecutor.PROBE_TRACE_FILE)) {
            source = MockServices.probeJsonl().getBytes(StandardCharsets.UTF_8);
            path = ExternalArtifactTaskExecutor.PROBE_TRACE_FILE;
        } else {
            return null;
        }
        int block = blockIndex(command);
        int from = Math.min(source.length,
                block * ExternalArtifactTaskExecutor.TRACE_READ_BLOCK_BYTES);
        int to = Math.min(source.length,
                from + ExternalArtifactTaskExecutor.TRACE_READ_BLOCK_BYTES);
        check(command.startsWith("dd if=" + path), "fixed trace path command");
        return Base64.getEncoder().encodeToString(Arrays.copyOfRange(source, from, to));
    }

    private static int blockIndex(String command) {
        int start = command.indexOf(" skip=");
        if (start < 0) throw new AssertionError("trace block command has no skip");
        start += " skip=".length();
        int end = start;
        while (end < command.length() && Character.isDigit(command.charAt(end))) end++;
        return Integer.parseInt(command.substring(start, end));
    }

    private static final class TraceFileRuntimeClient implements SandboxRuntimeClient {
        private final byte[] data;
        private int blockReads;
        private int malformedBlock = -1;
        private int shortBlock = -1;

        private TraceFileRuntimeClient(byte[] data) {
            this.data = data == null ? null : data.clone();
        }

        @Override
        public SandboxHandle create(SandboxRequest request) {
            throw new UnsupportedOperationException();
        }

        @Override
        public CommandResult command(String sandboxId, CommandRequest request) {
            String command = request.command();
            if (command.startsWith("wc -c < ")) {
                return data == null
                        ? new CommandResult(null, "", "missing", 1)
                        : new CommandResult(null, data.length + "\n", "", 0);
            }
            if (command.startsWith("if [ -f ")) {
                return new CommandResult(null, data == null ? "0\n" : data.length + "\n", "", 0);
            }
            if (!command.startsWith("dd if=") || data == null) {
                return new CommandResult(null, "", "unsupported", 1);
            }
            int block = blockIndex(command);
            blockReads++;
            if (block == malformedBlock) return new CommandResult(null, "%%%", "", 0);
            int from = Math.min(data.length,
                    block * ExternalArtifactTaskExecutor.TRACE_READ_BLOCK_BYTES);
            int to = Math.min(data.length,
                    from + ExternalArtifactTaskExecutor.TRACE_READ_BLOCK_BYTES);
            if (block == shortBlock && to > from) to--;
            return new CommandResult(null,
                    Base64.getEncoder().encodeToString(Arrays.copyOfRange(data, from, to)), "", 0);
        }

        @Override
        public void delete(String sandboxId) {
            throw new UnsupportedOperationException();
        }
    }

    private static final class TrustedRuntimeClient implements SandboxRuntimeClient {
        private final RuntimeAttestation attestation;
        private boolean created;

        private TrustedRuntimeClient(RuntimeAttestation attestation) {
            this.attestation = attestation;
        }

        @Override
        public SandboxHandle create(SandboxRequest request) {
            check(request.requiredCapability() == WorkerCapability.TRUSTED_DOCKER
                    && !request.fixtureOnly() && request.readOnlyArtifacts().size() == 1,
                    "trusted runtime request");
            created = true;
            return new SandboxHandle("trusted-sandbox-1",
                    new SandboxStatus(SandboxStatus.State.RUNNING, null, null), attestation);
        }

        @Override
        public CommandResult command(String sandboxId, CommandRequest request) {
            check(created && sandboxId.equals("trusted-sandbox-1"), "known trusted sandbox");
            String command = request.command();
            String stdout = traceReadOutput(command);
            return new CommandResult(null, stdout == null ? "" : stdout, "", 0);
        }

        @Override
        public void uploadFile(String sandboxId, java.nio.file.Path hostFile, String containerPath) {
            check(created && sandboxId.equals("trusted-sandbox-1"), "known trusted sandbox");
            check(containerPath.equals("/tmp/veyrion-trace/probe-plan.txt"), "probe plan upload path");
            check(java.nio.file.Files.isRegularFile(hostFile), "probe plan host file");
        }

        @Override
        public void delete(String sandboxId) {
            check(created && sandboxId.equals("trusted-sandbox-1"), "trusted sandbox cleanup");
            created = false;
        }
    }

    private static final class MockServices implements AutoCloseable {
        private final HttpServer server;
        private final ExecutorService executor = Executors.newCachedThreadPool();
        private final Map<String, TaskLifecycle> states = new LinkedHashMap<>();
        private final List<String> failedTasks = new ArrayList<>();
        private final String artifactDigest;
        private Map<String, Object> lastCreate;
        private Map<String, Object> lastCommand;
        private final List<String> commands = new ArrayList<>();
        private boolean failCommand;
        private int creates;
        private int deleted;

        private MockServices(String artifactDigest) throws IOException {
            this.artifactDigest = artifactDigest;
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", this::handle);
            server.setExecutor(executor);
        }

        void start() {
            server.start();
        }

        int port() {
            return server.getAddress().getPort();
        }

        private synchronized void handle(HttpExchange exchange) throws IOException {
            String path = exchange.getRequestURI().getPath();
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            if (path.startsWith("/internal/worker/v1/tasks/")) {
                handleWorker(exchange, path, body);
                return;
            }
            if (path.equals("/v1/sandboxes") && exchange.getRequestMethod().equals("POST")) {
                creates++;
                lastCreate = JsonCodec.parseObject(body);
                respond(exchange, 202, Map.of("id", "sandbox-1", "status", Map.of("state", "Running")));
            } else if (path.equals("/v1/sandboxes/sandbox-1/endpoints/44772")) {
                respond(exchange, 200, Map.of(
                        "endpoint", origin() + "/proxy/sandboxes/sandbox-1/port/44772",
                        "headers", Map.of()));
            } else if (path.equals("/proxy/sandboxes/sandbox-1/port/44772/command")) {
                Map<String, Object> command = JsonCodec.parseObject(body);
                String commandText = (String) command.get("command");
                commands.add(commandText);
                boolean artifactRun = commandText.contains(" -jar ")
                        || commandText.contains("/opt/veyrion/artifact/application.jar");
                if (artifactRun) lastCommand = command;
                String stdout = traceReadOutput(commandText);
                respond(exchange, 200, Map.of(
                        "id", "command-1", "stdout", stdout == null ? "" : stdout, "stderr", "",
                        "exit_code", failCommand && artifactRun ? 17 : 0));
            } else if (path.equals("/v1/sandboxes/sandbox-1")
                    && exchange.getRequestMethod().equals("DELETE")) {
                deleted++;
                respond(exchange, 204, null);
            } else {
                respond(exchange, 404, Map.of("code", "NOT_FOUND"));
            }
        }

        private void handleWorker(HttpExchange exchange, String path, String body) throws IOException {
            String suffix = path.substring("/internal/worker/v1/tasks/".length());
            String[] pieces = suffix.split("/");
            String taskId = pieces[0];
            TaskLifecycle state = states.computeIfAbsent(taskId, ignored -> TaskLifecycle.QUEUED);
            if (pieces.length == 1 && exchange.getRequestMethod().equals("GET")) {
                respond(exchange, 200, task(taskId, state));
                return;
            }
            String action = pieces[1];
            if (action.equals("lease")) {
                states.put(taskId, TaskLifecycle.LEASED);
                respond(exchange, 200, lease(taskId));
            } else if (action.equals("heartbeat")) {
                respond(exchange, 200, lease(taskId));
            } else if (action.equals("start")) {
                states.put(taskId, TaskLifecycle.RUNNING);
                respond(exchange, 200, task(taskId, TaskLifecycle.RUNNING));
            } else if (action.equals("trace")) {
                Map<String, Object> request = JsonCodec.parseObject(body);
                byte[] payload = java.util.Base64.getDecoder().decode((String) request.get("payloadBase64"));
                Map<String, Object> trace = new LinkedHashMap<>();
                trace.put("schemaVersion", 1);
                trace.put("workerContractVersion", 1);
                trace.put("projectId", "project-1");
                trace.put("artifactDigest", currentDigest());
                trace.put("scanId", "scan-1");
                trace.put("taskId", taskId);
                trace.put("sequence", request.get("sequence"));
                trace.put("previousDigest", null);
                trace.put("digest", request.get("digest"));
                trace.put("emittedAt", request.get("emittedAt"));
                trace.put("traceHeadDigest", request.get("digest"));
                trace.put("payloadBytes", payload.length);
                trace.put("totalPayloadBytes", payload.length);
                respond(exchange, 200, trace);
            } else if (action.equals("complete")) {
                states.put(taskId, TaskLifecycle.COMPLETED);
                respond(exchange, 200, task(taskId, TaskLifecycle.COMPLETED));
            } else if (action.equals("fail")) {
                states.put(taskId, TaskLifecycle.FAILED);
                failedTasks.add(taskId);
                respond(exchange, 200, task(taskId, TaskLifecycle.FAILED));
            } else {
                respond(exchange, 404, Map.of("code", "NOT_FOUND"));
            }
        }

        private Map<String, Object> task(String taskId, TaskLifecycle lifecycle) {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("schemaVersion", 1);
            result.put("workerContractVersion", 1);
            result.put("projectId", "project-1");
            result.put("artifactDigest", currentDigest());
            result.put("scanId", "scan-1");
            result.put("taskId", taskId);
            result.put("lifecycle", lifecycle.name());
            result.put("status", lifecycle.name());
            result.put("updatedAt", Instant.parse("2026-07-24T00:00:00Z").toString());
            result.put("targetEntryId", "entry-1");
            result.put("authorized", true);
            result.put("fixtureOnly", false);
            result.put("requiredCapability", capability(taskId).name());
            result.put("dynamicExecutionMode", capability(taskId) == WorkerCapability.STATIC_ONLY
                    ? "DYNAMIC_DISABLED" : capability(taskId).name()
                    + (lifecycle == TaskLifecycle.QUEUED ? "_QUEUED" : "_WORKER_MANAGED"));
            result.put("resourceBudget", Map.of(
                    "maxWallClockSeconds", 120,
                    "maxCpuMillis", 60_000,
                    "maxMemoryBytes", 256 * 1024 * 1024L,
                    "maxDiskBytes", 64 * 1024 * 1024L,
                    "maxTraceBytes", 1024 * 1024L));
            result.put("networkPolicy", Map.of("mode", "DENY", "allowlist", List.of()));
            boolean active = Set.of(TaskLifecycle.LEASED, TaskLifecycle.RUNNING, TaskLifecycle.PAUSED)
                    .contains(lifecycle);
            result.put("lease", active ? lease(taskId) : null);
            result.put("checkpoint", null);
            result.put("stopReason", lifecycle == TaskLifecycle.COMPLETED ? "COMPLETED"
                    : lifecycle == TaskLifecycle.FAILED ? "WORKER_FAILURE" : null);
            result.put("failureCode", lifecycle == TaskLifecycle.FAILED
                    ? "EXTERNAL_ARTIFACT_REJECTED" : null);
            return result;
        }

        private Map<String, Object> lease(String taskId) {
            return Map.ofEntries(
                    Map.entry("schemaVersion", 1),
                    Map.entry("workerContractVersion", 1),
                    Map.entry("projectId", "project-1"),
                    Map.entry("artifactDigest", currentDigest()),
                    Map.entry("scanId", "scan-1"),
                    Map.entry("taskId", taskId),
                    Map.entry("leaseId", "lease-" + taskId),
                    Map.entry("workerId", "worker-1"),
                    Map.entry("capability", capability(taskId).name()),
                    Map.entry("issuedAt", "2026-07-24T00:00:00Z"),
                    Map.entry("heartbeatAt", "2026-07-24T00:00:00Z"),
                    Map.entry("expiresAt", "2026-07-24T01:00:00Z"));
        }

        private static WorkerCapability capability(String taskId) {
            return taskId.equals("task-trusted-local")
                    ? WorkerCapability.TRUSTED_DOCKER : WorkerCapability.HARDENED_GVISOR;
        }

        @SuppressWarnings("unchecked")
        void assertSecureCreateAndCommand(String digest) {
            check(lastCreate != null && lastCommand != null, "sandbox calls observed");
            check(((Map<String, Object>) lastCreate.get("networkPolicy"))
                    .get("defaultAction").equals("deny"), "network deny");
            List<Map<String, Object>> mounts =
                    (List<Map<String, Object>>) lastCreate.get("readOnlyArtifacts");
            check(mounts.size() == 1
                    && mounts.get(0).get("sha256").equals(digest)
                    && mounts.get(0).get("sourceRef").equals("sha256:" + digest)
                    && !mounts.get(0).containsKey("sourceUri")
                    && Boolean.TRUE.equals(mounts.get(0).get("readOnly"))
                    && Boolean.TRUE.equals(mounts.get(0).get("verifyBeforeStart")),
                    "digest-pinned read-only artifact mount");
            check(lastCreate.containsKey("tmpfs") && !lastCreate.containsKey("volumes")
                    && !lastCreate.containsKey("env"), "controlled writable surface");
            String command = (String) lastCommand.get("command");
            check(command.contains("java -Dveyrion.sandbox.traceDir=/tmp/veyrion-trace")
                    && command.contains("-Dveyrion.sandbox.traceDir.authorized=true")
                    && command.contains("-Dveyrion.sandbox.dependencyMock=true")
                    && command.contains("dependencyMock=true")
                    && command.contains("-javaagent:/opt/veyrion/agent/veyrion-agent.jar")
                    && command.contains("-Djava.io.tmpdir=/tmp")
                    && command.contains("com.aq.jvmsentinel.agent.WaitHttpReady")
                    && command.contains("/tmp/veyrion-trace/http-port.stdout")
                    && command.contains("/tmp/veyrion-trace/wait-http-ready.err")
                    && command.contains("com.aq.jvmsentinel.agent.LoopbackHttpProbe --batch /tmp/veyrion-trace/probe-plan.txt \"$HTTP_PORT\"")
                    && command.contains("probe-plan.txt")
                    && command.contains("-Xmx64m")
                    && command.contains("probe selected http port")
                    && command.contains("invalid or dependency HTTP_PORT for probe")
                    && command.contains("-Dveyrion.loopbackProbe.port=\"$HTTP_PORT\"")
                    && !command.contains("probe preflight http-port.txt")
                    && !command.contains("od -An -tx1 /tmp/veyrion-trace/http-port.txt")
                    && command.contains("PROBE_JVM_OK=0")
                    && command.contains("probe_jvm_status=$?")
                    && command.contains("probe-status.txt")
                    && command.contains("probe_jvm_status=%s")
                    && !command.contains("LoopbackHttpProbe @/tmp/veyrion-trace/probe-plan.txt || true")
                    && !command.contains("--server.port=")
                    && command.contains("--spring.main.lazy-initialization=true")
                    && command.contains("jdbc:veyrion-mock:mem:veyrion")
                    && command.contains("--spring.datasource.hikari.initialization-fail-timeout=-1")
                    && command.contains("--spring.datasource.druid.initial-size=0")
                    && command.contains("--spring.flyway.enabled=false")
                    && command.contains("-Dorg.quartz.scheduler.instanceId=veyrion-sandbox")
                    && !command.contains("-Dorg.quartz.scheduler.instanceId=AUTO")
                    && command.contains("--spring.quartz.auto-startup=false")
                    && command.contains("--spring.quartz.job-store-type=memory")
                    && command.contains("probe_status=1")
                    && command.contains("[ \"$elapsed\" -lt 90 ]")
                    && !command.contains("[ \"$elapsed\" -lt 105 ]")
                    && !command.contains("[ \"$elapsed\" -lt 120 ]")
                    && !command.contains("while kill -0 \"$APP_PID\" 2>/dev/null && [ \"$probe_status\" -ne 0 ]")
                    && command.contains("exit 70")
                    && command.contains("exit 71")
                    && command.contains("保留应用进程供 PATH/TRIAGE 复用")
                    && !command.contains("探测完成，停止应用进程")
                    && command.contains("kill -TERM \"$APP_PID\"")
                    && command.contains("kill -KILL \"$APP_PID\""),
                    "fixed command with process listen-port discovery");
            check(((Number) lastCommand.get("uid")).intValue() == 0
                    && ((Number) lastCommand.get("gid")).intValue() == 0
                    && !lastCommand.containsKey("envs"), "container-root command without environment");
        }

        void assertRetainedProbeReused() {
            check(commands.stream().anyMatch(command ->
                            command.startsWith("rm -f " + ExternalArtifactTaskExecutor.PROBE_TRACE_FILE)
                                    && command.contains("复用已启动应用，准备本轮探针")),
                    "retained probe prepares trace files in existing sandbox");
            check(commands.stream().anyMatch(command ->
                            command.contains("com.aq.jvmsentinel.agent.LoopbackHttpProbe --batch "
                                    + ExternalArtifactTaskExecutor.TRACE_DIRECTORY
                                    + "/probe-plan.txt \"$HTTP_PORT\"")
                                    && command.contains("HTTP_PORT=8080")
                                    && !command.contains(" -jar ")),
                    "retained probe runs loopback batch without restarting the artifact");
            check(commands.stream().filter(command ->
                            command.contains("/opt/veyrion/artifact/application.jar")).count() == 1,
                    "artifact jar is started only once for retained probe sequence");
        }

        private String currentDigest() {
            return artifactDigest;
        }

        private String origin() {
            return "http://127.0.0.1:" + port();
        }

        private static String agentJsonl() {
            return "{\"schemaVersion\":1,\"sequence\":0,\"eventType\":\"AGENT_STARTED\","
                    + "\"provenanceKind\":\"RUNTIME_OBSERVED\","
                    + "\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"com.aq.jvmsentinel.instrumentation.VeyrionAgent\","
                    + "\"method\":\"premain\",\"timestamp\":\"2026-07-24T00:00:00Z\","
                    + "\"thread\":\"main\",\"detail\":{\"captureMode\":\"test\"}}\n";
        }

        static String probeJsonl() {
            return "{\"schemaVersion\":1,\"sequence\":0,\"eventType\":\"HTTP\","
                    + "\"provenanceKind\":\"APPLICATION_REPORTED\","
                    + "\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"com.aq.jvmsentinel.agent.LoopbackHttpProbe\","
                    + "\"method\":\"main\",\"timestamp\":\"2026-07-24T00:00:00Z\","
                    + "\"thread\":\"main\",\"detail\":{\"captureMode\":\"LOOPBACK_HTTP_PROBE\","
                    + "\"httpMethod\":\"POST\",\"route\":\"/sample/http-entry\","
                    + "\"requestTarget\":\"/sample/http-entry\",\"status\":\"200\","
                    + "\"port\":\"8080\",\"error\":\"\",\"outcomeClass\":\"HTTP_OBSERVED\","
                    + "\"track\":\"UNAUTH\"}}\n";
        }

        private static void respond(HttpExchange exchange, int status, Object value) throws IOException {
            byte[] bytes = value == null ? new byte[0]
                    : JsonCodec.stringify(value).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, status == 204 ? -1 : bytes.length);
            if (status != 204) exchange.getResponseBody().write(bytes);
            exchange.close();
        }

        @Override
        public void close() {
            server.stop(0);
            executor.shutdownNow();
        }
    }

}
