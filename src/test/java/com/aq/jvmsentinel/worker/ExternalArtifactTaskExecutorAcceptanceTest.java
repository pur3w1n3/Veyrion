package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.sandbox.OpenSandboxClient;
import com.aq.jvmsentinel.sandbox.OpenSandboxConfig;
import com.aq.jvmsentinel.sandbox.RuntimeAttestation;
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
            "non-root-v1", "read-only-rootfs-v1", "writable-tmp-v1",
            "controlled-tmpfs-v1", "digest-pinned-readonly-artifact-v1");

    private ExternalArtifactTaskExecutorAcceptanceTest() { }

    public static void main(String[] args) throws Exception {
        Path directory = Files.createTempDirectory("veyrion-external-acceptance-");
        Path jar = directory.resolve("application.jar");
        createJar(jar, "original");
        byte[] original = Files.readAllBytes(jar);
        String digest = sha256(original);

        MockServices mock = new MockServices(digest);
        mock.start();
        try {
            ExternalArtifactTaskExecutor.ArtifactRegistration registration =
                    new ExternalArtifactTaskExecutor.ArtifactRegistration(
                            "project-1", digest, jar, Files.size(jar), true);
            ExternalArtifactTaskExecutor executor = executor(mock, scope(digest, "task-success"), registration);
            ExternalArtifactTaskExecutor.ExecutionResult result =
                    executor.execute(new ExternalArtifactTaskExecutor.ExecutionRequest(
                            scope(digest, "task-success")));
            check(result.lifecycle() == TaskLifecycle.COMPLETED
                    && result.executedDigest().equals(digest)
                    && result.traceChunks() == 1, "successful execution");
            mock.assertSecureCreateAndCommand(digest);
            check(mock.deleted == 1, "successful sandbox cleanup");

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

            ExternalArtifactTaskExecutor fixture = executor(
                    mock, scope(digest, "task-fixture"), registration);
            int createsBeforeFixture = mock.creates;
            expect(SecurityException.class, () -> fixture.execute(
                    new ExternalArtifactTaskExecutor.ExecutionRequest(scope(digest, "task-fixture"))),
                    "fixture task rejection");
            check(mock.creates == createsBeforeFixture, "fixture task must not create external sandbox");

            expect(IllegalArgumentException.class,
                    () -> new ExternalArtifactTaskExecutor.RuntimePolicy("runtime:latest", releaseDecision()),
                    "unpinned runtime image");
            System.out.println("ExternalArtifactTaskExecutorAcceptanceTest: PASS");
        } finally {
            mock.close();
            Files.deleteIfExists(jar);
            Files.deleteIfExists(directory);
        }
    }

    private static ExternalArtifactTaskExecutor executor(
            MockServices mock, TaskScope scope,
            ExternalArtifactTaskExecutor.ArtifactRegistration registration) {
        URI origin = URI.create("http://127.0.0.1:" + mock.port() + "/");
        WorkerControlPlaneClient control = new WorkerControlPlaneClient(
                origin.resolve("internal/worker/v1/"), "worker-token", Duration.ofSeconds(5));
        RuntimeAttestation attestation = new RuntimeAttestation(
                "0.1.0", WorkerCapability.HARDENED_GVISOR, "runsc-gvisor",
                true, true, true, Set.of(FEATURES.split(",")));
        OpenSandboxClient sandbox = new OpenSandboxClient(new OpenSandboxConfig(
                origin.resolve("v1/"), "sandbox-key", "execd-token",
                Duration.ofSeconds(5), "0.1.0", attestation));
        return new ExternalArtifactTaskExecutor(control, sandbox, requested -> {
            check(requested.equals(scope), "catalog scope");
            return registration;
        }, new ExternalArtifactTaskExecutor.RuntimePolicy(IMAGE, releaseDecision()), "worker-1");
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
        try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(path))) {
            output.putNextEntry(new ZipEntry("BOOT-INF/classes/example.txt"));
            output.write(value.getBytes(StandardCharsets.UTF_8));
            output.closeEntry();
        }
    }

    private static String sha256(byte[] value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
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

    private static final class MockServices implements AutoCloseable {
        private final HttpServer server;
        private final ExecutorService executor = Executors.newCachedThreadPool();
        private final Map<String, TaskLifecycle> states = new LinkedHashMap<>();
        private final List<String> failedTasks = new ArrayList<>();
        private final String artifactDigest;
        private Map<String, Object> lastCreate;
        private Map<String, Object> lastCommand;
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
                if (commandText.startsWith("java ")) lastCommand = command;
                String stdout = commandText.equals("/bin/cat /tmp/veyrion-trace/agent-events.jsonl")
                        ? agentJsonl() : "";
                respond(exchange, 200, Map.of(
                        "id", "command-1", "stdout", stdout, "stderr", "",
                        "exit_code", failCommand && commandText.startsWith("java ") ? 17 : 0));
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
            boolean fixture = taskId.equals("task-fixture");
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
            result.put("fixtureOnly", fixture);
            result.put("requiredCapability", "HARDENED_GVISOR");
            result.put("dynamicExecutionMode", "DYNAMIC_DISABLED");
            result.put("fixtureId", null);
            result.put("imageUri", null);
            result.put("mainClass", null);
            result.put("fixtureDigest", null);
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
                    Map.entry("capability", "HARDENED_GVISOR"),
                    Map.entry("issuedAt", "2026-07-24T00:00:00Z"),
                    Map.entry("heartbeatAt", "2026-07-24T00:00:00Z"),
                    Map.entry("expiresAt", "2026-07-24T01:00:00Z"));
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
            check(lastCommand.get("command").equals(
                    "java -Dveyrion.sandbox.traceDir=/tmp/veyrion-trace"
                            + " -Dveyrion.sandbox.traceDir.authorized=true"
                            + " -javaagent:/opt/veyrion/agent/veyrion-agent.jar"
                            + "=maxBytes=1048576,maxEvents=4096"
                            + " -jar /opt/veyrion/artifact/application.jar"), "fixed command");
            check(((Number) lastCommand.get("uid")).intValue() == 10000
                    && ((Number) lastCommand.get("gid")).intValue() == 10000
                    && !lastCommand.containsKey("envs"), "non-root command without environment");
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
