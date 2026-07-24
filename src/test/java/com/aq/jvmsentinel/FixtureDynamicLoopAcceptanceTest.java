package com.aq.jvmsentinel;

import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.fixture.TrustedFixtureCatalog;
import com.aq.jvmsentinel.sandbox.OpenSandboxClient;
import com.aq.jvmsentinel.sandbox.OpenSandboxConfig;
import com.aq.jvmsentinel.sandbox.RuntimeAttestation;
import com.aq.jvmsentinel.worker.AgentJsonlTraceConverter;
import com.aq.jvmsentinel.worker.FixtureTaskExecutor;
import com.aq.jvmsentinel.worker.NetworkPolicy;
import com.aq.jvmsentinel.worker.ResourceBudget;
import com.aq.jvmsentinel.worker.TaskLifecycle;
import com.aq.jvmsentinel.worker.TaskScope;
import com.aq.jvmsentinel.worker.WorkerCapability;
import com.aq.jvmsentinel.worker.WorkerControlPlaneClient;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** End-to-end acceptance checks for one catalog-owned fixture execution. */
public final class FixtureDynamicLoopAcceptanceTest {
    private static final String API_KEY = "trusted-opensandbox-api-key";
    private static final String EXECD_TOKEN = "trusted-execd-token";
    private static final String WORKER_ID = "fixture-worker-1";
    private static final String VALID_AGENT_JSONL =
            "{\"schemaVersion\":1,\"sequence\":0,\"eventType\":\"AGENT_STARTED\","
                    + "\"provenanceKind\":\"RUNTIME_OBSERVED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"\",\"method\":\"premain\",\"timestamp\":\"2026-07-24T00:00:00Z\","
                    + "\"thread\":\"main\",\"detail\":{\"mode\":\"fixture\"}}\n"
                    + "{\"schemaVersion\":1,\"sequence\":1,\"eventType\":\"HTTP\","
                    + "\"provenanceKind\":\"APPLICATION_REPORTED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"fixture.HttpEntry\",\"method\":\"handle\",\"timestamp\":\"2026-07-24T00:00:01Z\","
                    + "\"thread\":\"main\",\"detail\":{\"path\":\"/fixture\"}}\n";

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("fixture-dynamic-loop");
        Path artifact = root.resolve("FixtureController.class");
        Files.writeString(artifact, "intentionally malformed metadata-only fixture descriptor");
        try (ControlPlaneServer controlPlane = new ControlPlaneServer(root, 0, "gui-token").start();
             MockOpenSandbox openSandbox = new MockOpenSandbox()) {
            openSandbox.start();
            HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
            ScanContext scan = createScan(http, controlPlane, artifact);
            URI workerBase = URI.create("http://" + controlPlane.address().getHostString() + ":"
                    + controlPlane.address().getPort() + "/internal/worker/v1/");
            WorkerControlPlaneClient worker = new WorkerControlPlaneClient(
                    workerBase, controlPlane.workerToken(), Duration.ofSeconds(3));
            OpenSandboxClient sandbox = sandboxClient(openSandbox);
            AgentJsonlTraceConverter converter = new AgentJsonlTraceConverter(
                    Clock.systemUTC(), 1024 * 1024, 64 * 1024, 10_000, 256 * 1024);
            FixtureTaskExecutor executor = new FixtureTaskExecutor(worker, sandbox, converter, WORKER_ID);

            check(guiPost(http, URI.create(controlPlane.baseUri() + "/scans/" + scan.scanId()
                            + "/dynamic-tasks"),
                    "{\"authorized\":true,\"fixtureId\":\"" + TrustedFixtureCatalog.HTTP_ENTRY_SMOKE_V1
                            + "\",\"command\":\"host-command\"}",
                    controlPlane.mutationToken(), "runtime-field-injection").statusCode() == 400,
                    "public command/path injection must be rejected");

            PublicTask success = createDynamicTask(http, controlPlane, scan, "dynamic-success");
            openSandbox.mode(Mode.SUCCESS);
            FixtureTaskExecutor.ExecutionResult result = executor.execute(success.request());
            check(result.lifecycle() == TaskLifecycle.COMPLETED && result.traceChunks() > 0,
                    "fixture execution completes with trace");
            Map<String, Object> completed = workerTask(http, workerBase, controlPlane.workerToken(), success.scope());
            check("COMPLETED".equals(completed.get("lifecycle")), "task reaches COMPLETED");
            check(controlPlane.sseHub().history(scan.scanId()).stream().anyMatch(event ->
                    "TraceCommitted".equals(event.eventType())
                            && success.scope().taskId().equals(event.context().taskId())),
                    "trace chain is published to SSE");
            check(controlPlane.sseHub().history(scan.scanId()).stream().anyMatch(event ->
                    "TaskStopped".equals(event.eventType())
                            && success.scope().taskId().equals(event.context().taskId())
                            && event.payload().contains("\"verificationStatus\":\"DYNAMIC_SUSPECTED\"")),
                    "terminal SSE remains DYNAMIC_SUSPECTED");
            assertPublicProjection(http, controlPlane, scan, success.scope());
            openSandbox.assertSuccessfulPolicy();

            int createsBeforePolicyRejects = openSandbox.createCount();
            try (MissingRuntimeWorker wrongCapability =
                         new MissingRuntimeWorker(success.scope(), true, true, WorkerCapability.STATIC_ONLY)) {
                wrongCapability.start();
                FixtureTaskExecutor rejected = isolatedExecutor(wrongCapability, sandbox, converter);
                expect(IllegalArgumentException.class, () -> rejected.execute(success.request()), "wrong capability");
                check(!wrongCapability.mutationObserved(), "wrong capability must be rejected before lease");
            }
            try (MissingRuntimeWorker notFixture =
                         new MissingRuntimeWorker(success.scope(), true, false, WorkerCapability.FIXTURE_RUNC)) {
                notFixture.start();
                FixtureTaskExecutor rejected = isolatedExecutor(notFixture, sandbox, converter);
                expect(IllegalArgumentException.class, () -> rejected.execute(success.request()), "fixtureOnly false");
                check(!notFixture.mutationObserved(), "fixtureOnly false must be rejected before lease");
            }
            check(openSandbox.createCount() == createsBeforePolicyRejects,
                    "policy rejection must not reach OpenSandbox");

            PublicTask sandboxFailure = createDynamicTask(http, controlPlane, scan, "dynamic-sandbox-failure");
            int commandsBeforeSandboxFailure = openSandbox.commandCount();
            openSandbox.mode(Mode.CREATE_FAILURE);
            expect(RuntimeException.class, () -> executor.execute(sandboxFailure.request()), "OpenSandbox failure");
            check("FAILED".equals(workerTask(http, workerBase, controlPlane.workerToken(),
                    sandboxFailure.scope()).get("lifecycle")), "OpenSandbox failure marks task failed");
            check(openSandbox.commandCount() == commandsBeforeSandboxFailure,
                    "OpenSandbox failure cannot complete a command");

            PublicTask malformedTrace = createDynamicTask(http, controlPlane, scan, "dynamic-malformed-trace");
            openSandbox.mode(Mode.MALFORMED_TRACE);
            expect(IllegalArgumentException.class, () -> executor.execute(malformedTrace.request()),
                    "malformed Agent JSONL");
            check("FAILED".equals(workerTask(http, workerBase, controlPlane.workerToken(),
                    malformedTrace.scope()).get("lifecycle")), "malformed trace marks task failed");

            try (MissingRuntimeWorker missing =
                         new MissingRuntimeWorker(success.scope(), false, true, WorkerCapability.FIXTURE_RUNC)) {
                missing.start();
                FixtureTaskExecutor missingExecutor = isolatedExecutor(missing, sandbox, converter);
                expect(SecurityException.class, () -> missingExecutor.execute(success.request()),
                        "missing runtime fields");
                check(!missing.mutationObserved(), "missing runtime fields must not lease or complete");
            }

            check(System.getProperty("veyrion.fixture.host.executed") == null,
                    "fixture must never execute in the host JVM");
            System.out.println("FixtureDynamicLoopAcceptanceTest: PASS");
        }
    }

    private static ScanContext createScan(HttpClient http, ControlPlaneServer server, Path artifact)
            throws Exception {
        Map<String, Object> project = json(guiPost(http, URI.create(server.baseUri() + "/projects"),
                "{\"name\":\"fixture-dynamic-loop\"}", server.mutationToken(), "fixture-project"));
        String projectId = text(project, "projectId");
        Map<String, Object> registered = json(guiPost(http,
                URI.create(server.baseUri() + "/projects/" + projectId + "/artifacts"),
                "{\"path\":\"" + escape(artifact.toString()) + "\"}",
                server.mutationToken(), "fixture-artifact"));
        String digest = text(registered, "artifactDigest");
        Map<String, Object> scan = json(guiPost(http,
                URI.create(server.baseUri() + "/projects/" + projectId + "/scans"),
                "{\"artifactDigest\":\"" + digest + "\",\"authorized\":true}",
                server.mutationToken(), "fixture-scan"));
        return new ScanContext(projectId, digest, text(scan, "scanId"));
    }

    private static PublicTask createDynamicTask(HttpClient http, ControlPlaneServer server,
                                                 ScanContext scan, String key) throws Exception {
        Map<String, Object> body = json(guiPost(http,
                URI.create(server.baseUri() + "/scans/" + scan.scanId() + "/dynamic-tasks"),
                "{\"authorized\":true,\"fixtureId\":\"" + TrustedFixtureCatalog.HTTP_ENTRY_SMOKE_V1 + "\"}",
                server.mutationToken(), key));
        TaskScope scope = new TaskScope(text(body, "projectId"), text(body, "artifactDigest"),
                text(body, "scanId"), text(body, "taskId"));
        ResourceBudget budget = new ResourceBudget(number(body, "maxWallClockSeconds"),
                number(body, "maxCpuMillis"), number(body, "maxMemoryBytes"),
                number(body, "maxDiskBytes"), number(body, "maxTraceBytes"));
        check(Boolean.TRUE.equals(body.get("fixtureOnly"))
                        && "FIXTURE_RUNC".equals(body.get("requiredCapability"))
                        && "DENY".equals(body.get("networkMode"))
                        && ((List<?>) body.get("networkAllowlist")).isEmpty(),
                "public task policy");
        return new PublicTask(scope, new FixtureTaskExecutor.ExecutionRequest(scope));
    }

    private static void assertPublicProjection(HttpClient http, ControlPlaneServer server,
                                               ScanContext scan, TaskScope scope) throws Exception {
        Map<String, Object> dashboard = json(http.send(HttpRequest.newBuilder(
                        URI.create(server.baseUri() + "/projects/" + scan.projectId() + "/dashboard"))
                .GET().build(), HttpResponse.BodyHandlers.ofString()));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> paths = (List<Map<String, Object>>) (List<?>) dashboard.get("paths");
        check(paths.size() >= 2, "static and dynamic paths are both retained");
        Map<String, Object> staticPath = paths.stream()
                .filter(path -> !path.containsKey("taskId")).findFirst().orElseThrow();
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> staticSteps =
                (List<Map<String, Object>>) (List<?>) staticPath.get("steps");
        check(staticSteps.stream().allMatch(step -> "INFERENCE".equals(step.get("provenanceKind"))
                        && !step.containsKey("sequence")),
                "static path remains compatible with the strict GUI provenance contract");
        Map<String, Object> dynamic = paths.stream()
                .filter(path -> scope.taskId().equals(path.get("taskId"))).findFirst().orElseThrow();
        check("DYNAMIC_SUSPECTED".equals(dynamic.get("verificationStatus"))
                        && Boolean.TRUE.equals(dynamic.get("fixtureOnly"))
                        && "FIXTURE_RUNC".equals(dynamic.get("requiredCapability"))
                        && "FIXTURE_RUNC_COMPLETED".equals(dynamic.get("dynamicExecutionMode"))
                        && "COMPLETED".equals(dynamic.get("stopReason")),
                "dynamic public path fields");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> steps = (List<Map<String, Object>>) (List<?>) dynamic.get("steps");
        check(steps.stream().allMatch(step -> "DYNAMIC_SUSPECTED".equals(step.get("verificationStatus"))
                        && step.get("eventType") instanceof String
                        && step.get("sequence") instanceof Number
                        && step.get("evidenceRefs") instanceof List<?> refs && !refs.isEmpty()),
                "dynamic step provenance fields");
        check(steps.stream().anyMatch(step -> "RUNTIME_OBSERVED".equals(step.get("provenanceKind")))
                        && steps.stream().anyMatch(step -> "APPLICATION_REPORTED".equals(step.get("provenanceKind"))),
                "both Agent provenance kinds are public");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> flattened = (List<Map<String, Object>>) (List<?>) dashboard.get("path");
        check(flattened.equals(steps), "flattened dashboard path prefers latest dynamic path");
        String evidenceId = (String) ((List<?>) steps.get(0).get("evidenceRefs")).get(0);
        Map<String, Object> evidence = json(http.send(HttpRequest.newBuilder(
                        URI.create(server.baseUri() + "/evidence/" + evidenceId)).GET().build(),
                HttpResponse.BodyHandlers.ofString()));
        check("veyrion-agent".equals(evidence.get("source"))
                        && "DYNAMIC_SUSPECTED".equals(evidence.get("verificationStatus"))
                        && ((String) evidence.get("snapshotRef")).contains("task:" + scope.taskId())
                        && ((String) evidence.get("snapshotRef")).contains("digest:")
                        && ((String) evidence.get("snapshotRef")).contains("sequence:")
                        && ((String) evidence.get("summary")).contains("veyrion-agent"),
                "dynamic evidence endpoint and summary binding");
        check(!dashboard.toString().contains("VERIFIED"), "dynamic projection never emits VERIFIED");
    }

    private static FixtureTaskExecutor isolatedExecutor(MissingRuntimeWorker source,
                                                        OpenSandboxClient sandbox,
                                                        AgentJsonlTraceConverter converter) {
        WorkerControlPlaneClient client = new WorkerControlPlaneClient(
                source.baseUri(), "isolated-worker-token", Duration.ofSeconds(2));
        return new FixtureTaskExecutor(client, sandbox, converter, WORKER_ID);
    }

    private static OpenSandboxClient sandboxClient(MockOpenSandbox mock) {
        RuntimeAttestation attestation = new RuntimeAttestation(
                "0.1.0", WorkerCapability.FIXTURE_RUNC, "runc", true, true, true,
                Set.of("lifecycle-v1", "execd-command-v1", "network-deny-v1",
                        "resource-budget-v1", "non-root-v1", "read-only-rootfs-v1"));
        return new OpenSandboxClient(new OpenSandboxConfig(
                mock.baseUri().resolve("v1/"), API_KEY, EXECD_TOKEN,
                Duration.ofSeconds(2), "0.1.0", attestation));
    }

    private static Map<String, Object> workerTask(HttpClient http, URI workerBase,
                                                   String token, TaskScope scope) throws Exception {
        String query = "projectId=" + scope.projectId() + "&artifactDigest=" + scope.artifactDigest()
                + "&scanId=" + scope.scanId();
        HttpRequest request = HttpRequest.newBuilder(
                        URI.create(workerBase + "tasks/" + scope.taskId() + "?" + query))
                .header("X-Sentinel-Worker-Authorization", token).GET().build();
        return json(http.send(request, HttpResponse.BodyHandlers.ofString()));
    }

    private static HttpResponse<String> guiPost(HttpClient http, URI uri, String body,
                                                 String token, String key) throws Exception {
        return http.send(HttpRequest.newBuilder(uri)
                        .header("Content-Type", "application/json")
                        .header("X-Sentinel-Authorization", token)
                        .header("Idempotency-Key", key)
                        .POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static Map<String, Object> json(HttpResponse<String> response) {
        check(response.statusCode() >= 200 && response.statusCode() < 300,
                "unexpected HTTP " + response.statusCode() + ": " + response.body());
        return JsonCodec.parseObject(response.body());
    }

    private static String text(Map<String, Object> body, String key) {
        Object value = body.get(key);
        if (!(value instanceof String text)) throw new AssertionError(key + " missing");
        return text;
    }

    private static long number(Map<String, Object> body, String key) {
        Object value = body.get(key);
        if (!(value instanceof Number number)) throw new AssertionError(key + " missing");
        return number.longValue();
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static <T extends Throwable> T expect(Class<T> type, ThrowingRunnable runnable, String message)
            throws Exception {
        try {
            runnable.run();
        } catch (Throwable actual) {
            if (type.isInstance(actual)) return type.cast(actual);
            throw actual;
        }
        throw new AssertionError("expected " + type.getSimpleName() + ": " + message);
    }

    @FunctionalInterface
    private interface ThrowingRunnable { void run() throws Exception; }

    private enum Mode { SUCCESS, CREATE_FAILURE, MALFORMED_TRACE }
    private record ScanContext(String projectId, String digest, String scanId) { }
    private record PublicTask(TaskScope scope, FixtureTaskExecutor.ExecutionRequest request) { }
    private record Observed(String method, String path, String lifecycleKey, String execdToken,
                            String body) { }

    private static final class MockOpenSandbox implements AutoCloseable {
        private final HttpServer server;
        private final ExecutorService executor = Executors.newCachedThreadPool();
        private final List<Observed> observed = new ArrayList<>();
        private final Map<String, Mode> sandboxModes = new LinkedHashMap<>();
        private volatile Mode nextMode = Mode.SUCCESS;
        private int nextId;

        private MockOpenSandbox() throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", this::handle);
            server.setExecutor(executor);
        }

        void start() { server.start(); }
        URI baseUri() { return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/"); }
        void mode(Mode mode) { nextMode = mode; }

        private synchronized void handle(HttpExchange exchange) throws IOException {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String path = exchange.getRequestURI().getPath();
            observed.add(new Observed(exchange.getRequestMethod(), path,
                    exchange.getRequestHeaders().getFirst("OPEN-SANDBOX-API-KEY"),
                    exchange.getRequestHeaders().getFirst("X-EXECD-ACCESS-TOKEN"), body));
            if (path.equals("/v1/sandboxes") && exchange.getRequestMethod().equals("POST")) {
                if (nextMode == Mode.CREATE_FAILURE) {
                    respond(exchange, 503, "{\"code\":\"UNAVAILABLE\"}");
                    return;
                }
                String id = "fixture-sandbox-" + (++nextId);
                sandboxModes.put(id, nextMode);
                respond(exchange, 202, handle(id));
                return;
            }
            String id = sandboxId(path);
            if (id != null && path.equals("/v1/sandboxes/" + id + "/endpoints/44772")) {
                respond(exchange, 200, JsonCodec.stringify(Map.of(
                        "endpoint", baseUri() + "proxy/sandboxes/" + id + "/port/44772",
                        "headers", Map.of())));
            } else if (id != null && path.equals("/v1/sandboxes/" + id)
                    && exchange.getRequestMethod().equals("DELETE")) {
                respond(exchange, 204, "");
            } else if (id != null && path.equals("/proxy/sandboxes/" + id + "/port/44772/command")) {
                Map<String, Object> command = JsonCodec.parseObject(body);
                String text = (String) command.get("command");
                String stdout = text.startsWith("/bin/cat ")
                        ? (sandboxModes.get(id) == Mode.MALFORMED_TRACE
                        ? "{\"schemaVersion\":1,\"sequence\":0,\"verificationStatus\":\"VERIFIED\"}\n"
                        : VALID_AGENT_JSONL)
                        : "";
                respond(exchange, 200, JsonCodec.stringify(Map.of(
                        "id", "command-" + id, "stdout", stdout, "stderr", "", "exit_code", 0)));
            } else {
                respond(exchange, 404, "{\"code\":\"NOT_FOUND\"}");
            }
        }

        private static String sandboxId(String path) {
            String marker = "/sandboxes/";
            int start = path.indexOf(marker);
            if (start < 0) return null;
            start += marker.length();
            int end = path.indexOf('/', start);
            return end < 0 ? path.substring(start) : path.substring(start, end);
        }

        private static String handle(String id) {
            return JsonCodec.stringify(Map.of("id", id, "status", Map.of("state", "Running")));
        }

        private static void respond(HttpExchange exchange, int status, String body) throws IOException {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, status == 204 ? -1 : bytes.length);
            if (status != 204) exchange.getResponseBody().write(bytes);
            exchange.close();
        }

        synchronized int createCount() {
            return (int) observed.stream().filter(value ->
                    value.path().equals("/v1/sandboxes") && value.method().equals("POST")).count();
        }

        synchronized int commandCount() {
            return (int) observed.stream().filter(value -> value.path().endsWith("/command")).count();
        }

        synchronized void assertSuccessfulPolicy() {
            Observed create = observed.stream().filter(value -> value.path().equals("/v1/sandboxes")
                    && value.method().equals("POST")).findFirst().orElseThrow();
            Map<String, Object> request = JsonCodec.parseObject(create.body());
            @SuppressWarnings("unchecked")
            Map<String, Object> network = (Map<String, Object>) request.get("networkPolicy");
            @SuppressWarnings("unchecked")
            Map<String, Object> extensions = (Map<String, Object>) request.get("extensions");
            check("deny".equals(network.get("defaultAction")), "sandbox network deny");
            check("true".equals(extensions.get("veyrion.nonRoot")), "sandbox non-root");
            check("true".equals(extensions.get("veyrion.readOnlyRootFilesystem")), "read-only root");
            check(request.containsKey("resourceLimits"), "sandbox resource limits");
            check(!request.containsKey("volumes") && !request.containsKey("env"), "no host paths or environment");

            List<Observed> commands = observed.stream().filter(value -> value.path().endsWith("/command")).toList();
            check(commands.size() >= 2, "run and trace-read commands");
            Map<String, Object> run = JsonCodec.parseObject(commands.get(0).body());
            String command = (String) run.get("command");
            check(command.contains("-Dveyrion.sandbox.traceDir=/sandbox/trace")
                            && command.contains("-Dveyrion.sandbox.traceDir.authorized=true")
                            && command.contains("-javaagent:/opt/veyrion/agent/veyrion-agent.jar")
                            && command.endsWith("'com.aq.jvmsentinel.fixture.HttpEntryFixture'"),
                    "trusted fixture command template");
            check(!command.contains("host-command"), "frontend command cannot reach sandbox");
            check(((Number) run.get("uid")).intValue() > 0
                            && ((Number) run.get("gid")).intValue() > 0,
                    "execd command is non-root");
            Map<String, Object> read = JsonCodec.parseObject(commands.get(1).body());
            check("/bin/cat /sandbox/trace/agent-events.jsonl".equals(read.get("command")),
                    "fixed trace read command");
            for (Observed value : observed) {
                check(!value.body().contains(API_KEY) && !value.body().contains(EXECD_TOKEN),
                        "trusted secrets never enter request bodies");
                if (value.path().startsWith("/v1/")) {
                    check(API_KEY.equals(value.lifecycleKey()), "lifecycle uses trusted API key");
                }
                if (value.path().startsWith("/proxy/")) {
                    check(EXECD_TOKEN.equals(value.execdToken()), "execd uses trusted token");
                }
            }
        }

        @Override public void close() {
            server.stop(0);
            executor.shutdownNow();
        }
    }

    private static final class MissingRuntimeWorker implements AutoCloseable {
        private final HttpServer server;
        private final ExecutorService executor = Executors.newSingleThreadExecutor();
        private final TaskScope scope;
        private final boolean includeRuntime;
        private final boolean fixtureOnly;
        private final WorkerCapability capability;
        private volatile boolean mutationObserved;

        private MissingRuntimeWorker(TaskScope scope, boolean includeRuntime, boolean fixtureOnly,
                                     WorkerCapability capability) throws IOException {
            this.scope = scope;
            this.includeRuntime = includeRuntime;
            this.fixtureOnly = fixtureOnly;
            this.capability = capability;
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", this::handle);
            server.setExecutor(executor);
        }

        void start() { server.start(); }
        URI baseUri() {
            return URI.create("http://127.0.0.1:" + server.getAddress().getPort()
                    + "/internal/worker/v1/");
        }
        boolean mutationObserved() { return mutationObserved; }

        private void handle(HttpExchange exchange) throws IOException {
            if (!exchange.getRequestMethod().equals("GET")) mutationObserved = true;
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("schemaVersion", 1);
            body.put("workerContractVersion", 1);
            body.put("projectId", scope.projectId());
            body.put("artifactDigest", scope.artifactDigest());
            body.put("scanId", scope.scanId());
            body.put("taskId", scope.taskId());
            body.put("lifecycle", "QUEUED");
            body.put("status", "QUEUED");
            body.put("updatedAt", Instant.now().toString());
            body.put("targetEntryId", "entry-1");
            body.put("authorized", true);
            body.put("fixtureOnly", fixtureOnly);
            body.put("requiredCapability", capability.name());
            body.put("resourceBudget", Map.of(
                    "maxWallClockSeconds", 60, "maxCpuMillis", 30_000,
                    "maxMemoryBytes", 128L * 1024 * 1024, "maxDiskBytes", 64L * 1024 * 1024,
                    "maxTraceBytes", 2L * 1024 * 1024));
            body.put("networkPolicy", Map.of("mode", "DENY", "allowlist", List.of()));
            body.put("dynamicExecutionMode", capability == WorkerCapability.FIXTURE_RUNC
                    ? "FIXTURE_RUNC_QUEUED" : "DYNAMIC_DISABLED");
            if (includeRuntime) {
                body.put("fixtureId", TrustedFixtureCatalog.HTTP_ENTRY_SMOKE_V1);
                body.put("imageUri", "registry.invalid/veyrion/fixture-http-entry@sha256:"
                        + "7bb52f8ad62998aabb45d0f797cb93f22b3e8619f8737d2a65dfc750956f729d");
                body.put("mainClass", "com.aq.jvmsentinel.fixture.HttpEntryFixture");
                body.put("fixtureDigest",
                        "7bb52f8ad62998aabb45d0f797cb93f22b3e8619f8737d2a65dfc750956f729d");
            }
            body.put("lease", null);
            body.put("checkpoint", null);
            body.put("stopReason", null);
            body.put("failureCode", null);
            byte[] bytes = JsonCodec.stringify(body).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        }

        @Override public void close() {
            server.stop(0);
            executor.shutdownNow();
        }
    }
}
