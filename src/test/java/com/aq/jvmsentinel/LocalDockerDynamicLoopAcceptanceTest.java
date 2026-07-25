package com.aq.jvmsentinel;

import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderDefinition;
import com.aq.jvmsentinel.provider.chat.ChatTransport;
import com.aq.jvmsentinel.provider.chat.ProviderChatTransport;
import com.aq.jvmsentinel.sandbox.LocalDockerTrustedSandboxClient;
import com.aq.jvmsentinel.worker.LocalArtifactWorkerLoop;
import com.aq.jvmsentinel.worker.TaskLifecycle;
import com.aq.jvmsentinel.worker.WorkerControlPlaneClient;
import com.fasterxml.jackson.databind.JsonNode;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Real Docker acceptance from public dynamic-task enqueue through immutable trace projection. */
public final class LocalDockerDynamicLoopAcceptanceTest {
    private LocalDockerDynamicLoopAcceptanceTest() { }

    public static void main(String[] args) throws Exception {
        String image = System.getenv("VEYRION_DOCKER_RUNTIME_IMAGE");
        if (image == null || image.isBlank()) {
            throw new AssertionError("VEYRION_DOCKER_RUNTIME_IMAGE is required");
        }
        String artifactValue = System.getenv("VEYRION_TEST_ARTIFACT_JAR");
        if (artifactValue == null || artifactValue.isBlank()) {
            throw new AssertionError("VEYRION_TEST_ARTIFACT_JAR is required");
        }
        Path artifact = Path.of(artifactValue).toAbsolutePath().normalize();
        check(Files.isRegularFile(artifact), "backend-managed executable test JAR exists");
        Path root = Files.createTempDirectory("veyrion-docker-loop-");
        String token = "local-docker-loop-token";
        HttpClient http = HttpClient.newHttpClient();

        try (ControlPlaneServer server = new ControlPlaneServer(
                root, 0, token, root.resolve("control.db"),
                (provider, credential) -> { throw new AssertionError("inventory is not used"); },
                new ControlledOpenAiTransport()).start();
             LocalArtifactWorkerLoop worker = new LocalArtifactWorkerLoop(
                     server.baseUri().resolve("/internal/worker/v1/"), server.workerToken(),
                     new LocalDockerTrustedSandboxClient(), server::requireLocalArtifact, image)) {
            String expectedDigest = HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(artifact)));
            Path content = root.resolve(".veyrion/artifacts/sha256")
                    .resolve(expectedDigest.substring(0, 2))
                    .resolve(expectedDigest + ".jar");
            Files.createDirectories(content.getParent());
            Files.copy(artifact, content);
            String projectId = text(post(http, URI.create(server.baseUri() + "/projects"),
                    Map.of("name", "Docker loop"), token), "projectId");
            Map<String, Object> registered = post(http,
                    URI.create(server.baseUri() + "/projects/" + projectId + "/artifacts"),
                    Map.of("path", content.toString(), "type", "JAR"), token);
            String digest = text(registered, "artifactDigest");
            String scanId = text(post(http,
                    URI.create(server.baseUri() + "/projects/" + projectId + "/scans"),
                    Map.of("artifactDigest", digest, "authorized", true), token), "scanId");
            String taskId = text(post(http,
                    URI.create(server.baseUri() + "/scans/" + scanId + "/dynamic-tasks"),
                    Map.of("authorized", true), token), "taskId");
            check(worker.executeQueuedOnce(), "local Docker worker consumes the queued task");

            WorkerControlPlaneClient control = new WorkerControlPlaneClient(
                    server.baseUri().resolve("/internal/worker/v1/"),
                    server.workerToken(), Duration.ofSeconds(10));
            long deadline = System.nanoTime() + Duration.ofSeconds(90).toNanos();
            TaskLifecycle lifecycle = TaskLifecycle.QUEUED;
            while (System.nanoTime() < deadline) {
                lifecycle = control.list(projectId, scanId).stream()
                        .filter(task -> task.scope().taskId().equals(taskId))
                        .findFirst().orElseThrow().lifecycle();
                if (lifecycle == TaskLifecycle.COMPLETED || lifecycle == TaskLifecycle.FAILED) break;
                Thread.sleep(250);
            }
            if (lifecycle != TaskLifecycle.COMPLETED) {
                URI taskUri = URI.create(server.baseUri().resolve("/internal/worker/v1/")
                        + "tasks/" + taskId + "?projectId=" + projectId
                        + "&artifactDigest=" + digest + "&scanId=" + scanId);
                Map<String, Object> failed = workerGet(http, taskUri, server.workerToken());
                throw new AssertionError("local Docker worker completes task: " + failed);
            }

            URI dashboardUri = URI.create(server.baseUri() + "/projects/" + projectId + "/dashboard");
            Map<String, Object> dashboard = Map.of();
            long projectionDeadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
            while (System.nanoTime() < projectionDeadline) {
                dashboard = get(http, dashboardUri);
                if (dashboard.toString().contains("DYNAMIC_SUSPECTED")
                        && dashboard.toString().contains(taskId)) break;
                Thread.sleep(100);
            }
            check(dashboard.toString().contains("DYNAMIC_SUSPECTED")
                            && dashboard.toString().contains(taskId)
                            && dashboard.toString().contains("AGENT_INSTRUMENTED")
                            && dashboard.toString().contains("HTTP"),
                    "dynamic trace is projected to the dashboard: " + dashboard);

            String providerId = text(post(http, URI.create(server.baseUri() + "/providers"),
                    Map.of("name", "E2E OpenAI", "kind", "OPENAI_CHAT",
                            "baseUrl", "http://127.0.0.1:3000", "model", "e2e-model",
                            "apiKey", "e2e-provider-secret", "enabled", true), token), "providerId");
            for (String role : List.of("PRE_ANALYSIS", "PATH_EXPLORATION",
                    "DYNAMIC_VERIFICATION", "VULNERABILITY_TRIAGE", "REPORT_GENERATION")) {
                patch(http, URI.create(server.baseUri() + "/projects/" + projectId
                                + "/role-assignments/" + role),
                        Map.of("providerId", providerId, "model", "e2e-model"), token);
                String jobId = text(post(http, URI.create(server.baseUri() + "/projects/"
                                + projectId + "/ai-jobs"),
                        Map.of("role", role, "scanId", scanId, "authorized", true), token), "aiJobId");
                Map<String, Object> job = awaitJob(http, server.baseUri(), jobId, token);
                check("COMPLETED".equals(job.get("status")),
                        role + " AI job completes: " + job);
                Map<String, Object> events = operatorGet(http,
                        URI.create(server.baseUri() + "/ai-jobs/" + jobId + "/events"), token);
                String eventText = events.toString();
                check(eventText.contains("PROVIDER_REQUEST")
                                && eventText.contains("PROVIDER_RESPONSE")
                                && eventText.contains("TOOL_CALL")
                                && eventText.contains("facts_search")
                                && eventText.contains("MODEL_INFERENCE"),
                        role + " exposes provider, tool, and inference events: " + events);
            }
        } finally {
            // Docker bind mounts can briefly keep the managed JAR locked on Windows.
            deleteTreeBestEffort(root);
        }
        System.out.println("LocalDockerDynamicLoopAcceptanceTest: PASS");
    }

    private static Map<String, Object> post(HttpClient client, URI uri,
                                            Map<String, Object> body, String token) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(uri)
                .header("Content-Type", "application/json")
                .header("X-Sentinel-Authorization", token)
                .header("Idempotency-Key", UUID.randomUUID().toString())
                .POST(HttpRequest.BodyPublishers.ofString(JsonCodec.stringify(body))).build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        check(response.statusCode() >= 200 && response.statusCode() < 300,
                "request succeeds: HTTP " + response.statusCode() + " " + response.body());
        return JsonCodec.parseObject(response.body());
    }

    private static Map<String, Object> get(HttpClient client, URI uri) throws Exception {
        HttpResponse<String> response = client.send(
                HttpRequest.newBuilder(uri).GET().build(), HttpResponse.BodyHandlers.ofString());
        check(response.statusCode() == 200, "GET succeeds");
        return JsonCodec.parseObject(response.body());
    }

    private static Map<String, Object> patch(HttpClient client, URI uri,
                                             Map<String, Object> body, String token) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(uri)
                .header("Content-Type", "application/json")
                .header("X-Sentinel-Authorization", token)
                .header("Idempotency-Key", UUID.randomUUID().toString())
                .method("PATCH", HttpRequest.BodyPublishers.ofString(JsonCodec.stringify(body))).build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        check(response.statusCode() >= 200 && response.statusCode() < 300,
                "PATCH succeeds: HTTP " + response.statusCode() + " " + response.body());
        return JsonCodec.parseObject(response.body());
    }

    private static Map<String, Object> operatorGet(HttpClient client, URI uri, String token)
            throws Exception {
        HttpResponse<String> response = client.send(HttpRequest.newBuilder(uri)
                        .header("X-Sentinel-Authorization", token).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        check(response.statusCode() == 200,
                "operator GET succeeds: HTTP " + response.statusCode() + " " + response.body());
        return JsonCodec.parseObject(response.body());
    }

    private static Map<String, Object> awaitJob(
            HttpClient client, URI baseUri, String jobId, String token) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(15).toNanos();
        Map<String, Object> job = Map.of();
        while (System.nanoTime() < deadline) {
            job = operatorGet(client, URI.create(baseUri + "/ai-jobs/" + jobId), token);
            if (List.of("COMPLETED", "FAILED", "BLOCKED", "CANCELLED").contains(job.get("status"))) {
                return job;
            }
            Thread.sleep(50);
        }
        throw new AssertionError("AI job did not finish: " + job);
    }

    private static Map<String, Object> workerGet(HttpClient client, URI uri, String token)
            throws Exception {
        HttpResponse<String> response = client.send(HttpRequest.newBuilder(uri)
                        .header("X-Sentinel-Worker-Authorization", token).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        check(response.statusCode() == 200, "Worker GET succeeds");
        return JsonCodec.parseObject(response.body());
    }

    private static String text(Map<String, Object> value, String field) {
        Object candidate = value.get(field);
        if (!(candidate instanceof String text) || text.isBlank()) {
            throw new AssertionError("missing " + field);
        }
        return text;
    }

    private static void deleteTreeBestEffort(Path root) {
        if (root == null || !Files.exists(root)) return;
        for (int attempt = 0; attempt < 8; attempt++) {
            try {
                try (var paths = Files.walk(root)) {
                    for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) {
                        Files.deleteIfExists(path);
                    }
                }
                if (!Files.exists(root)) return;
            } catch (Exception ignored) {
            }
            try {
                Thread.sleep(250L * (attempt + 1));
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static final class ControlledOpenAiTransport implements ChatTransport {
        @Override
        public ProviderChatTransport.Response send(
                ProviderDefinition provider, byte[] credential, JsonNode request,
                ProviderChatTransport.Limits limits) {
            check("e2e-provider-secret".equals(
                            new String(credential, java.nio.charset.StandardCharsets.UTF_8)),
                    "AI transport receives the configured credential");
            String requestText = request.toString();
            check(requestText.contains("\"facts_search\"")
                            && requestText.contains("untrusted data")
                            && !requestText.contains("e2e-provider-secret"),
                    "AI request includes fixed tools and excludes credentials");
            String body = requestText.contains("\"role\":\"tool\"")
                    ? "{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{"
                    + "\"role\":\"assistant\",\"content\":\"bounded end-to-end inference\"}}]}"
                    : "{\"choices\":[{\"finish_reason\":\"tool_calls\",\"message\":{"
                    + "\"role\":\"assistant\",\"content\":null,\"tool_calls\":[{\"id\":\"tool-e2e\","
                    + "\"type\":\"function\",\"function\":{\"name\":\"facts_search\","
                    + "\"arguments\":\"{\\\"kind\\\":\\\"EVIDENCE\\\",\\\"limit\\\":1}\"}}]}}]}";
            return new ProviderChatTransport.Response(200,
                    body.getBytes(java.nio.charset.StandardCharsets.UTF_8), "request-e2e", 1);
        }
    }
}
