package com.aq.jvmsentinel;

import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.sandbox.LocalDockerTrustedSandboxClient;
import com.aq.jvmsentinel.worker.LocalArtifactWorkerLoop;
import com.aq.jvmsentinel.worker.TaskLifecycle;
import com.aq.jvmsentinel.worker.WorkerControlPlaneClient;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
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
                "127.0.0.1", 0, root, token, root.resolve("control.db")).start();
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
                            && dashboard.toString().contains(taskId),
                    "dynamic trace is projected to the dashboard: " + dashboard);
        } finally {
            deleteTree(root);
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

    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) return;
        try (var paths = Files.walk(root)) {
            for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
