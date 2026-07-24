package com.aq.jvmsentinel;

import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.fixture.TrustedFixtureCatalog;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/** End-to-end checks for the public trusted-fixture queue boundary and shared Worker runtime. */
public final class DynamicTaskAcceptanceTest {
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("dynamic-task-acceptance");
        Path artifact = root.resolve("FixtureController.class");
        Files.writeString(artifact, "intentionally malformed metadata-only fixture descriptor");

        try (ControlPlaneServer server = new ControlPlaneServer(root, 0, "gui-token").start()) {
            HttpClient client = HttpClient.newHttpClient();
            URI api = server.baseUri();
            URI worker = URI.create("http://" + server.address().getHostString() + ":"
                    + server.address().getPort() + "/internal/worker/v1");

            String projectId = text(ok(guiPost(client, URI.create(api + "/projects"),
                    "{\"name\":\"dynamic\"}", server.mutationToken(), "project-dynamic")), "projectId");
            String digest = text(ok(guiPost(client, URI.create(api + "/projects/" + projectId + "/artifacts"),
                    "{\"path\":\"" + escape(artifact.toString()) + "\"}",
                    server.mutationToken(), "artifact-dynamic")), "artifactDigest");
            String scanId = text(ok(guiPost(client, URI.create(api + "/projects/" + projectId + "/scans"),
                    "{\"artifactDigest\":\"" + digest + "\",\"authorized\":true}",
                    server.mutationToken(), "scan-dynamic")), "scanId");
            URI dynamic = URI.create(api + "/scans/" + scanId + "/dynamic-tasks");
            check(workerPost(client, URI.create(worker + "/tasks"),
                    "{\"projectId\":\"" + projectId + "\",\"artifactDigest\":\"" + digest
                            + "\",\"scanId\":\"" + scanId + "\",\"taskId\":\"worker-injected-fixture\""
                            + ",\"targetEntryId\":\"entry-1\",\"authorized\":true,\"fixtureOnly\":true"
                            + ",\"requiredCapability\":\"FIXTURE_RUNC\",\"networkMode\":\"DENY\"}",
                    server.workerToken(), "worker-injected-fixture").statusCode() == 403,
                    "Worker token cannot mint fixture tasks outside the trusted catalog");
            String fixtureBody = "{\"authorized\":true,\"fixtureId\":\""
                    + TrustedFixtureCatalog.HTTP_ENTRY_SMOKE_V1 + "\"}";

            check(guiPost(client, dynamic, fixtureBody, null, "public-no-token").statusCode() == 401,
                    "public dynamic task requires GUI token");
            check(guiPost(client, dynamic, fixtureBody, "wrong-token", "public-wrong-token").statusCode() == 401,
                    "wrong GUI token rejected");
            check(guiPost(client, dynamic, fixtureBody, server.mutationToken(), null).statusCode() == 400,
                    "Idempotency-Key required");
            check(guiPost(client, dynamic,
                    "{\"authorized\":false,\"fixtureId\":\"" + TrustedFixtureCatalog.HTTP_ENTRY_SMOKE_V1 + "\"}",
                    server.mutationToken(), "public-denied").statusCode() == 403,
                    "explicit authorization required");
            check(guiPost(client, dynamic, "{\"authorized\":true,\"fixtureId\":\"unknown\"}",
                    server.mutationToken(), "public-unknown").statusCode() == 404,
                    "unknown fixture rejected");

            for (String field : List.of("image", "command", "path", "traceDir", "capability")) {
                String injected = "{\"authorized\":true,\"fixtureId\":\""
                        + TrustedFixtureCatalog.HTTP_ENTRY_SMOKE_V1 + "\",\"" + field + "\":\"attacker\"}";
                check(guiPost(client, dynamic, injected, server.mutationToken(),
                        "inject-" + field).statusCode() == 400, field + " injection rejected");
            }

            HttpResponse<String> queuedResponse = guiPost(client, dynamic, fixtureBody,
                    server.mutationToken(), "public-create");
            check(queuedResponse.statusCode() == 202, "trusted fixture queued");
            Map<String, Object> queued = ok(queuedResponse);
            String taskId = text(queued, "taskId");
            check(Long.valueOf(1).equals(queued.get("schemaVersion")), "response schema version");
            check("QUEUED".equals(queued.get("status")), "queue-only status");
            check("DYNAMIC_SUSPECTED".equals(queued.get("verificationStatus")), "dynamic status is suspected");
            check("FIXTURE_RUNC".equals(queued.get("requiredCapability")), "fixture capability forced");
            check(Boolean.TRUE.equals(queued.get("fixtureOnly")), "fixtureOnly forced");
            check("DENY".equals(queued.get("networkMode")), "network denied");
            check("FIXTURE_RUNC_QUEUED".equals(queued.get("dynamicExecutionMode")), "queued execution mode");
            check(!queuedResponse.body().contains(server.workerToken()), "public response does not expose worker token");
            check(!queuedResponse.body().contains("VERIFIED"), "queue response is not verified");

            HttpResponse<String> replayResponse = guiPost(client, dynamic, fixtureBody,
                    server.mutationToken(), "public-create");
            check(replayResponse.statusCode() == 200
                    && taskId.equals(text(ok(replayResponse), "taskId")), "idempotent replay returns same task");
            String differentFixture = "{\"authorized\":true,\"fixtureId\":\""
                    + TrustedFixtureCatalog.HTTP_ENTRY_SMOKE_V2 + "\"}";
            check(guiPost(client, dynamic, differentFixture,
                    server.mutationToken(), "public-create").statusCode() == 409,
                    "idempotency payload conflict rejected");

            Map<String, Object> listed = ok(workerGet(client, URI.create(worker + "/tasks?scanId=" + scanId),
                    server.workerToken()));
            List<?> tasks = (List<?>) listed.get("tasks");
            check(tasks.size() == 1, "public task visible to shared Worker coordinator");
            Map<?, ?> workerTask = (Map<?, ?>) tasks.get(0);
            check(taskId.equals(workerTask.get("taskId")), "worker sees same task");
            check(Boolean.TRUE.equals(workerTask.get("fixtureOnly"))
                    && "FIXTURE_RUNC".equals(workerTask.get("requiredCapability")), "worker policy remains forced");
            check(workerTask.get("imageUri") instanceof String && workerTask.get("mainClass") instanceof String,
                    "worker receives catalog-owned runtime material");

            URI task = URI.create(worker + "/tasks/" + taskId);
            String scope = "\"projectId\":\"" + projectId + "\",\"artifactDigest\":\"" + digest
                    + "\",\"scanId\":\"" + scanId + "\"";
            check(workerPost(client, URI.create(task + "/lease"),
                    "{" + scope + ",\"workerId\":\"worker-dynamic\",\"capabilities\":[\"STATIC_ONLY\"]}",
                    server.workerToken(), "lease-wrong-capability").statusCode() == 403,
                    "worker without FIXTURE_RUNC cannot lease");
            check(workerPost(client, URI.create(task + "/lease"),
                    "{\"projectId\":\"" + projectId + "\",\"artifactDigest\":\"" + "0".repeat(64)
                            + "\",\"scanId\":\"" + scanId
                            + "\",\"workerId\":\"worker-dynamic\",\"capabilities\":[\"FIXTURE_RUNC\"]}",
                    server.workerToken(), "lease-wrong-scope").statusCode() == 403,
                    "worker scope mismatch rejected");

            Map<String, Object> lease = ok(workerPost(client, URI.create(task + "/lease"),
                    "{" + scope + ",\"workerId\":\"worker-dynamic\",\"capabilities\":[\"FIXTURE_RUNC\"]}",
                    server.workerToken(), "lease-dynamic"));
            String leaseId = text(lease, "leaseId");
            String leaseScope = scope + ",\"leaseId\":\"" + leaseId + "\",\"workerId\":\"worker-dynamic\"";
            check(workerPost(client, URI.create(task + "/start"), "{" + leaseScope + "}",
                    server.workerToken(), "start-dynamic").statusCode() == 200, "worker starts queued task");
            check(workerPost(client, URI.create(task + "/trace"),
                    "{" + leaseScope + ",\"sequence\":0,\"payloadBase64\":\"dHJhY2U=\"}",
                    server.workerToken(), "trace-dynamic").statusCode() == 201, "worker commits trace");
            HttpResponse<String> completed = workerPost(client, URI.create(task + "/complete"),
                    "{" + leaseScope + "}", server.workerToken(), "complete-dynamic");
            check(completed.statusCode() == 200
                    && "COMPLETED".equals(ok(completed).get("lifecycle")), "worker completes task");

            System.out.println("DynamicTaskAcceptanceTest: PASS");
        }
    }

    private static HttpResponse<String> guiPost(HttpClient client, URI uri, String body, String token, String key)
            throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(uri).header("Content-Type", "application/json");
        if (token != null) request.header("X-Sentinel-Authorization", token);
        if (key != null) request.header("Idempotency-Key", key);
        return client.send(request.POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> workerPost(HttpClient client, URI uri, String body, String token, String key)
            throws Exception {
        HttpRequest request = HttpRequest.newBuilder(uri).header("Content-Type", "application/json")
                .header("X-Sentinel-Worker-Authorization", token).header("Idempotency-Key", key)
                .POST(HttpRequest.BodyPublishers.ofString(body)).build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> workerGet(HttpClient client, URI uri, String token) throws Exception {
        return client.send(HttpRequest.newBuilder(uri).header("X-Sentinel-Worker-Authorization", token).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static Map<String, Object> ok(HttpResponse<String> response) {
        check(response.statusCode() >= 200 && response.statusCode() < 300,
                "unexpected HTTP " + response.statusCode() + ": " + response.body());
        return JsonCodec.parseObject(response.body());
    }

    private static String text(Map<String, Object> body, String key) {
        Object value = body.get(key);
        if (!(value instanceof String text)) throw new AssertionError(key + " missing");
        return text;
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
