package com.aq.jvmsentinel;

import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.JsonCodec;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * 验收：workspace audit-history delete 持久化、project-scoped、auth 上 fail-closed。
 * 仅 CRUD UX — 不发明 VERIFIED 声称。
 */
public final class AuditHistoryDeleteAcceptanceTest {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("veyrion-audit-history-delete");
        Path artifact = root.resolve("UploadFileExecController.class");
        Files.writeString(artifact, "metadata-only fixture");
        try (ControlPlaneServer server = new ControlPlaneServer(root).start()) {
            HttpClient client = HttpClient.newHttpClient();
            String token = server.mutationToken();

            check(delete(client, uri(server, "/projects/missing/scans/missing"), null).statusCode() == 401,
                    "delete scan requires bearer token");

            String projectA = text(ok(createProject(client, server, token, "history-a")), "projectId");
            String projectB = text(ok(createProject(client, server, token, "history-b")), "projectId");
            String digestA = registerArtifact(client, server, token, projectA, artifact);
            String digestB = registerArtifact(client, server, token, projectB, artifact);

            String scanA = text(ok(createScan(client, server, token, projectA, digestA, "scan-a")), "scanId");
            String scanB = text(ok(createScan(client, server, token, projectB, digestB, "scan-b")), "scanId");

            HttpResponse<String> wrongProject = delete(client,
                    uri(server, "/projects/" + projectB + "/scans/" + scanA), token);
            check(wrongProject.statusCode() == 404, "wrong project scope is rejected");
            check(listContains(client, server, projectA, scanA), "wrong-project delete must not remove scan");
            check(listContains(client, server, projectB, scanB), "sibling project history remains");

            // 裸 scan 子表为空；delete 不得要求 1-row 子 DELETE。
            HttpResponse<String> deleted = delete(client,
                    uri(server, "/projects/" + projectA + "/scans/" + scanA), token);
            check(deleted.statusCode() == 204,
                    "authorized project-scoped delete returns 204 (empty dependents allowed): "
                            + deleted.statusCode() + " " + deleted.body());
            check(!listContains(client, server, projectA, scanA), "deleted scan absent from subsequent list");
            check(getScan(client, server, scanA).statusCode() == 404, "deleted scan GET is not found");
            check(listContains(client, server, projectB, scanB), "other project scan is untouched");

            HttpResponse<String> replay = delete(client,
                    uri(server, "/projects/" + projectA + "/scans/" + scanA), token);
            check(replay.statusCode() == 404, "repeat delete of missing scan is fail-closed");

            String scanBare = text(ok(createScan(client, server, token, projectA, digestA, "scan-bare")), "scanId");
            HttpResponse<String> deletedBare = delete(client,
                    uri(server, "/projects/" + projectA + "/scans/" + scanBare), token);
            check(deletedBare.statusCode() == 204, "second empty-dependent scan delete returns 204");
            check(!listContains(client, server, projectA, scanBare), "second deleted scan absent from list");

            // 原 409 SCAN_ACTIVE：卡住 QUEUED worker task 须 cancel-then-delete → 204。
            String scanQueued = text(ok(createScan(client, server, token, projectA, digestA, "scan-queued")),
                    "scanId");
            HttpResponse<String> enqueued = workerEnqueue(client, server, projectA, digestA, scanQueued,
                    "task-stuck-queued");
            check(enqueued.statusCode() == 202, "enqueue stuck QUEUED task: " + enqueued.body());
            Map<String, Object> queuedTask = JsonCodec.parseObject(enqueued.body());
            check("QUEUED".equals(queuedTask.get("lifecycle")), "worker task is QUEUED before delete");
            HttpResponse<String> deletedQueued = delete(client,
                    uri(server, "/projects/" + projectA + "/scans/" + scanQueued), token);
            check(deletedQueued.statusCode() == 204,
                    "cancel-then-delete with stuck QUEUED returns 204 (not 409): "
                            + deletedQueued.statusCode() + " " + deletedQueued.body());
            check(!listContains(client, server, projectA, scanQueued),
                    "scan with former stuck QUEUED task absent after delete");
            check(getScan(client, server, scanQueued).statusCode() == 404,
                    "scan with former stuck QUEUED task GET is not found");
        }
        System.out.println("AuditHistoryDeleteAcceptanceTest: PASS (" + checks + " checks)");
    }

    private static HttpResponse<String> workerEnqueue(HttpClient client, ControlPlaneServer server,
                                                      String projectId, String digest, String scanId,
                                                      String taskId) throws Exception {
        String body = "{\"projectId\":\"" + projectId + "\",\"artifactDigest\":\"" + digest
                + "\",\"scanId\":\"" + scanId + "\",\"taskId\":\"" + taskId
                + "\",\"targetEntryId\":\"entry-history-delete\""
                + ",\"authorized\":true,\"requiredCapability\":\"STATIC_ONLY\",\"networkMode\":\"DENY\"}";
        URI tasks = server.baseUri().resolve("/internal/worker/v1/tasks");
        return client.send(HttpRequest.newBuilder(tasks)
                .header("Content-Type", "application/json")
                .header("X-Sentinel-Worker-Authorization", server.workerToken())
                .header("Idempotency-Key", "history-delete-" + taskId)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build(), HttpResponse.BodyHandlers.ofString());
    }

    private static boolean listContains(HttpClient client, ControlPlaneServer server,
                                        String projectId, String scanId) throws Exception {
        HttpResponse<String> response = client.send(HttpRequest.newBuilder(
                        uri(server, "/projects/" + projectId + "/scans"))
                .header("Authorization", "Bearer " + server.mutationToken())
                .GET().build(), HttpResponse.BodyHandlers.ofString());
        check(response.statusCode() == 200, "list scans succeeds");
        Map<String, Object> body = JsonCodec.parseObject(response.body());
        Object scans = body.get("scans");
        if (!(scans instanceof List<?> list)) return false;
        for (Object item : list) {
            if (item instanceof Map<?, ?> map && scanId.equals(map.get("scanId"))) return true;
        }
        return false;
    }

    private static HttpResponse<String> getScan(HttpClient client, ControlPlaneServer server, String scanId)
            throws Exception {
        return client.send(HttpRequest.newBuilder(uri(server, "/scans/" + scanId))
                .header("Authorization", "Bearer " + server.mutationToken())
                .GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> createProject(HttpClient client, ControlPlaneServer server,
                                                      String token, String name) throws Exception {
        return request(client, uri(server, "/projects"), "POST",
                "{\"name\":\"" + name + "\"}", token, "project-" + UUID.randomUUID());
    }

    private static String registerArtifact(HttpClient client, ControlPlaneServer server, String token,
                                           String projectId, Path artifact) throws Exception {
        HttpResponse<String> response = request(client,
                uri(server, "/projects/" + projectId + "/artifacts"), "POST",
                "{\"path\":\"" + escape(artifact.toString()) + "\"}",
                token, "artifact-" + UUID.randomUUID());
        return text(ok(response), "artifactDigest");
    }

    private static HttpResponse<String> createScan(HttpClient client, ControlPlaneServer server, String token,
                                                   String projectId, String digest, String key) throws Exception {
        return request(client, uri(server, "/projects/" + projectId + "/scans"), "POST",
                "{\"artifactDigest\":\"" + digest + "\",\"authorized\":true}", token, key);
    }

    private static HttpResponse<String> delete(HttpClient client, URI uri, String token) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(uri)
                .header("Content-Type", "application/json")
                .header("Idempotency-Key", "delete-" + UUID.randomUUID())
                .method("DELETE", HttpRequest.BodyPublishers.noBody());
        if (token != null) request.header("Authorization", "Bearer " + token);
        return client.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> request(HttpClient client, URI uri, String method, String json,
                                                String token, String idempotencyKey) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(uri)
                .header("Content-Type", "application/json")
                .header("Idempotency-Key", idempotencyKey)
                .method(method, HttpRequest.BodyPublishers.ofString(json));
        if (token != null) request.header("Authorization", "Bearer " + token);
        return client.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static URI uri(ControlPlaneServer server, String path) {
        return URI.create(server.baseUri() + path);
    }

    private static Map<String, Object> ok(HttpResponse<String> response) {
        check(response.statusCode() >= 200 && response.statusCode() < 300,
                "unexpected response " + response.statusCode() + ": " + response.body());
        return JsonCodec.parseObject(response.body());
    }

    private static String text(Map<?, ?> value, String key) {
        Object result = value.get(key);
        check(result instanceof String text && !text.isBlank(), key + " present");
        return (String) result;
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
