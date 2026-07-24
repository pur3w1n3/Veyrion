package com.aq.jvmsentinel;

import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.JsonCodec;

import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Map;

/** End-to-end checks for the authenticated, in-memory Worker contract API. */
public final class WorkerControlPlaneAcceptanceTest {
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("worker-control-plane");
        Path artifact = root.resolve("WorkerFixture.class");
        Files.writeString(artifact, "metadata-only worker fixture");
        try (ControlPlaneServer server = new ControlPlaneServer(root, 0, "gui-token").start()) {
            HttpClient client = HttpClient.newHttpClient();
            URI api = server.baseUri();
            URI worker = URI.create("http://" + server.address().getHostString() + ":"
                    + server.address().getPort() + "/internal/worker/v1");

            check(!server.workerToken().equals(server.mutationToken()), "worker token must be independent");
            Map<String, Object> health = json(get(client, URI.create(api + "/health")));
            check("DYNAMIC_DISABLED".equals(health.get("dynamicExecutionMode")), "dynamic execution remains disabled");
            check(Long.valueOf(1).equals(health.get("workerContractVersion")), "worker contract version");

            HttpResponse<String> projectResponse = guiPost(client, URI.create(api + "/projects"),
                    "{\"name\":\"worker-contract\"}", server.mutationToken(), "project-worker");
            String projectId = text(json(projectResponse), "projectId");
            URI artifacts = URI.create(api + "/projects/" + projectId + "/artifacts");
            HttpResponse<String> artifactResponse = guiPost(client, artifacts,
                    "{\"path\":\"" + escape(artifact.toString()) + "\"}",
                    server.mutationToken(), "artifact-worker");
            String digest = text(json(artifactResponse), "artifactDigest");
            URI scans = URI.create(api + "/projects/" + projectId + "/scans");
            HttpResponse<String> scanResponse = guiPost(client, scans,
                    "{\"artifactDigest\":\"" + digest + "\",\"authorized\":true}",
                    server.mutationToken(), "scan-worker");
            String scanId = text(json(scanResponse), "scanId");

            HttpResponse<String> workerOnGui = guiPost(client, URI.create(api + "/projects"), "{}",
                    server.workerToken(), "cross-worker");
            check(workerOnGui.statusCode() == 401, "worker token cannot mutate GUI API");

            String taskBody = taskBody(projectId, digest, scanId, "task-a", "entry-a");
            HttpResponse<String> guiOnWorker = workerPost(client, URI.create(worker + "/tasks"), taskBody,
                    server.mutationToken(), "enqueue-a");
            check(guiOnWorker.statusCode() == 401, "GUI token cannot call Worker API");
            check(workerPost(client, URI.create(worker + "/tasks"), taskBody, null, "enqueue-a").statusCode() == 401,
                    "Worker API requires authentication");
            check(workerPost(client, URI.create(worker + "/tasks"), taskBody, server.workerToken(), null).statusCode() == 400,
                    "Worker mutations require idempotency key");

            HttpResponse<String> enqueue = workerPost(client, URI.create(worker + "/tasks"), taskBody,
                    server.workerToken(), "enqueue-a");
            check(enqueue.statusCode() == 202, "enqueue task");
            check("QUEUED".equals(json(enqueue).get("lifecycle")), "queued lifecycle");
            HttpResponse<String> replay = workerPost(client, URI.create(worker + "/tasks"), taskBody,
                    server.workerToken(), "enqueue-a");
            check(replay.statusCode() == 202, "enqueue replay");
            HttpResponse<String> conflict = workerPost(client, URI.create(worker + "/tasks"),
                    taskBody(projectId, digest, scanId, "task-a", "entry-different"),
                    server.workerToken(), "enqueue-a");
            check(conflict.statusCode() == 409, "idempotency payload conflict");

            String wrongDigest = "0".repeat(64);
            HttpResponse<String> wrongScope = workerPost(client, URI.create(worker + "/tasks"),
                    taskBody(projectId, wrongDigest, scanId, "task-wrong", "entry-a"),
                    server.workerToken(), "enqueue-wrong");
            check(wrongScope.statusCode() == 403, "scope mismatch rejected");

            String scope = scope(projectId, digest, scanId);
            HttpResponse<String> list = workerGet(client, URI.create(worker + "/tasks"), server.workerToken());
            check(list.statusCode() == 200 && ((java.util.List<?>) json(list).get("tasks")).size() == 1,
                    "authorized task list");
            URI taskA = URI.create(worker + "/tasks/task-a");
            HttpResponse<String> get = workerGet(client, URI.create(taskA + "?" + queryScope(projectId, digest, scanId)),
                    server.workerToken());
            check(get.statusCode() == 200 && "task-a".equals(json(get).get("taskId")), "authorized task get");

            HttpResponse<String> lease = action(client, taskA, "lease",
                    scope + ",\"workerId\":\"worker-a\",\"capabilities\":[\"STATIC_ONLY\"],\"durationSeconds\":120",
                    server.workerToken(), "lease-a");
            check(lease.statusCode() == 200, "lease task");
            String leaseId = text(json(lease), "leaseId");
            check(action(client, taskA, "start",
                    scope + ",\"leaseId\":\"" + leaseId + "\",\"workerId\":\"worker-other\"",
                    server.workerToken(), "start-wrong").statusCode() == 403, "worker scope mismatch rejected");
            check(action(client, taskA, "start",
                    leaseAction(scope, leaseId, "worker-a"), server.workerToken(), "start-a").statusCode() == 200,
                    "start task");

            String oversized = Base64.getEncoder().encodeToString(new byte[1024 * 1024 + 1]);
            HttpResponse<String> oversizedTrace = action(client, taskA, "trace",
                    leaseAction(scope, leaseId, "worker-a")
                            + ",\"sequence\":0,\"payloadBase64\":\"" + oversized + "\"",
                    server.workerToken(), "trace-large");
            check(oversizedTrace.statusCode() == 400, "decoded trace payload is bounded");

            HttpResponse<String> gap = action(client, taskA, "trace",
                    leaseAction(scope, leaseId, "worker-a")
                            + ",\"sequence\":1,\"previousDigest\":\"" + "0".repeat(64)
                            + "\",\"payloadBase64\":\"YQ==\"",
                    server.workerToken(), "trace-gap");
            check(gap.statusCode() == 409, "trace discontinuity rejected");

            HttpResponse<String> trace = action(client, taskA, "trace",
                    leaseAction(scope, leaseId, "worker-a")
                            + ",\"sequence\":0,\"payloadBase64\":\"dHJhY2UtMA==\"",
                    server.workerToken(), "trace-0");
            check(trace.statusCode() == 201, "trace committed");
            String traceDigest = text(json(trace), "digest");
            HttpResponse<String> traceConflict = action(client, taskA, "trace",
                    leaseAction(scope, leaseId, "worker-a")
                            + ",\"sequence\":0,\"payloadBase64\":\"ZGlmZmVyZW50\"",
                    server.workerToken(), "trace-0");
            check(traceConflict.statusCode() == 409, "trace idempotency conflict");

            HttpResponse<String> pause = action(client, taskA, "pause",
                    leaseAction(scope, leaseId, "worker-a")
                            + ",\"checkpointId\":\"checkpoint-a\",\"traceSequence\":0,\"traceHeadDigest\":\""
                            + traceDigest + "\"",
                    server.workerToken(), "pause-a");
            check(pause.statusCode() == 200 && "PAUSED".equals(json(pause).get("lifecycle")), "pause task");
            check(action(client, taskA, "resume", leaseAction(scope, leaseId, "worker-a"),
                    server.workerToken(), "resume-a").statusCode() == 200, "resume task");
            check(action(client, taskA, "heartbeat",
                    leaseAction(scope, leaseId, "worker-a") + ",\"extensionSeconds\":120",
                    server.workerToken(), "heartbeat-a").statusCode() == 200, "heartbeat lease");
            HttpResponse<String> completed = action(client, taskA, "complete",
                    leaseAction(scope, leaseId, "worker-a"), server.workerToken(), "complete-a");
            check(completed.statusCode() == 200 && "COMPLETED".equals(json(completed).get("lifecycle")),
                    "complete task");

            enqueue(client, worker, server.workerToken(), taskBody(projectId, digest, scanId, "task-b", "entry-b"),
                    "enqueue-b");
            URI taskB = URI.create(worker + "/tasks/task-b");
            HttpResponse<String> cancelled = action(client, taskB, "cancel",
                    scope, server.workerToken(), "cancel-b");
            check(cancelled.statusCode() == 200 && "CANCELLED".equals(json(cancelled).get("lifecycle")),
                    "cancel queued task");

            enqueue(client, worker, server.workerToken(), taskBody(projectId, digest, scanId, "task-c", "entry-c"),
                    "enqueue-c");
            URI taskC = URI.create(worker + "/tasks/task-c");
            HttpResponse<String> leaseC = action(client, taskC, "lease",
                    scope + ",\"workerId\":\"worker-c\",\"capabilities\":[\"STATIC_ONLY\"]",
                    server.workerToken(), "lease-c");
            String leaseCId = text(json(leaseC), "leaseId");
            HttpResponse<String> failed = action(client, taskC, "fail",
                    leaseAction(scope, leaseCId, "worker-c")
                            + ",\"reason\":\"WORKER_FAILURE\",\"failureCode\":\"fixture-failure\"",
                    server.workerToken(), "fail-c");
            check(failed.statusCode() == 200 && "FAILED".equals(json(failed).get("lifecycle")), "fail task");

            check(server.sseHub().history(scanId).stream().anyMatch(e -> "TraceCommitted".equals(e.eventType())),
                    "TraceCommitted SSE retained");
            check(server.sseHub().history(scanId).stream().anyMatch(e -> "TaskStopped".equals(e.eventType())
                    && "task-a".equals(e.context().taskId())), "TaskStopped SSE retained");
            check(server.sseHub().history(scanId).stream().anyMatch(e -> "ScanCompleted".equals(e.eventType())
                    && "task-a".equals(e.context().taskId())), "terminal ScanCompleted SSE retained");
            String sse = readSse(server, scanId);
            check(sse.contains("event: TraceCommitted"), "TraceCommitted SSE replay");
            check(sse.contains("\"taskId\":\"task-a\""), "SSE carries task scope");
            System.out.println("WorkerControlPlaneAcceptanceTest: PASS");
        }
    }

    private static void enqueue(HttpClient client, URI worker, String token, String body, String key) throws Exception {
        check(workerPost(client, URI.create(worker + "/tasks"), body, token, key).statusCode() == 202, "enqueue helper");
    }

    private static HttpResponse<String> action(HttpClient client, URI task, String action, String fields,
                                               String token, String key) throws Exception {
        return workerPost(client, URI.create(task + "/" + action), "{" + fields + "}", token, key);
    }

    private static String taskBody(String projectId, String digest, String scanId, String taskId, String entryId) {
        return "{" + scope(projectId, digest, scanId) + ",\"taskId\":\"" + taskId
                + "\",\"targetEntryId\":\"" + entryId
                + "\",\"authorized\":true,\"requiredCapability\":\"STATIC_ONLY\",\"networkMode\":\"DENY\"}";
    }

    private static String scope(String projectId, String digest, String scanId) {
        return "\"projectId\":\"" + projectId + "\",\"artifactDigest\":\"" + digest
                + "\",\"scanId\":\"" + scanId + "\"";
    }

    private static String leaseAction(String scope, String leaseId, String workerId) {
        return scope + ",\"leaseId\":\"" + leaseId + "\",\"workerId\":\"" + workerId + "\"";
    }

    private static String queryScope(String projectId, String digest, String scanId) {
        return "projectId=" + projectId + "&artifactDigest=" + digest + "&scanId=" + scanId;
    }

    private static HttpResponse<String> guiPost(HttpClient client, URI uri, String body, String token, String key)
            throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri).header("Content-Type", "application/json");
        if (token != null) builder.header("X-Sentinel-Authorization", token);
        if (key != null) builder.header("Idempotency-Key", key);
        return client.send(builder.POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> workerPost(HttpClient client, URI uri, String body, String token, String key)
            throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri).header("Content-Type", "application/json");
        if (token != null) builder.header("X-Sentinel-Worker-Authorization", token);
        if (key != null) builder.header("Idempotency-Key", key);
        return client.send(builder.POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> workerGet(HttpClient client, URI uri, String token) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri);
        if (token != null) builder.header("X-Sentinel-Worker-Authorization", token);
        return client.send(builder.GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> get(HttpClient client, URI uri) throws Exception {
        return client.send(HttpRequest.newBuilder(uri).GET().build(), HttpResponse.BodyHandlers.ofString());
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

    private static String readSse(ControlPlaneServer server, String scanId) throws Exception {
        try (Socket socket = new Socket(server.address().getHostString(), server.address().getPort())) {
            socket.setSoTimeout(5000);
            String request = "GET /api/v1/scans/" + scanId + "/events HTTP/1.1\r\n"
                    + "Host: localhost\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n";
            socket.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();
            byte[] buffer = new byte[8192];
            StringBuilder result = new StringBuilder();
            int count;
            while ((count = socket.getInputStream().read(buffer)) >= 0) {
                result.append(new String(buffer, 0, count, StandardCharsets.UTF_8));
            }
            return result.toString();
        }
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
