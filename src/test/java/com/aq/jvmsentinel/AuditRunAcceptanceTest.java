package com.aq.jvmsentinel;

import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.provider.chat.ProviderChatTransport;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/** Public API acceptance for idempotent static-scan plus PRE_ANALYSIS orchestration. */
public final class AuditRunAcceptanceTest {
    private AuditRunAcceptanceTest() { }

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("veyrion-audit-run-");
        String token = "audit-run-token";
        HttpClient client = HttpClient.newHttpClient();
        String projectId;
        String body;
        String scanId;
        String jobId;
        try {
        try (ControlPlaneServer server = new ControlPlaneServer(
                root, 0, token, root.resolve("control.db"),
                (provider, credential) -> { throw new AssertionError("inventory is not used"); },
                (provider, credential, request, limits) -> {
                    String requestText = request.toString();
                    check(requestText.contains("SCAN_SUMMARY")
                                    && requestText.contains("ENTRY_SUMMARY")
                                    && requestText.contains("entryCount")
                                    && requestText.contains("entry ids")
                                    && requestText.contains("kind=ENTRY"),
                            "PRE prompt includes bounded static scan and entry summaries");
                    return new ProviderChatTransport.Response(
                            200,
                            ("{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"role\":\"assistant\","
                                    + "\"content\":\"evidence-linked pre-analysis\"}}]}")
                                    .getBytes(StandardCharsets.UTF_8),
                            "audit-request", 1);
                }).start()) {
            Path artifact = root.resolve("AuditEntryController.class");
            Files.writeString(artifact, "metadata-only audit fixture");
            projectId = text(ok(send(client, uri(server, "/projects"), "POST",
                    "{\"name\":\"Audit run\"}", token, "project")), "projectId");
            String artifactId = text(ok(send(client,
                    uri(server, "/projects/" + projectId + "/artifacts"), "POST",
                    "{\"path\":\"" + escape(artifact.toString()) + "\",\"type\":\"CLASS\"}",
                    token, "artifact")), "artifactId");
            String providerId = text(ok(send(client, uri(server, "/providers"), "POST",
                    "{\"name\":\"Audit provider\",\"kind\":\"OPENAI_CHAT\","
                            + "\"baseUrl\":\"http://127.0.0.1:3000\",\"model\":\"audit-model\","
                            + "\"apiKey\":\"audit-secret\"}", token, "provider")), "providerId");
            ok(send(client, uri(server, "/projects/" + projectId
                            + "/role-assignments/PRE_ANALYSIS"), "PATCH",
                    "{\"providerId\":\"" + providerId + "\",\"model\":\"audit-model\"}",
                    token, "binding"));

            URI auditRuns = uri(server, "/projects/" + projectId + "/audit-runs");
            body = "{\"artifactId\":\"" + artifactId
                    + "\",\"authorized\":true,\"aiAuthorized\":true,"
                    + "\"outputLanguage\":\"ZH_CN\","
                    + "\"networkMode\":\"DENY\",\"dangerousActionMode\":\"DRY_RUN\"}";
            HttpResponse<String> createdResponse = send(
                    client, auditRuns, "POST", body, token, "audit-once");
            check(createdResponse.statusCode() == 202, "audit run is accepted");
            Map<String, Object> created = ok(createdResponse);
            scanId = text(created, "scanId");
            Map<String, Object> job = object(created, "preAnalysisJob");
            jobId = text(job, "aiJobId");
            check(scanId.equals(object(created, "scan").get("scanId"))
                            && scanId.equals(job.get("scanId"))
                            && "PRE_ANALYSIS".equals(job.get("role"))
                            && "ZH_CN".equals(job.get("outputLanguage")),
                    "scan and PRE_ANALYSIS share one immutable scanId");
            check("COMPLETED".equals(awaitJob(client, server, jobId, token).get("status")),
                    "PRE_ANALYSIS completes");

            HttpResponse<String> secondResponse = send(
                    client, auditRuns, "POST", body, token, "audit-twice");
            check(secondResponse.statusCode() == 202,
                    "the same registered artifact accepts a distinct second audit");
            Map<String, Object> second = ok(secondResponse);
            String secondScanId = text(second, "scanId");
            String secondJobId = text(object(second, "preAnalysisJob"), "aiJobId");
            check(!scanId.equals(secondScanId) && !jobId.equals(secondJobId)
                            && "ZH_CN".equals(object(second, "preAnalysisJob").get("outputLanguage")),
                    "a new idempotency key creates a new immutable scan and language-bound job");
            check("COMPLETED".equals(awaitJob(client, server, secondJobId, token).get("status")),
                    "second PRE_ANALYSIS completes");

            HttpResponse<String> replayResponse = send(
                    client, auditRuns, "POST", body, token, "audit-once");
            check(replayResponse.statusCode() == 200, "audit run replay is idempotent");
            Map<String, Object> replay = ok(replayResponse);
            check(scanId.equals(replay.get("scanId"))
                            && jobId.equals(object(replay, "preAnalysisJob").get("aiJobId")),
                    "replay returns the original scan and job");
            Map<String, Object> jobs = ok(send(client,
                    uri(server, "/projects/" + projectId + "/ai-jobs"), "GET", "", token, null));
            long preAnalysisJobs = jobs.get("aiJobs") instanceof List<?> values
                    ? values.stream().filter(item -> item instanceof Map<?, ?> map
                            && "PRE_ANALYSIS".equals(map.get("role"))).count()
                    : -1L;
            check(preAnalysisJobs == 2,
                    "idempotent replay does not duplicate either PRE_ANALYSIS job");

            check(send(client, auditRuns, "POST",
                    body.replace("\"DENY\"", "\"ALLOWLIST\""), token, "audit-once").statusCode() == 409,
                    "same key with a different audit payload is rejected");
            check(send(client, auditRuns, "POST",
                    body.replace(",\"aiAuthorized\":true", ""), token, "audit-missing").statusCode() == 403,
                    "AI authorization is independently required");
            check(send(client, auditRuns, "POST",
                    body.replace("\"ZH_CN\"", "\"JA\""), token, "audit-language").statusCode() == 400,
                    "unsupported report language is rejected");
        }
        try (ControlPlaneServer restarted = new ControlPlaneServer(
                root, 0, token, root.resolve("control.db"),
                (provider, credential) -> { throw new AssertionError("inventory is not used"); },
                (provider, credential, request, limits) -> new ProviderChatTransport.Response(
                        200, "{\"choices\":[]}".getBytes(StandardCharsets.UTF_8),
                        "restart-request", 1)).start()) {
            HttpResponse<String> replayAfterRestart = send(client,
                    uri(restarted, "/projects/" + projectId + "/audit-runs"),
                    "POST", body, token, "audit-once");
            check(replayAfterRestart.statusCode() == 200, "audit replay survives restart");
            Map<String, Object> replay = ok(replayAfterRestart);
            check(scanId.equals(replay.get("scanId"))
                            && jobId.equals(object(replay, "preAnalysisJob").get("aiJobId")),
                    "restart replay returns the original immutable audit resources");
            Map<String, Object> jobs = ok(send(client,
                    uri(restarted, "/projects/" + projectId + "/ai-jobs"), "GET", "", token, null));
            long preAnalysisJobs = jobs.get("aiJobs") instanceof List<?> values
                    ? values.stream().filter(item -> item instanceof Map<?, ?> map
                            && "PRE_ANALYSIS".equals(map.get("role"))).count()
                    : -1L;
            check(preAnalysisJobs == 2,
                    "restart replay does not duplicate PRE_ANALYSIS jobs");
        }
        } finally {
            deleteTree(root);
        }
        System.out.println("AuditRunAcceptanceTest: PASS");
    }

    private static Map<String, Object> awaitJob(
            HttpClient client, ControlPlaneServer server, String jobId, String token) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        Map<String, Object> job = Map.of();
        while (System.nanoTime() < deadline) {
            job = ok(send(client, uri(server, "/ai-jobs/" + jobId), "GET", "", token, null));
            if (List.of("COMPLETED", "FAILED", "BLOCKED", "CANCELLED").contains(job.get("status"))) return job;
            Thread.sleep(20);
        }
        throw new AssertionError("AI job did not finish: " + job);
    }

    private static HttpResponse<String> send(
            HttpClient client, URI uri, String method, String body, String token, String key) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                .header("Content-Type", "application/json")
                .header("X-Sentinel-Authorization", token);
        if (key != null) builder.header("Idempotency-Key", key);
        HttpRequest.BodyPublisher publisher = HttpRequest.BodyPublishers.ofString(body);
        HttpRequest request = switch (method) {
            case "POST" -> builder.POST(publisher).build();
            case "PATCH" -> builder.method("PATCH", publisher).build();
            default -> builder.GET().build();
        };
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static URI uri(ControlPlaneServer server, String path) {
        return URI.create(server.baseUri() + path);
    }

    private static Map<String, Object> ok(HttpResponse<String> response) {
        check(response.statusCode() >= 200 && response.statusCode() < 300,
                "request succeeds: HTTP " + response.statusCode() + " " + response.body());
        return JsonCodec.parseObject(response.body());
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Map<String, Object> value, String field) {
        Object candidate = value.get(field);
        if (!(candidate instanceof Map<?, ?>)) throw new AssertionError("missing object " + field);
        return (Map<String, Object>) candidate;
    }

    private static String text(Map<String, Object> value, String field) {
        Object candidate = value.get(field);
        if (!(candidate instanceof String text) || text.isBlank()) {
            throw new AssertionError("missing " + field);
        }
        return text;
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) return;
        try (var paths = Files.walk(root)) {
            for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) {
                try {
                    Files.deleteIfExists(path);
                } catch (java.io.IOException ignored) {
                    path.toFile().deleteOnExit();
                }
            }
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
