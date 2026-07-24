package com.aq.jvmsentinel;

import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.JsonCodec;

import java.net.URI;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/** Dependency-free HTTP contract checks for the local Control Plane MVP. */
public final class ControlPlaneAcceptanceTest {
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("jvm-control-plane");
        Path artifact = root.resolve("UploadFileExecController.class");
        Files.writeString(artifact, "metadata-only fixture");
        try (ControlPlaneServer server = new ControlPlaneServer(root).start()) {
            HttpClient client = HttpClient.newHttpClient();
            URI base = server.baseUri();
            HttpResponse<String> unauthorized = request(client, URI.create(base + "/projects"), "POST", "{}", null);
            check(unauthorized.statusCode() == 401, "mutations require local token");

            HttpResponse<String> projectResponse = request(client, URI.create(base + "/projects"), "POST",
                    "{\"name\":\"fixture\"}", server.mutationToken(), "project-once");
            check(projectResponse.statusCode() == 201, "project create");
            Map<String, Object> project = JsonCodec.parseObject(projectResponse.body());
            String projectId = (String) project.get("projectId");
            HttpResponse<String> duplicateProject = request(client, URI.create(base + "/projects"), "POST",
                    "{\"name\":\"different\"}", server.mutationToken(), "project-once");
            check(duplicateProject.statusCode() == 200, "idempotent project replay");
            check(projectId.equals(JsonCodec.parseObject(duplicateProject.body()).get("projectId")), "idempotent project id");

            URI artifacts = URI.create(base + "/projects/" + projectId + "/artifacts");
            HttpResponse<String> artifactResponse = request(client, artifacts, "POST",
                    "{\"path\":\"" + escape(artifact.toString()) + "\"}", server.mutationToken(), "artifact-once");
            check(artifactResponse.statusCode() == 201, "artifact register");
            String digest = (String) JsonCodec.parseObject(artifactResponse.body()).get("artifactDigest");
            check(digest != null && digest.length() == 64, "artifact digest");
            HttpResponse<String> duplicateArtifact = request(client, artifacts, "POST",
                    "{\"path\":\"" + escape(artifact.toString()) + "\"}", server.mutationToken(), "artifact-once");
            check(duplicateArtifact.statusCode() == 200, "idempotent artifact replay");
            check(digest.equals(JsonCodec.parseObject(duplicateArtifact.body()).get("artifactDigest")), "idempotent artifact digest");

            URI scans = URI.create(base + "/projects/" + projectId + "/scans");
            HttpResponse<String> missingConsent = request(client, scans, "POST",
                    "{\"artifactDigest\":\"" + digest + "\"}", server.mutationToken());
            check(missingConsent.statusCode() == 403, "scan consent must be explicit");
            HttpResponse<String> scanResponse = request(client, scans, "POST",
                    "{\"artifactDigest\":\"" + digest + "\",\"authorized\":true}", server.mutationToken(), "scan-once");
            check(scanResponse.statusCode() == 202, "scan create");
            Map<String, Object> scan = JsonCodec.parseObject(scanResponse.body());
            check("STATIC_INFERRED".equals(scan.get("verificationStatus")), "scan must be static inferred");
            String scanId = (String) scan.get("scanId");
            HttpResponse<String> duplicateScan = request(client, scans, "POST",
                    "{\"artifactDigest\":\"" + digest + "\",\"authorized\":true}", server.mutationToken(), "scan-once");
            check(duplicateScan.statusCode() == 200, "idempotent scan replay");
            check(scanId.equals(JsonCodec.parseObject(duplicateScan.body()).get("scanId")), "idempotent scan id");
            HttpResponse<String> unauthorizedReplay = request(client, scans, "POST",
                    "{\"artifactDigest\":\"" + digest + "\"}", server.mutationToken(), "scan-once");
            check(unauthorizedReplay.statusCode() == 403, "scan replay still requires explicit consent");

            HttpResponse<String> dashboard = client.send(HttpRequest.newBuilder(
                    URI.create(base + "/projects/" + projectId + "/dashboard")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            check(dashboard.statusCode() == 200, "dashboard response");
            Map<String, Object> dashboardBody = JsonCodec.parseObject(dashboard.body());
            check(projectId.equals(dashboardBody.get("projectId")), "dashboard project scope");
            check(scanId.equals(dashboardBody.get("scanId")), "dashboard scan scope");
            check(((java.util.List<?>) dashboardBody.get("entries")).size() == 1, "entry DTO");

            HttpResponse<String> entries = client.send(HttpRequest.newBuilder(
                    URI.create(base + "/projects/" + projectId + "/entries")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            check(entries.statusCode() == 200 && JsonCodec.parseObject(entries.body()).containsKey("entries"),
                    "entries endpoint");
            HttpResponse<String> paths = client.send(HttpRequest.newBuilder(
                    URI.create(base + "/scans/" + scanId + "/paths")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            check(paths.statusCode() == 200, "paths endpoint");
            HttpResponse<String> evidenceList = client.send(HttpRequest.newBuilder(
                    URI.create(base + "/scans/" + scanId + "/evidence")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            check(evidenceList.statusCode() == 200, "evidence endpoint");
            java.util.List<?> evidenceItems = (java.util.List<?>) JsonCodec.parseObject(evidenceList.body()).get("evidence");
            check(!evidenceItems.isEmpty(), "evidence DTO");
            String evidenceId = (String) ((Map<?, ?>) evidenceItems.get(0)).get("evidenceId");
            HttpResponse<String> evidenceDetail = client.send(HttpRequest.newBuilder(
                    URI.create(base + "/evidence/" + evidenceId)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            check(evidenceDetail.statusCode() == 200, "evidence detail");

            HttpResponse<String> findings = client.send(HttpRequest.newBuilder(
                    URI.create(base + "/scans/" + scanId + "/findings")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            check(findings.statusCode() == 200, "findings endpoint");
            java.util.List<?> findingItems = (java.util.List<?>) JsonCodec.parseObject(findings.body()).get("findings");
            check(!findingItems.isEmpty(), "finding DTO");
            String findingId = (String) ((Map<?, ?>) findingItems.get(0)).get("findingId");
            HttpResponse<String> findingDetail = client.send(HttpRequest.newBuilder(
                    URI.create(base + "/findings/" + findingId)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            check(findingDetail.statusCode() == 200, "finding detail");

            check(server.sseHub().history(scanId).stream().anyMatch(e -> e.eventType().equals("ScanCompleted")),
                    "SSE completion event retained");
            String sse = readSse(server, scanId);
            check(sse.contains("event: ScanCompleted"), "SSE replay");
            check(sse.contains("\"schemaVersion\":1"), "SSE schema version");
            System.out.println("ControlPlaneAcceptanceTest: PASS");
        }
    }

    private static HttpResponse<String> request(HttpClient client, URI uri, String method, String body, String token)
            throws Exception {
        return request(client, uri, method, body, token, null);
    }

    private static HttpResponse<String> request(HttpClient client, URI uri, String method, String body,
                                                String token, String idempotencyKey) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri).header("Content-Type", "application/json");
        if (token != null) builder.header("X-Sentinel-Authorization", token);
        if (idempotencyKey != null) builder.header("Idempotency-Key", idempotencyKey);
        HttpRequest request = "POST".equals(method) ? builder.POST(HttpRequest.BodyPublishers.ofString(body)).build()
                : builder.GET().build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static String escape(String value) { return value.replace("\\", "\\\\").replace("\"", "\\\""); }
    private static String readSse(ControlPlaneServer server, String scanId) throws Exception {
        try (Socket socket = new Socket(server.address().getHostString(), server.address().getPort())) {
            socket.setSoTimeout(3000);
            String request = "GET /api/v1/scans/" + scanId + "/events HTTP/1.1\r\n"
                    + "Host: localhost\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n";
            socket.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();
            byte[] buffer = new byte[8192];
            StringBuilder result = new StringBuilder();
            while (!result.toString().contains("event: ScanCompleted")) {
                int count = socket.getInputStream().read(buffer);
                if (count < 0) break;
                result.append(new String(buffer, 0, count, StandardCharsets.UTF_8));
            }
            return result.toString();
        }
    }
    private static void check(boolean value, String message) { if (!value) throw new AssertionError(message); }
}
