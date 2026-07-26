package com.aq.jvmsentinel;

import com.aq.jvmsentinel.artifact.ArtifactRegistry;
import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.model.ArtifactDescriptor;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Main-style HTTP acceptance checks for bounded managed artifact uploads. */
public final class ArtifactUploadAcceptanceTest {
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("veyrion-artifact-upload");
        byte[] jar = validJar();
        Path source = root.resolve("browser-selected.jar");
        Files.write(source, jar);
        String digest = sha256(jar);
        Path uploadRoot = Files.createDirectories(root.resolve(".veyrion").resolve("uploads"));
        Path stalePart = uploadRoot.resolve("upload-" + "0".repeat(32) + ".part");
        Files.writeString(stalePart, "abandoned");
        Path retainedContent = Files.createDirectories(root.resolve(".veyrion").resolve("artifacts")
                .resolve("sha256").resolve("ff")).resolve("retained.jar");
        Files.writeString(retainedContent, "must-not-be-cleaned");

        restartResume(root, jar);

        try (ControlPlaneServer server = new ControlPlaneServer(root).start()) {
            check(!Files.exists(stalePart), "Startup must remove abandoned upload parts");
            check(Files.exists(retainedContent), "Startup must not remove content storage");
            HttpClient client = HttpClient.newHttpClient();
            String base = server.baseUri().toString();
            String projectId = createProject(client, base, server.mutationToken(), "upload-primary");
            String otherProjectId = createProject(client, base, server.mutationToken(), "upload-other");
            server.artifactRegistry().register(source);

            HttpResponse<String> workerRejected = initialize(client, base, projectId,
                    "worker.jar", jar.length, digest, server.workerToken());
            check(workerRejected.statusCode() == 401, "Worker token must not initialize uploads");

            String uploadId = uploadId(initializeOk(client, base, projectId,
                    "fixture.jar", jar.length, digest, server.mutationToken()));
            int split = Math.max(1, jar.length / 2);
            byte[] first = java.util.Arrays.copyOfRange(jar, 0, split);
            byte[] second = java.util.Arrays.copyOfRange(jar, split, jar.length);

            HttpResponse<String> tampered = put(client, base, projectId, uploadId, 0,
                    first, "0".repeat(64), server.mutationToken());
            check(tampered.statusCode() == 422, "Tampered chunk must be rejected");
            check(nextOffset(put(client, base, projectId, uploadId, 0,
                    first, sha256(first), server.mutationToken())) == split,
                    "First chunk must advance offset");

            HttpResponse<String> outOfOrder = put(client, base, projectId, uploadId, split + 1L,
                    second, sha256(second), server.mutationToken());
            check(outOfOrder.statusCode() == 409, "Out-of-order chunk must be rejected");
            HttpResponse<String> crossProject = put(client, base, otherProjectId, uploadId, split,
                    second, sha256(second), server.mutationToken());
            check(crossProject.statusCode() == 404, "Upload session must be project scoped");
            check(nextOffset(put(client, base, projectId, uploadId, split,
                    second, sha256(second), server.mutationToken())) == jar.length,
                    "Second chunk must complete bytes");

            HttpResponse<String> noAuthorization = complete(client, base, projectId, uploadId,
                    false, server.mutationToken());
            check(noAuthorization.statusCode() == 403, "Completion must require explicit authorization");
            HttpResponse<String> completed = complete(client, base, projectId, uploadId,
                    true, server.mutationToken());
            check(completed.statusCode() == 201, "Valid upload must complete");
            check(digest.equals(JsonCodec.parseObject(completed.body()).get("artifactDigest")),
                    "Completed artifact digest");

            Path managed = root.resolve(".veyrion").resolve("artifacts").resolve("sha256")
                    .resolve(digest.substring(0, 2)).resolve(digest + ".jar");
            check(Files.isRegularFile(managed, LinkOption.NOFOLLOW_LINKS), "Content-addressed artifact path");
            check(Files.isSameFile(managed, server.store().artifact(
                    server.store().requireProject(projectId), digest).normalizedPath()),
                    "Project registration must reference managed copy");

            Files.delete(source);
            ArtifactDescriptor descriptor = server.store().artifact(server.store().requireProject(projectId), digest);
            server.artifactRegistry().verifyUnchanged(descriptor);
            HttpResponse<String> scan = json(client, URI.create(base + "/projects/" + projectId + "/scans"),
                    "POST", "{\"artifactDigest\":\"" + digest + "\",\"authorized\":true}",
                    server.mutationToken());
            check(scan.statusCode() == 202, "Managed copy must remain scannable after source deletion");

            String duplicateId = uploadId(initializeOk(client, base, projectId,
                    "duplicate.jar", jar.length, digest, server.mutationToken()));
            check(put(client, base, projectId, duplicateId, 0, jar, digest,
                    server.mutationToken()).statusCode() == 200, "Duplicate bytes upload");
            check(complete(client, base, projectId, duplicateId, true,
                    server.mutationToken()).statusCode() == 201, "Same digest completion is idempotent");
            check(Files.isSameFile(managed, server.store().artifact(
                    server.store().requireProject(projectId), digest).normalizedPath()),
                    "Same digest must retain one managed path");

            byte[] corruptZip = "not-a-zip".getBytes(StandardCharsets.UTF_8);
            String corruptId = uploadId(initializeOk(client, base, projectId,
                    "corrupt.war", corruptZip.length, sha256(corruptZip), server.mutationToken()));
            put(client, base, projectId, corruptId, 0, corruptZip, sha256(corruptZip), server.mutationToken());
            check(complete(client, base, projectId, corruptId, true,
                    server.mutationToken()).statusCode() == 422, "Corrupt ZIP must be rejected");
            check(delete(client, base, projectId, corruptId, server.mutationToken()).statusCode() == 204,
                    "Rejected upload must be cancellable");

            byte[] tooLarge = new byte[4 * 1024 * 1024 + 1];
            String tooLargeDigest = sha256(tooLarge);
            String tooLargeId = uploadId(initializeOk(client, base, projectId,
                    "large.class", tooLarge.length, tooLargeDigest, server.mutationToken()));
            try {
                check(put(client, base, projectId, tooLargeId, 0, tooLarge, tooLargeDigest,
                        server.mutationToken()).statusCode() == 413, "Chunk hard limit must be enforced");
            } catch (java.io.IOException transportRejected) {
                // The bounded HTTP body reader may close the connection before
                // a response when a client exceeds the request hard limit.
            }
            delete(client, base, projectId, tooLargeId, server.mutationToken());

            byte[] boundary = new byte[]{1, 2, 3};
            String boundaryId = uploadId(initializeOk(client, base, projectId,
                    "boundary.class", 2, sha256(new byte[]{1, 2}), server.mutationToken()));
            check(put(client, base, projectId, boundaryId, 0, boundary, sha256(boundary),
                    server.mutationToken()).statusCode() == 413, "Declared size boundary must be enforced");
            delete(client, base, projectId, boundaryId, server.mutationToken());

            HttpResponse<String> badName = initialize(client, base, projectId,
                    "../client-path.jar", jar.length, digest, server.mutationToken());
            check(badName.statusCode() == 400, "Client paths must not be accepted as file names");

            HttpResponse<String> cors = client.send(HttpRequest.newBuilder(
                            URI.create(base + "/projects/" + projectId + "/artifact-uploads"))
                    .header("Origin", "http://localhost:5173")
                    .method("OPTIONS", HttpRequest.BodyPublishers.noBody()).build(),
                    HttpResponse.BodyHandlers.ofString());
            check(cors.statusCode() == 204
                            && cors.headers().firstValue("Access-Control-Allow-Methods").orElse("").contains("PUT")
                            && cors.headers().firstValue("Access-Control-Allow-Headers").orElse("")
                            .contains("X-Chunk-SHA256"),
                    "CORS must allow upload method and digest header");
            System.out.println("ArtifactUploadAcceptanceTest: PASS");
        }
    }

    private static void restartResume(Path root, byte[] jar) throws Exception {
        Path database = root.resolve("control-plane.db");
        String token = "restart-token";
        String digest = sha256(jar);
        String uploadId;
        String projectId = null;
        int split = Math.max(1, jar.length / 2);
        try (ControlPlaneServer first = new ControlPlaneServer(root, 0, token, database).start()) {
            HttpClient client = HttpClient.newHttpClient();
            String base = first.baseUri().toString();
            projectId = createProject(client, base, token, "restart-project");
            uploadId = uploadId(initializeOk(client, base, projectId, "restart.jar", jar.length,
                    digest, token));
            byte[] firstChunk = java.util.Arrays.copyOfRange(jar, 0, split);
            check(nextOffset(put(client, base, projectId, uploadId, 0, firstChunk,
                    sha256(firstChunk), token)) == split, "Restart fixture first chunk");
        }
        try (ControlPlaneServer second = new ControlPlaneServer(root, 0, token, database).start()) {
            HttpClient client = HttpClient.newHttpClient();
            String base = second.baseUri().toString();
            byte[] remaining = java.util.Arrays.copyOfRange(jar, split, jar.length);
            check(nextOffset(put(client, base, projectId, uploadId, split, remaining,
                    sha256(remaining), token)) == jar.length, "Restart fixture resumed offset");
            check(complete(client, base, projectId, uploadId, true, token).statusCode() == 201,
                    "Restart fixture completion");
        }
    }

    private static String createProject(HttpClient client, String base, String token, String name) throws Exception {
        HttpResponse<String> response = json(client, URI.create(base + "/projects"), "POST",
                "{\"name\":\"" + name + "\"}", token);
        check(response.statusCode() == 201, "Project creation");
        return (String) JsonCodec.parseObject(response.body()).get("projectId");
    }

    private static HttpResponse<String> initializeOk(HttpClient client, String base, String projectId,
                                                      String fileName, long size, String digest,
                                                      String token) throws Exception {
        HttpResponse<String> response = initialize(client, base, projectId, fileName, size, digest, token);
        check(response.statusCode() == 201, "Upload initialization: " + response.body());
        return response;
    }

    private static HttpResponse<String> initialize(HttpClient client, String base, String projectId,
                                                    String fileName, long size, String digest,
                                                    String token) throws Exception {
        String body = "{\"fileName\":\"" + fileName + "\",\"sizeBytes\":" + size
                + ",\"sha256\":\"" + digest + "\"}";
        return json(client, URI.create(base + "/projects/" + projectId + "/artifact-uploads"),
                "POST", body, token);
    }

    private static HttpResponse<String> put(HttpClient client, String base, String projectId,
                                            String uploadId, long offset, byte[] bytes,
                                            String digest, String token) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(base + "/projects/" + projectId
                        + "/artifact-uploads/" + uploadId + "?offset=" + offset))
                .header("X-Sentinel-Authorization", token)
                .header("Content-Type", "application/octet-stream")
                .header("X-Chunk-SHA256", digest)
                .PUT(HttpRequest.BodyPublishers.ofByteArray(bytes)).build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> complete(HttpClient client, String base, String projectId,
                                                 String uploadId, boolean authorized,
                                                 String token) throws Exception {
        return json(client, URI.create(base + "/projects/" + projectId + "/artifact-uploads/"
                + uploadId + "/complete"), "POST", "{\"authorized\":" + authorized + "}", token);
    }

    private static HttpResponse<String> delete(HttpClient client, String base, String projectId,
                                               String uploadId, String token) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(base + "/projects/" + projectId
                        + "/artifact-uploads/" + uploadId))
                .header("X-Sentinel-Authorization", token).DELETE().build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> json(HttpClient client, URI uri, String method,
                                             String body, String token) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri).header("Content-Type", "application/json");
        if (token != null) builder.header("X-Sentinel-Authorization", token);
        return client.send(builder.method(method, HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static String uploadId(HttpResponse<String> response) {
        return (String) JsonCodec.parseObject(response.body()).get("uploadId");
    }

    private static long nextOffset(HttpResponse<String> response) {
        check(response.statusCode() == 200, "Chunk response: " + response.body());
        return ((Number) JsonCodec.parseObject(response.body()).get("nextOffset")).longValue();
    }

    private static byte[] validJar() throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
            zip.putNextEntry(new ZipEntry("sample/UploadController.class"));
            zip.write("metadata-only fixture".getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
        }
        return bytes.toByteArray();
    }

    private static String sha256(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
