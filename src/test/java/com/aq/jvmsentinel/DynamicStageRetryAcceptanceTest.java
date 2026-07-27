package com.aq.jvmsentinel;

import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.JsonCodec;

import javax.tools.JavaCompiler;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Stage retry for DYNAMIC_OBSERVATION: terminal FAILED allows retry; leftover QUEUED is
 * superseded; focus-probe stays fail-closed busy while a live task exists.
 */
public final class DynamicStageRetryAcceptanceTest {
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("dynamic-stage-retry");
        try {
            Path jar = buildFixtureJar(root);
            String token = "dynamic-stage-retry-token";
            HttpClient client = HttpClient.newHttpClient();
            try (ControlPlaneServer server = new ControlPlaneServer(
                    root, 0, token, root.resolve("state/control-plane.db")).start()) {
                URI base = server.baseUri();
                String projectId = text(request(client, URI.create(base + "/projects"), "POST",
                        "{\"name\":\"dynamic-stage-retry\"}", token, "dsr-project"), "projectId");
                String digest = text(request(client,
                        URI.create(base + "/projects/" + projectId + "/artifacts"), "POST",
                        "{\"path\":\"" + escape(jar.toString()) + "\"}", token, "dsr-artifact"),
                        "artifactDigest");
                Map<String, Object> scan = json(request(client,
                        URI.create(base + "/projects/" + projectId + "/scans"), "POST",
                        "{\"artifactDigest\":\"" + digest + "\",\"authorized\":true}",
                        token, "dsr-scan"));
                String scanId = text(scan, "scanId");
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> entries = (List<Map<String, Object>>) scan.get("entries");
                check(entries != null && !entries.isEmpty(), "scan exposes HTTP entries");
                String entryId = text(entries.get(0), "id");

                URI retryUri = URI.create(base + "/projects/" + projectId + "/audit-stage-retries");
                URI dynamicUri = URI.create(base + "/scans/" + scanId + "/dynamic-tasks");
                URI focusUri = URI.create(base + "/scans/" + scanId + "/entries/" + entryId + "/focus-probe");
                URI workerBase = base.resolve("/internal/worker/v1/");

                // 1) QUEUED dynamic task blocks focus-probe (fail-closed), but stage retry supersedes.
                HttpResponse<String> queued = request(client, dynamicUri, "POST",
                        "{\"authorized\":true}", token, "dsr-dynamic-queued");
                check(queued.statusCode() == 202, "create dynamic task: " + queued.body());
                Map<String, Object> queuedBody = json(queued);
                check("QUEUED".equals(queuedBody.get("status")), "first dynamic task is QUEUED");
                String queuedTaskId = text(queuedBody, "taskId");

                HttpResponse<String> busyFocus = request(client, focusUri, "POST",
                        "{\"authorized\":true,\"maxRequests\":1}", token, "dsr-focus-busy");
                check(busyFocus.statusCode() == 409, "focus-probe busy while QUEUED");
                check("DYNAMIC_TASK_BUSY".equals(json(busyFocus).get("code")), "focus busy code");

                HttpResponse<String> retrySupersede = request(client, retryUri, "POST",
                        "{\"scanId\":\"" + scanId + "\",\"stage\":\"DYNAMIC_OBSERVATION\",\"authorized\":true}",
                        token, "dsr-retry-supersede");
                check(retrySupersede.statusCode() == 202, "stage retry supersedes QUEUED: " + retrySupersede.body());
                Map<String, Object> supersedeBody = json(retrySupersede);
                check(Boolean.TRUE.equals(supersedeBody.get("pipelineArmed")), "retry arms pipeline");
                @SuppressWarnings("unchecked")
                Map<String, Object> newTask = (Map<String, Object>) supersedeBody.get("dynamicTask");
                check(newTask != null, "retry returns dynamicTask");
                String retryTaskId = text(newTask, "taskId");
                check(!queuedTaskId.equals(retryTaskId), "retry enqueues a new task id");
                check(Number.class.cast(supersedeBody.get("supersededCount")).intValue() >= 1,
                        "retry reports supersededCount");

                Map<String, Object> cancelled = workerGet(client,
                        URI.create(workerBase + "tasks/" + queuedTaskId
                                + "?projectId=" + projectId + "&artifactDigest=" + digest + "&scanId=" + scanId),
                        server.workerToken());
                check("CANCELLED".equals(cancelled.get("lifecycle")), "superseded QUEUED becomes CANCELLED");

                // 2) FAILED (EXTERNAL_ARTIFACT_REJECTED) is terminal — stage retry must succeed again.
                String scope = "\"projectId\":\"" + projectId + "\",\"artifactDigest\":\"" + digest
                        + "\",\"scanId\":\"" + scanId + "\",\"taskId\":\"" + retryTaskId + "\"";
                HttpResponse<String> lease = workerPost(client,
                        URI.create(workerBase + "tasks/" + retryTaskId + "/lease"),
                        "{" + scope + ",\"workerId\":\"dsr-worker\",\"capabilities\":[\"TRUSTED_DOCKER\"],"
                                + "\"durationSeconds\":120}",
                        server.workerToken(), "dsr-lease");
                check(lease.statusCode() == 200, "lease retry task: " + lease.body());
                String leaseId = text(json(lease), "leaseId");
                HttpResponse<String> failed = workerPost(client,
                        URI.create(workerBase + "tasks/" + retryTaskId + "/fail"),
                        "{" + scope + ",\"leaseId\":\"" + leaseId + "\",\"workerId\":\"dsr-worker\","
                                + "\"reason\":\"WORKER_FAILURE\",\"failureCode\":\"EXTERNAL_ARTIFACT_REJECTED\","
                                + "\"failureDiagnostic\":\"upload host file size is outside trusted sandbox limits\"}",
                        server.workerToken(), "dsr-fail");
                check(failed.statusCode() == 200, "fail retry task: " + failed.body());
                check("FAILED".equals(json(failed).get("lifecycle")), "failed lifecycle");
                check("EXTERNAL_ARTIFACT_REJECTED".equals(json(failed).get("failureCode")),
                        "failed failureCode");

                HttpResponse<String> retryAfterFail = request(client, retryUri, "POST",
                        "{\"scanId\":\"" + scanId + "\",\"stage\":\"DYNAMIC_OBSERVATION\",\"authorized\":true}",
                        token, "dsr-retry-after-fail");
                check(retryAfterFail.statusCode() == 202,
                        "stage retry after FAILED: " + retryAfterFail.body());
                @SuppressWarnings("unchecked")
                Map<String, Object> afterFailTask = (Map<String, Object>) json(retryAfterFail).get("dynamicTask");
                check(afterFailTask != null, "retry-after-fail returns dynamicTask");
                check("QUEUED".equals(afterFailTask.get("status")), "new task after FAILED is QUEUED");
                check(!retryTaskId.equals(text(afterFailTask, "taskId")),
                        "retry-after-fail creates a distinct task");

                // 3) Live QUEUED still blocks focus-probe (no silent supersede on probe path).
                HttpResponse<String> stillBusy = request(client, focusUri, "POST",
                        "{\"authorized\":true,\"maxRequests\":1}", token, "dsr-focus-still-busy");
                check(stillBusy.statusCode() == 409, "focus-probe still fail-closed busy");
                check("DYNAMIC_TASK_BUSY".equals(json(stillBusy).get("code")), "focus still busy code");

                System.out.println("DynamicStageRetryAcceptanceTest: PASS");
            }
        } finally {
            deleteTree(root);
        }
    }

    private static Path buildFixtureJar(Path root) throws Exception {
        Path sources = Files.createDirectories(root.resolve("sources"));
        Path classes = Files.createDirectories(root.resolve("classes"));
        source(sources, "org/springframework/web/bind/annotation/RestController.java", """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE)
                public @interface RestController {}
                """);
        source(sources, "org/springframework/web/bind/annotation/GetMapping.java", """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
                public @interface GetMapping { String[] value() default {}; String[] path() default {}; }
                """);
        source(sources, "app/RetryController.java", """
                package app;
                import org.springframework.web.bind.annotation.*;
                @RestController
                public class RetryController {
                    @GetMapping("/retry")
                    public String retry(String q) { return q == null ? "ok" : q; }
                }
                """);
        compile(sources, classes);
        Path jar = root.resolve("retry-fixture.jar");
        try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(jar));
             Stream<Path> stream = Files.walk(classes)) {
            output.putNextEntry(new ZipEntry("META-INF/MANIFEST.MF"));
            output.write("Manifest-Version: 1.0\nMain-Class: app.RetryController\n\n"
                    .getBytes(StandardCharsets.UTF_8));
            output.closeEntry();
            for (Path file : stream.filter(Files::isRegularFile).toList()) {
                output.putNextEntry(new ZipEntry(
                        "BOOT-INF/classes/" + classes.relativize(file).toString().replace('\\', '/')));
                Files.copy(file, output);
                output.closeEntry();
            }
        }
        return jar;
    }

    private static void source(Path root, String relative, String content) throws Exception {
        Path file = root.resolve(relative);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content, StandardCharsets.UTF_8);
    }

    private static void compile(Path sources, Path classes) throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        check(compiler != null, "tests require a JDK compiler");
        List<Path> sourceFiles;
        try (Stream<Path> stream = Files.walk(sources)) {
            sourceFiles = stream.filter(path -> path.toString().endsWith(".java")).toList();
        }
        try (StandardJavaFileManager manager =
                     compiler.getStandardFileManager(null, null, StandardCharsets.UTF_8)) {
            boolean success = compiler.getTask(null, manager, null,
                    List.of("--release", "17", "-parameters", "-d", classes.toString()), null,
                    manager.getJavaFileObjectsFromPaths(sourceFiles)).call();
            check(success, "fixture compilation");
        }
    }

    private static HttpResponse<String> request(HttpClient client, URI uri, String method, String body,
                                                String token, String idempotencyKey) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri).header("Content-Type", "application/json");
        if (token != null) builder.header("X-Sentinel-Authorization", token);
        if (idempotencyKey != null) builder.header("Idempotency-Key", idempotencyKey);
        HttpRequest httpRequest = "POST".equals(method)
                ? builder.POST(HttpRequest.BodyPublishers.ofString(body)).build()
                : builder.GET().build();
        return client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> workerPost(HttpClient client, URI uri, String body, String token,
                                                   String key) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri).header("Content-Type", "application/json");
        if (token != null) builder.header("X-Sentinel-Worker-Authorization", token);
        if (key != null) builder.header("Idempotency-Key", key);
        return client.send(builder.POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static Map<String, Object> workerGet(HttpClient client, URI uri, String token) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri);
        if (token != null) builder.header("X-Sentinel-Worker-Authorization", token);
        HttpResponse<String> response = client.send(builder.GET().build(), HttpResponse.BodyHandlers.ofString());
        check(response.statusCode() == 200, "worker get: " + response.body());
        return JsonCodec.parseObject(response.body());
    }

    private static Map<String, Object> json(HttpResponse<String> response) {
        return JsonCodec.parseObject(response.body());
    }

    private static String text(HttpResponse<String> response, String key) {
        return text(json(response), key);
    }

    private static String text(Map<String, Object> body, String key) {
        Object value = body.get(key);
        check(value instanceof String text && !text.isBlank(), key + " present");
        return (String) value;
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) return;
        try (Stream<Path> walk = Files.walk(root)) {
            List<Path> paths = walk.sorted((left, right) -> right.compareTo(left)).toList();
            for (Path path : paths) Files.deleteIfExists(path);
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
