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
 * P0-01 单 entry focus-probe API 的 acceptance：
 * 未授权 → 403，已授权 → 202 DYNAMIC_SUSPECTED，幂等 replay → 200，busy → 409。
 */
public final class EntryFocusProbeAcceptanceTest {
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("entry-focus-probe");
        try {
            Path jar = buildFixtureJar(root);
            String token = "focus-probe-token";
            HttpClient client = HttpClient.newHttpClient();
            try (ControlPlaneServer server = new ControlPlaneServer(
                    root, 0, token, root.resolve("state/control-plane.db")).start()) {
                URI base = server.baseUri();
                String projectId = text(request(client, URI.create(base + "/projects"), "POST",
                        "{\"name\":\"focus-probe\"}", token, "focus-project"), "projectId");
                String digest = text(request(client,
                        URI.create(base + "/projects/" + projectId + "/artifacts"), "POST",
                        "{\"path\":\"" + escape(jar.toString()) + "\"}", token, "focus-artifact"),
                        "artifactDigest");
                Map<String, Object> scan = json(request(client,
                        URI.create(base + "/projects/" + projectId + "/scans"), "POST",
                        "{\"artifactDigest\":\"" + digest + "\",\"authorized\":true}",
                        token, "focus-scan"));
                String scanId = text(scan, "scanId");
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> entries = (List<Map<String, Object>>) scan.get("entries");
                check(entries != null && !entries.isEmpty(), "scan exposes HTTP entries");
                String entryId = text(entries.get(0), "id");
                check("HTTP".equalsIgnoreCase(String.valueOf(entries.get(0).get("protocol"))),
                        "focus fixture entry is HTTP");

                URI focusUri = URI.create(base + "/scans/" + scanId + "/entries/" + entryId + "/focus-probe");

                HttpResponse<String> unauthorized = request(client, focusUri, "POST",
                        "{\"authorized\":false}", token, "focus-denied");
                check(unauthorized.statusCode() == 403, "focus-probe requires explicit authorization");
                check("AUTHORIZATION_REQUIRED".equals(json(unauthorized).get("code")),
                        "unauthorized focus-probe code");

                HttpResponse<String> missingKey = request(client, focusUri, "POST",
                        "{\"authorized\":true}", token);
                check(missingKey.statusCode() == 400, "focus-probe requires Idempotency-Key");

                HttpResponse<String> accepted = request(client, focusUri, "POST",
                        "{\"authorized\":true,\"maxRequests\":1}", token, "focus-once");
                check(accepted.statusCode() == 202, "authorized focus-probe accepted: " + accepted.body());
                Map<String, Object> body = json(accepted);
                check("DYNAMIC_SUSPECTED".equals(body.get("verificationStatus")),
                        "focus-probe returns DYNAMIC_SUSPECTED");
                check(!"VERIFIED".equals(body.get("verificationStatus")),
                        "focus-probe must not mark VERIFIED");
                check("MOCK".equals(body.get("dependencyMode")), "focus-probe dependencyMode is MOCK");
                check(Boolean.FALSE.equals(body.get("replayed")), "first focus-probe is not replayed");
                check(entryId.equals(body.get("entrypointId")), "focus-probe entrypointId");
                check(scanId.equals(body.get("scanId")), "focus-probe scanId");
                check(projectId.equals(body.get("projectId")), "focus-probe projectId");
                String taskId = text(body, "taskId");
                check(body.get("lifecycle") != null, "focus-probe lifecycle present");
                check(body.get("requiredCapability") != null, "focus-probe requiredCapability present");

                HttpResponse<String> replay = request(client, focusUri, "POST",
                        "{\"authorized\":true,\"maxRequests\":1}", token, "focus-once");
                check(replay.statusCode() == 200, "idempotent focus-probe replay");
                Map<String, Object> replayBody = json(replay);
                check(taskId.equals(replayBody.get("taskId")), "idempotent focus-probe same task");
                check(Boolean.TRUE.equals(replayBody.get("replayed")), "idempotent focus-probe replayed");
                check("DYNAMIC_SUSPECTED".equals(replayBody.get("verificationStatus")),
                        "idempotent replay stays DYNAMIC_SUSPECTED");

                // 首 task 仍 QUEUED（无 worker），第二 key 须 fail-closed busy。
                HttpResponse<String> busy = request(client, focusUri, "POST",
                        "{\"authorized\":true,\"maxRequests\":1}", token, "focus-busy");
                check(busy.statusCode() == 409, "busy scan rejects second focus-probe");
                check("DYNAMIC_TASK_BUSY".equals(json(busy).get("code")), "busy code DYNAMIC_TASK_BUSY");

                System.out.println("EntryFocusProbeAcceptanceTest: PASS");
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
        source(sources, "app/FocusController.java", """
                package app;
                import org.springframework.web.bind.annotation.*;
                @RestController
                public class FocusController {
                    @GetMapping("/focus")
                    public String focus(String q) { return q == null ? "ok" : q; }
                }
                """);
        compile(sources, classes);
        Path jar = root.resolve("focus-fixture.jar");
        try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(jar));
             Stream<Path> stream = Files.walk(classes)) {
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
                                                String token) throws Exception {
        return request(client, uri, method, body, token, null);
    }

    private static HttpResponse<String> request(HttpClient client, URI uri, String method, String body,
                                                String token, String idempotencyKey) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri).header("Content-Type", "application/json");
        if (token != null) builder.header("X-Sentinel-Authorization", token);
        if (idempotencyKey != null) builder.header("Idempotency-Key", idempotencyKey);
        HttpRequest request = "POST".equals(method)
                ? builder.POST(HttpRequest.BodyPublishers.ofString(body)).build()
                : builder.GET().build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
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
