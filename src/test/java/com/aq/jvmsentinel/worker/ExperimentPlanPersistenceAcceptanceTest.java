package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.model.ExperimentPlan;
import com.aq.jvmsentinel.model.IdentityTrack;

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

/** 实验计划在 Control Plane 重启后仍保留（V014）。 */
public final class ExperimentPlanPersistenceAcceptanceTest {
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("exp-plan-persist");
        try {
            Path jar = buildFixtureJar(root);
            Path database = root.resolve("state/control-plane.db");
            String token = "plan-persist-token";
            HttpClient client = HttpClient.newHttpClient();
            String projectId;
            String scanId;
            String planId = "plan:persist-1";
            String fuzzJson = "{\"sinkCategory\":\"SQL\",\"probeTemplates\":[\"union\"]}";
            try (ControlPlaneServer server = new ControlPlaneServer(root, 0, token, database).start()) {
                URI base = server.baseUri();
                projectId = text(request(client, URI.create(base + "/projects"), "POST",
                        "{\"name\":\"plan-persist\"}", token, "pp-project"), "projectId");
                String digest = text(request(client,
                        URI.create(base + "/projects/" + projectId + "/artifacts"), "POST",
                        "{\"path\":\"" + escape(jar.toString()) + "\"}", token, "pp-artifact"),
                        "artifactDigest");
                Map<String, Object> scan = json(request(client,
                        URI.create(base + "/projects/" + projectId + "/scans"), "POST",
                        "{\"artifactDigest\":\"" + digest + "\",\"authorized\":true}",
                        token, "pp-scan"));
                scanId = text(scan, "scanId");
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> entries = (List<Map<String, Object>>) scan.get("entries");
                String entryId = text(entries.get(0), "id");
                server.acceptExperimentPlan(scanId, new ExperimentPlan(
                        planId, "entry:" + entryId, IdentityTrack.UNAUTH, "GET",
                        "application/json", List.of(), false, "2xx", "", 2,
                        List.of("q=persisted"), "COMPLETED", "", fuzzJson));
                Map<String, Object> dashboard = json(request(client,
                        URI.create(base + "/projects/" + projectId + "/dashboard?scanId=" + scanId),
                        "GET", null, token, null));
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> plans =
                        (List<Map<String, Object>>) dashboard.get("experimentPlans");
                check(plans != null && plans.stream().anyMatch(row -> planId.equals(row.get("planId"))),
                        "plan visible before restart");
                check(plans.stream().anyMatch(row -> planId.equals(row.get("planId"))
                                && fuzzJson.equals(row.get("fuzzStrategyJson"))),
                        "dashboard emits fuzzStrategyJson");
                check(dashboard.get("verifiedFindings") instanceof List<?> verified && verified.isEmpty(),
                        "verifiedFindings remains empty scaffolding");
            }
            try (ControlPlaneServer restarted = new ControlPlaneServer(root, 0, token, database).start()) {
                Map<String, Object> dashboard = json(request(client,
                        URI.create(restarted.baseUri() + "/projects/" + projectId
                                + "/dashboard?scanId=" + scanId),
                        "GET", null, token, null));
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> plans =
                        (List<Map<String, Object>>) dashboard.get("experimentPlans");
                check(plans != null && plans.stream().anyMatch(row -> planId.equals(row.get("planId"))),
                        "plan restored after restart");
                check(plans.stream().anyMatch(row -> planId.equals(row.get("planId"))
                                && fuzzJson.equals(row.get("fuzzStrategyJson"))),
                        "fuzzStrategyJson restored after restart");
                Map<String, Object> health = json(request(client,
                        URI.create(restarted.baseUri() + "/health"), "GET", null, token, null));
                check(Boolean.FALSE.equals(health.get("verifiedAllowed")),
                        "health verifiedAllowed=false");
                check("TRUSTED_DOCKER_NEVER_VERIFIED".equals(health.get("verifiedReasonCode")),
                        "health verifiedReasonCode");
            }
            System.out.println("ExperimentPlanPersistenceAcceptanceTest: PASS");
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
        source(sources, "app/PersistController.java", """
                package app;
                import org.springframework.web.bind.annotation.*;
                @RestController
                public class PersistController {
                    @GetMapping("/focus")
                    public String focus(String q) { return q == null ? "ok" : q; }
                }
                """);
        compile(sources, classes);
        Path jar = root.resolve("persist-fixture.jar");
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
                                                String token, String idempotencyKey) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri).header("Content-Type", "application/json");
        if (token != null) builder.header("X-Sentinel-Authorization", token);
        if (idempotencyKey != null) builder.header("Idempotency-Key", idempotencyKey);
        HttpRequest request = "GET".equals(method)
                ? builder.GET().build()
                : builder.method(method, HttpRequest.BodyPublishers.ofString(body == null ? "" : body)).build();
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
