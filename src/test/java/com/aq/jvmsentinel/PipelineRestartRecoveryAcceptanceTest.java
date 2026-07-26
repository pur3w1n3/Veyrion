package com.aq.jvmsentinel;

import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.provider.chat.ProviderChatTransport;

import javax.tools.ToolProvider;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

/** Proves that an armed pipeline and its queued dynamic task survive a Control Plane restart. */
public final class PipelineRestartRecoveryAcceptanceTest {
    private PipelineRestartRecoveryAcceptanceTest() { }

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("veyrion-pipeline-restart-");
        Path database = root.resolve("control.db");
        Path artifact = executableControllerJar(root);
        String token = "pipeline-restart-token";
        HttpClient client = HttpClient.newHttpClient();
        String projectId;
        String scanId;
        String taskId;
        try {
            try (ControlPlaneServer first = server(root, database, token).start()) {
                projectId = text(ok(send(client, uri(first, "/projects"), "POST",
                        "{\"name\":\"pipeline restart\"}", token, "project")), "projectId");
                String artifactId = text(ok(send(client,
                        uri(first, "/projects/" + projectId + "/artifacts"), "POST",
                        "{\"path\":\"" + escape(artifact.toString()) + "\"}", token, "artifact")),
                        "artifactId");
                String providerId = text(ok(send(client, uri(first, "/providers"), "POST",
                        "{\"name\":\"pipeline provider\",\"kind\":\"OPENAI_CHAT\"," +
                                "\"baseUrl\":\"http://127.0.0.1:3000\",\"model\":\"pipeline-model\"," +
                                "\"apiKey\":\"pipeline-secret\"}", token, "provider")), "providerId");
                for (String role : List.of("PRE_ANALYSIS", "AUTH_ANALYSIS")) {
                    ok(send(client, uri(first, "/projects/" + projectId + "/role-assignments/" + role),
                            "PATCH", "{\"providerId\":\"" + providerId + "\",\"model\":\"pipeline-model\"}",
                            token, "binding-" + role));
                }
                Map<String, Object> audit = ok(send(client,
                        uri(first, "/projects/" + projectId + "/audit-runs"), "POST",
                        "{\"artifactId\":\"" + artifactId + "\",\"authorized\":true,"
                                + "\"aiAuthorized\":true,\"outputLanguage\":\"ZH_CN\","
                                + "\"networkMode\":\"DENY\",\"dangerousActionMode\":\"DRY_RUN\"}",
                        token, "audit"));
                scanId = text(audit, "scanId");
                String jobId = text(object(audit, "preAnalysisJob"), "aiJobId");
                check("COMPLETED".equals(awaitJob(client, first, jobId, token).get("status")),
                        "PRE_ANALYSIS completes before restart");
                String authJobId = awaitRoleJob(client, first, projectId, scanId, "AUTH_ANALYSIS", token);
                check("COMPLETED".equals(awaitJob(client, first, authJobId, token).get("status")),
                        "AUTH_ANALYSIS completes before dynamic observation");
                Map<String, Object> task = awaitSingleTask(client, first, scanId, token);
                taskId = text(task, "taskId");
                check(List.of("QUEUED", "LEASED", "RUNNING", "PAUSED").contains(task.get("status")),
                        "dynamic observation is still active when the server stops");
            }

            try (ControlPlaneServer restarted = server(root, database, token).start()) {
                Map<String, Object> restored = awaitSingleTask(client, restarted, scanId, token);
                check(taskId.equals(restored.get("taskId")), "restart restores the original dynamic task");
                Map<String, Object> tasks = ok(send(client,
                        uri(restarted, "/scans/" + scanId + "/dynamic-tasks"), "GET", "", token, null));
                check(tasks.get("dynamicTasks") instanceof List<?> values && values.size() == 1,
                        "pipeline recovery does not enqueue a duplicate dynamic task");
                Map<String, Object> jobs = ok(send(client,
                        uri(restarted, "/projects/" + projectId + "/ai-jobs"), "GET", "", token, null));
                long completedRoles = jobs.get("aiJobs") instanceof List<?> values
                        ? values.stream().filter(item -> item instanceof Map<?, ?> map
                                && List.of("PRE_ANALYSIS", "AUTH_ANALYSIS").contains(map.get("role"))
                                && "COMPLETED".equals(map.get("status"))).count()
                        : -1L;
                check(completedRoles == 2,
                        "pipeline recovery does not duplicate completed PRE/AUTH jobs");
            }

            try (var connection = DriverManager.getConnection("jdbc:sqlite:" + database);
                 var statement = connection.prepareStatement(
                         "SELECT armed,next_stage FROM audit_pipeline_runs WHERE scan_id=?")) {
                statement.setString(1, scanId);
                try (var rows = statement.executeQuery()) {
                    check(rows.next() && rows.getInt(1) == 1
                                    && "DYNAMIC_OBSERVATION".equals(rows.getString(2)),
                            "pipeline cursor remains armed at the active dynamic stage");
                }
            }
        } finally {
            deleteTree(root);
        }
        System.out.println("PipelineRestartRecoveryAcceptanceTest: PASS");
    }

    private static ControlPlaneServer server(Path root, Path database, String token) {
        return new ControlPlaneServer(root, 0, token, database,
                (provider, credential) -> { throw new AssertionError("inventory is not used"); },
                (provider, credential, request, limits) -> new ProviderChatTransport.Response(
                        200, ("{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{" +
                                "\"role\":\"assistant\",\"content\":\"pre-analysis complete\"}}]}")
                                .getBytes(StandardCharsets.UTF_8), "pipeline-request", 1));
    }

    private static Path executableControllerJar(Path root) throws Exception {
        Path sources = Files.createDirectories(root.resolve("sources"));
        Path classes = Files.createDirectories(root.resolve("classes"));
        source(sources, "org/springframework/web/bind/annotation/RestController.java", """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE)
                public @interface RestController { }
                """);
        source(sources, "org/springframework/web/bind/annotation/GetMapping.java", """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
                public @interface GetMapping { String[] value() default {}; String[] path() default {}; }
                """);
        source(sources, "app/RestartController.java", """
                package app;
                import org.springframework.web.bind.annotation.*;
                @RestController
                public class RestartController {
                    public static void main(String[] args) { }
                    @GetMapping("/restart") public String restart() { return "ok"; }
                }
                """);
        var compiler = ToolProvider.getSystemJavaCompiler();
        check(compiler != null, "JDK compiler is required");
        List<String> files;
        try (var stream = Files.walk(sources)) {
            files = stream.filter(path -> path.toString().endsWith(".java")).map(Path::toString).toList();
        }
        List<String> arguments = new java.util.ArrayList<>(List.of("-d", classes.toString(), "--release", "17"));
        arguments.addAll(files);
        check(compiler.run(null, null, null, arguments.toArray(String[]::new)) == 0,
                "controller fixture compiles");
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().put(Attributes.Name.MAIN_CLASS, "app.RestartController");
        Path jar = root.resolve("restart-controller.jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar), manifest);
             var stream = Files.walk(classes)) {
            for (Path file : stream.filter(Files::isRegularFile).toList()) {
                String entry = classes.relativize(file).toString().replace('\\', '/');
                output.putNextEntry(new JarEntry(entry));
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

    private static Map<String, Object> awaitJob(HttpClient client, ControlPlaneServer server,
                                                 String jobId, String token) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (System.nanoTime() < deadline) {
            Map<String, Object> job = ok(send(client, uri(server, "/ai-jobs/" + jobId),
                    "GET", "", token, null));
            if (List.of("COMPLETED", "FAILED", "BLOCKED", "CANCELLED").contains(job.get("status"))) return job;
            Thread.sleep(20);
        }
        throw new AssertionError("AI job did not finish");
    }

    private static String awaitRoleJob(HttpClient client, ControlPlaneServer server, String projectId,
                                       String scanId, String role, String token) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (System.nanoTime() < deadline) {
            Map<String, Object> jobs = ok(send(client,
                    uri(server, "/projects/" + projectId + "/ai-jobs"), "GET", "", token, null));
            if (jobs.get("aiJobs") instanceof List<?> values) {
                for (Object item : values) {
                    if (item instanceof Map<?, ?> map
                            && scanId.equals(map.get("scanId"))
                            && role.equals(map.get("role"))
                            && map.get("aiJobId") instanceof String jobId
                            && !jobId.isBlank()) {
                        return jobId;
                    }
                }
            }
            Thread.sleep(20);
        }
        throw new AssertionError(role + " job was not created");
    }

    private static Map<String, Object> awaitSingleTask(HttpClient client, ControlPlaneServer server,
                                                       String scanId, String token) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (System.nanoTime() < deadline) {
            Map<String, Object> response = ok(send(client,
                    uri(server, "/scans/" + scanId + "/dynamic-tasks"), "GET", "", token, null));
            if (response.get("dynamicTasks") instanceof List<?> values && values.size() == 1) {
                return objectValue(values.get(0));
            }
            Thread.sleep(20);
        }
        throw new AssertionError("dynamic task was not queued");
    }

    private static HttpResponse<String> send(HttpClient client, URI uri, String method, String body,
                                             String token, String key) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri).header("Content-Type", "application/json")
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

    private static URI uri(ControlPlaneServer server, String path) { return URI.create(server.baseUri() + path); }
    private static String escape(String value) { return value.replace("\\", "\\\\").replace("\"", "\\\""); }

    private static Map<String, Object> ok(HttpResponse<String> response) {
        check(response.statusCode() >= 200 && response.statusCode() < 300,
                "request succeeds: HTTP " + response.statusCode() + " " + response.body());
        return JsonCodec.parseObject(response.body());
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Map<String, Object> value, String key) {
        return objectValue(value.get(key));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> objectValue(Object value) {
        if (!(value instanceof Map<?, ?>)) throw new AssertionError("expected object");
        return (Map<String, Object>) value;
    }

    private static String text(Map<String, Object> value, String key) {
        Object result = value.get(key);
        if (!(result instanceof String text) || text.isBlank()) throw new AssertionError("missing " + key);
        return text;
    }

    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) return;
        try (var paths = Files.walk(root)) {
            for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) {
                try {
                    Files.deleteIfExists(path);
                } catch (java.io.IOException ignored) {
                    // Windows may keep the SQLite WAL briefly locked after close.
                    path.toFile().deleteOnExit();
                }
            }
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
