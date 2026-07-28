package com.aq.jvmsentinel;

import com.aq.jvmsentinel.ai.AuditPipelineCoordinator;
import com.aq.jvmsentinel.ai.AuditPipelineCoordinator.PipelineStage;
import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.AiJobData;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
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
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

/**
 * P0-02: BLOCKED, cancel, stale QUEUED dynamic, and retry prerequisite/idempotency terminals.
 */
public final class PipelineTerminalLifecycleAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) throws Exception {
        blockedExpectedJobDisarmsPipeline();
        cancelExpectedJobRecordsAttemptAndDisarms();
        staleQueuedDynamicBecomesDynamicDisabled();
        retryRequiresPrerequisiteAndIdempotency();
        System.out.println("PipelineTerminalLifecycleAcceptanceTest passed ("
                + ASSERTIONS.get() + " assertions)");
    }

    private static void blockedExpectedJobDisarmsPipeline() throws Exception {
        List<String> stops = new CopyOnWriteArrayList<>();
        AuditPipelineCoordinator coordinator = new AuditPipelineCoordinator(
                new AuditPipelineCoordinator.Actions() {
                    @Override
                    public String createRoleJob(String projectId, String scanId, AgentRole role,
                                                AiOutputLanguage language, String actorId) {
                        return "job-blocked";
                    }

                    @Override
                    public void submitRoleJob(String jobId, String actorId) {
                        throw new AssertionError("BLOCKED job must not be submitted");
                    }

                    @Override
                    public String enqueueDynamic(String scanId, String actorId) {
                        throw new AssertionError("dynamic must not enqueue");
                    }

                    @Override
                    public boolean hasRunningDynamicTask(String scanId) {
                        return false;
                    }

                    @Override
                    public void replaceCursor(AuditPipelineCoordinator.Cursor cursor,
                                              boolean armed, String stopReason) {
                        if (!armed) {
                            stops.add(stopReason);
                        }
                    }

                    @Override
                    public boolean compareAndAdvance(AuditPipelineCoordinator.Cursor expected,
                                                     AuditPipelineCoordinator.Cursor next,
                                                     boolean armed, String stopReason) {
                        if (!armed) {
                            stops.add(stopReason);
                        }
                        return true;
                    }

                    @Override
                    public String jobStatus(String jobId) {
                        return "BLOCKED";
                    }

                    @Override
                    public String jobStopReason(String jobId) {
                        return "ROLE_BINDING_REQUIRED";
                    }
                });
        coordinator.armForJob("scan-blocked", "project-a", "op", AiOutputLanguage.ZH_CN,
                PipelineStage.PRE_ANALYSIS, "job-blocked");
        coordinator.onAiJobFinished(job("job-blocked", "scan-blocked", AgentRole.PRE_ANALYSIS,
                "BLOCKED", "ROLE_BINDING_REQUIRED"));
        check(!coordinator.isArmed("scan-blocked"), "BLOCKED expected job disarms pipeline");
        check(stops.stream().anyMatch(value -> value != null && value.contains("ROLE_BINDING_REQUIRED")),
                "BLOCKED disarm records provider/binding stop reason");
    }

    private static void cancelExpectedJobRecordsAttemptAndDisarms() throws Exception {
        Path root = Files.createTempDirectory("veyrion-p002-cancel-");
        Path database = root.resolve("control.db");
        String token = "p002-cancel-token";
        String keys = UUID.randomUUID().toString();
        HttpClient client = HttpClient.newHttpClient();
        // Hang until interrupted so cancel always races ahead of provider completion.
        try (ControlPlaneServer server = new ControlPlaneServer(root, 0, token, database,
                (provider, credential) -> { throw new AssertionError("inventory unused"); },
                (provider, credential, request, limits) -> {
                    try {
                        Thread.sleep(60_000L);
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                    }
                    return new ProviderChatTransport.Response(
                            200, ("{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{"
                            + "\"role\":\"assistant\",\"content\":\"ok\"}}]}")
                            .getBytes(StandardCharsets.UTF_8), "req", 1);
                }).start()) {
            String projectId = text(ok(send(client, uri(server, "/projects"), "POST",
                    "{\"name\":\"cancel pipeline\"}", token, keys + "-project")), "projectId");
            String artifactId = text(ok(send(client, uri(server, "/projects/" + projectId + "/artifacts"),
                    "POST", "{\"path\":\"" + escape(executableControllerJar(root).toString()) + "\"}",
                    token, keys + "-artifact")), "artifactId");
            String providerId = text(ok(send(client, uri(server, "/providers"), "POST",
                    "{\"name\":\"cancel provider\",\"kind\":\"OPENAI_CHAT\","
                            + "\"baseUrl\":\"http://127.0.0.1:3999\",\"model\":\"m\","
                            + "\"apiKey\":\"secret\"}", token, keys + "-provider")), "providerId");
            ok(send(client, uri(server, "/projects/" + projectId + "/role-assignments/PRE_ANALYSIS"),
                    "PATCH", "{\"providerId\":\"" + providerId + "\",\"model\":\"m\"}",
                    token, keys + "-bind-pre"));
            Map<String, Object> audit = ok(send(client,
                    uri(server, "/projects/" + projectId + "/audit-runs"), "POST",
                    "{\"artifactId\":\"" + artifactId + "\",\"authorized\":true,"
                            + "\"aiAuthorized\":true,\"outputLanguage\":\"ZH_CN\","
                            + "\"networkMode\":\"DENY\",\"dangerousActionMode\":\"DRY_RUN\"}",
                    token, keys + "-audit"));
            String scanId = text(audit, "scanId");
            String jobId = text(object(audit, "preAnalysisJob"), "aiJobId");
            long cancelDeadline = System.nanoTime() + Duration.ofSeconds(15).toNanos();
            while (System.nanoTime() < cancelDeadline) {
                Map<String, Object> current = okGet(client, uri(server, "/ai-jobs/" + jobId), token);
                Object status = current.get("status");
                if ("RUNNING".equals(status) || "QUEUED".equals(status)) {
                    break;
                }
                if ("COMPLETED".equals(status) || "FAILED".equals(status) || "BLOCKED".equals(status)) {
                    throw new AssertionError("cancel fixture became terminal before cancel: " + status);
                }
                Thread.sleep(40);
            }
            ok(send(client, uri(server, "/ai-jobs/" + jobId), "PATCH",
                    "{\"action\":\"cancel\"}", token, null));
            Map<String, Object> job = null;
            long cancelledDeadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
            while (System.nanoTime() < cancelledDeadline) {
                job = okGet(client, uri(server, "/ai-jobs/" + jobId), token);
                if ("CANCELLED".equals(job.get("status"))) {
                    break;
                }
                if (List.of("COMPLETED", "FAILED", "BLOCKED").contains(String.valueOf(job.get("status")))) {
                    throw new AssertionError("cancel raced into unexpected terminal: " + job.get("status"));
                }
                Thread.sleep(40);
            }
            check(job != null && "CANCELLED".equals(job.get("status")),
                    "expected job is cancelled, was " + (job == null ? null : job.get("status")));
            String stopReason = null;
            boolean disarmed = false;
            long disarmDeadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
            while (System.nanoTime() < disarmDeadline) {
                try (var connection = DriverManager.getConnection("jdbc:sqlite:" + database);
                     var statement = connection.prepareStatement(
                             "SELECT armed,stop_reason FROM audit_pipeline_runs WHERE scan_id=?")) {
                    statement.setString(1, scanId);
                    try (var rows = statement.executeQuery()) {
                        if (rows.next() && rows.getInt(1) == 0) {
                            disarmed = true;
                            stopReason = rows.getString(2);
                            break;
                        }
                    }
                }
                Thread.sleep(40);
            }
            check(disarmed, "cancel disarms pipeline");
            check(stopReason != null && stopReason.contains("USER_CANCELLED"),
                    "cancel stop reason references USER_CANCELLED");
            boolean auditSeen = false;
            long auditDeadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
            while (System.nanoTime() < auditDeadline) {
                try (var connection = DriverManager.getConnection("jdbc:sqlite:" + database);
                     var statement = connection.prepareStatement(
                             "SELECT COUNT(*) FROM audit_events WHERE action='audit-pipeline.cancel' "
                                     + "AND target_id=?")) {
                    statement.setString(1, jobId);
                    try (var rows = statement.executeQuery()) {
                        if (rows.next() && rows.getInt(1) >= 1) {
                            auditSeen = true;
                            break;
                        }
                    }
                }
                Thread.sleep(40);
            }
            check(auditSeen, "cancel records operator-targeted pipeline attempt audit");
        } finally {
            deleteTree(root);
        }
    }

    private static void staleQueuedDynamicBecomesDynamicDisabled() throws Exception {
        Path root = Files.createTempDirectory("veyrion-p002-stale-");
        Path database = root.resolve("control.db");
        String token = "p002-stale-token";
        String keys = UUID.randomUUID().toString();
        HttpClient client = HttpClient.newHttpClient();
        try (ControlPlaneServer server = server(root, database, token).start()) {
            String projectId = text(ok(send(client, uri(server, "/projects"), "POST",
                    "{\"name\":\"stale dynamic\"}", token, keys + "-project")), "projectId");
            Path artifact = executableControllerJar(root);
            String artifactId = text(ok(send(client, uri(server, "/projects/" + projectId + "/artifacts"),
                    "POST", "{\"path\":\"" + escape(artifact.toString()) + "\"}",
                    token, keys + "-artifact")), "artifactId");
            String providerId = text(ok(send(client, uri(server, "/providers"), "POST",
                    "{\"name\":\"stale provider\",\"kind\":\"OPENAI_CHAT\","
                            + "\"baseUrl\":\"http://127.0.0.1:3998\",\"model\":\"m\","
                            + "\"apiKey\":\"secret\"}", token, keys + "-provider")), "providerId");
            for (String role : List.of("PRE_ANALYSIS", "AUTH_ANALYSIS")) {
                ok(send(client, uri(server, "/projects/" + projectId + "/role-assignments/" + role),
                        "PATCH", "{\"providerId\":\"" + providerId + "\",\"model\":\"m\"}",
                        token, keys + "-bind-" + role));
            }
            Map<String, Object> audit = ok(send(client,
                    uri(server, "/projects/" + projectId + "/audit-runs"), "POST",
                    "{\"artifactId\":\"" + artifactId + "\",\"authorized\":true,"
                            + "\"aiAuthorized\":true,\"outputLanguage\":\"ZH_CN\","
                            + "\"networkMode\":\"DENY\",\"dangerousActionMode\":\"DRY_RUN\"}",
                    token, keys + "-audit"));
            String scanId = text(audit, "scanId");
            String preJob = text(object(audit, "preAnalysisJob"), "aiJobId");
            check("COMPLETED".equals(awaitJob(client, server, preJob, token).get("status")),
                    "PRE completes");
            String authJob = awaitRoleJob(client, server, projectId, scanId, "AUTH_ANALYSIS", token);
            check("COMPLETED".equals(awaitJob(client, server, authJob, token).get("status")),
                    "AUTH completes");
            Map<String, Object> task = awaitSingleTask(client, server, scanId, token);
            String taskId = text(task, "taskId");
            check("QUEUED".equals(task.get("status")), "dynamic observation is queued without worker");
            int failed = server.reclaimStaleDynamicTasks(Duration.ZERO);
            check(failed >= 1, "stale reclaim fails queued dynamic tasks");
            Map<String, Object> tasks = okGet(client,
                    uri(server, "/scans/" + scanId + "/dynamic-tasks"), token);
            Map<?, ?> restored = firstTask(tasks);
            check(taskId.equals(restored.get("taskId")), "same task is terminalized");
            check("FAILED".equals(restored.get("status")), "queued task becomes FAILED");
            check("WORKER_UNAVAILABLE".equals(restored.get("failureCode"))
                            || String.valueOf(restored.get("stopReason")).contains("WALL_CLOCK"),
                    "failure communicates worker unavailability / dynamic disabled");
            boolean disarmed = false;
            long disarmDeadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
            while (System.nanoTime() < disarmDeadline) {
                try (var connection = DriverManager.getConnection("jdbc:sqlite:" + database);
                     var statement = connection.prepareStatement(
                             "SELECT armed FROM audit_pipeline_runs WHERE scan_id=?")) {
                    statement.setString(1, scanId);
                    try (var rows = statement.executeQuery()) {
                        if (rows.next() && rows.getInt(1) == 0) {
                            disarmed = true;
                            break;
                        }
                    }
                }
                Thread.sleep(40);
            }
            check(disarmed, "stale dynamic failure disarms pipeline");
        } finally {
            deleteTree(root);
        }
    }

    private static void retryRequiresPrerequisiteAndIdempotency() throws Exception {
        Path root = Files.createTempDirectory("veyrion-p002-retry-");
        Path database = root.resolve("control.db");
        String token = "p002-retry-token";
        String keys = UUID.randomUUID().toString();
        String retryPreKey = keys + "-retry-pre-1";
        HttpClient client = HttpClient.newHttpClient();
        try (ControlPlaneServer server = server(root, database, token).start()) {
            String projectId = text(ok(send(client, uri(server, "/projects"), "POST",
                    "{\"name\":\"retry gates\"}", token, keys + "-project")), "projectId");
            String digest = text(ok(send(client, uri(server, "/projects/" + projectId + "/artifacts"),
                    "POST", "{\"path\":\"" + escape(executableControllerJar(root).toString()) + "\"}",
                    token, keys + "-artifact")), "artifactDigest");
            Map<String, Object> scan = ok(send(client, uri(server, "/projects/" + projectId + "/scans"),
                    "POST", "{\"artifactDigest\":\"" + digest + "\",\"authorized\":true,"
                            + "\"networkMode\":\"DENY\",\"dangerousActionMode\":\"DRY_RUN\"}",
                    token, keys + "-scan"));
            String scanId = text(scan, "scanId");
            HttpResponse<String> missing = send(client,
                    uri(server, "/projects/" + projectId + "/audit-stage-retries"), "POST",
                    "{\"scanId\":\"" + scanId + "\",\"stage\":\"AUTH_ANALYSIS\",\"authorized\":true,"
                            + "\"aiAuthorized\":true,\"outputLanguage\":\"ZH_CN\"}",
                    token, keys + "-retry-auth-missing");
            check(missing.statusCode() == 409, "AUTH retry without PRE is rejected");
            check(missing.body().contains("RETRY_PREREQUISITE_MISSING"),
                    "missing prerequisite uses RETRY_PREREQUISITE_MISSING");

            String providerId = text(ok(send(client, uri(server, "/providers"), "POST",
                    "{\"name\":\"retry provider\",\"kind\":\"OPENAI_CHAT\","
                            + "\"baseUrl\":\"http://127.0.0.1:3997\",\"model\":\"m\","
                            + "\"apiKey\":\"secret\"}", token, keys + "-provider")), "providerId");
            ok(send(client, uri(server, "/projects/" + projectId + "/role-assignments/PRE_ANALYSIS"),
                    "PATCH", "{\"providerId\":\"" + providerId + "\",\"model\":\"m\"}",
                    token, keys + "-bind-pre"));
            Map<String, Object> first = ok(send(client,
                    uri(server, "/projects/" + projectId + "/audit-stage-retries"), "POST",
                    "{\"scanId\":\"" + scanId + "\",\"stage\":\"PRE_ANALYSIS\",\"authorized\":true,"
                            + "\"aiAuthorized\":true,\"outputLanguage\":\"ZH_CN\"}",
                    token, retryPreKey));
            Map<String, Object> replay = ok(send(client,
                    uri(server, "/projects/" + projectId + "/audit-stage-retries"), "POST",
                    "{\"scanId\":\"" + scanId + "\",\"stage\":\"PRE_ANALYSIS\",\"authorized\":true,"
                            + "\"aiAuthorized\":true,\"outputLanguage\":\"ZH_CN\"}",
                    token, retryPreKey));
            check(text(object(first, "aiJob"), "aiJobId")
                            .equals(text(object(replay, "aiJob"), "aiJobId")),
                    "retry Idempotency-Key replays the same stage attempt resource");
            HttpResponse<String> conflict = send(client,
                    uri(server, "/projects/" + projectId + "/audit-stage-retries"), "POST",
                    "{\"scanId\":\"" + scanId + "\",\"stage\":\"PRE_ANALYSIS\",\"authorized\":true,"
                            + "\"aiAuthorized\":true,\"outputLanguage\":\"EN\"}",
                    token, retryPreKey);
            check(conflict.statusCode() == 409, "retry idempotency payload conflict fails closed");
            check(conflict.body().contains("IDEMPOTENCY_CONFLICT"),
                    "payload conflict surfaces IDEMPOTENCY_CONFLICT (not a busy-lock swallow)");
        } finally {
            deleteTree(root);
        }
    }

    private static ControlPlaneServer server(Path root, Path database, String token) {
        return new ControlPlaneServer(root, 0, token, database,
                (provider, credential) -> { throw new AssertionError("inventory unused"); },
                (provider, credential, request, limits) -> {
                    try {
                        Thread.sleep(800L);
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                    }
                    return new ProviderChatTransport.Response(
                            200, ("{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{"
                            + "\"role\":\"assistant\",\"content\":\"ok\"}}]}")
                            .getBytes(StandardCharsets.UTF_8), "req", 1);
                });
    }

    private static Path executableControllerJar(Path root) throws Exception {
        Path sources = Files.createDirectories(root.resolve("sources-" + System.nanoTime()));
        Path classes = Files.createDirectories(root.resolve("classes-" + System.nanoTime()));
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
        source(sources, "app/TerminalController.java", """
                package app;
                import org.springframework.web.bind.annotation.*;
                @RestController
                public class TerminalController {
                    public static void main(String[] args) { }
                    @GetMapping("/ok") public String ok() { return "ok"; }
                }
                """);
        var compiler = ToolProvider.getSystemJavaCompiler();
        check(compiler != null, "JDK compiler is required");
        List<String> files;
        try (var stream = Files.walk(sources)) {
            files = stream.filter(path -> path.toString().endsWith(".java")).map(Path::toString).toList();
        }
        List<String> arguments = new ArrayList<>(List.of("-d", classes.toString(), "--release", "17"));
        arguments.addAll(files);
        check(compiler.run(null, null, null, arguments.toArray(String[]::new)) == 0, "fixture compiles");
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().put(Attributes.Name.MAIN_CLASS, "app.TerminalController");
        Path jar = root.resolve("terminal-" + System.nanoTime() + ".jar");
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

    private static AiJobData job(String jobId, String scanId, AgentRole role, String status, String stop) {
        return new AiJobData(
                jobId, "local", "project-a", scanId, "a".repeat(64),
                role, "provider-a", "model-a", "{\"schemaVersion\":1}", true, status, stop,
                "[]", null, 0, 0, "[]", null, Instant.now().toString(), Instant.now().toString());
    }

    private static Map<String, Object> awaitJob(HttpClient client, ControlPlaneServer server,
                                                 String jobId, String token) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos();
        while (System.nanoTime() < deadline) {
            Map<String, Object> job = okGet(client, uri(server, "/ai-jobs/" + jobId), token);
            if (List.of("COMPLETED", "FAILED", "BLOCKED", "CANCELLED").contains(job.get("status"))) {
                return job;
            }
            Thread.sleep(40);
        }
        throw new AssertionError("AI job did not finish");
    }

    private static String awaitRoleJob(HttpClient client, ControlPlaneServer server, String projectId,
                                       String scanId, String role, String token) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos();
        while (System.nanoTime() < deadline) {
            Map<String, Object> jobs = okGet(client,
                    uri(server, "/projects/" + projectId + "/ai-jobs"), token);
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
            Thread.sleep(40);
        }
        throw new AssertionError(role + " job was not created");
    }

    private static Map<String, Object> awaitSingleTask(HttpClient client, ControlPlaneServer server,
                                                       String scanId, String token) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos();
        while (System.nanoTime() < deadline) {
            Map<String, Object> response = okGet(client,
                    uri(server, "/scans/" + scanId + "/dynamic-tasks"), token);
            if (response.get("dynamicTasks") instanceof List<?> values && values.size() == 1) {
                return objectValue(values.get(0));
            }
            Thread.sleep(40);
        }
        throw new AssertionError("dynamic task was not queued");
    }

    private static Map<?, ?> firstTask(Map<String, Object> tasks) {
        Object list = tasks.get("dynamicTasks");
        check(list instanceof List<?> values && !values.isEmpty(), "dynamicTasks present");
        Object first = ((List<?>) list).get(0);
        check(first instanceof Map<?, ?>, "task object");
        return (Map<?, ?>) first;
    }

    private static HttpResponse<String> send(HttpClient client, URI uri, String method, String body,
                                             String token, String key) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri).header("Content-Type", "application/json")
                .header("X-Sentinel-Authorization", token);
        if (key != null) {
            builder.header("Idempotency-Key", key);
        }
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

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static Map<String, Object> ok(HttpResponse<String> response) {
        check(response.statusCode() >= 200 && response.statusCode() < 300,
                "request succeeds: HTTP " + response.statusCode() + " " + response.body());
        return JsonCodec.parseObject(response.body());
    }

    /**
     * Read-only GET helper: retries only transient {@code 409 PERSISTENCE_REJECTED}
     * (SQLite busy during concurrent AI/cancel writes). Real conflicts still fail.
     */
    private static Map<String, Object> okGet(HttpClient client, URI uri, String token) throws Exception {
        HttpResponse<String> last = null;
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (System.nanoTime() < deadline) {
            last = send(client, uri, "GET", "", token, null);
            if (last.statusCode() >= 200 && last.statusCode() < 300) {
                return JsonCodec.parseObject(last.body());
            }
            if (last.statusCode() == 409 && last.body() != null
                    && last.body().contains("PERSISTENCE_REJECTED")) {
                Thread.sleep(50);
                continue;
            }
            break;
        }
        check(false, "GET succeeds: HTTP "
                + (last == null ? "?" : last.statusCode() + " " + last.body()));
        return Map.of();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Map<String, Object> value, String key) {
        return objectValue(value.get(key));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> objectValue(Object value) {
        if (!(value instanceof Map<?, ?>)) {
            throw new AssertionError("expected object");
        }
        return (Map<String, Object>) value;
    }

    private static String text(Map<String, Object> value, String key) {
        Object result = value.get(key);
        if (!(result instanceof String text) || text.isBlank()) {
            throw new AssertionError("missing " + key);
        }
        return text;
    }

    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) {
            return;
        }
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
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
    }
}
