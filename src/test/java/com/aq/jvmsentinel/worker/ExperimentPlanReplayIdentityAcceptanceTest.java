package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.model.ExperimentPlan;
import com.aq.jvmsentinel.model.IdentityTrack;

import javax.tools.JavaCompiler;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * P0-08: replay creates a new attempt while preserving immutable experimentPlanId identity.
 */
public final class ExperimentPlanReplayIdentityAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();
    private static final String PLAN_ID = "plan:replay-identity-1";

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        replayPreservesPlanAndDistinguishesAttempts();
        System.out.println("ExperimentPlanReplayIdentityAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void replayPreservesPlanAndDistinguishesAttempts() throws Exception {
        Path root = Files.createTempDirectory("exp-plan-replay");
        try {
            Path jar = buildFixtureJar(root);
            String token = "exp-plan-replay-token";
            HttpClient client = HttpClient.newHttpClient();
            try (ControlPlaneServer server = new ControlPlaneServer(
                    root, 0, token, root.resolve("state/control-plane.db")).start()) {
                URI base = server.baseUri();
                String projectId = text(request(client, URI.create(base + "/projects"), "POST",
                        "{\"name\":\"exp-plan-replay\"}", token, "replay-project"), "projectId");
                String digest = text(request(client,
                        URI.create(base + "/projects/" + projectId + "/artifacts"), "POST",
                        "{\"path\":\"" + escape(jar.toString()) + "\"}", token, "replay-artifact"),
                        "artifactDigest");
                Map<String, Object> scan = json(request(client,
                        URI.create(base + "/projects/" + projectId + "/scans"), "POST",
                        "{\"artifactDigest\":\"" + digest + "\",\"authorized\":true}",
                        token, "replay-scan"));
                String scanId = text(scan, "scanId");
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> entries = (List<Map<String, Object>>) scan.get("entries");
                String entryId = text(entries.get(0), "id");
                String entryRef = "entry:" + entryId;

                server.acceptExperimentPlan(scanId, new ExperimentPlan(
                        PLAN_ID, entryRef, IdentityTrack.UNAUTH, "GET",
                        "application/json", List.of(), false, "2xx", "", 2,
                        List.of("q=from-plan"), "COMPLETED", ""));

                URI focusUri = URI.create(base + "/scans/" + scanId + "/entries/" + entryId + "/focus-probe");
                HttpResponse<String> focus = request(client, focusUri, "POST",
                        "{\"authorized\":true,\"experimentPlanId\":\"" + PLAN_ID + "\"}",
                        token, "focus-plan-once");
                check(focus.statusCode() == 202, "focus with bound plan accepted");
                Map<String, Object> focusBody = json(focus);
                String focusTaskId = text(focusBody, "taskId");
                check("INITIAL".equals(focusBody.get("attemptKind")), "focus first accept is INITIAL");
                check(PLAN_ID.equals(focusBody.get("experimentPlanId")),
                        "focus response carries experimentPlanId");
                cancelActiveDynamicTasks(server, projectId, scanId);

                ApiDtos.PathRunDto benign = pathRun("pathrun-b1", scanId, entryRef, PLAN_ID,
                        "GET /focus?q=benign",
                        "SELECT id FROM t WHERE q='benign'", false);
                ApiDtos.PathRunDto meta = pathRun("pathrun-m1", scanId, entryRef, PLAN_ID,
                        "GET /focus?q=" + SqlDiffProbe.META_MARKER,
                        "SELECT id FROM t WHERE q='" + SqlDiffProbe.META_MARKER, true);
                server.store().replacePathRunsForTask(projectId, digest, scanId, "task-seed-replay",
                        List.of(benign, meta), Instant.now().toString());

                Map<String, Object> dashboard = json(request(client,
                        URI.create(base + "/projects/" + projectId + "/dashboard?scanId=" + scanId),
                        "GET", null, token, null));
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> cards =
                        (List<Map<String, Object>>) dashboard.get("sqlExperimentCards");
                check(cards != null && !cards.isEmpty(), "dashboard exposes sqlExperimentCards");
                String cardId = text(cards.get(0), "cardId");
                check(PLAN_ID.equals(cards.get(0).get("experimentPlanId")),
                        "card carries experimentPlanId from PathRuns");

                URI replayUri = URI.create(base + "/scans/" + scanId + "/experiment-cards/"
                        + cardId + "/replay");
                HttpResponse<String> firstReplay = request(client, replayUri, "POST",
                        "{\"authorized\":true}", token, "replay-key-a");
                check(firstReplay.statusCode() == 202, "first card replay accepted");
                Map<String, Object> firstBody = json(firstReplay);
                String replayTaskA = text(firstBody, "taskId");
                check(PLAN_ID.equals(firstBody.get("experimentPlanId")),
                        "replay response experimentPlanId matches card");
                check("REPLAY".equals(firstBody.get("attemptKind")),
                        "first replay attemptKind is REPLAY");
                check(!focusTaskId.equals(replayTaskA),
                        "different idempotency key yields new task vs prior focus");
                check(Boolean.FALSE.equals(firstBody.get("replayed")), "first replay not replayed flag");

                HttpResponse<String> idempotentReplay = request(client, replayUri, "POST",
                        "{\"authorized\":true}", token, "replay-key-a");
                check(idempotentReplay.statusCode() == 200, "idempotent card replay");
                Map<String, Object> idempotentBody = json(idempotentReplay);
                check(replayTaskA.equals(idempotentBody.get("taskId")),
                        "same idempotency key returns same taskId");
                check(Boolean.TRUE.equals(idempotentBody.get("replayed")), "idempotent replayed=true");
                check("REPLAY".equals(idempotentBody.get("attemptKind")),
                        "idempotent replay attemptKind REPLAY");
                check(PLAN_ID.equals(idempotentBody.get("experimentPlanId")),
                        "idempotent replay keeps experimentPlanId");

                cancelActiveDynamicTasks(server, projectId, scanId);
                HttpResponse<String> secondReplay = request(client, replayUri, "POST",
                        "{\"authorized\":true}", token, "replay-key-b");
                check(secondReplay.statusCode() == 202, "second card replay with new key accepted");
                Map<String, Object> secondBody = json(secondReplay);
                String replayTaskB = text(secondBody, "taskId");
                check(!replayTaskA.equals(replayTaskB),
                        "different idempotency key yields distinct replay task");
                check(!focusTaskId.equals(replayTaskB),
                        "second replay task differs from prior focus task");
                check(PLAN_ID.equals(secondBody.get("experimentPlanId")),
                        "second replay keeps card experimentPlanId");
            }
        } finally {
            deleteTree(root);
        }
    }

    private static void cancelActiveDynamicTasks(ControlPlaneServer server, String projectId, String scanId)
            throws Exception {
        Field workerApiField = ControlPlaneServer.class.getDeclaredField("workerApi");
        workerApiField.setAccessible(true);
        Object workerApi = workerApiField.get(server);
        Method cancel = workerApi.getClass().getDeclaredMethod(
                "cancelActiveDynamicTasks", String.class, String.class);
        cancel.setAccessible(true);
        cancel.invoke(workerApi, projectId, scanId);
    }

    private static ApiDtos.PathRunDto pathRun(String id, String scanId, String entryRef, String planId,
                                              String requestSummary, String sql, boolean meta) {
        return new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION, id, scanId, entryRef, "UNAUTH", "attempt-0", planId,
                "GET", "application/json", requestSummary, "COMPLETED", 200,
                true, true,
                List.of(new ApiDtos.SqlEventDto(sql, meta ? "meta" : "benign", "READ", !meta, meta, "MOCK")),
                "COMPLETED", "DYNAMIC_SUSPECTED", List.of("ev-" + id), "MOCK", "");
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
        Path jar = root.resolve("replay-fixture.jar");
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
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}
