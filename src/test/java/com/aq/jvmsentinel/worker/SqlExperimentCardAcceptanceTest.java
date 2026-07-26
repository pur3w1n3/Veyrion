package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.model.SqlExperimentCard;
import com.aq.jvmsentinel.model.VerificationStatus;

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
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * P1-01: D3 SQL experiment cards from PathRun pairs; GUI/API replay stays MOCK and never VERIFIED.
 */
public final class SqlExperimentCardAcceptanceTest {
    public static void main(String[] args) throws Exception {
        builderEmitsSuspectCardFromBenignMetaPair();
        cardRejectsVerifiedClaim();
        controlPlaneReplayIsIdempotentAndMockLabeled();
        System.out.println("SqlExperimentCardAcceptanceTest: PASS");
    }

    private static void builderEmitsSuspectCardFromBenignMetaPair() {
        String scanId = "scan-d3";
        String entry = "entry:entry-sql-1";
        ApiDtos.PathRunDto benign = pathRun("pathrun-benign", scanId, entry, "UNAUTH",
                "GET /api/users?q=alice",
                "SELECT id FROM users WHERE name='alice'", false);
        ApiDtos.PathRunDto meta = pathRun("pathrun-meta", scanId, entry, "UNAUTH",
                "GET /api/users?q=" + SqlDiffProbe.META_MARKER,
                "SELECT id FROM users WHERE name='" + SqlDiffProbe.META_MARKER,
                true);
        List<SqlExperimentCard> cards = SqlExperimentCardBuilder.fromPathRuns(scanId, List.of(benign, meta));
        check(!cards.isEmpty(), "builder emits at least one D3 card");
        SqlExperimentCard card = cards.get(0);
        check(entry.equals(card.entrypointRef()), "card entrypointRef");
        check(card.sqlBefore().contains("alice"), "sqlBefore from benign");
        check(card.sqlAfter().toLowerCase().contains("veyrion-sqli-meta"), "sqlAfter carries meta marker");
        check(card.structureInfluenced(), "D2 structureInfluenced expected for meta pair");
        check(VerificationStatus.DYNAMIC_SUSPECTED.name().equals(card.verificationStatus()),
                "default card status DYNAMIC_SUSPECTED");
        check(!"VERIFIED".equals(card.verificationStatus()), "D3 never VERIFIED");
        check("MOCK".equals(card.dependencyMode()) || !card.dependencyMode().isBlank(),
                "dependencyMode present");
        check(card.pathRunRefs().contains("pathrun-benign") && card.pathRunRefs().contains("pathrun-meta"),
                "pathRunRefs cite both runs");
    }

    private static void cardRejectsVerifiedClaim() {
        try {
            new SqlExperimentCard(
                    "sqlexp-bad", "scan-x", "entry:e1",
                    com.aq.jvmsentinel.model.IdentityTrack.UNAUTH, null,
                    "q=1", "q=meta", "SELECT 1", "SELECT 1 OR 1=1", true,
                    "COMPLETED", "MOCK", "VERIFIED", List.of(), List.of());
            throw new AssertionError("VERIFIED card must be rejected");
        } catch (IllegalArgumentException expected) {
            check(expected.getMessage().contains("VERIFIED"), "reject message mentions VERIFIED");
        }
    }

    private static void controlPlaneReplayIsIdempotentAndMockLabeled() throws Exception {
        Path root = Files.createTempDirectory("sql-exp-card");
        try {
            Path jar = buildFixtureJar(root);
            String token = "sql-exp-token";
            HttpClient client = HttpClient.newHttpClient();
            try (ControlPlaneServer server = new ControlPlaneServer(
                    root, 0, token, root.resolve("state/control-plane.db")).start()) {
                URI base = server.baseUri();
                String projectId = text(request(client, URI.create(base + "/projects"), "POST",
                        "{\"name\":\"sql-exp\"}", token, "sql-project"), "projectId");
                String digest = text(request(client,
                        URI.create(base + "/projects/" + projectId + "/artifacts"), "POST",
                        "{\"path\":\"" + escape(jar.toString()) + "\"}", token, "sql-artifact"),
                        "artifactDigest");
                Map<String, Object> scan = json(request(client,
                        URI.create(base + "/projects/" + projectId + "/scans"), "POST",
                        "{\"artifactDigest\":\"" + digest + "\",\"authorized\":true}",
                        token, "sql-scan"));
                String scanId = text(scan, "scanId");
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> entries = (List<Map<String, Object>>) scan.get("entries");
                check(entries != null && !entries.isEmpty(), "scan has entries");
                String entryId = text(entries.get(0), "id");
                String entryRef = "entry:" + entryId;

                ApiDtos.PathRunDto benign = pathRun("pathrun-b1", scanId, entryRef, "UNAUTH",
                        "GET /focus?q=benign",
                        "SELECT id FROM t WHERE q='benign'", false);
                ApiDtos.PathRunDto meta = pathRun("pathrun-m1", scanId, entryRef, "UNAUTH",
                        "GET /focus?q=" + SqlDiffProbe.META_MARKER,
                        "SELECT id FROM t WHERE q='" + SqlDiffProbe.META_MARKER, true);
                server.store().replacePathRunsForTask(projectId, digest, scanId, "task-seed-d3",
                        List.of(benign, meta), Instant.now().toString());

                Map<String, Object> dashboard = json(request(client,
                        URI.create(base + "/projects/" + projectId + "/dashboard?scanId=" + scanId),
                        "GET", null, token, null));
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> cards =
                        (List<Map<String, Object>>) dashboard.get("sqlExperimentCards");
                check(cards != null && !cards.isEmpty(), "dashboard exposes sqlExperimentCards");
                String cardId = text(cards.get(0), "cardId");
                check(!"VERIFIED".equals(cards.get(0).get("verificationStatus")),
                        "dashboard card not VERIFIED");
                check(Boolean.TRUE.equals(cards.get(0).get("replayable")), "card replayable");

                URI replayUri = URI.create(base + "/scans/" + scanId + "/experiment-cards/"
                        + cardId + "/replay");
                HttpResponse<String> denied = request(client, replayUri, "POST",
                        "{\"authorized\":false}", token, "card-denied");
                check(denied.statusCode() == 403, "card replay requires authorization");

                HttpResponse<String> accepted = request(client, replayUri, "POST",
                        "{\"authorized\":true}", token, "card-once");
                check(accepted.statusCode() == 202, "card replay accepted: " + accepted.body());
                Map<String, Object> body = json(accepted);
                check("DYNAMIC_SUSPECTED".equals(body.get("verificationStatus")),
                        "replay stays DYNAMIC_SUSPECTED");
                check("MOCK".equals(body.get("dependencyMode")), "replay dependencyMode MOCK");
                check(cardId.equals(body.get("cardId")), "replay echoes cardId");
                check(Boolean.TRUE.equals(body.get("sqlExperimentReplay")), "sqlExperimentReplay flag");
                String taskId = text(body, "taskId");

                HttpResponse<String> replay = request(client, replayUri, "POST",
                        "{\"authorized\":true}", token, "card-once");
                check(replay.statusCode() == 200, "idempotent card replay");
                check(taskId.equals(json(replay).get("taskId")), "idempotent same task");
                check(Boolean.TRUE.equals(json(replay).get("replayed")), "idempotent replayed");
            }
        } finally {
            deleteTree(root);
        }
    }

    private static ApiDtos.PathRunDto pathRun(String id, String scanId, String entryRef, String track,
                                              String requestSummary, String sql, boolean meta) {
        return new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION, id, scanId, entryRef, track, "attempt-0", null,
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
        Path jar = root.resolve("sql-exp-fixture.jar");
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
