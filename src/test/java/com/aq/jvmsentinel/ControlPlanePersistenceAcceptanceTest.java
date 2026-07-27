package com.aq.jvmsentinel;

import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.util.List;
import java.util.Map;

/** Restart recovery, project soft-delete, and fail-closed migration checks. */
public final class ControlPlanePersistenceAcceptanceTest {
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("veyrion-persistence");
        Path database = root.resolve("state").resolve("control-plane.db");
        Path artifact = root.resolve("UploadFileExecController.class");
        Files.writeString(artifact, "metadata-only fixture");
        String token = "persistence-test-token";
        HttpClient client = HttpClient.newHttpClient();

        String projectId;
        String digest;
        String scanId;
        String evidenceId;
        String findingId;
        try (ControlPlaneServer first = new ControlPlaneServer(root, 0, token, database).start()) {
            check("SQLITE".equals(body(get(client, first.baseUri())).get("persistenceMode")),
                    "health exposes SQLite mode");
            Map<String, Object> project = body(send(client, uri(first, "/projects"),
                    "POST", "{\"name\":\"restart fixture\"}", token, "persist-project"));
            projectId = text(project, "projectId");

            URI artifacts = uri(first, "/projects/" + projectId + "/artifacts");
            Map<String, Object> storedArtifact = body(send(client, artifacts, "POST",
                    "{\"path\":\"" + escape(artifact.toString()) + "\"}", token, "persist-artifact"));
            digest = text(storedArtifact, "artifactDigest");

            URI scans = uri(first, "/projects/" + projectId + "/scans");
            Map<String, Object> scan = body(send(client, scans, "POST",
                    "{\"artifactDigest\":\"" + digest + "\",\"authorized\":true}", token, "persist-scan"));
            scanId = text(scan, "scanId");

            Map<String, Object> evidence = body(get(client,
                    uri(first, "/scans/" + scanId + "/evidence")));
            evidenceId = text(first((List<?>) evidence.get("evidence")), "evidenceId");
            Map<String, Object> findings = body(get(client,
                    uri(first, "/scans/" + scanId + "/findings")));
            findingId = text(first((List<?>) findings.get("findings")), "findingId");

            check(send(client, uri(first, "/projects/" + projectId), "PATCH",
                    "{\"name\":\"unauthorized\"}", null).statusCode() == 401,
                    "project patch requires mutation token");
            HttpResponse<String> patched = send(client,
                    uri(first, "/projects/" + projectId), "PATCH",
                    "{\"name\":\"renamed\",\"status\":\"ARCHIVED\"}", token);
            check(patched.statusCode() == 200, "project patch succeeds");
            Map<String, Object> patchedBody = body(patched);
            check("renamed".equals(patchedBody.get("name"))
                    && "ARCHIVED".equals(patchedBody.get("status")), "project patch is visible");
        }

        try (ControlPlaneServer restarted = new ControlPlaneServer(root, 0, token, database).start()) {
            HttpResponse<String> projectReplay = send(client, uri(restarted, "/projects"), "POST",
                    "{\"name\":\"restart fixture\"}", token, "persist-project");
            check(projectReplay.statusCode() == 200
                            && projectId.equals(body(projectReplay).get("projectId")),
                    "project idempotency survives restart");
            check(send(client, uri(restarted, "/projects"), "POST",
                    "{\"name\":\"different\"}", token, "persist-project").statusCode() == 409,
                    "project idempotency payload conflict survives restart");
            HttpResponse<String> artifactReplay = send(client,
                    uri(restarted, "/projects/" + projectId + "/artifacts"), "POST",
                    "{\"path\":\"" + escape(artifact.toString()) + "\"}", token, "persist-artifact");
            check(artifactReplay.statusCode() == 200
                            && digest.equals(body(artifactReplay).get("artifactDigest")),
                    "artifact idempotency survives restart");
            HttpResponse<String> scanReplay = send(client,
                    uri(restarted, "/projects/" + projectId + "/scans"), "POST",
                    "{\"artifactDigest\":\"" + digest + "\",\"authorized\":true}", token, "persist-scan");
            check(scanReplay.statusCode() == 200 && scanId.equals(body(scanReplay).get("scanId")),
                    "scan idempotency survives restart");
            Map<String, Object> projects = body(get(client, uri(restarted, "/projects")));
            check(((List<?>) projects.get("projects")).size() == 1, "project list survives restart");
            Map<String, Object> project = body(get(client,
                    uri(restarted, "/projects/" + projectId)));
            check("renamed".equals(project.get("name")) && "ARCHIVED".equals(project.get("status")),
                    "project update survives restart");
            check(digest.equals(project.get("artifactDigest")), "artifact metadata survives restart");
            check(scanId.equals(project.get("scanId")), "latest scan survives restart");
            check(get(client, uri(restarted, "/scans/" + scanId)).statusCode() == 200,
                    "scan snapshot survives restart");
            check(get(client, uri(restarted, "/evidence/" + evidenceId)).statusCode() == 200,
                    "evidence survives restart");
            check(get(client, uri(restarted, "/findings/" + findingId)).statusCode() == 200,
                    "finding survives restart");
            Map<String, Object> chains = body(get(client,
                    uri(restarted, "/attack-chains?projectId=" + projectId)));
            check(!((List<?>) chains.get("attackChains")).isEmpty(), "attack chain survives restart");

            HttpResponse<String> deleted = send(client,
                    uri(restarted, "/projects/" + projectId), "DELETE", "", token);
            check(deleted.statusCode() == 204, "project soft delete succeeds");
            check(get(client, uri(restarted, "/projects/" + projectId)).statusCode() == 404,
                    "soft-deleted project is hidden");
            check(get(client, uri(restarted, "/scans/" + scanId)).statusCode() == 404,
                    "soft-deleted project data is hidden");
            check(((List<?>) body(get(client, uri(restarted, "/projects")))
                    .get("projects")).isEmpty(), "soft-deleted project is absent from list");
        }

        ControlPlaneStore rebuilt = ControlPlaneStore.sqlite(database, root);
        check(rebuilt.project(projectId) == null, "soft deletion survives Store reconstruction");
        try (var connection = DriverManager.getConnection("jdbc:sqlite:" + database);
             var statement = connection.prepareStatement(
                     "SELECT deleted_at FROM projects WHERE project_id=?")) {
            statement.setString(1, projectId);
            try (var rows = statement.executeQuery()) {
                check(rows.next() && rows.getString(1) != null, "project row is retained with deleted_at");
            }
        }

        Path badRoot = Files.createTempDirectory("veyrion-bad-migration");
        Path badDatabase = badRoot.resolve("bad.db");
        ControlPlaneStore.sqlite(badDatabase, badRoot);
        try (var connection = DriverManager.getConnection("jdbc:sqlite:" + badDatabase);
             var statement = connection.createStatement()) {
            statement.executeUpdate("UPDATE schema_migrations SET checksum='tampered' WHERE version=2");
        }
        expect(SQLiteControlPlanePersistence.MigrationException.class,
                () -> ControlPlaneStore.sqlite(badDatabase, badRoot),
                "migration checksum mismatch must fail closed");
        Path badV3Root = Files.createTempDirectory("veyrion-bad-v003");
        Path badV3Database = badV3Root.resolve("bad-v003.db");
        ControlPlaneStore.sqlite(badV3Database, badV3Root);
        try (var connection = DriverManager.getConnection("jdbc:sqlite:" + badV3Database);
             var statement = connection.createStatement()) {
            statement.executeUpdate("UPDATE schema_migrations SET checksum='tampered' WHERE version=3");
        }
        expect(SQLiteControlPlanePersistence.MigrationException.class,
                () -> ControlPlaneStore.sqlite(badV3Database, badV3Root),
                "provider protocol migration checksum mismatch must fail closed");
        Path badV4Root = Files.createTempDirectory("veyrion-bad-v004");
        Path badV4Database = badV4Root.resolve("bad-v004.db");
        ControlPlaneStore.sqlite(badV4Database, badV4Root);
        try (var connection = DriverManager.getConnection("jdbc:sqlite:" + badV4Database);
             var statement = connection.createStatement()) {
            statement.executeUpdate("UPDATE schema_migrations SET checksum='tampered' WHERE version=4");
        }
        expect(SQLiteControlPlanePersistence.MigrationException.class,
                () -> ControlPlaneStore.sqlite(badV4Database, badV4Root),
                "AI job migration checksum mismatch must fail closed");
        Path badV5Root = Files.createTempDirectory("veyrion-bad-v005");
        Path badV5Database = badV5Root.resolve("bad-v005.db");
        ControlPlaneStore.sqlite(badV5Database, badV5Root);
        try (var connection = DriverManager.getConnection("jdbc:sqlite:" + badV5Database);
             var statement = connection.createStatement()) {
            statement.executeUpdate("UPDATE schema_migrations SET checksum='tampered' WHERE version=5");
        }
        expect(SQLiteControlPlanePersistence.MigrationException.class,
                () -> ControlPlaneStore.sqlite(badV5Database, badV5Root),
                "AI job event migration checksum mismatch must fail closed");
        Path badV6Root = Files.createTempDirectory("veyrion-bad-v006");
        Path badV6Database = badV6Root.resolve("bad-v006.db");
        ControlPlaneStore.sqlite(badV6Database, badV6Root);
        try (var connection = DriverManager.getConnection("jdbc:sqlite:" + badV6Database);
             var statement = connection.createStatement()) {
            statement.executeUpdate("UPDATE schema_migrations SET checksum='tampered' WHERE version=6");
        }
        expect(SQLiteControlPlanePersistence.MigrationException.class,
                () -> ControlPlaneStore.sqlite(badV6Database, badV6Root),
                "dynamic verification role migration checksum mismatch must fail closed");
        Path badV7Root = Files.createTempDirectory("veyrion-bad-v007");
        Path badV7Database = badV7Root.resolve("bad-v007.db");
        ControlPlaneStore.sqlite(badV7Database, badV7Root);
        try (var connection = DriverManager.getConnection("jdbc:sqlite:" + badV7Database);
             var statement = connection.createStatement()) {
            statement.executeUpdate("UPDATE schema_migrations SET checksum='tampered' WHERE version=7");
        }
        expect(SQLiteControlPlanePersistence.MigrationException.class,
                () -> ControlPlaneStore.sqlite(badV7Database, badV7Root),
                "persistent worker migration checksum mismatch must fail closed");
        Path badV8Root = Files.createTempDirectory("veyrion-bad-v008");
        Path badV8Database = badV8Root.resolve("bad-v008.db");
        ControlPlaneStore.sqlite(badV8Database, badV8Root);
        try (var connection = DriverManager.getConnection("jdbc:sqlite:" + badV8Database);
             var statement = connection.createStatement()) {
            statement.executeUpdate("UPDATE schema_migrations SET checksum='tampered' WHERE version=8");
        }
        expectFailure(() -> ControlPlaneStore.sqlite(badV8Database, badV8Root),
                "artifact upload migration checksum mismatch must fail closed");
        Path badV9Root = Files.createTempDirectory("veyrion-bad-v009");
        Path badV9Database = badV9Root.resolve("bad-v009.db");
        ControlPlaneStore.sqlite(badV9Database, badV9Root);
        try (var connection = DriverManager.getConnection("jdbc:sqlite:" + badV9Database);
             var statement = connection.createStatement()) {
            statement.executeUpdate("UPDATE schema_migrations SET checksum='tampered' WHERE version=9");
        }
        expectFailure(() -> ControlPlaneStore.sqlite(badV9Database, badV9Root),
                "SSE event migration checksum mismatch must fail closed");
        Path badV10Root = Files.createTempDirectory("veyrion-bad-v010");
        Path badV10Database = badV10Root.resolve("bad-v010.db");
        ControlPlaneStore.sqlite(badV10Database, badV10Root);
        try (var connection = DriverManager.getConnection("jdbc:sqlite:" + badV10Database);
             var statement = connection.createStatement()) {
            statement.executeUpdate("UPDATE schema_migrations SET checksum='tampered' WHERE version=10");
        }
        expectFailure(() -> ControlPlaneStore.sqlite(badV10Database, badV10Root),
                "role prompt migration checksum mismatch must fail closed");
        Path badV11Root = Files.createTempDirectory("veyrion-bad-v011");
        Path badV11Database = badV11Root.resolve("bad-v011.db");
        ControlPlaneStore.sqlite(badV11Database, badV11Root);
        try (var connection = DriverManager.getConnection("jdbc:sqlite:" + badV11Database);
             var statement = connection.createStatement()) {
            statement.executeUpdate("UPDATE schema_migrations SET checksum='tampered' WHERE version=11");
        }
        expectFailure(() -> ControlPlaneStore.sqlite(badV11Database, badV11Root),
                "persistent idempotency migration checksum mismatch must fail closed");
        Path badV1Root = Files.createTempDirectory("veyrion-bad-v001");
        Path badV1Database = badV1Root.resolve("bad-v001.db");
        ControlPlaneStore.sqlite(badV1Database, badV1Root);
        try (var connection = DriverManager.getConnection("jdbc:sqlite:" + badV1Database);
             var statement = connection.createStatement()) {
            statement.executeUpdate("UPDATE schema_migrations SET checksum='tampered' WHERE version=1");
        }
        expect(SQLiteControlPlanePersistence.MigrationException.class,
                () -> ControlPlaneStore.sqlite(badV1Database, badV1Root),
                "V001 checksum mismatch must fail closed");
        Path upgradeRoot = Files.createTempDirectory("veyrion-v001-upgrade");
        Path upgradeDatabase = upgradeRoot.resolve("upgrade.db");
        ControlPlaneStore.sqlite(upgradeDatabase, upgradeRoot);
        try (var connection = DriverManager.getConnection("jdbc:sqlite:" + upgradeDatabase);
             var statement = connection.createStatement()) {
            statement.executeUpdate("PRAGMA foreign_keys=OFF");
            for (String table : List.of("ai_job_events", "audit_events", "ai_jobs", "project_ai_role_bindings",
                    "provider_credentials", "providers", "operator_tokens", "operators",
                    "dynamic_probe_plans", "audit_pipeline_runs", "control_plane_idempotency",
                    "worker_trace_chunks", "worker_tasks", "artifact_upload_sessions", "sse_events",
                    "path_runs", "experiment_plans")) {
                statement.executeUpdate("DROP TABLE IF EXISTS " + table);
            }
            statement.executeUpdate("DELETE FROM schema_migrations WHERE version>=2");
        }
        ControlPlaneStore.sqlite(upgradeDatabase, upgradeRoot);
        try (var connection = DriverManager.getConnection("jdbc:sqlite:" + upgradeDatabase);
             var statement = connection.createStatement();
             var rows = statement.executeQuery("SELECT count(*) FROM schema_migrations")) {
            check(rows.next() && rows.getInt(1) == 15, "V001 database upgrades through ordered V015");
        }
        expect(IllegalArgumentException.class,
                () -> ControlPlaneStore.sqlite(root.getParent().resolve("outside.db"), root),
                "database path outside the allowed root must be rejected");

        Path planRoot = Files.createTempDirectory("veyrion-v011-probe-plan");
        Path planDatabase = planRoot.resolve("plan.db");
        SQLiteControlPlanePersistence planPersistence =
                new SQLiteControlPlanePersistence(planDatabase, planRoot);
        var plan = new SQLiteControlPlanePersistence.ProbePlanData(
                "task-plan", "project-plan", "a".repeat(64), "scan-plan", "entry-plan",
                "[\"q=marker\"]", 1, "b".repeat(64), "2026-07-26T00:00:00Z");
        planPersistence.saveProbePlan(plan);
        check(planPersistence.loadProbePlans().equals(List.of(plan)),
                "V011 probe plan metadata survives persistence reconstruction");

        System.out.println("ControlPlanePersistenceAcceptanceTest: PASS");
    }

    private static HttpResponse<String> get(HttpClient client, URI uri) throws Exception {
        return client.send(HttpRequest.newBuilder(uri).GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private static URI uri(ControlPlaneServer server, String path) {
        return URI.create(server.baseUri() + path);
    }

    private static HttpResponse<String> send(HttpClient client, URI uri, String method, String json, String token)
            throws Exception {
        return send(client, uri, method, json, token, null);
    }

    private static HttpResponse<String> send(HttpClient client, URI uri, String method, String json,
                                             String token, String idempotencyKey) throws Exception {
        HttpRequest.BodyPublisher publisher = json.isEmpty()
                ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(json);
        HttpRequest.Builder request = HttpRequest.newBuilder(uri).header("Content-Type", "application/json");
        if (token != null) request.header("X-Sentinel-Authorization", token);
        if (idempotencyKey != null) request.header("Idempotency-Key", idempotencyKey);
        return client.send(request.method(method, publisher).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static Map<String, Object> body(HttpResponse<String> response) {
        check(response.statusCode() >= 200 && response.statusCode() < 300,
                "unexpected HTTP response " + response.statusCode() + ": " + response.body());
        return JsonCodec.parseObject(response.body());
    }

    private static Map<?, ?> first(List<?> values) {
        check(values != null && !values.isEmpty() && values.get(0) instanceof Map<?, ?>,
                "expected a non-empty object list");
        return (Map<?, ?>) values.get(0);
    }

    private static String text(Map<?, ?> value, String key) {
        Object result = value.get(key);
        check(result instanceof String && !((String) result).isBlank(), key + " is required");
        return (String) result;
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static <T extends Throwable> void expect(Class<T> type, ThrowingRunnable action, String message)
            throws Exception {
        try {
            action.run();
        } catch (Throwable actual) {
            if (type.isInstance(actual)) return;
            throw actual;
        }
        throw new AssertionError("expected " + type.getSimpleName() + ": " + message);
    }

    private static void expectFailure(ThrowingRunnable action, String message) throws Exception {
        try {
            action.run();
        } catch (Throwable expected) {
            return;
        }
        throw new AssertionError("expected failure: " + message);
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
