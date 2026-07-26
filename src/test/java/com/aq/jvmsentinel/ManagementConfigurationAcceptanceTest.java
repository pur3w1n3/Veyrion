package com.aq.jvmsentinel;

import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.security.ProviderSecretCipher;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.util.List;
import java.util.Map;

/** End-to-end local management configuration, RBAC, redaction, and restart checks. */
public final class ManagementConfigurationAcceptanceTest {
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("veyrion-management");
        Path database = root.resolve("state").resolve("control-plane.db");
        String bootstrap = "bootstrap-management-token";
        String secret = "test-provider-secret-zero-echo-41f087";
        HttpClient client = HttpClient.newHttpClient();

        String projectId;
        String providerId;
        String jobId;
        String viewerId;
        String viewerPat;
        try (ControlPlaneServer server = new ControlPlaneServer(root, 0, bootstrap, database).start()) {
            check(send(client, uri(server, "/providers"), "GET", "", server.workerToken()).statusCode() == 401,
                    "Worker token is rejected by operator routes");

            Map<String, Object> project = ok(send(client, uri(server, "/projects"), "POST",
                    "{\"name\":\"management fixture\"}", bootstrap));
            projectId = text(project, "projectId");

            String providerJson = "{\"name\":\"Provider A\",\"kind\":\"OPENAI_COMPATIBLE\","
                    + "\"baseUrl\":\"https://provider.invalid/v1\",\"model\":\"model-a\","
                    + "\"apiKey\":\"" + secret + "\",\"enabled\":true}";
            HttpResponse<String> providerResponse = send(client, uri(server, "/providers"),
                    "POST", providerJson, bootstrap);
            check(!providerResponse.body().contains(secret), "provider response has zero secret echo");
            Map<String, Object> provider = ok(providerResponse);
            providerId = text(provider, "providerId");
            check(Boolean.TRUE.equals(provider.get("hasCredential")), "credential configured flag is returned");

            HttpResponse<String> loopbackAnthropic = send(client, uri(server, "/providers"), "POST",
                    "{\"name\":\"Loopback Anthropic\",\"kind\":\"ANTHROPIC_MESSAGES\","
                            + "\"baseUrl\":\"http://127.0.0.1:3000\",\"model\":\"local-claude\","
                            + "\"apiKey\":\"loopback-secret\"}", bootstrap);
            check(loopbackAnthropic.statusCode() == 201
                            && !loopbackAnthropic.body().contains("loopback-secret"),
                    "native Anthropic permits plaintext loopback without echoing its credential");
            String loopbackProviderId = text(ok(loopbackAnthropic), "providerId");
            check(send(client, uri(server, "/providers/" + loopbackProviderId),
                    "DELETE", "", bootstrap).statusCode() == 204,
                    "loopback provider cleanup");

            HttpResponse<String> lanOpenAi = send(client, uri(server, "/providers"), "POST",
                    "{\"name\":\"LAN OpenAI\",\"kind\":\"OPENAI_CHAT\","
                            + "\"baseUrl\":\"http://192.168.1.10:3000/v1\",\"model\":\"lan-model\","
                            + "\"apiKey\":\"lan-secret\"}", bootstrap);
            check(lanOpenAi.statusCode() == 201 && !lanOpenAi.body().contains("lan-secret"),
                    "explicit LAN HTTP provider is accepted without echoing its credential");
            String lanProviderId = text(ok(lanOpenAi), "providerId");
            check(send(client, uri(server, "/providers/" + lanProviderId),
                    "DELETE", "", bootstrap).statusCode() == 204,
                    "LAN HTTP provider cleanup");

            String endpointSecret = "userinfo-secret-must-not-echo";
            HttpResponse<String> invalidEndpoint = send(client, uri(server, "/providers"), "POST",
                    "{\"name\":\"bad\",\"kind\":\"OPENAI_COMPATIBLE\","
                            + "\"baseUrl\":\"https://" + endpointSecret + "@provider.invalid/v1\"}",
                    bootstrap);
            check(invalidEndpoint.statusCode() == 400
                            && !invalidEndpoint.body().contains(endpointSecret),
                    "invalid endpoint is rejected without echo");
            check(send(client, uri(server, "/providers"), "POST",
                    "{\"name\":\"bad-local\",\"kind\":\"LOCAL\","
                            + "\"baseUrl\":\"http://192.0.2.1:11434\"}", bootstrap).statusCode() == 400,
                    "LOCAL provider rejects non-loopback endpoint");
            check(send(client, uri(server, "/providers"), "POST",
                    "{\"name\":\"bad-query\",\"kind\":\"AZURE_OPENAI\","
                            + "\"baseUrl\":\"https://provider.invalid/?x=1\"}", bootstrap).statusCode() == 400,
                    "remote provider rejects query component");

            Map<String, Object> viewer = ok(send(client, uri(server, "/operators"), "POST",
                    "{\"username\":\"viewer-a\",\"role\":\"VIEWER\"}", bootstrap));
            viewerId = text(viewer, "operatorId");
            viewerPat = text(viewer, "personalAccessToken");
            String listedOperators = send(client, uri(server, "/operators"), "GET", "", bootstrap).body();
            check(!listedOperators.contains(viewerPat) && !listedOperators.contains("personalAccessToken"),
                    "PAT is returned once only");
            check(send(client, uri(server, "/providers"), "POST", providerJson, viewerPat).statusCode() == 403,
                    "default-deny RBAC blocks provider management");

            URI roleUri = uri(server, "/projects/" + projectId
                    + "/role-assignments/PRE_ANALYSIS");
            Map<String, Object> role = ok(send(client, roleUri, "PATCH",
                    "{\"providerId\":\"" + providerId + "\",\"model\":\"model-a\"}", bootstrap));
            check(projectId.equals(role.get("projectId")), "role assignment remains project scoped");
            check(send(client, uri(server, "/projects/missing/role-assignments/PRE_ANALYSIS"),
                    "PATCH", "{\"providerId\":\"" + providerId + "\",\"model\":\"model-a\"}",
                    bootstrap).statusCode() == 404, "cross-project role write is rejected");

            check(send(client, uri(server, "/projects/" + projectId + "/ai-jobs"), "POST",
                    "{\"role\":\"PRE_ANALYSIS\"}", bootstrap).statusCode() == 403,
                    "AI job requires explicit request authorization");
            Map<String, Object> job = ok(send(client,
                    uri(server, "/projects/" + projectId + "/ai-jobs"), "POST",
                    "{\"role\":\"PRE_ANALYSIS\",\"authorized\":true}", bootstrap));
            jobId = text(job, "aiJobId");
            check("BLOCKED".equals(job.get("status"))
                            && "SCAN_REQUIRED".equals(job.get("errorCode")),
                    "AI job without a persisted scan is explicitly blocked");
            check(job.get("stages") instanceof List<?> stages && stages.size() == 1,
                    "AI job contains only its requested, versioned role stage");
            check(!job.toString().contains("VERIFIED"), "AI job never fabricates VERIFIED output");
            URI eventUri = uri(server, "/ai-jobs/" + jobId + "/events");
            check(send(client, eventUri, "GET", "", server.workerToken()).statusCode() == 401,
                    "Worker token is rejected by the AI job event route");
            Map<String, Object> emptyEvents = ok(send(client, eventUri, "GET", "", viewerPat));
            check(jobId.equals(emptyEvents.get("aiJobId"))
                            && projectId.equals(emptyEvents.get("projectId"))
                            && emptyEvents.get("aiJobEvents") instanceof List<?> events
                            && events.isEmpty(),
                    "AI job event response is authenticated and explicitly project scoped");
            check(send(client, uri(server, "/ai-jobs/missing/events"),
                    "GET", "", bootstrap).statusCode() == 404,
                    "AI job event route rejects an unknown job");

            Map<String, Object> audits = ok(send(client, uri(server,
                    "/projects/" + projectId + "/audit-events"), "GET", "", bootstrap));
            check(!((List<?>) audits.get("auditEvents")).isEmpty(), "project audit events are readable");

            ok(send(client, uri(server, "/operators/" + viewerId), "PATCH",
                    "{\"role\":\"VIEWER\",\"revokeTokens\":true}", bootstrap));
            check(send(client, uri(server, "/providers"), "GET", "", viewerPat).statusCode() == 401,
                    "revoked PAT is rejected");
        }

        assertSecretAbsent(root, secret);
        try (var connection = DriverManager.getConnection("jdbc:sqlite:" + database);
             var statement = connection.createStatement()) {
            statement.executeUpdate("DROP TABLE IF EXISTS ai_job_events");
            statement.executeUpdate("DROP TABLE IF EXISTS dynamic_probe_plans");
            statement.executeUpdate("DROP TABLE IF EXISTS audit_pipeline_runs");
            statement.executeUpdate("DROP TABLE IF EXISTS control_plane_idempotency");
            statement.executeUpdate("DROP TABLE IF EXISTS sse_events");
            statement.executeUpdate("DROP TABLE IF EXISTS worker_trace_chunks");
            statement.executeUpdate("DROP TABLE IF EXISTS worker_tasks");
            statement.executeUpdate("DROP TABLE IF EXISTS path_runs");
            statement.executeUpdate("""
                    CREATE TABLE project_ai_role_bindings_legacy (
                        project_id TEXT NOT NULL,
                        role TEXT NOT NULL CHECK (role IN (
                            'PRE_ANALYSIS','PATH_EXPLORATION','DYNAMIC_VERIFICATION',
                            'VULNERABILITY_TRIAGE','REPORT_GENERATION')),
                        workspace_id TEXT NOT NULL,
                        provider_id TEXT NOT NULL,
                        model TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        PRIMARY KEY (project_id, role))
                    """);
            statement.executeUpdate("INSERT INTO project_ai_role_bindings_legacy "
                    + "SELECT project_id,role,workspace_id,provider_id,model,updated_at "
                    + "FROM project_ai_role_bindings "
                    + "WHERE role IN ('PRE_ANALYSIS','PATH_EXPLORATION','DYNAMIC_VERIFICATION',"
                    + "'VULNERABILITY_TRIAGE','REPORT_GENERATION')");
            statement.executeUpdate("DROP TABLE project_ai_role_bindings");
            statement.executeUpdate("ALTER TABLE project_ai_role_bindings_legacy "
                    + "RENAME TO project_ai_role_bindings");
            int removed = statement.executeUpdate("DELETE FROM schema_migrations WHERE version>=5");
            check(removed == 9,
                    "V005-V013 are removed to emulate an existing V004 installation");
            check(statement.executeUpdate("UPDATE ai_jobs SET status='FAILED', stop_reason='HTTP_500'") == 1,
                    "legacy fixture represents a failed job without detailed event rows");
        }
        try (ControlPlaneServer restarted = new ControlPlaneServer(root, 0, bootstrap, database).start()) {
            Map<String, Object> providers = ok(send(client, uri(restarted, "/providers"),
                    "GET", "", bootstrap));
            check(((List<?>) providers.get("providers")).size() == 1,
                    "provider survives restart");
            Map<String, Object> roles = ok(send(client,
                    uri(restarted, "/projects/" + projectId + "/role-assignments"),
                    "GET", "", bootstrap));
            check(((List<?>) roles.get("roleAssignments")).size() == 1,
                    "role assignment survives restart");
            Map<String, Object> jobs = ok(send(client,
                    uri(restarted, "/projects/" + projectId + "/ai-jobs"),
                    "GET", "", bootstrap));
            check(jobId.equals(text(first((List<?>) jobs.get("aiJobs")), "aiJobId")),
                    "AI job survives restart");
            Map<String, Object> migratedEvents = ok(send(client,
                    uri(restarted, "/ai-jobs/" + jobId + "/events"),
                    "GET", "", bootstrap));
            check(jobId.equals(migratedEvents.get("aiJobId"))
                            && projectId.equals(migratedEvents.get("projectId")),
                    "migrated AI job event envelope retains job and project scope");
            Map<?, ?> migratedEvent = first((List<?>) migratedEvents.get("aiJobEvents"));
            check(migratedEvent.get("sequence") instanceof Number sequence
                            && sequence.longValue() == 1
                            && jobId.equals(migratedEvent.get("aiJobId"))
                            && projectId.equals(migratedEvent.get("projectId"))
                            && "MIGRATED_SNAPSHOT".equals(migratedEvent.get("stage"))
                            && "FAILED".equals(migratedEvent.get("status"))
                            && migratedEvent.get("failureDiagnostic") instanceof String diagnostic
                            && diagnostic.contains("HTTP_500")
                            && diagnostic.contains("provider response body was not retained"),
                    "failed V004 jobs receive one ordered snapshot with a clear retained-data diagnostic");
            Map<String, Object> audits = ok(send(client, uri(restarted, "/audit-events"),
                    "GET", "", bootstrap));
            check(!((List<?>) audits.get("auditEvents")).isEmpty(), "global audit survives restart");
        }

        try (var connection = DriverManager.getConnection("jdbc:sqlite:" + database);
             var query = connection.createStatement();
             var rows = query.executeQuery("SELECT ciphertext FROM provider_credentials")) {
            check(rows.next(), "encrypted provider credential exists");
            byte[] ciphertext = rows.getBytes(1);
            ciphertext[ciphertext.length - 1] ^= 1;
            try (var update = connection.prepareStatement(
                    "UPDATE provider_credentials SET ciphertext=?")) {
                update.setBytes(1, ciphertext);
                check(update.executeUpdate() == 1, "ciphertext tamper applied");
            }
        }
        ControlPlaneStore tampered = ControlPlaneStore.sqlite(database, root);
        try {
            tampered.verifyProviderCredential(providerId);
            throw new AssertionError("tampered ciphertext was accepted");
        } catch (ProviderSecretCipher.SecretIntegrityException expected) {
            // AES-GCM authentication fails closed.
        }

        System.out.println("ManagementConfigurationAcceptanceTest: PASS");
    }

    private static void assertSecretAbsent(Path root, String secret) throws Exception {
        byte[] needle = secret.getBytes(StandardCharsets.UTF_8);
        try (var paths = Files.walk(root)) {
            for (Path path : paths.filter(Files::isRegularFile).toList()) {
                byte[] data = Files.readAllBytes(path);
                check(indexOf(data, needle) < 0, "plaintext provider secret found in " + path.getFileName());
            }
        }
    }

    private static int indexOf(byte[] data, byte[] needle) {
        outer: for (int i = 0; i <= data.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) if (data[i + j] != needle[j]) continue outer;
            return i;
        }
        return -1;
    }

    private static URI uri(ControlPlaneServer server, String path) {
        return URI.create(server.baseUri() + path);
    }

    private static HttpResponse<String> send(HttpClient client, URI uri, String method,
                                             String json, String token) throws Exception {
        HttpRequest.BodyPublisher publisher = json.isEmpty()
                ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(json);
        HttpRequest.Builder request = HttpRequest.newBuilder(uri).header("Content-Type", "application/json");
        if (token != null) request.header("Authorization", "Bearer " + token);
        return client.send(request.method(method, publisher).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static Map<String, Object> ok(HttpResponse<String> response) {
        check(response.statusCode() >= 200 && response.statusCode() < 300,
                "unexpected response " + response.statusCode() + ": " + response.body());
        return JsonCodec.parseObject(response.body());
    }

    private static Map<?, ?> first(List<?> values) {
        check(values != null && !values.isEmpty() && values.get(0) instanceof Map<?, ?>,
                "expected non-empty object list");
        return (Map<?, ?>) values.get(0);
    }

    private static String text(Map<?, ?> value, String key) {
        Object result = value.get(key);
        check(result instanceof String && !((String) result).isBlank(), key + " is required");
        return (String) result;
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
