package com.aq.jvmsentinel;

import com.aq.jvmsentinel.ai.AuthBypassFeasibility;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.control.service.ProbePlanService;
import com.aq.jvmsentinel.model.AuthBypassTechnique;
import com.aq.jvmsentinel.model.ExperimentPlan;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.model.PathOutcomeClass;
import com.aq.jvmsentinel.model.PathOutcomeClassifier;
import com.aq.jvmsentinel.model.VerificationStatus;
import com.aq.jvmsentinel.worker.DynamicConfirmedGate;
import com.aq.jvmsentinel.worker.SqlDiffProbe;
import com.aq.jvmsentinel.worker.SqlExperimentCardBuilder;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

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
 * P1-20: single-entry debug baseline with fixture strategy + mock-transport identity chain
 * AUTH / AUTH_CONFIRM → PathRun → report → replay. Declared AUDITED for mock transport only;
 * no live Docker; VERIFIED remains closed.
 */
public final class SingleEntryDebugBaselineAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String BASELINE_RESOURCE = "baselines/p1-20-single-entry-debug.json";

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        JsonNode baseline = loadBaseline();
        checkBaselineContract(baseline);
        String planId = baseline.path("identity").path("experimentPlanId").asText();
        authMaterializationMatchesStrategy(baseline);
        authConfirmPassDistinctFromInitial(baseline);
        endToEndIdentityWithMockTransport(planId, baseline);
        System.out.println("SingleEntryDebugBaselineAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static JsonNode loadBaseline() throws Exception {
        try (var in = SingleEntryDebugBaselineAcceptanceTest.class.getClassLoader()
                .getResourceAsStream(BASELINE_RESOURCE)) {
            check(in != null, "baseline fixture present: " + BASELINE_RESOURCE);
            return JSON.readTree(in);
        }
    }

    private static void checkBaselineContract(JsonNode baseline) {
        check("p1-20-single-entry-debug".equals(baseline.path("baselineId").asText()),
                "baselineId matches P1-20");
        check("AUDITED".equals(baseline.path("status").asText()), "baseline status AUDITED");
        check(baseline.path("auditedScope").asText().contains("mock-transport"),
                "audited scope names mock-transport");
        check("/focus".equals(baseline.path("artifact").path("entryRoute").asText()),
                "fixed high-value entry route");
        check(baseline.path("pipeline").path("mockTransportAllowed").asBoolean(false),
                "mock transport allowed");
        check(baseline.path("pipeline").path("forbidVerified").asBoolean(false),
                "VERIFIED forbidden in strategy");
        check(baseline.path("identity").path("unavailableMustNotForgeToken").asBoolean(false),
                "IDENTITY_UNAVAILABLE must not forge tokens");
        check(AuthBypassFeasibility.AUTH_PASS_INITIAL.equals(
                        baseline.path("identity").path("authPasses").path("initial").asText()),
                "baseline declares AUTH_INITIAL");
        check(AuthBypassFeasibility.AUTH_PASS_CONFIRM.equals(
                        baseline.path("identity").path("authPasses").path("confirm").asText()),
                "baseline declares AUTH_BYPASS_CONFIRM");
        check(baseline.path("evidence").path("requireExperimentPlanIdOnReportToReplay").asBoolean(false),
                "report→replay requires experimentPlanId");
    }

    private static void authConfirmPassDistinctFromInitial(JsonNode baseline) {
        String initial = baseline.path("identity").path("authPasses").path("initial").asText();
        String confirm = baseline.path("identity").path("authPasses").path("confirm").asText();
        check(AuthBypassFeasibility.AUTH_PASS_INITIAL.equals(initial), "AUTH_INITIAL constant");
        check(AuthBypassFeasibility.AUTH_PASS_CONFIRM.equals(confirm),
                "AUTH_BYPASS_CONFIRM constant");
        check(!initial.equals(confirm), "AUTH_CONFIRM pass is distinct from AUTH_INITIAL");
        check(baseline.path("pipeline").path("stages").toString().contains("AUTH_CONFIRM"),
                "pipeline stages list AUTH_CONFIRM");
    }

    private static void authMaterializationMatchesStrategy(JsonNode baseline) {
        for (JsonNode technique : baseline.path("identity").path("authTechniques")) {
            String id = technique.asText();
            check(AuthBypassTechnique.tryParse(id).isPresent(), "technique recognized: " + id);
            ProbePlanService.AuthMaterialized mat =
                    ProbePlanService.materializeAiPocAuth(id, null, null, null);
            if ("MISSING_AUTH".equals(id)) {
                check(mat.identityAvailable() && mat.authToken().isBlank(),
                        "MISSING_AUTH is available without forged bearer");
            } else if ("EMPTY_BEARER".equals(id)) {
                check(mat.identityAvailable(), "EMPTY_BEARER available without harvest");
                check(mat.track() == IdentityTrack.BYPASS_CANDIDATE,
                        "EMPTY_BEARER stays BYPASS_CANDIDATE (not UNAUTH omission)");
                check(mat.authToken() != null && !mat.authToken().isEmpty(),
                        "EMPTY_BEARER uses blank-ish bearer material, not omitted UNAUTH");
            } else if ("ALG_NONE".equals(id)) {
                check(mat.identityAvailable() && mat.authToken().contains("."),
                        "ALG_NONE mints unsigned JWT without harvest");
            }
        }
        ProbePlanService.AuthMaterialized unavailable =
                ProbePlanService.materializeAiPocAuth("DEFAULT_SECRET_HS256", null, null, null);
        check(!unavailable.identityAvailable(), "no-harvest DEFAULT_SECRET is IDENTITY_UNAVAILABLE");
        check(unavailable.authToken().isBlank(), "unavailable track does not forge token");
        check(unavailable.provenance() != null
                        && unavailable.provenance().contains("IDENTITY_UNAVAILABLE"),
                "unavailable provenance is explicit");
    }

    private static void endToEndIdentityWithMockTransport(String planId, JsonNode baseline)
            throws Exception {
        Path root = Files.createTempDirectory("p1-20-single-entry");
        try {
            Path jar = buildFixtureJar(root);
            String token = "p1-20-debug-token";
            HttpClient client = HttpClient.newHttpClient();
            try (ControlPlaneServer server = new ControlPlaneServer(
                    root, 0, token, root.resolve("state/control-plane.db")).start()) {
                URI base = server.baseUri();
                String projectId = text(request(client, URI.create(base + "/projects"), "POST",
                        "{\"name\":\"p1-20-debug\"}", token, "p1-20-project"), "projectId");
                String digest = text(request(client,
                        URI.create(base + "/projects/" + projectId + "/artifacts"), "POST",
                        "{\"path\":\"" + escape(jar.toString()) + "\"}", token, "p1-20-artifact"),
                        "artifactDigest");
                check(digest.matches("[a-f0-9]{64}"), "artifact digest is sha256 hex");
                Map<String, Object> scan = json(request(client,
                        URI.create(base + "/projects/" + projectId + "/scans"), "POST",
                        "{\"artifactDigest\":\"" + digest + "\",\"authorized\":true}",
                        token, "p1-20-scan"));
                String scanId = text(scan, "scanId");
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> entries = (List<Map<String, Object>>) scan.get("entries");
                check(entries != null && !entries.isEmpty(), "scan exposes entries");
                String entryId = text(entries.get(0), "id");
                String entryRef = "entry:" + entryId;
                check("/focus".equals(text(entries.get(0), "route"))
                                || String.valueOf(entries.get(0).get("route")).contains("focus"),
                        "fixture entry matches baseline route");

                // AUTH stage (mock): plan accepted for fixed entry × UNAUTH track.
                server.acceptExperimentPlan(scanId, new ExperimentPlan(
                        planId, entryRef, IdentityTrack.UNAUTH, "GET",
                        "application/json", List.of("q"), false, "2xx", "", 2,
                        List.of("q=benign", "q=" + SqlDiffProbe.META_MARKER), "COMPLETED", ""));

                // PathRun stage (mock transport): seed benign/meta SQL evidence.
                ApiDtos.PathRunDto benign = pathRun("pr-p120-b", scanId, entryRef, planId,
                        "GET /focus?q=benign",
                        "SELECT id FROM t WHERE q='benign'", false, "DYNAMIC_SUSPECTED");
                ApiDtos.PathRunDto meta = pathRun("pr-p120-m", scanId, entryRef, planId,
                        "GET /focus?q=" + SqlDiffProbe.META_MARKER,
                        "SELECT id FROM t WHERE q='" + SqlDiffProbe.META_MARKER, true,
                        "DYNAMIC_SUSPECTED");
                server.store().replacePathRunsForTask(projectId, digest, scanId, "task-p120-seed",
                        List.of(benign, meta), Instant.now().toString());

                // H3 may confirm; VERIFIED must never appear.
                var modelPathRun = new com.aq.jvmsentinel.model.PathRun(
                        meta.pathRunId(), meta.scanId(), meta.entrypointRef(), IdentityTrack.UNAUTH,
                        meta.attemptId(), meta.experimentPlanId(), meta.method(), meta.contentType(),
                        meta.requestSummary(), PathOutcomeClass.HTTP_OBSERVED, meta.httpStatus(),
                        true, true,
                        List.of(new com.aq.jvmsentinel.model.SqlEvent(
                                meta.sqlEvents().get(0).sqlText(), "", "READ", false, true, "MOCK")),
                        "COMPLETED", "DYNAMIC_SUSPECTED", meta.evidenceRefs(), "MOCK", "");
                VerificationStatus h3 = DynamicConfirmedGate.evaluate(modelPathRun, SqlDiffProbe.META_MARKER);
                check(h3 == VerificationStatus.DYNAMIC_CONFIRMED
                                || h3 == VerificationStatus.DYNAMIC_SUSPECTED,
                        "H3 stays within allowed max statuses");
                check(h3 != VerificationStatus.VERIFIED, "baseline never opens VERIFIED");

                // TRIAGE / D3 card identity from PathRuns.
                var cards = SqlExperimentCardBuilder.fromPathRuns(scanId, List.of(benign, meta));
                check(!cards.isEmpty(), "D3 card built from mock PathRun pair");
                check(planId.equals(cards.get(0).experimentPlanId()),
                        "TRIAGE card carries experimentPlanId");
                check(!"VERIFIED".equals(cards.get(0).verificationStatus()),
                        "D3 card never claims VERIFIED");

                // Replay identity (mock transport cancel + replay accept).
                Map<String, Object> dashboard = json(request(client,
                        URI.create(base + "/projects/" + projectId + "/dashboard?scanId=" + scanId),
                        "GET", null, token, null));
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> cardMaps =
                        (List<Map<String, Object>>) dashboard.get("sqlExperimentCards");
                check(cardMaps != null && !cardMaps.isEmpty(), "dashboard exposes D3 cards");
                String cardId = text(cardMaps.get(0), "cardId");
                check(planId.equals(cardMaps.get(0).get("experimentPlanId")),
                        "dashboard card keeps experimentPlanId");

                // Report → replay identity: dashboard report/card planId must match replay.
                check(planId.equals(cardMaps.get(0).get("experimentPlanId")),
                        "report/dashboard card planId is replay source identity");
                Object reportPlan = dashboard.get("experimentPlans");
                if (reportPlan instanceof List<?> plans && !plans.isEmpty()
                        && plans.get(0) instanceof Map<?, ?> planMap) {
                    Object reportedId = planMap.containsKey("experimentPlanId")
                            ? planMap.get("experimentPlanId") : planMap.get("planId");
                    if (reportedId != null && !String.valueOf(reportedId).isBlank()) {
                        check(planId.equals(String.valueOf(reportedId)),
                                "report experimentPlans carry same planId");
                    }
                }

                cancelActiveDynamicTasks(server, projectId, scanId);
                HttpResponse<String> replay = request(client,
                        URI.create(base + "/scans/" + scanId + "/experiment-cards/" + cardId + "/replay"),
                        "POST", "{\"authorized\":true}", token, "p1-20-replay");
                check(replay.statusCode() == 202 || replay.statusCode() == 200,
                        "replay accepted under mock transport");
                Map<String, Object> replayBody = json(replay);
                check(planId.equals(replayBody.get("experimentPlanId")),
                        "report→replay preserves experimentPlanId identity");
                check("REPLAY".equals(replayBody.get("attemptKind"))
                                || Boolean.TRUE.equals(replayBody.get("replayed"))
                                || replayBody.get("taskId") != null,
                        "replay returns attempt/task identity");

                // AUTH_CONFIRM three-state gate (mock): hypothesis / contrast / insufficient.
                AuthBypassFeasibility.BypassConfirmation hypothesis =
                        AuthBypassFeasibility.evaluateBypassConfirmation(
                                "{\"summary\":\"feasibility only\"}", List.of(), List.of());
                check(hypothesis.status() == AuthBypassFeasibility.BypassConfirmationStatus.HYPOTHESIS,
                        "AUTH_CONFIRM without claim stays HYPOTHESIS");
                ApiDtos.PathRunDto challenge = new ApiDtos.PathRunDto(
                        ApiDtos.SCHEMA_VERSION, "pr-p120-auth", scanId, entryRef,
                        "BYPASS_CANDIDATE", "attempt-auth", planId, "GET", "application/json",
                        "GET /focus", "AUTH_CHALLENGE", 401, true, false, List.of(),
                        "AUTH_CHALLENGE", "DYNAMIC_SUSPECTED", List.of("ev-auth"), "MOCK", "");
                AuthBypassFeasibility.BypassConfirmation contrast =
                        AuthBypassFeasibility.evaluateBypassConfirmation(
                                "{\"bypassConfirmation\":{\"status\":\"DYNAMIC_CONTRAST\"},"
                                        + "\"summary\":\"AUTH_BYPASS_CONFIRMED\"}",
                                List.of(challenge), List.of());
                check(contrast.status() == AuthBypassFeasibility.BypassConfirmationStatus.DYNAMIC_CONTRAST,
                        "AUTH_CONFIRM with AUTH_CHALLENGE PathRun → DYNAMIC_CONTRAST");
                AuthBypassFeasibility.BypassConfirmation insufficient =
                        AuthBypassFeasibility.evaluateBypassConfirmation(
                                "{\"bypassConfirmation\":{\"status\":\"DYNAMIC_CONTRAST\"},"
                                        + "\"summary\":\"AUTH_BYPASS_CONFIRMED\"}",
                                List.of(), List.of());
                check(insufficient.status()
                                == AuthBypassFeasibility.BypassConfirmationStatus.INSUFFICIENT_EVIDENCE,
                        "AUTH_CONFIRM claim without PathRun → INSUFFICIENT_EVIDENCE");

                // AUTH contrast codes remain classifiable without live Docker.
                check(PathOutcomeClassifier.classify(401, "", "unauthorized")
                                == PathOutcomeClass.AUTH_CHALLENGE,
                        "MISSING_AUTH contrast 401 → AUTH_CHALLENGE");
                check(PathOutcomeClassifier.classify(200, "", "ok")
                                == PathOutcomeClass.HTTP_OBSERVED,
                        "pass-gate 200 → HTTP_OBSERVED");
                check(baseline.path("pipeline").path("forbidVerified").asBoolean(),
                        "strategy forbidVerified remains true after run");
            }
        } finally {
            deleteTree(root);
        }
    }

    private static ApiDtos.PathRunDto pathRun(String id, String scanId, String entryRef, String planId,
                                              String requestSummary, String sql, boolean meta,
                                              String status) {
        return new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION, id, scanId, entryRef, "UNAUTH", "attempt-0", planId,
                "GET", "application/json", requestSummary, "HTTP_OBSERVED", 200,
                true, true,
                List.of(new ApiDtos.SqlEventDto(sql, meta ? "meta" : "benign", "READ", !meta, meta, "MOCK")),
                "COMPLETED", status, List.of("ev-" + id), "MOCK", "");
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
        Path jar = root.resolve("p1-20-focus-fixture.jar");
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
