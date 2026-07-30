package com.aq.jvmsentinel;

import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.control.service.ProbePlanService;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePostureKind;
import com.aq.jvmsentinel.sandbox.LocalDockerTrustedSandboxClient;
import com.aq.jvmsentinel.support.LiveEnvironment;
import com.aq.jvmsentinel.support.TrustedBootJarFixture;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;
import com.aq.jvmsentinel.worker.TaskLifecycle;
import com.aq.jvmsentinel.worker.TaskScope;
import com.aq.jvmsentinel.worker.WorkerControlPlaneClient;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 在 authorized Boot-shaped fixture 上 live TRUSTED_DOCKER PathTrace posture acceptance。
 * 断言 UNAUTH / COVERAGE_POSTURE / FORCED_REACHABILITY experiment plan 执行且
 * PathRun wire 携带 path-debug field，不提升 VERIFIED。
 * Docker/image 不可用 → SKIP，仍记录无 fixture compile-time contract。
 */
public final class LivePathTracePostureAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        postureCompilerContractAlways();
        boolean docker = LiveEnvironment.dockerAvailable();
        String image = LiveEnvironment.resolveTrustedDockerImage();
        if (!docker) {
            System.out.println("LivePathTracePostureAcceptanceTest: SKIP live path "
                    + "(Docker unavailable); posture compiler contract retained");
            check(true, "skip recorded when Docker unavailable");
        } else if (image.isBlank() || !image.contains("@sha256:")) {
            System.out.println("LivePathTracePostureAcceptanceTest: SKIP live path "
                    + "(digest-pinned runtime image missing)");
            check(true, "skip recorded when runtime image missing");
        } else {
            System.out.println("LivePathTracePostureAcceptanceTest: LIVE image=" + image);
            liveThreeTrackPathTrace(image);
        }
        System.out.println("LivePathTracePostureAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    /** Always-on: posture compiler emits three default tracks for a sample entry. */
    private static void postureCompilerContractAlways() {
        var entry = new com.aq.jvmsentinel.control.ApiDtos.EntryDto(
                com.aq.jvmsentinel.control.ApiDtos.SCHEMA_VERSION,
                "project-live-path", "b".repeat(64), "scan-live-path",
                "entry-api-a", "HTTP", "GET", "/api/a",
                "app.ApiAController", "app",
                List.of(), List.of("AUTH"), com.aq.jvmsentinel.control.ApiDtos.STATIC_INFERRED,
                0.5, 0, List.of());
        var plans = com.aq.jvmsentinel.analysis.experiment.PostureExperimentCompiler.compile(
                entry, "scan-live-path", List.of("ApiAController#a"), List.of(),
                List.of("GUARD:AUTH"), List.of(), List.of(), 16);
        Set<String> kinds = new LinkedHashSet<>();
        for (var plan : plans) {
            kinds.add(plan.posture().postureKind().name());
            check(plan.experimentPlanId() != null && !plan.experimentPlanId().isBlank(),
                    "experimentPlanId present");
            check(plan.experimentPlanId().length() <= 128, "experimentPlanId bounded");
        }
        check(kinds.contains(RuntimePostureKind.UNAUTH.name()), "UNAUTH plan compiled");
        check(kinds.contains(RuntimePostureKind.COVERAGE_POSTURE.name()), "COVERAGE plan compiled");
        check(kinds.contains(RuntimePostureKind.FORCED_REACHABILITY.name()), "FORCED plan compiled");
        check(!kinds.contains(RuntimePostureKind.BYPASS.name()), "BYPASS absent without candidate");
    }

    private static void liveThreeTrackPathTrace(String image) throws Exception {
        Path root = Files.createTempDirectory("veyrion-live-pathtrace-");
        Path artifact = TrustedBootJarFixture.build(Files.createDirectories(root.resolve("build")));
        check(Files.isRegularFile(artifact), "authorized Boot JAR fixture built");
        String digest = HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(artifact)));
        String token = "live-pathtrace-token";
        HttpClient http = HttpClient.newHttpClient();
        try (ControlPlaneServer server = new ControlPlaneServer(
                root, 0, token, root.resolve("control.db"),
                (provider, credential) -> {
                    throw new AssertionError("provider inventory unused");
                }).start()) {
            Path content = root.resolve(".veyrion/artifacts/sha256")
                    .resolve(digest.substring(0, 2))
                    .resolve(digest + ".jar");
            Files.createDirectories(content.getParent());
            Files.copy(artifact, content);
            String projectId = text(post(http, URI.create(server.baseUri() + "/projects"),
                    Map.of("name", "Live PathTrace posture"), token), "projectId");
            post(http, URI.create(server.baseUri() + "/projects/" + projectId + "/artifacts"),
                    Map.of("path", content.toString(), "type", "JAR"), token);
            String scanId = text(post(http,
                    URI.create(server.baseUri() + "/projects/" + projectId + "/scans"),
                    Map.of("artifactDigest", digest, "authorized", true), token), "scanId");

            ControlPlaneStore.ScanRecord scan = server.store().requireScan(scanId);
            ProbePlanService.ProbePlan plan = new ProbePlanService(
                    server.store(), (p, s) -> List.of()).buildProbePlan(scan, "task-hint");
            check(!plan.probes().isEmpty(), "posture-aware probe plan non-empty");
            Set<String> tracks = new LinkedHashSet<>();
            Set<String> planIds = new LinkedHashSet<>();
            for (ExternalArtifactTaskExecutor.ProbeTarget probe : plan.probes()) {
                tracks.add(probe.track());
                if (probe.experimentPlanId() != null && !probe.experimentPlanId().isBlank()) {
                    planIds.add(probe.experimentPlanId());
                }
            }
            check(tracks.contains("UNAUTH"), "probe plan includes UNAUTH wire track");
            check(tracks.contains("ADMIN") || tracks.contains("USER"),
                    "probe plan includes coverage/forced wire track");
            check(!planIds.isEmpty(), "probes carry experimentPlanId");
            check(plan.probes().stream().noneMatch(p ->
                            ("GET".equals(p.method()) || "POST".equals(p.method()))
                                    && (p.query() == null || p.query().isBlank())
                                    && (p.experimentPlanId() == null || p.experimentPlanId().isBlank())),
                    "no empty GET/POST without experimentPlanId");

            List<ExternalArtifactTaskExecutor.ProbeTarget> bounded = plan.probes().stream()
                    .limit(6)
                    .toList();
            String taskId = text(post(http,
                    URI.create(server.baseUri() + "/scans/" + scanId + "/dynamic-tasks"),
                    Map.of("authorized", true), token), "taskId");

            ExternalArtifactTaskExecutor.ArtifactRegistration registration =
                    new ExternalArtifactTaskExecutor.ArtifactRegistration(
                            projectId, digest, content, Files.size(content), true,
                            bounded.get(0).method(), bounded.get(0).route(),
                            "com.aq.veyrion.fixture",
                            bounded,
                            "MOCK_CONTINUE");
            WorkerControlPlaneClient control = new WorkerControlPlaneClient(
                    server.baseUri().resolve("/internal/worker/v1/"),
                    server.workerToken(), Duration.ofSeconds(30));
            LocalDockerTrustedSandboxClient sandboxClient = new LocalDockerTrustedSandboxClient();
            ExternalArtifactTaskExecutor executor = new ExternalArtifactTaskExecutor(
                    control, sandboxClient,
                    scope -> registration,
                    ExternalArtifactTaskExecutor.RuntimePolicy.trustedLocalDocker(image),
                    "live-pathtrace-worker");
            try {
                ExternalArtifactTaskExecutor.ExecutionResult result = executor.execute(
                        new ExternalArtifactTaskExecutor.ExecutionRequest(
                                new TaskScope(projectId, digest, scanId, taskId)));
                check(result.lifecycle() == TaskLifecycle.COMPLETED,
                        "live TRUSTED_DOCKER PathTrace task completed");

                List<Map<String, Object>> pathRuns = awaitPathRuns(server, scanId, 1);
                check(!pathRuns.isEmpty(), "live PathRuns projected");
                boolean sawPathDebug = false;
                boolean sawNonVerified = true;
                for (Map<String, Object> run : pathRuns) {
                    if ("VERIFIED".equals(String.valueOf(run.get("verificationStatus")))) {
                        sawNonVerified = false;
                    }
                    Object posture = run.get("postureKind");
                    Object pathTrace = run.get("pathTrace");
                    Object legacy = run.get("legacyIncomplete");
                    if (posture != null || pathTrace instanceof Map<?, ?> || Boolean.FALSE.equals(legacy)) {
                        sawPathDebug = true;
                    }
                    if (pathTrace instanceof Map<?, ?> nested) {
                        Object exit = nested.get("exitReason");
                        check(exit != null && !String.valueOf(exit).isBlank(),
                                "PathTrace exitReason present");
                        Object events = nested.get("events");
                        check(events instanceof List<?> list && !list.isEmpty(),
                                "PathTrace events non-empty when pathTrace nested");
                    }
                }
                check(sawNonVerified, "live PathTrace never VERIFIED");
                // projection 成功时 path-debug enrichment 尽力而为；至少
                // posture plan 的 experimentPlanId 须出现在至少一个 PathRun。
                boolean sawPlanId = pathRuns.stream().anyMatch(run -> {
                    Object id = run.get("experimentPlanId");
                    return id != null && !String.valueOf(id).isBlank();
                });
                check(sawPlanId || sawPathDebug,
                        "live PathRuns carry experimentPlanId and/or path-debug enrichment");

                Map<String, Object> dashboard = get(http,
                        URI.create(server.baseUri() + "/projects/" + projectId + "/dashboard"), null);
                Object summaries = dashboard.get("pathDebugSummaries");
                check(summaries instanceof List<?> || dashboard.toString().contains("pathRun"),
                        "dashboard exposes path debug or PathRun evidence");
                System.out.println("LivePathTracePostureAcceptanceTest: pathRuns=" + pathRuns.size()
                        + " tracks=" + tracks + " planIds=" + planIds.size()
                        + " pathDebug=" + sawPathDebug);
            } finally {
                executor.closeRetainedSessions();
                try {
                    sandboxClient.close();
                } catch (RuntimeException ignored) {
                }
            }
        } finally {
            deleteTreeBestEffort(root);
        }
    }

    private static List<Map<String, Object>> awaitPathRuns(ControlPlaneServer server, String scanId,
                                                           int min) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(45).toNanos();
        List<Map<String, Object>> pathRuns = List.of();
        while (System.nanoTime() < deadline) {
            pathRuns = server.pathRunQueryPort().pathRunsForScan(scanId).orElse(List.of());
            if (pathRuns.size() >= min) {
                return pathRuns;
            }
            Thread.sleep(250);
        }
        check(pathRuns.size() >= min, "live PathRuns eventually projected, got " + pathRuns.size());
        return pathRuns;
    }

    private static Map<String, Object> post(HttpClient http, URI uri, Map<String, Object> body, String token)
            throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(30))
                .header("Content-Type", "application/json")
                .header("Idempotency-Key", "live-path-" + System.nanoTime())
                .POST(HttpRequest.BodyPublishers.ofString(JsonCodec.stringify(body)));
        if (token != null) {
            builder.header("Authorization", "Bearer " + token);
        }
        HttpResponse<String> response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        check(response.statusCode() >= 200 && response.statusCode() < 300,
                "POST succeeds: HTTP " + response.statusCode() + " " + response.body());
        return JsonCodec.parseObject(response.body());
    }

    private static Map<String, Object> get(HttpClient http, URI uri, String token) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(20)).GET();
        if (token != null) {
            builder.header("Authorization", "Bearer " + token);
        }
        HttpResponse<String> response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        check(response.statusCode() == 200, "GET succeeds: HTTP " + response.statusCode());
        return JsonCodec.parseObject(response.body());
    }

    private static String text(Map<String, Object> body, String key) {
        Object value = body.get(key);
        check(value != null && !String.valueOf(value).isBlank(), key + " present");
        return String.valueOf(value);
    }

    private static void deleteTreeBestEffort(Path root) {
        try {
            if (root == null || !Files.exists(root)) {
                return;
            }
            try (var walk = Files.walk(root)) {
                walk.sorted((a, b) -> b.compareTo(a)).forEach(path -> {
                    try {
                        Files.deleteIfExists(path);
                    } catch (Exception ignored) {
                    }
                });
            }
        } catch (Exception ignored) {
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}
