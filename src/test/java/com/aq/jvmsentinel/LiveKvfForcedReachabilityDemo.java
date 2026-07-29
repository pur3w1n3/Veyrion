package com.aq.jvmsentinel;

import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.control.service.ProbePlanService;
import com.aq.jvmsentinel.sandbox.LocalDockerTrustedSandboxClient;
import com.aq.jvmsentinel.support.LiveEnvironment;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;
import com.aq.jvmsentinel.worker.TaskLifecycle;
import com.aq.jvmsentinel.worker.TaskScope;
import com.aq.jvmsentinel.worker.WorkerControlPlaneClient;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Manual Docker demo: kvf Shiro JAR under FORCED_REACHABILITY + session seed.
 * Always releases retained sandboxes in {@code finally}. Not a VERIFIED claim.
 */
public final class LiveKvfForcedReachabilityDemo {
    private static final String DEFAULT_KVF =
            "E:/ai/Veyrion/samples/.veyrion/artifacts/sha256/7b/"
                    + "7b2113c240e1abb74747145f95eac259b30276d2973c0a8afb3dedb58fab1752.jar";

    private LiveKvfForcedReachabilityDemo() {
    }

    public static void main(String[] args) throws Exception {
        Path jar = Path.of(args.length > 0 ? args[0] : DEFAULT_KVF).toAbsolutePath().normalize();
        if (!Files.isRegularFile(jar)) {
            throw new IllegalStateException("kvf JAR missing: " + jar);
        }
        boolean docker = LiveEnvironment.dockerAvailable();
        String image = LiveEnvironment.resolveTrustedDockerImage();
        System.out.println("=== LiveKvfForcedReachabilityDemo ===");
        System.out.println("jar=" + jar);
        System.out.println("docker=" + docker + " image=" + (image.isBlank() ? "(none)" : image));
        if (!docker || image.isBlank() || !image.contains("@sha256:")) {
            throw new IllegalStateException(
                    "digest-pinned TRUSTED_DOCKER image required; rebuild with "
                            + "Start-Veyrion -WithDockerRuntime -RebuildRuntimeImage");
        }

        String digest = HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(jar)));
        System.out.println("sha256=" + digest);

        Path root = Files.createTempDirectory("veyrion-kvf-forced-");
        LocalDockerTrustedSandboxClient sandboxClient = null;
        ExternalArtifactTaskExecutor executor = null;
        try {
            String token = "kvf-forced-token";
            HttpClient http = HttpClient.newHttpClient();
            try (ControlPlaneServer server = new ControlPlaneServer(
                    root, 0, token, root.resolve("control.db"),
                    (provider, credential) -> {
                        throw new AssertionError("provider unused");
                    }).start()) {
                Path content = root.resolve(".veyrion/artifacts/sha256")
                        .resolve(digest.substring(0, 2))
                        .resolve(digest + ".jar");
                Files.createDirectories(content.getParent());
                Files.copy(jar, content);

                String projectId = text(post(http, URI.create(server.baseUri() + "/projects"),
                        Map.of("name", "Kvf Forced Reachability"), token), "projectId");
                post(http, URI.create(server.baseUri() + "/projects/" + projectId + "/artifacts"),
                        Map.of("path", content.toString(), "type", "JAR"), token);
                String scanId = text(post(http,
                        URI.create(server.baseUri() + "/projects/" + projectId + "/scans"),
                        Map.of("artifactDigest", digest, "authorized", true), token), "scanId");

                ControlPlaneStore.ScanRecord scan = server.store().requireScan(scanId);
                System.out.println("entries=" + scan.dto().entries().size()
                        + " sinks=" + scan.dto().sinks().size());

                ProbePlanService.ProbePlan plan = new ProbePlanService(
                        server.store(), (p, s) -> List.of()).buildProbePlan(scan, "kvf-forced");
                List<ExternalArtifactTaskExecutor.ProbeTarget> forcedHeavy = selectProbes(plan.probes());
                System.out.println("probePlan total=" + plan.probes().size()
                        + " selected=" + forcedHeavy.size());
                for (ExternalArtifactTaskExecutor.ProbeTarget probe : forcedHeavy) {
                    System.out.println("  " + probe.track() + " " + probe.method() + " "
                            + probe.route()
                            + " cookie=" + (probe.cookieHeader().isBlank() ? "-" : "yes")
                            + " auth=" + (probe.authHeader().isBlank() ? "-" : "yes")
                            + " plan=" + probe.experimentPlanId());
                }
                if (forcedHeavy.isEmpty()) {
                    throw new IllegalStateException("no probes selected for live run");
                }

                String taskId = text(post(http,
                        URI.create(server.baseUri() + "/scans/" + scanId + "/dynamic-tasks"),
                        Map.of("authorized", true), token), "taskId");

                ExternalArtifactTaskExecutor.ArtifactRegistration registration =
                        new ExternalArtifactTaskExecutor.ArtifactRegistration(
                                projectId, digest, content, Files.size(content), true,
                                forcedHeavy.get(0).method(), forcedHeavy.get(0).route(),
                                "com.kalvin.kvf",
                                forcedHeavy,
                                "MOCK_CONTINUE");

                WorkerControlPlaneClient control = new WorkerControlPlaneClient(
                        server.baseUri().resolve("/internal/worker/v1/"),
                        server.workerToken(), Duration.ofSeconds(60));
                sandboxClient = new LocalDockerTrustedSandboxClient();
                executor = new ExternalArtifactTaskExecutor(
                        control, sandboxClient,
                        scope -> registration,
                        ExternalArtifactTaskExecutor.RuntimePolicy.trustedLocalDocker(image),
                        "kvf-forced-worker");

                TaskScope scope = new TaskScope(projectId, digest, scanId, taskId);
                try {
                    var before = control.get(scope);
                    System.out.println("preExecute lifecycle=" + before.lifecycle()
                            + " capability=" + before.requiredCapability()
                            + " authorized=" + before.authorized()
                            + " budgetWall=" + before.resourceBudget().maxWallClockSeconds());
                    ExternalArtifactTaskExecutor.ExecutionResult result = executor.execute(
                            new ExternalArtifactTaskExecutor.ExecutionRequest(scope));
                    System.out.println("lifecycle=" + result.lifecycle()
                            + " chunks=" + result.traceChunks());
                } catch (RuntimeException ex) {
                    System.out.println("EXECUTE_FAILED: " + ex.getClass().getSimpleName()
                            + ": " + ex.getMessage());
                    printDynamicTaskDiagnostics(http, server, scanId, token);
                }

                List<Map<String, Object>> pathRuns = awaitPathRuns(server, scanId, 1);
                summarize(pathRuns);
                summarizePathTraces(server, scanId, pathRuns);
            }
        } finally {
            if (executor != null) {
                try {
                    executor.closeRetainedSessions();
                    System.out.println("released retained sandbox sessions");
                } catch (RuntimeException ex) {
                    System.out.println("closeRetainedSessions: " + ex.getMessage());
                }
            }
            if (sandboxClient != null) {
                try {
                    sandboxClient.close();
                } catch (RuntimeException ignored) {
                }
            }
            purgeVeyrionTrustedContainers();
            deleteTreeBestEffort(root);
            System.out.println("cleanup done");
        }
    }

    /** Prefer FORCED planIds / ADMIN tracks on a few high-signal routes. */
    private static List<ExternalArtifactTaskExecutor.ProbeTarget> selectProbes(
            List<ExternalArtifactTaskExecutor.ProbeTarget> probes) {
        List<ExternalArtifactTaskExecutor.ProbeTarget> forced = new ArrayList<>();
        List<ExternalArtifactTaskExecutor.ProbeTarget> other = new ArrayList<>();
        for (ExternalArtifactTaskExecutor.ProbeTarget probe : probes) {
            if (probe == null) continue;
            String planId = probe.experimentPlanId() == null ? "" : probe.experimentPlanId();
            boolean isForced = planId.toUpperCase(Locale.ROOT).contains("FORCED");
            boolean interesting = probe.route() != null && (
                    probe.route().toLowerCase(Locale.ROOT).contains("admin")
                            || probe.route().toLowerCase(Locale.ROOT).contains("user")
                            || probe.route().toLowerCase(Locale.ROOT).contains("sys")
                            || probe.route().toLowerCase(Locale.ROOT).contains("generator")
                            || probe.route().toLowerCase(Locale.ROOT).contains("check/code")
                            || probe.route().equals("/")
                            || probe.route().contains("login"));
            if (isForced && interesting) {
                forced.add(probe);
            } else if (isForced) {
                other.add(probe);
            }
        }
        List<ExternalArtifactTaskExecutor.ProbeTarget> out = new ArrayList<>();
        // Prefer QLExpress expression-injection surface (exact /generator/check/code).
        forced.stream()
                .filter(p -> p.route() != null
                        && p.route().replace('\\', '/').endsWith("/generator/check/code"))
                .findFirst()
                .ifPresent(out::add);
        if (out.isEmpty()) {
            forced.stream()
                    .filter(p -> p.route() != null && p.route().contains("/generator/check/code"))
                    .findFirst()
                    .ifPresent(out::add);
        }
        for (ExternalArtifactTaskExecutor.ProbeTarget probe : forced) {
            if (out.size() >= 4) break;
            if (out.stream().anyMatch(existing -> existing.route().equals(probe.route())
                    && existing.experimentPlanId().equals(probe.experimentPlanId()))) {
                continue;
            }
            out.add(probe);
        }
        for (ExternalArtifactTaskExecutor.ProbeTarget probe : other) {
            if (out.size() >= 5) break;
            out.add(probe);
        }
        if (out.isEmpty()) {
            return probes.stream().limit(4).collect(Collectors.toList());
        }
        // Always include one UNAUTH twin for contrast when present.
        probes.stream()
                .filter(p -> "UNAUTH".equals(p.track()))
                .filter(p -> out.stream().anyMatch(f -> f.route().equals(p.route())))
                .findFirst()
                .ifPresent(unauth -> {
                    if (out.stream().noneMatch(p -> "UNAUTH".equals(p.track()))) {
                        out.add(0, unauth);
                    }
                });
        return out.stream().limit(5).collect(Collectors.toList());
    }

    private static void summarize(List<Map<String, Object>> pathRuns) {
        System.out.println("--- PathRuns (" + pathRuns.size() + ") ---");
        if (!pathRuns.isEmpty()) {
            System.out.println("sampleKeys=" + pathRuns.get(0).keySet());
        }
        Set<String> statuses = new LinkedHashSet<>();
        boolean sawForcedAllow = false;
        boolean sawNon302Admin = false;
        boolean sawEntryHit = false;
        for (Map<String, Object> run : pathRuns) {
            Object httpStatus = first(run, "httpStatus", "status");
            Object track = first(run, "identityTrack", "track", "identity");
            Object posture = first(run, "postureKind", "runtimePosture", "posture");
            Object outcome = first(run, "outcomeClass", "outcome");
            Object planId = first(run, "experimentPlanId", "planId");
            statuses.add(String.valueOf(httpStatus));
            Object entryHit = run.get("entryHit");
            Object forcedGuards = run.get("forcedGuardRefs");
            Object lastHop = run.get("lastBusinessHop");
            Object exitReason = run.get("exitReason");
            System.out.println("  track=" + track
                    + " posture=" + posture
                    + " http=" + httpStatus
                    + " outcome=" + outcome
                    + " entryHit=" + entryHit
                    + " forcedGuards=" + forcedGuards
                    + " lastHop=" + lastHop
                    + " exit=" + exitReason
                    + " plan=" + planId);
            String blob = run.toString().toLowerCase(Locale.ROOT);
            if (blob.contains("forced_allow") || blob.contains("forced_reachability")
                    || "FORCED_REACHABILITY".equals(String.valueOf(posture))) {
                sawForcedAllow = true;
            }
            if (Boolean.TRUE.equals(entryHit)
                    || "true".equalsIgnoreCase(String.valueOf(entryHit))
                    || blob.contains("\"entryhit\":true")) {
                sawEntryHit = true;
            }
            int status = -1;
            try {
                status = Integer.parseInt(String.valueOf(httpStatus));
            } catch (NumberFormatException ignored) {
            }
            if (!"UNAUTH".equals(String.valueOf(track)) && status > 0 && status != 302 && status != 401) {
                sawNon302Admin = true;
            }
        }
        System.out.println("httpStatuses=" + statuses
                + " sawForcedSignal=" + sawForcedAllow
                + " sawEntryHit=" + sawEntryHit
                + " sawNonWallPrivilegedHttp=" + sawNon302Admin);
        System.out.println("NOTE: non-wall HTTP under FORCED is exploration evidence "
                + "(INSTRUMENTATION_REACHABILITY), not VERIFIED exploitability.");
    }

    private static void summarizePathTraces(ControlPlaneServer server, String scanId,
                                            List<Map<String, Object>> pathRuns) {
        System.out.println("--- PathTraces ---");
        int forcedWithHops = 0;
        int forcedEmpty = 0;
        int forcedGuardAllow = 0;
        int forcedEffect = 0;
        for (Map<String, Object> run : pathRuns) {
            String pathRunId = String.valueOf(run.get("pathRunId"));
            if (pathRunId == null || pathRunId.isBlank() || "null".equals(pathRunId)) {
                continue;
            }
            var trace = server.store().pathTraceForPathRun(pathRunId);
            if (trace == null) {
                System.out.println("  missing PathTrace for " + pathRunId);
                continue;
            }
            String posture = trace.posture() == null || trace.posture().postureKind() == null
                    ? "?" : trace.posture().postureKind().name();
            int hops = 0;
            int guards = 0;
            int forcedGuards = 0;
            int effects = 0;
            int entries = 0;
            for (var event : trace.events()) {
                if (event == null || event.kind() == null) continue;
                switch (event.kind().name()) {
                    case "METHOD_HOP" -> hops++;
                    case "GUARD_DECISION" -> {
                        guards++;
                        if (event.forced()) forcedGuards++;
                    }
                    case "EFFECT_TRIGGERED" -> effects++;
                    case "ENTRY_HIT" -> entries++;
                    default -> {
                    }
                }
            }
            boolean isForced = posture.contains("FORCED");
            if (isForced) {
                if (hops > 0) forcedWithHops++;
                else forcedEmpty++;
                if (forcedGuards > 0) forcedGuardAllow++;
                if (effects > 0) forcedEffect++;
            }
            System.out.println("  " + pathRunId
                    + " posture=" + posture
                    + " events=" + trace.events().size()
                    + " ENTRY_HIT=" + entries
                    + " METHOD_HOP=" + hops
                    + " GUARD=" + guards
                    + " FORCED_ALLOW=" + forcedGuards
                    + " EFFECT=" + effects
                    + " lastHop=" + trace.lastBusinessHop());
        }
        System.out.println("forcedWithMethodHops=" + forcedWithHops
                + " forcedEmptyTraces=" + forcedEmpty
                + " forcedWithFORCED_ALLOW=" + forcedGuardAllow
                + " forcedWithEffect=" + forcedEffect);
    }

    private static Object first(Map<String, Object> run, String... keys) {
        for (String key : keys) {
            Object value = run.get(key);
            if (value != null && !String.valueOf(value).isBlank()) {
                return value;
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static void printDynamicTaskDiagnostics(HttpClient http, ControlPlaneServer server,
                                                    String scanId, String token) {
        try {
            HttpRequest request = HttpRequest.newBuilder(
                            URI.create(server.baseUri() + "/scans/" + scanId + "/dynamic-tasks"))
                    .timeout(Duration.ofSeconds(30))
                    .header("Authorization", "Bearer " + token)
                    .GET()
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            System.out.println("dynamic-tasks HTTP " + response.statusCode());
            Map<String, Object> body = JsonCodec.parseObject(response.body());
            Object tasks = body.get("dynamicTasks");
            if (!(tasks instanceof List<?> list)) {
                System.out.println("dynamicTasks body=" + response.body());
                return;
            }
            for (Object item : list) {
                if (!(item instanceof Map<?, ?> raw)) continue;
                Map<String, Object> task = (Map<String, Object>) raw;
                System.out.println("  taskId=" + task.get("taskId")
                        + " lifecycle=" + task.get("lifecycle")
                        + " failureCode=" + task.get("failureCode")
                        + " failureDiagnostic=" + task.get("failureDiagnostic"));
            }
        } catch (Exception ex) {
            System.out.println("dynamic-tasks diagnostics failed: " + ex.getMessage());
        }
    }

    private static List<Map<String, Object>> awaitPathRuns(ControlPlaneServer server, String scanId,
                                                           int min) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(90).toNanos();
        List<Map<String, Object>> pathRuns = List.of();
        while (System.nanoTime() < deadline) {
            pathRuns = server.pathRunQueryPort().pathRunsForScan(scanId).orElse(List.of());
            if (pathRuns.size() >= min) {
                return pathRuns;
            }
            Thread.sleep(400);
        }
        return pathRuns;
    }

    private static void purgeVeyrionTrustedContainers() {
        try {
            Process list = new ProcessBuilder("docker", "ps", "-aq",
                    "--filter", "name=veyrion-trusted-").start();
            String ids = new String(list.getInputStream().readAllBytes()).trim();
            list.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            if (ids.isBlank()) {
                System.out.println("no veyrion-trusted-* containers to remove");
                return;
            }
            List<String> cmd = new ArrayList<>();
            cmd.add("docker");
            cmd.add("rm");
            cmd.add("-f");
            for (String id : ids.split("\\s+")) {
                if (!id.isBlank()) {
                    cmd.add(id);
                }
            }
            Process rm = new ProcessBuilder(cmd).inheritIO().start();
            rm.waitFor(30, java.util.concurrent.TimeUnit.SECONDS);
            System.out.println("removed veyrion-trusted-* containers");
        } catch (Exception ex) {
            System.out.println("docker cleanup skipped: " + ex.getMessage());
        }
    }

    private static Map<String, Object> post(HttpClient http, URI uri, Map<String, Object> body, String token)
            throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(120))
                .header("Content-Type", "application/json")
                .header("Idempotency-Key", "kvf-forced-" + System.nanoTime())
                .POST(HttpRequest.BodyPublishers.ofString(JsonCodec.stringify(body)));
        if (token != null) {
            builder.header("Authorization", "Bearer " + token);
        }
        HttpResponse<String> response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException("POST failed HTTP " + response.statusCode()
                    + " " + response.body());
        }
        return JsonCodec.parseObject(response.body());
    }

    private static String text(Map<String, Object> body, String key) {
        Object value = body.get(key);
        if (value == null || String.valueOf(value).isBlank()) {
            throw new IllegalStateException(key + " missing");
        }
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
}
