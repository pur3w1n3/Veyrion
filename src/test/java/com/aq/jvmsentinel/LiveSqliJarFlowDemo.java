package com.aq.jvmsentinel;

import com.aq.jvmsentinel.analysis.experiment.WorldPackPlanner;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.control.service.ProbePlanService;
import com.aq.jvmsentinel.domain.pathdebug.WorldPackDependencyMode;
import com.aq.jvmsentinel.sandbox.LocalDockerTrustedSandboxClient;
import com.aq.jvmsentinel.support.LiveEnvironment;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;
import com.aq.jvmsentinel.worker.SqlDiffProbe;
import com.aq.jvmsentinel.worker.TaskLifecycle;
import com.aq.jvmsentinel.worker.TaskScope;
import com.aq.jvmsentinel.worker.WorkerControlPlaneClient;

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
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * 手动 demo（非 gate）：端到端 scan 脆弱 Boot-shaped JAR 并打印
 * P0-21 接线修复后的 static finding + live PathTrace / verification outcome。
 */
public final class LiveSqliJarFlowDemo {
    private LiveSqliJarFlowDemo() {
    }

    public static void main(String[] args) throws Exception {
        boolean docker = LiveEnvironment.dockerAvailable();
        String image = LiveEnvironment.resolveTrustedDockerImage();
        System.out.println("=== LiveSqliJarFlowDemo ===");
        System.out.println("docker=" + docker + " image=" + (image.isBlank() ? "(none)" : image));
        if (!docker || image.isBlank() || !image.contains("@sha256:")) {
            throw new IllegalStateException("digest-pinned TRUSTED_DOCKER image required for this demo");
        }

        Path root = Files.createTempDirectory("veyrion-sqli-demo-");
        try {
            Path jar = buildVulnerableJar(Files.createDirectories(root.resolve("build")));
            String digest = HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(jar)));
            System.out.println("artifact=" + jar.getFileName() + " sha256=" + digest);
            String token = "sqli-demo-token";
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
                        Map.of("name", "SQLi PathDebug Demo"), token), "projectId");
                post(http, URI.create(server.baseUri() + "/projects/" + projectId + "/artifacts"),
                        Map.of("path", content.toString(), "type", "JAR"), token);
                String scanId = text(post(http,
                        URI.create(server.baseUri() + "/projects/" + projectId + "/scans"),
                        Map.of("artifactDigest", digest, "authorized", true), token), "scanId");

                ControlPlaneStore.ScanRecord scan = server.store().requireScan(scanId);
                printStaticFindings(scan);

                ProbePlanService.ProbePlan plan = new ProbePlanService(
                        server.store(), (p, s) -> List.of()).buildProbePlan(scan, "demo-task");
                List<ExternalArtifactTaskExecutor.ProbeTarget> probes = forceSqliProbes(plan.probes());
                System.out.println("\n--- Probe plan (bounded) ---");
                System.out.println("count=" + probes.size()
                        + " worldPackModeHint="
                        + WorldPackPlanner.resolveRuntimeDependencyMode(
                                probes.stream()
                                        .map(p -> server.store().postureExperiment(p.experimentPlanId()))
                                        .filter(p -> p != null)
                                        .toList()));
                for (ExternalArtifactTaskExecutor.ProbeTarget probe : probes) {
                    System.out.println("  " + probe.track() + " " + probe.method() + " "
                            + probe.route()
                            + (probe.query().isBlank() ? "" : "?" + probe.query())
                            + " plan=" + probe.experimentPlanId());
                }

                String taskId = text(post(http,
                        URI.create(server.baseUri() + "/scans/" + scanId + "/dynamic-tasks"),
                        Map.of("authorized", true), token), "taskId");

                // 优先 control-plane 注册（exploration stage → MOCK_CONTINUE）。
                ExternalArtifactTaskExecutor.ArtifactRegistration registration =
                        server.requireLocalArtifact(
                                new TaskScope(projectId, digest, scanId, taskId));
                WorldPackDependencyMode mode = WorldPackDependencyMode.valueOf(
                        registration.worldPackDependencyMode());
                System.out.println("\n--- Runtime registration ---");
                System.out.println("worldPackDependencyMode=" + mode
                        + " probes=" + registration.probePlan().size()
                        + " classPrefix=" + registration.classPrefix());

                WorkerControlPlaneClient control = new WorkerControlPlaneClient(
                        server.baseUri().resolve("/internal/worker/v1/"),
                        server.workerToken(), Duration.ofSeconds(45));
                LocalDockerTrustedSandboxClient sandbox = new LocalDockerTrustedSandboxClient();
                ExternalArtifactTaskExecutor executor = new ExternalArtifactTaskExecutor(
                        control, sandbox,
                        scope -> {
                            // 保持 resolved World Pack mode 时用 SQLi 聚焦 probe 重绑。
                            return new ExternalArtifactTaskExecutor.ArtifactRegistration(
                                    registration.projectId(), registration.sha256(),
                                    registration.path(), registration.sizeBytes(),
                                    registration.executableSpringBootJar(),
                                    probes.get(0).method(), probes.get(0).route(),
                                    registration.classPrefix(),
                                    probes,
                                    registration.worldPackDependencyMode());
                        },
                        ExternalArtifactTaskExecutor.RuntimePolicy.trustedLocalDocker(image),
                        "sqli-demo-worker");
                try {
                    ExternalArtifactTaskExecutor.ExecutionResult result = executor.execute(
                            new ExternalArtifactTaskExecutor.ExecutionRequest(
                                    new TaskScope(projectId, digest, scanId, taskId)));
                    System.out.println("dynamicLifecycle=" + result.lifecycle()
                            + " traceChunks=" + result.traceChunks());
                    if (result.lifecycle() != TaskLifecycle.COMPLETED) {
                        throw new AssertionError("dynamic task did not complete: " + result);
                    }

                    List<Map<String, Object>> pathRuns = awaitPathRuns(server, scanId, 1);
                    printPathRuns(pathRuns);

                    Map<String, Object> dashboard = get(http,
                            URI.create(server.baseUri() + "/projects/" + projectId + "/dashboard"),
                            token);
                    Object summaries = dashboard.get("pathDebugSummaries");
                    System.out.println("\n--- Dashboard pathDebugSummaries ---");
                    System.out.println(summaries == null ? "(absent)" : JsonCodec.stringify(summaries));

                    printVerdict(scan, pathRuns, mode);
                } finally {
                    executor.closeRetainedSessions();
                    try {
                        sandbox.close();
                    } catch (RuntimeException ignored) {
                        // 尽力：demo 不得留下 veyrion-trusted-* 容器
                    }
                }
            }
        } finally {
            deleteTreeBestEffort(root);
        }
    }

    private static void printStaticFindings(ControlPlaneStore.ScanRecord scan) {
        System.out.println("\n--- Static scan ---");
        System.out.println("scanId=" + scan.dto().scanId()
                + " verificationStatus=" + scan.dto().verificationStatus()
                + " entries=" + scan.dto().entries().size()
                + " sinks=" + scan.dto().sinks().size()
                + " findings=" + scan.dto().findings().size());
        for (ApiDtos.EntryDto entry : scan.dto().entries()) {
            System.out.println("  entry " + entry.method() + " " + entry.route()
                    + " class=" + entry.declaringClass()
                    + " status=" + entry.verificationStatus());
        }
        for (ApiDtos.SinkDto sink : scan.dto().sinks()) {
            System.out.println("  sink cat=" + sink.category()
                    + " symbol=" + sink.symbol()
                    + " status=" + sink.verificationStatus()
                    + " src=" + truncate(sink.source(), 120));
        }
        for (ApiDtos.FindingDto finding : scan.dto().findings()) {
            System.out.println("  FINDING title=" + finding.title()
                    + " severity=" + finding.severity()
                    + " status=" + finding.verificationStatus()
                    + " entry=" + finding.entrypointId()
                    + " sink=" + finding.sinkId());
        }
        if (scan.dto().findings().isEmpty()) {
            System.out.println("  (no FindingDto rows — check sinks/entries for STATIC_INFERRED signals)");
        }
    }

    private static void printPathRuns(List<Map<String, Object>> pathRuns) {
        System.out.println("\n--- Dynamic PathRuns (" + pathRuns.size() + ") ---");
        int i = 0;
        for (Map<String, Object> run : pathRuns) {
            i++;
            System.out.println("[" + i + "] track=" + run.get("track")
                    + " status=" + run.get("httpStatus")
                    + " verification=" + run.get("verificationStatus")
                    + " outcome=" + run.get("outcomeClass")
                    + " entryHit=" + run.get("entryHit")
                    + " parameterBound=" + run.get("parameterBound")
                    + " posture=" + run.get("postureKind")
                    + " plan=" + run.get("experimentPlanId"));
            System.out.println("    summary=" + truncate(String.valueOf(run.get("requestSummary")), 160));
            Object sql = run.get("sqlEvents");
            if (sql != null) {
                System.out.println("    sqlEvents=" + truncate(String.valueOf(sql), 240));
            }
            Object pathTrace = run.get("pathTrace");
            if (pathTrace instanceof Map<?, ?> trace) {
                System.out.println("    pathTrace.exitReason=" + trace.get("exitReason")
                        + " lastBusinessHop=" + trace.get("lastBusinessHop")
                        + " legacyIncomplete=" + trace.get("legacyIncomplete"));
                Object events = trace.get("events");
                if (events instanceof List<?> list) {
                    System.out.println("    pathTrace.events=" + list.size());
                    int shown = 0;
                    for (Object event : list) {
                        if (!(event instanceof Map<?, ?> ev)) continue;
                        System.out.println("      - " + ev.get("kind")
                                + " | " + truncate(String.valueOf(ev.get("summary")), 100)
                                + " | " + ev.get("subjectRef"));
                        if (++shown >= 12) {
                            System.out.println("      ... truncated");
                            break;
                        }
                    }
                }
            } else {
                System.out.println("    pathTrace=(none nested on wire)");
            }
        }
    }

    private static void printVerdict(ControlPlaneStore.ScanRecord scan,
                                     List<Map<String, Object>> pathRuns,
                                     WorldPackDependencyMode mode) {
        boolean staticSql = scan.dto().sinks().stream()
                .anyMatch(s -> "SQL".equalsIgnoreCase(s.category()))
                || scan.dto().findings().stream()
                .anyMatch(f -> String.valueOf(f.title()).toUpperCase().contains("SQL")
                        || String.valueOf(f.sinkId()).toUpperCase().contains("SQL"));
        boolean sawMarkerSql = pathRuns.stream().anyMatch(run ->
                String.valueOf(run.get("sqlEvents")).contains("veyrion-sqli-meta")
                        || String.valueOf(run.get("requestSummary")).contains("veyrion-sqli-meta"));
        boolean dynamicConfirmed = pathRuns.stream().anyMatch(run ->
                "DYNAMIC_CONFIRMED".equals(String.valueOf(run.get("verificationStatus"))));
        boolean dynamicSuspected = pathRuns.stream().anyMatch(run ->
                "DYNAMIC_SUSPECTED".equals(String.valueOf(run.get("verificationStatus"))));
        boolean methodHop = pathRuns.stream().anyMatch(run -> {
            Object pt = run.get("pathTrace");
            if (!(pt instanceof Map<?, ?> trace)) return false;
            Object events = trace.get("events");
            if (!(events instanceof List<?> list)) return false;
            return list.stream().anyMatch(e -> e instanceof Map<?, ?> m
                    && "METHOD_HOP".equals(String.valueOf(m.get("kind"))));
        });
        boolean effect = pathRuns.stream().anyMatch(run -> {
            Object pt = run.get("pathTrace");
            if (!(pt instanceof Map<?, ?> trace)) return false;
            Object events = trace.get("events");
            if (!(events instanceof List<?> list)) return false;
            return list.stream().anyMatch(e -> e instanceof Map<?, ?> m
                    && ("EFFECT_TRIGGERED".equals(String.valueOf(m.get("kind")))
                    || String.valueOf(m.get("kind")).contains("EFFECT")));
        });
        boolean neverVerified = pathRuns.stream().noneMatch(run ->
                "VERIFIED".equals(String.valueOf(run.get("verificationStatus"))));

        System.out.println("\n=== Verdict ===");
        System.out.println("worldPackMode=" + mode);
        System.out.println("staticSqlSignal=" + staticSql);
        System.out.println("liveMarkerInSqlOrRequest=" + sawMarkerSql);
        System.out.println("DYNAMIC_SUSPECTED=" + dynamicSuspected);
        System.out.println("DYNAMIC_CONFIRMED=" + dynamicConfirmed);
        System.out.println("PathTrace.METHOD_HOP=" + methodHop);
        System.out.println("PathTrace.EFFECT=" + effect);
        System.out.println("neverVERIFIED=" + neverVerified);
        if (staticSql && dynamicConfirmed) {
            System.out.println("RESULT: SQL injection evidence chain CLOSED — "
                    + "STATIC_INFERRED + DYNAMIC_CONFIRMED (VERIFIED remains closed).");
        } else if (staticSql && (dynamicSuspected && sawMarkerSql)) {
            System.out.println("RESULT: static SQL + marker observed, but not DYNAMIC_CONFIRMED.");
        } else if (staticSql) {
            System.out.println("RESULT: static SQL finding present; dynamic did not reach "
                    + "DYNAMIC_CONFIRMED (check PathTrace / SQL capture above).");
        } else {
            System.out.println("RESULT: static SQL signal missing on this fixture — "
                    + "dynamic path-debug still useful for coverage evidence.");
        }
        if (!dynamicConfirmed) {
            throw new AssertionError("expected at least one DYNAMIC_CONFIRMED PathRun for marker SQL");
        }
    }

    /**
     * 优先 /search probe 并 stamp META_MARKER query 供 H3 风格 observation。
     */
    private static List<ExternalArtifactTaskExecutor.ProbeTarget> forceSqliProbes(
            List<ExternalArtifactTaskExecutor.ProbeTarget> fromPlan) {
        // 说明：ProbeTarget query charset 禁止 raw quote；percent-encode H3 marker。
        String marker = "q=" + java.net.URLEncoder.encode(
                SqlDiffProbe.META_MARKER, StandardCharsets.UTF_8);
        String benign = "q=benign";
        List<ExternalArtifactTaskExecutor.ProbeTarget> search = new ArrayList<>();
        for (ExternalArtifactTaskExecutor.ProbeTarget probe : fromPlan) {
            if (probe == null) continue;
            if (!"/search".equals(probe.route()) && !probe.route().endsWith("/search")) {
                continue;
            }
            String planId = boundedPlanId(probe.experimentPlanId());
            search.add(new ExternalArtifactTaskExecutor.ProbeTarget(
                    probe.method(), probe.route(), benign, probe.track(),
                    probe.authHeader(), probe.bladeAuthHeader(), planId));
            search.add(new ExternalArtifactTaskExecutor.ProbeTarget(
                    probe.method(), probe.route(), marker, probe.track(),
                    probe.authHeader(), probe.bladeAuthHeader(), planId));
        }
        if (!search.isEmpty()) {
            return search.stream().limit(8).toList();
        }
        List<ExternalArtifactTaskExecutor.ProbeTarget> fallback = new ArrayList<>();
        for (ExternalArtifactTaskExecutor.ProbeTarget probe : fromPlan) {
            if (probe == null) continue;
            fallback.add(new ExternalArtifactTaskExecutor.ProbeTarget(
                    "GET", "/search", marker, probe.track(),
                    probe.authHeader(), probe.bladeAuthHeader(),
                    boundedPlanId(probe.experimentPlanId())));
            if (fallback.size() >= 6) break;
        }
        if (fallback.isEmpty()) {
            fallback.add(new ExternalArtifactTaskExecutor.ProbeTarget(
                    "GET", "/search", marker, "UNAUTH", "", "", "plan:demo-unauth"));
            fallback.add(new ExternalArtifactTaskExecutor.ProbeTarget(
                    "GET", "/search", marker, "ADMIN", "", "", "plan:demo-admin"));
        }
        return List.copyOf(fallback);
    }

    private static String boundedPlanId(String planId) {
        if (planId == null || planId.isBlank()) {
            return "plan:demo";
        }
        String trimmed = planId.trim();
        return trimmed.length() <= 128 ? trimmed : trimmed.substring(0, 128);
    }

    private static Path buildVulnerableJar(Path root) throws Exception {
        Path sources = Files.createDirectories(root.resolve("sources"));
        Path classes = Files.createDirectories(root.resolve("classes"));
        write(sources, "org/springframework/web/bind/annotation/RestController.java", """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE)
                public @interface RestController {}
                """);
        write(sources, "org/springframework/web/bind/annotation/GetMapping.java", """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
                public @interface GetMapping { String[] value() default {}; String[] path() default {}; }
                """);
        write(sources, "app/UserRepository.java", """
                package app;
                public final class UserRepository {
                    public void findByQuery(String query) throws Exception {
                        try {
                            Class.forName("com.aq.jvmsentinel.instrumentation.mock.VeyrionMockDriver");
                        } catch (ClassNotFoundException ignored) { }
                        try (java.sql.Connection connection =
                                     java.sql.DriverManager.getConnection("jdbc:veyrion-mock:demo");
                             java.sql.Statement statement = connection.createStatement()) {
                            statement.executeQuery(query);
                        }
                    }
                }
                """);
        write(sources, "app/UserService.java", """
                package app;
                public final class UserService {
                    private final UserRepository repository = new UserRepository();
                    public void search(String query) throws Exception {
                        repository.findByQuery(query);
                    }
                }
                """);
        write(sources, "app/UserController.java", """
                package app;
                import org.springframework.web.bind.annotation.*;
                @RestController
                public final class UserController {
                    private final UserService service = new UserService();
                    @GetMapping("/search")
                    public void search(String q) throws Exception {
                        service.search(q);
                    }
                }
                """);
        write(sources, "com/aq/veyrion/fixture/SqliDemoApp.java", """
                package com.aq.veyrion.fixture;
                import com.sun.net.httpserver.Headers;
                import com.sun.net.httpserver.HttpExchange;
                import com.sun.net.httpserver.HttpServer;
                import java.io.OutputStream;
                import java.lang.reflect.Method;
                import java.net.InetSocketAddress;
                import java.net.URLDecoder;
                import java.nio.charset.StandardCharsets;
                import java.sql.Connection;
                import java.sql.DriverManager;
                import java.sql.Statement;
                public final class SqliDemoApp {
                    public static void main(String[] args) throws Exception {
                        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
                        server.createContext("/search", SqliDemoApp::handleSearch);
                        server.createContext("/", exchange -> {
                            byte[] body = "ok".getBytes(StandardCharsets.UTF_8);
                            exchange.sendResponseHeaders(200, body.length);
                            try (OutputStream out = exchange.getResponseBody()) { out.write(body); }
                        });
                        server.start();
                        Thread.currentThread().join();
                    }
                    private static void handleSearch(HttpExchange exchange) {
                        try {
                            bindCorrelation(exchange.getRequestHeaders());
                            String q = queryParam(exchange.getRequestURI().getRawQuery(), "q");
                            String sql = "SELECT id FROM users WHERE name='" + q + "'";
                            // sensor hop 的 cross-method call chain（Controller→Service→Repo 模式）。
                            app.UserService service = new app.UserService();
                            service.search(sql);
                            byte[] body = ("ok:" + sql.hashCode()).getBytes(StandardCharsets.UTF_8);
                            exchange.getResponseHeaders().add("Content-Type", "text/plain");
                            exchange.sendResponseHeaders(200, body.length);
                            try (OutputStream out = exchange.getResponseBody()) { out.write(body); }
                        } catch (Exception failure) {
                            try {
                                byte[] body = ("err:" + failure.getClass().getSimpleName())
                                        .getBytes(StandardCharsets.UTF_8);
                                exchange.sendResponseHeaders(500, body.length);
                                try (OutputStream out = exchange.getResponseBody()) { out.write(body); }
                            } catch (Exception ignored) { }
                        } finally {
                            releaseCorrelation();
                        }
                    }
                    private static String queryParam(String raw, String key) {
                        if (raw == null || raw.isBlank()) return "";
                        for (String part : raw.split("&")) {
                            int eq = part.indexOf('=');
                            if (eq <= 0) continue;
                            String name = URLDecoder.decode(part.substring(0, eq), StandardCharsets.UTF_8);
                            if (key.equals(name)) {
                                return URLDecoder.decode(part.substring(eq + 1), StandardCharsets.UTF_8);
                            }
                        }
                        return "";
                    }
                    private static void bindCorrelation(Headers headers) {
                        try {
                            String correlation = headers.getFirst("X-Veyrion-Correlation-Id");
                            if (correlation == null || correlation.isBlank()) return;
                            Class<?> runtime = Class.forName(
                                    "com.aq.jvmsentinel.instrumentation.AgentRuntime");
                            Method bind = runtime.getMethod("bindRequestCorrelation", String.class);
                            bind.invoke(null, correlation);
                        } catch (ReflectiveOperationException ignored) { }
                    }
                    private static void releaseCorrelation() {
                        try {
                            Class<?> runtime = Class.forName(
                                    "com.aq.jvmsentinel.instrumentation.AgentRuntime");
                            Method release = runtime.getMethod("releaseRequestCorrelation");
                            release.invoke(null);
                        } catch (ReflectiveOperationException ignored) { }
                    }
                }
                """);
        compile(sources, classes);
        Path jar = root.resolve("sqli-pathdebug-demo.jar");
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().put(Attributes.Name.MAIN_CLASS, "com.aq.veyrion.fixture.SqliDemoApp");
        manifest.getMainAttributes().putValue("Start-Class", "com.aq.veyrion.fixture.SqliDemoApp");
        manifest.getMainAttributes().putValue("Spring-Boot-Version", "3.3.0-fixture");
        try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(jar));
             Stream<Path> stream = Files.walk(classes)) {
            output.putNextEntry(new ZipEntry("META-INF/MANIFEST.MF"));
            manifest.write(output);
            output.closeEntry();
            for (Path file : stream.filter(Files::isRegularFile).toList()) {
                String relative = classes.relativize(file).toString().replace('\\', '/');
                if (relative.startsWith("com/aq/veyrion/fixture/") || relative.startsWith("app/")) {
                    output.putNextEntry(new ZipEntry(relative));
                    Files.copy(file, output);
                    output.closeEntry();
                }
                output.putNextEntry(new ZipEntry("BOOT-INF/classes/" + relative));
                Files.copy(file, output);
                output.closeEntry();
            }
            output.putNextEntry(new ZipEntry("BOOT-INF/classes/application.properties"));
            output.write("server.port=8080\n".getBytes(StandardCharsets.UTF_8));
            output.closeEntry();
            output.putNextEntry(new ZipEntry("org/springframework/boot/loader/launch/JarLauncher.class"));
            output.write(new byte[]{(byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE, 0, 0, 0, 55});
            output.closeEntry();
        }
        return jar;
    }

    private static List<Map<String, Object>> awaitPathRuns(ControlPlaneServer server, String scanId,
                                                           int min) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(60).toNanos();
        List<Map<String, Object>> pathRuns = List.of();
        while (System.nanoTime() < deadline) {
            pathRuns = server.pathRunQueryPort().pathRunsForScan(scanId).orElse(List.of());
            if (pathRuns.size() >= min) {
                return pathRuns;
            }
            Thread.sleep(250);
        }
        return pathRuns;
    }

    private static void write(Path root, String relative, String content) throws Exception {
        Path file = root.resolve(relative);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content, StandardCharsets.UTF_8);
    }

    private static void compile(Path sources, Path classes) throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            throw new IllegalStateException("JDK compiler required");
        }
        List<Path> files;
        try (Stream<Path> stream = Files.walk(sources)) {
            files = stream.filter(path -> path.toString().endsWith(".java")).toList();
        }
        try (StandardJavaFileManager manager =
                     compiler.getStandardFileManager(null, null, StandardCharsets.UTF_8)) {
            boolean success = compiler.getTask(null, manager, null,
                    List.of("--release", "17", "-parameters", "-d", classes.toString()), null,
                    manager.getJavaFileObjectsFromPaths(files)).call();
            if (!success) {
                throw new IllegalStateException("demo fixture compilation failed");
            }
        }
    }

    private static Map<String, Object> post(HttpClient http, URI uri, Map<String, Object> body, String token)
            throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(60))
                .header("Content-Type", "application/json")
                .header("Idempotency-Key", "sqli-demo-" + System.nanoTime())
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

    private static Map<String, Object> get(HttpClient http, URI uri, String token) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(30)).GET();
        if (token != null) {
            builder.header("Authorization", "Bearer " + token);
        }
        HttpResponse<String> response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("GET failed HTTP " + response.statusCode());
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

    private static String truncate(String value, int max) {
        if (value == null) return "";
        return value.length() <= max ? value : value.substring(0, max) + "...";
    }

    private static void deleteTreeBestEffort(Path root) {
        try {
            if (root == null || !Files.exists(root)) return;
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
