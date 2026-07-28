package com.aq.jvmsentinel;

import com.aq.jvmsentinel.analysis.ArtifactMetadataReader;
import com.aq.jvmsentinel.analysis.PreAnalysisResult;
import com.aq.jvmsentinel.analysis.PreAnalysisService;
import com.aq.jvmsentinel.analysis.contrast.ContrastLedger;
import com.aq.jvmsentinel.artifact.ArtifactRegistry;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.model.BytecodeFactIndex;

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
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * P0-10 residual: Controller handler binds to repository-layer sink via persisted taint paths.
 */
public final class CrossMethodFindingBindAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        Path root = Files.createTempDirectory("cross-method-bind");
        try {
            Path jar = buildFixture(root);
            verifyPreAnalysis(jar);
            verifyControlPlaneBinding(root, jar);
            System.out.println("CrossMethodFindingBindAcceptanceTest: PASS ("
                    + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
        } finally {
            deleteTree(root);
        }
    }

    private static Path buildFixture(Path root) throws Exception {
        Path sources = Files.createDirectories(root.resolve("sources"));
        Path classes = Files.createDirectories(root.resolve("classes"));
        writeFixtures(sources);
        compile(sources, classes);
        Path jar = root.resolve("cross-bind.jar");
        archive(classes, jar);
        return jar;
    }

    private static void verifyPreAnalysis(Path jar) throws Exception {
        PreAnalysisResult result = new PreAnalysisService().analyze(
                ArtifactMetadataReader.read(new ArtifactRegistry(jar.getParent()).register(jar)));
        BytecodeFactIndex index = result.bytecodeFactIndex();
        List<BytecodeFactIndex.TaintPath> sqlPaths = index.taintPaths().stream()
                .filter(path -> "SQL".equals(path.category()))
                .filter(path -> path.sourceMethod().equals("search"))
                .filter(path -> path.sourceOwner().contains("UserController"))
                .toList();
        check(!sqlPaths.isEmpty(), "controller search parameter reaches SQL sink cross-method");
        BytecodeFactIndex.TaintPath path = sqlPaths.get(0);
        check(path.sinkOwner().contains("UserRepository") || path.sinkOwner().contains("java.sql"),
                "sink owner is repository layer or JDBC API, not controller");
        check(!path.sinkOwner().contains("UserController"),
                "sink owner is not the controller handler class");
        check(path.steps().stream().anyMatch(step -> step.kind().equals("CALL")),
                "persisted path includes cross-method CALL steps");
        check(result.sinkCatalog().sinks().stream()
                        .anyMatch(sink -> sink.category().equals("SQL")
                                && sink.source().contains("taint-path=" + path.id())),
                "SQL sink taint-path token matches analysis path id " + path.id());
        check(result.sinkCatalog().sinks().stream()
                        .anyMatch(sink -> sink.category().equals("SQL")
                                && (sink.symbol().contains("UserRepository")
                                || sink.symbol().contains("java.sql"))),
                "SQL sink symbol binds to repository or JDBC layer not controller");
    }

    private static void verifyControlPlaneBinding(Path root, Path jar) throws Exception {
        String token = "cross-bind-token";
        Path database = root.resolve("state/control-plane.db");
        HttpClient client = HttpClient.newHttpClient();
        String scanId;
        String controllerEntryId;
        String sqlSinkId;
        String taintPathId;
        String projectId;

        try (ControlPlaneServer server = new ControlPlaneServer(root, 0, token, database).start()) {
            Map<String, Object> project = ok(send(client, uri(server, "/projects"), "POST",
                    "{\"name\":\"cross bind\"}", token));
            projectId = text(project, "projectId");
            Map<String, Object> artifact = ok(send(client,
                    uri(server, "/projects/" + projectId + "/artifacts"), "POST",
                    "{\"path\":\"" + escape(jar.toString()) + "\"}", token));
            Map<String, Object> scan = ok(send(client,
                    uri(server, "/projects/" + projectId + "/scans"), "POST",
                    "{\"artifactDigest\":\"" + text(artifact, "artifactDigest")
                            + "\",\"authorized\":true}", token));
            scanId = text(scan, "scanId");
            controllerEntryId = text(byRoute(array(scan, "entries"), "/search"), "id");

            Map<String, Object> sqlSink = array(scan, "sinks").stream()
                    .filter(value -> value instanceof Map<?, ?> item
                            && "SQL".equals(item.get("category"))
                            && String.valueOf(item.get("source")).contains("taint-path="))
                    .map(value -> (Map<String, Object>) value)
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("missing SQL sink with taint-path evidence"));
            sqlSinkId = text(sqlSink, "id");
            String sinkSymbol = String.valueOf(sqlSink.get("symbol"));
            String sinkSource = text(sqlSink, "source");
            check(!sinkSymbol.contains("UserController"),
                    "taint-linked SQL sink is not the controller handler method");
            check(sinkSymbol.contains("UserRepository") || sinkSymbol.contains("java.sql"),
                    "taint-linked SQL sink symbol is repository or JDBC layer");

            ControlPlaneStore store = server.store();
            ApiDtos.SinkDto linkedSink = store.requireScan(scanId).dto().sinks().stream()
                    .filter(sink -> sqlSinkId.equals(sink.id()))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("missing sink dto " + sqlSinkId));
            taintPathId = StaticFactSnapshot.taintPathIdFromSink(
                    linkedSink, store.requireScan(scanId).evidence());
            check(!taintPathId.isBlank(), "resolved taint path id from sink evidence");

            StaticFactSnapshot facts = store.staticFacts(scanId).orElseThrow(
                    () -> new AssertionError("static facts persisted for scan"));
            List<String> persistedIds = facts.taintPaths().stream().map(BytecodeFactIndex.TaintPath::id).toList();
            check(!persistedIds.isEmpty(), "static facts include taint paths");
            check(persistedIds.contains(taintPathId),
                    "static facts contain sink taint-path id " + taintPathId + "; persisted=" + persistedIds);
            BytecodeFactIndex.TaintPath boundPath = facts.taintPaths().stream()
                    .filter(path -> path.id().equals(taintPathId))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("persisted path for taint id " + taintPathId));
            ApiDtos.EntryDto boundEntry = StaticFactSnapshot.findEntryForTaintSource(
                    store.requireScan(scanId).dto().entries(),
                    store.requireScan(scanId).evidence(),
                    boundPath);
            check(boundEntry != null && controllerEntryId.equals(boundEntry.id()),
                    "StaticFactSnapshot binds path source to controller entry " + controllerEntryId
                            + " (source=" + boundPath.sourceOwner() + "#" + boundPath.sourceMethod() + ")");

            Map<String, Object> findings = ok(send(client,
                    uri(server, "/scans/" + scanId + "/findings"), "GET", "", token));
            Map<String, Object> sqlFinding = array(findings, "findings").stream()
                    .filter(value -> value instanceof Map<?, ?> item
                            && sqlSinkId.equals(item.get("sinkId")))
                    .map(value -> (Map<String, Object>) value)
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("missing finding for SQL sink"));
            check(controllerEntryId.equals(text(sqlFinding, "entrypointId")),
                    "finding binds controller entry id " + controllerEntryId
                            + " not entry-unbound; got " + sqlFinding.get("entrypointId"));
            check(!"entry-unbound".equals(sqlFinding.get("entrypointId")),
                    "finding must not remain entry-unbound when static paths exist");
            check("/search".equals(text(sqlFinding, "entry")),
                    "finding route is controller handler /search");

            check(StaticFactSnapshot.hasPersistedSteps(store.staticFacts(scanId)),
                    "persisted static facts include non-empty taint steps");
            BytecodeFactIndex.TaintPath persisted = boundPath;
            check(!persisted.steps().isEmpty(), "persisted path steps non-empty before reload");
            check(persisted.sourceOwner().contains("UserController")
                            && "search".equals(persisted.sourceMethod()),
                    "persisted path source is controller search handler");

            List<BytecodeFactIndex.TaintPath> contrastPaths = StaticFactSnapshot.resolveContrastTaintPaths(
                    store.staticFacts(scanId), store.requireScan(scanId).dto().sinks());
            BytecodeFactIndex.TaintPath contrastPath = contrastPaths.stream()
                    .filter(path -> path.id().equals(taintPathId))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("contrast paths include persisted id"));
            check(!contrastPath.steps().isEmpty(),
                    "contrast authority uses persisted steps not stub for path id " + taintPathId);
            ContrastLedger.Ledger ledger = ContrastLedger.build(
                    store.requireScan(scanId).dto().entries(),
                    store.requireScan(scanId).dto().sinks(),
                    store.requireScan(scanId).evidence(),
                    List.of(),
                    contrastPaths);
            check(ledger.rows().stream().anyMatch(row -> taintPathId.equals(row.taintPathId())
                            && row.entryRefs().contains("entry:" + controllerEntryId)),
                    "contrast row links taint path to controller entry ref");
            System.out.println("Cross-method bind evidence: controllerEntryId=" + controllerEntryId
                    + " route=/search taintPathId=" + taintPathId + " sqlSinkId=" + sqlSinkId
                    + " findingEntrypointId=" + text(sqlFinding, "entrypointId"));
        }

        ControlPlaneStore reopened = ControlPlaneStore.sqlite(database, root);
        StaticFactSnapshot restored = reopened.staticFacts(scanId).orElseThrow(
                () -> new AssertionError("static facts survive sqlite reload"));
        BytecodeFactIndex.TaintPath reloaded = restored.taintPaths().stream()
                .filter(path -> path.id().equals(taintPathId))
                .findFirst()
                .orElseThrow(() -> new AssertionError("reloaded path for taint id"));
        check(!reloaded.steps().isEmpty(), "persisted path steps non-empty after sqlite reload");
        check(reloaded.steps().stream().anyMatch(step -> "CALL".equals(step.kind())),
                "reloaded path retains cross-method CALL step");

        verifyLegacyStubFallback(root);
    }

    private static void verifyLegacyStubFallback(Path root) throws Exception {
        Path legacyRoot = Files.createTempDirectory(root, "legacy-fallback");
        ControlPlaneStore store = ControlPlaneStore.sqlite(legacyRoot.resolve("legacy.db"), legacyRoot);
        String now = Instant.now().toString();
        store.bootstrapOperator("bootstrap-token", now);
        var project = store.createProject("project-legacy", "Legacy", now, "local-admin");
        String digest = "b".repeat(64);
        Path artifact = legacyRoot.resolve("Legacy.class");
        Files.writeString(artifact, "fixture");
        store.registerArtifact(project, new com.aq.jvmsentinel.model.ArtifactDescriptor(
                "artifact-legacy", com.aq.jvmsentinel.model.ArtifactType.CLASS,
                artifact, Files.size(artifact), digest, true, Instant.parse(now), "Legacy.class"),
                "local-admin");
        var sink = new ApiDtos.SinkDto(ApiDtos.SCHEMA_VERSION, project.projectId(), digest, "scan-legacy-only",
                "sink-legacy", "SQL", "app.UserRepository#findByQuery(Ljava/lang/String;)V",
                "taint-path=tp-legacy-stub-only", ApiDtos.STATIC_INFERRED, 0.7, List.of());
        var scan = new ApiDtos.ScanDto(ApiDtos.SCHEMA_VERSION, project.projectId(), digest, "scan-legacy-only",
                "COMPLETED", ApiDtos.STATIC_INFERRED, ApiDtos.MOCK, now, now, List.of(),
                List.of(), List.of(), List.of(sink), List.of(), List.of());
        store.saveScan(new ControlPlaneStore.ScanRecord(scan, Map.of(), List.of(), List.of()), "local-admin");
        check(store.staticFacts("scan-legacy-only").isEmpty(),
                "legacy scan has no static facts row");
        List<BytecodeFactIndex.TaintPath> legacyPaths = StaticFactSnapshot.resolveContrastTaintPaths(
                store.staticFacts("scan-legacy-only"), scan.sinks());
        check(legacyPaths.stream().allMatch(path -> path.steps().isEmpty()),
                "legacy-only scan still falls back to empty-step stub paths");
    }

    private static void writeFixtures(Path root) throws Exception {
        source(root, "org/springframework/web/bind/annotation/RestController.java", """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE)
                public @interface RestController {}
                """);
        source(root, "org/springframework/web/bind/annotation/GetMapping.java", """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
                public @interface GetMapping { String[] value() default {}; }
                """);
        source(root, "app/UserRepository.java", """
                package app;
                public final class UserRepository {
                    public void findByQuery(String query) throws Exception {
                        java.sql.DriverManager.getConnection("jdbc:hsql:mem:test")
                                .createStatement().executeQuery(query);
                    }
                }
                """);
        source(root, "app/UserService.java", """
                package app;
                public final class UserService {
                    private final UserRepository repository = new UserRepository();
                    public void search(String query) throws Exception {
                        repository.findByQuery(query);
                    }
                }
                """);
        source(root, "app/UserController.java", """
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

    private static void archive(Path classes, Path jar) throws Exception {
        try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(jar));
             Stream<Path> stream = Files.walk(classes)) {
            for (Path file : stream.filter(Files::isRegularFile).toList()) {
                output.putNextEntry(new ZipEntry(
                        "BOOT-INF/classes/" + classes.relativize(file).toString().replace('\\', '/')));
                Files.copy(file, output);
                output.closeEntry();
            }
        }
    }

    private static HttpResponse<String> send(HttpClient client, URI uri, String method,
                                             String body, String token) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                .header("Content-Type", "application/json")
                .header("X-Sentinel-Authorization", token);
        HttpRequest request = "POST".equals(method)
                ? builder.POST(HttpRequest.BodyPublishers.ofString(body)).build()
                : builder.GET().build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static URI uri(ControlPlaneServer server, String path) {
        return URI.create(server.baseUri() + path);
    }

    private static Map<String, Object> ok(HttpResponse<String> response) {
        check(response.statusCode() >= 200 && response.statusCode() < 300,
                "request succeeds: HTTP " + response.statusCode() + " " + response.body());
        return JsonCodec.parseObject(response.body());
    }

    @SuppressWarnings("unchecked")
    private static List<Object> array(Map<String, Object> value, String field) {
        Object candidate = value.get(field);
        if (!(candidate instanceof List<?> list)) throw new AssertionError("missing array " + field);
        return (List<Object>) list;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> byRoute(List<Object> values, String route) {
        return values.stream().filter(value -> value instanceof Map<?, ?> item
                        && route.equals(item.get("route")))
                .map(value -> (Map<String, Object>) value)
                .findFirst()
                .orElseThrow(() -> new AssertionError("missing entry for route " + route));
    }

    private static String text(Map<String, Object> value, String field) {
        Object candidate = value.get(field);
        if (!(candidate instanceof String text) || text.isBlank()) {
            throw new AssertionError("missing " + field);
        }
        return text;
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) return;
        try (Stream<Path> paths = Files.walk(root)) {
            for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}
