package com.aq.jvmsentinel;

import com.aq.jvmsentinel.analysis.ArtifactMetadataReader;
import com.aq.jvmsentinel.analysis.PreAnalysisInput;
import com.aq.jvmsentinel.analysis.PreAnalysisResult;
import com.aq.jvmsentinel.analysis.PreAnalysisService;
import com.aq.jvmsentinel.analysis.coverage.CoverageMatrixProjector;
import com.aq.jvmsentinel.analysis.universe.ArtifactUniverseBuilder;
import com.aq.jvmsentinel.artifact.ArtifactRegistry;
import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.domain.coverage.CoverageMatrix;
import com.aq.jvmsentinel.domain.universe.ArtifactUniverse;
import com.aq.jvmsentinel.domain.universe.CoverageGap;
import com.aq.jvmsentinel.domain.universe.UniverseScope;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.BytecodeFactIndex;

import javax.tools.JavaCompiler;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * P1-01: Artifact Universe scopes, nested Boot dependency gaps, unresolved dynamics,
 * coverage matrix summary, and runtime diff hook.
 */
public final class ArtifactUniverseAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        Path root = Files.createTempDirectory("artifact-universe");
        try {
            Path jar = buildBootFixture(root);
            verifyUniverseBuild(root, jar);
            verifyPersistenceAndCoverage(root, jar);
            System.out.println("ArtifactUniverseAcceptanceTest: PASS ("
                    + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
        } finally {
            deleteTree(root);
        }
    }

    private static void verifyUniverseBuild(Path root, Path jar) throws Exception {
        ArtifactRegistry registry = new ArtifactRegistry(root);
        ArtifactDescriptor descriptor = registry.register(jar);
        PreAnalysisInput input = ArtifactMetadataReader.read(descriptor);
        PreAnalysisResult result = new PreAnalysisService().analyze(input);
        BytecodeFactIndex index = result.bytecodeFactIndex();

        ArtifactUniverse universe = ArtifactUniverseBuilder.build(
                descriptor, index, List.of("HTTP", "CUSTOM_PROTO"));

        check(universe.isMaterialized(), "universe materialized");
        check(universe.applicationClassCount() > 0, "APPLICATION classes present");
        check(universe.dependencies().stream().anyMatch(dep ->
                        dep.name().equals("wrapper-lib.jar")
                                && dep.scope() == UniverseScope.THIRD_PARTY
                                && dep.expanded()
                                && dep.note() != null
                                && dep.note().contains("one-layer expand")
                                && dep.digestSha256() != null
                                && dep.digestSha256().matches("[0-9a-f]{64}")),
                "BOOT-INF/lib one-layer expanded as THIRD_PARTY with digest");
        check(universe.classes().stream().anyMatch(cls ->
                        cls.scope() == UniverseScope.THIRD_PARTY
                                && cls.archivePath() != null
                                && cls.archivePath().startsWith("BOOT-INF/lib/wrapper-lib.jar!/")),
                "nested lib class appears with jar!/ archive path");
        check(universe.dependencies().stream().anyMatch(dep ->
                        dep.name().equals("fat-lib.jar")
                                && dep.expanded()
                                && dep.note() != null
                                && dep.note().contains("truncated")),
                "fat nested lib truncated note");
        check(universe.coverageGaps().stream().anyMatch(gap ->
                        CoverageGap.KIND_BUDGET_TRUNCATED.equals(gap.kind())
                                && gap.stopReason().contains("NESTED_CLASS_BUDGET")),
                "nested lib class budget CoverageGap present");
        check(universe.coverageGaps().stream().anyMatch(gap ->
                        CoverageGap.KIND_UNKNOWN_PROTOCOL.equals(gap.kind())),
                "unknown protocol CoverageGap present");
        check(universe.coverageGaps().stream().anyMatch(gap ->
                        CoverageGap.KIND_INVOKEDYNAMIC.equals(gap.kind())
                                || CoverageGap.KIND_REFLECTION.equals(gap.kind())
                                || CoverageGap.KIND_PROXY.equals(gap.kind())
                                || CoverageGap.KIND_UNRESOLVED_CALL.equals(gap.kind())),
                "reflection/proxy/invokedynamic/unresolved gaps from bytecode");
        check(universe.configs().stream().anyMatch(cfg ->
                        cfg.path().contains("application.properties")
                                && cfg.scope() == UniverseScope.APPLICATION),
                "application config scoped APPLICATION");
        check(universe.resources().stream().anyMatch(res ->
                        res.path().startsWith("org/springframework/boot/loader/")
                                && res.scope() == UniverseScope.GENERATED),
                "Boot loader resource scoped GENERATED");

        List<CoverageGap> runtimeDiff = universe.diffWithRuntimeLoadedClasses(List.of(
                "com.example.universe.AppController",
                "com.example.universe.RuntimeOnly"));
        check(runtimeDiff.stream().anyMatch(gap ->
                        CoverageGap.KIND_RUNTIME_ONLY_CLASS.equals(gap.kind())),
                "runtime-only class gap from diff hook");
        check(runtimeDiff.stream().anyMatch(gap ->
                        CoverageGap.KIND_STATIC_NOT_LOADED.equals(gap.kind())),
                "static-not-loaded gap from diff hook");
        check(universe.coverageGaps().stream().anyMatch(gap ->
                        CoverageGap.KIND_MULTI_VERSION_CLASS.equals(gap.kind())),
                "multi-version class gap marked");

        StaticFactSnapshot snapshot = StaticFactSnapshot.fromBytecodeIndex(index, universe);
        check(snapshot.artifactUniverse().isMaterialized(), "snapshot carries universe");
        String json = snapshot.toJson();
        check(json.contains("\"schemaVersion\":4"), "persisted schemaVersion 4");
        check(json.contains("artifactUniverse"), "JSON embeds artifactUniverse");
        StaticFactSnapshot restored = StaticFactSnapshot.fromJson(json);
        check(restored.artifactUniverse().dependencies().size()
                        == snapshot.artifactUniverse().dependencies().size(),
                "universe dependencies survive JSON round-trip");
        check(StaticFactSnapshot.fromJson(
                        "{\"schemaVersion\":2,\"coverageStatus\":\"COMPLETE\",\"taintPaths\":[],"
                                + "\"analysisCoverage\":{\"callGraphEdgeBudget\":0,\"taintStateBudget\":0,"
                                + "\"callGraphEdgesProduced\":0,\"taintStatesVisited\":0,\"complete\":true,"
                                + "\"stopReasons\":[]},\"classes\":[],\"fields\":[],\"methods\":[],"
                                + "\"memberAccesses\":[],\"callEdges\":[],\"unresolvedDynamics\":[],"
                                + "\"artifactCallGraph\":[],\"truncateReasons\":[]}")
                        .artifactUniverse().isMaterialized() == false,
                "schema v2 reads without universe");
    }

    private static void verifyPersistenceAndCoverage(Path root, Path jar) throws Exception {
        String token = "universe-token";
        Path database = root.resolve("state/control-plane.db");
        HttpClient client = HttpClient.newHttpClient();
        try (ControlPlaneServer server = new ControlPlaneServer(root, 0, token, database).start()) {
            Map<String, Object> project = ok(send(client, uri(server, "/projects"), "POST",
                    "{\"name\":\"universe slice\"}", token));
            String projectId = text(project, "projectId");
            Map<String, Object> artifact = ok(send(client,
                    uri(server, "/projects/" + projectId + "/artifacts"), "POST",
                    "{\"path\":\"" + escape(jar.toString()) + "\"}", token));
            Map<String, Object> scan = ok(send(client,
                    uri(server, "/projects/" + projectId + "/scans"), "POST",
                    "{\"artifactDigest\":\"" + text(artifact, "artifactDigest")
                            + "\",\"authorized\":true}", token));
            String scanId = text(scan, "scanId");

            Optional<StaticFactSnapshot> facts = server.store().staticFacts(scanId);
            check(facts.isPresent(), "static facts persisted");
            check(facts.get().artifactUniverse().isMaterialized(), "persisted universe materialized");
            check(facts.get().artifactUniverse().thirdPartyDependencyCount() >= 1,
                    "persisted nested dependency count");
            check(facts.get().artifactUniverse().dependencies().stream().anyMatch(dep ->
                            dep.expanded() && dep.name().equals("wrapper-lib.jar")),
                    "persisted one-layer expanded dependency");
            check(facts.get().artifactUniverse().coverageGaps().stream().anyMatch(gap ->
                            CoverageGap.KIND_BUDGET_TRUNCATED.equals(gap.kind())
                                    || CoverageGap.KIND_UNEXPANDED_DEPENDENCY.equals(gap.kind())),
                    "persisted nested expand/truncation gap");

            CoverageMatrix matrix = CoverageMatrixProjector.project(
                    scanId,
                    facts,
                    server.store().requireScan(scanId).dto().entries(),
                    server.store().requireScan(scanId).dto().dependencies(),
                    server.store().requireScan(scanId).dto().sinks(),
                    server.store().hypotheses(scanId),
                    List.of());
            check(matrix.artifactUniverseSummary().dependencyCount() >= 1,
                    "coverage matrix dependencyCount from universe");
            check(matrix.artifactUniverseSummary().classCount() > 0,
                    "coverage matrix classCount from universe");
            check(matrix.artifactUniverseSummary().note().contains("ARTIFACT_UNIVERSE"),
                    "coverage note marks ARTIFACT_UNIVERSE");
            check(matrix.gaps().unknown() > 0 || matrix.gaps().unresolved() > 0,
                    "universe gaps contribute to coverage gaps");

            // P1-01: runtime-loaded class fixture merges into scan facts + CoverageMatrix.
            List<String> runtimeFixture = List.of(
                    "com.example.universe.AppController",
                    "com.example.universe.RuntimeOnlyLoaded");
            server.mergeRuntimeLoadedClasses(scanId, runtimeFixture, "local-admin");
            Optional<StaticFactSnapshot> afterRuntime = server.store().staticFacts(scanId);
            check(afterRuntime.isPresent(), "facts present after runtime merge");
            check(afterRuntime.get().runtimeLoadedClasses().contains(
                            "com.example.universe.RuntimeOnlyLoaded"),
                    "runtime fixture persisted on snapshot");
            check(afterRuntime.get().effectiveArtifactUniverse().coverageGaps().stream().anyMatch(gap ->
                            CoverageGap.KIND_RUNTIME_ONLY_CLASS.equals(gap.kind())),
                    "runtime-only gap merged into universe");
            CoverageMatrix withRuntime = CoverageMatrixProjector.project(
                    scanId,
                    afterRuntime,
                    server.store().requireScan(scanId).dto().entries(),
                    server.store().requireScan(scanId).dto().dependencies(),
                    server.store().requireScan(scanId).dto().sinks(),
                    server.store().hypotheses(scanId),
                    List.of());
            check(withRuntime.gaps().unknown() > 0, "CoverageMatrix reflects runtime diff gaps");
            check(withRuntime.artifactUniverseSummary().note().contains("ARTIFACT_UNIVERSE"),
                    "coverage still marks ARTIFACT_UNIVERSE after runtime merge");
        }
    }

    private static Path buildBootFixture(Path root) throws Exception {
        Path sources = Files.createDirectories(root.resolve("sources"));
        Path classes = Files.createDirectories(root.resolve("classes"));
        Path pkg = Files.createDirectories(sources.resolve("com/example/universe"));
        Files.writeString(pkg.resolve("AppController.java"), """
                package com.example.universe;
                import java.lang.reflect.Method;
                import java.lang.reflect.Proxy;
                import org.springframework.web.bind.annotation.GetMapping;
                import org.springframework.web.bind.annotation.RestController;
                @RestController
                public class AppController {
                    interface Worker { String work(); }
                    @GetMapping("/ping")
                    public Object ping(Method reflected) throws Exception {
                        Runnable lambda = () -> {};
                        lambda.run();
                        Object dynamic = reflected.invoke(this);
                        Object proxy = Proxy.newProxyInstance(
                                getClass().getClassLoader(), new Class<?>[]{Worker.class},
                                (p, m, args) -> "proxy");
                        return dynamic + String.valueOf(proxy);
                    }
                }
                """);
        Path spring = Files.createDirectories(sources.resolve("org/springframework/web/bind/annotation"));
        Files.writeString(spring.resolve("RestController.java"), """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.Retention;
                import java.lang.annotation.RetentionPolicy;
                @Retention(RetentionPolicy.RUNTIME)
                public @interface RestController {}
                """);
        Files.writeString(spring.resolve("GetMapping.java"), """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.Retention;
                import java.lang.annotation.RetentionPolicy;
                @Retention(RetentionPolicy.RUNTIME)
                public @interface GetMapping { String value() default ""; }
                """);
        compile(sources, classes);

        byte[] nestedJar = minimalJarBytes("lib/Helper.class", new byte[]{
                (byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE, 0, 0, 0, 55, 0, 1
        });
        byte[] fatNestedJar = fatNestedJarBytes(ArtifactUniverseBuilder.MAX_NESTED_LIB_CLASSES + 8);

        Path jar = root.resolve("universe-boot.jar");
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(jar))) {
            try (Stream<Path> stream = Files.walk(classes)) {
                for (Path file : stream.filter(Files::isRegularFile).toList()) {
                    String relative = classes.relativize(file).toString().replace('\\', '/');
                    zos.putNextEntry(new ZipEntry("BOOT-INF/classes/" + relative));
                    zos.write(Files.readAllBytes(file));
                    zos.closeEntry();
                }
            }
            zos.putNextEntry(new ZipEntry("BOOT-INF/classes/application.properties"));
            zos.write("app.name=universe-fixture\n".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
            zos.putNextEntry(new ZipEntry("BOOT-INF/lib/wrapper-lib.jar"));
            zos.write(nestedJar);
            zos.closeEntry();
            zos.putNextEntry(new ZipEntry("BOOT-INF/lib/fat-lib.jar"));
            zos.write(fatNestedJar);
            zos.closeEntry();
            // Duplicate application class under a second archive path → MULTI_VERSION_CLASS gap.
            Path appClass = classes.resolve("com/example/universe/AppController.class");
            if (Files.isRegularFile(appClass)) {
                zos.putNextEntry(new ZipEntry("com/example/universe/AppController.class"));
                zos.write(Files.readAllBytes(appClass));
                zos.closeEntry();
            }
            zos.putNextEntry(new ZipEntry("org/springframework/boot/loader/extra.txt"));
            zos.write("boot-loader-marker\n".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }
        return jar;
    }

    private static byte[] minimalJarBytes(String entryName, byte[] content) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(bytes)) {
            zos.putNextEntry(new ZipEntry(entryName));
            zos.write(content);
            zos.closeEntry();
        }
        return bytes.toByteArray();
    }

    private static byte[] fatNestedJarBytes(int classCount) throws Exception {
        byte[] stub = new byte[]{
                (byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE, 0, 0, 0, 55, 0, 1
        };
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(bytes)) {
            for (int i = 0; i < classCount; i++) {
                zos.putNextEntry(new ZipEntry("com/example/fat/C" + i + ".class"));
                zos.write(stub);
                zos.closeEntry();
            }
        }
        return bytes.toByteArray();
    }

    private static void compile(Path sources, Path classes) throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        check(compiler != null, "tests require a JDK compiler");
        List<Path> files;
        try (Stream<Path> stream = Files.walk(sources)) {
            files = stream.filter(path -> path.toString().endsWith(".java")).toList();
        }
        try (StandardJavaFileManager manager =
                     compiler.getStandardFileManager(null, null, StandardCharsets.UTF_8)) {
            boolean success = compiler.getTask(null, manager, null,
                    List.of("--release", "17", "-d", classes.toString()), null,
                    manager.getJavaFileObjectsFromPaths(files)).call();
            check(success, "fixture compilation");
        }
    }

    private static Map<String, Object> ok(HttpResponse<String> response) throws Exception {
        check(response.statusCode() >= 200 && response.statusCode() < 300,
                "HTTP " + response.statusCode() + ": " + response.body());
        @SuppressWarnings("unchecked")
        Map<String, Object> body = new com.fasterxml.jackson.databind.ObjectMapper()
                .readValue(response.body(), Map.class);
        return body;
    }

    private static HttpResponse<String> send(
            HttpClient client, URI uri, String method, String body, String token) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json");
        if ("GET".equals(method)) {
            builder.GET();
        } else {
            builder.method(method, HttpRequest.BodyPublishers.ofString(body == null ? "" : body));
        }
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static URI uri(ControlPlaneServer server, String path) {
        return URI.create(server.baseUri() + path);
    }

    private static String text(Map<String, Object> map, String key) {
        Object value = map.get(key);
        check(value != null, key + " present");
        return String.valueOf(value);
    }

    private static String escape(String path) {
        return path.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) return;
        try (Stream<Path> stream = Files.walk(root)) {
            List<Path> paths = stream.sorted((a, b) -> b.getNameCount() - a.getNameCount()).toList();
            for (Path path : paths) {
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
