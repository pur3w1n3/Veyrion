package com.aq.jvmsentinel;

import com.aq.jvmsentinel.analysis.ArtifactMetadataReader;
import com.aq.jvmsentinel.analysis.PreAnalysisInput;
import com.aq.jvmsentinel.analysis.PreAnalysisResult;
import com.aq.jvmsentinel.analysis.PreAnalysisService;
import com.aq.jvmsentinel.analysis.spi.AnalysisProvider;
import com.aq.jvmsentinel.analysis.spi.DetectorProvider;
import com.aq.jvmsentinel.analysis.spi.EffectModelProvider;
import com.aq.jvmsentinel.analysis.spi.EntryProvider;
import com.aq.jvmsentinel.analysis.spi.GuardModelProvider;
import com.aq.jvmsentinel.analysis.spi.ProviderBundle;
import com.aq.jvmsentinel.analysis.spi.ProviderContext;
import com.aq.jvmsentinel.analysis.spi.ProviderContribution;
import com.aq.jvmsentinel.analysis.spi.ProviderKind;
import com.aq.jvmsentinel.analysis.spi.ProviderOutputGate;
import com.aq.jvmsentinel.analysis.spi.ProviderRegistry;
import com.aq.jvmsentinel.analysis.spi.defaults.DefaultJvmProviders;
import com.aq.jvmsentinel.artifact.ArtifactRegistry;
import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.domain.ir.EffectNode;
import com.aq.jvmsentinel.domain.ir.EntryNode;
import com.aq.jvmsentinel.domain.ir.GuardNode;
import com.aq.jvmsentinel.domain.ir.StableNodeIds;
import com.aq.jvmsentinel.model.ArtifactDescriptor;

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
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * P1-03：版本化 Provider SPI — default 包装 PreAnalysis；TestOnly 可添加
 * 说明：entry/effect/guard/detector；unload scope 隔离；gate 拒绝 Finding/status 提升。
 */
public final class ProviderSpiAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();
    private static final String TEST_SCOPE = "test-only-provider-scope";
    private static final String TEST_PROVIDER_ID = "test-only-multi-provider";

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        Path root = Files.createTempDirectory("provider-spi");
        try {
            ProviderRegistry.resetForTests();
            Path jar = buildFixture(root);
            verifyDefaultsAndTestOnly(root, jar);
            verifyGateRejectsFindingAndStatusElevation();
            verifyScanBuildUsesProviderBundle(root, jar);
            System.out.println("ProviderSpiAcceptanceTest: PASS ("
                    + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
        } finally {
            ProviderRegistry.resetForTests();
            deleteTree(root);
        }
    }

    /**
     * 说明：P1-03：scan build path collect ProviderBundle；DefaultJvmProviders 与 TestOnly
     * contribution 为合并进 scan 的权威 entry/effect/guard source。
     */
    private static void verifyScanBuildUsesProviderBundle(Path root, Path jar) throws Exception {
        ProviderRegistry.resetForTests();
        TestOnlyProvider testOnly = new TestOnlyProvider(null);
        ProviderRegistry.register(testOnly);
        String token = "provider-spi-token";
        Path database = root.resolve("state/provider-spi.db");
        HttpClient client = HttpClient.newHttpClient();
        try (ControlPlaneServer server = new ControlPlaneServer(root, 0, token, database).start()) {
            Map<String, Object> project = ok(send(client, uri(server, "/projects"), "POST",
                    "{\"name\":\"provider spi slice\"}", token));
            String projectId = text(project, "projectId");
            Map<String, Object> artifact = ok(send(client,
                    uri(server, "/projects/" + projectId + "/artifacts"), "POST",
                    "{\"path\":\"" + escape(jar.toString()) + "\"}", token));
            Map<String, Object> scan = ok(send(client,
                    uri(server, "/projects/" + projectId + "/scans"), "POST",
                    "{\"artifactDigest\":\"" + text(artifact, "artifactDigest")
                            + "\",\"authorized\":true}", token));
            String scanId = text(scan, "scanId");

            Object entriesObj = scan.get("entries");
            check(entriesObj instanceof List<?> && !((List<?>) entriesObj).isEmpty(),
                    "scan has entries from DefaultJvmProviders/PreAnalysis");
            boolean hasTestOnlyEntry = false;
            for (Object item : (List<?>) entriesObj) {
                if (!(item instanceof Map<?, ?> entry)) continue;
                if ("/test-only/hook".equals(String.valueOf(entry.get("route")))) {
                    hasTestOnlyEntry = true;
                    break;
                }
            }
            check(hasTestOnlyEntry, "TestOnly provider entry merged into scan");

            Object sinksObj = scan.get("sinks");
            check(sinksObj instanceof List<?>, "scan sinks present");
            boolean hasCustomEffect = false;
            boolean hasDefaultSql = false;
            for (Object item : (List<?>) sinksObj) {
                if (!(item instanceof Map<?, ?> sink)) continue;
                String category = String.valueOf(sink.get("category"));
                String symbol = String.valueOf(sink.get("symbol"));
                if ("CUSTOM_EFFECT".equals(category)
                        || symbol.contains("TestOnly")) {
                    hasCustomEffect = true;
                }
                if ("SQL".equals(category)) {
                    hasDefaultSql = true;
                }
            }
            check(hasDefaultSql, "DefaultJvmProviders/PreAnalysis SQL effect in scan");
            check(hasCustomEffect, "TestOnly custom effect merged into scan sinks");

            // Unload TestOnly：新 scan 不得保留该 provider scope。
            check(ProviderRegistry.unregister(testOnly), "TestOnly unregistered before second scan");
            Map<String, Object> scan2 = ok(send(client,
                    uri(server, "/projects/" + projectId + "/scans"), "POST",
                    "{\"artifactDigest\":\"" + text(artifact, "artifactDigest")
                            + "\",\"authorized\":true}", token));
            boolean stillHasTestOnly = false;
            Object entries2 = scan2.get("entries");
            if (entries2 instanceof List<?> list) {
                for (Object item : list) {
                    if (item instanceof Map<?, ?> entry
                            && "/test-only/hook".equals(String.valueOf(entry.get("route")))) {
                        stillHasTestOnly = true;
                    }
                }
            }
            check(!stillHasTestOnly, "unload isolates TestOnly from subsequent scans");
            check(scanId != null && !scanId.isBlank(), "first scanId recorded");
        } finally {
            ProviderRegistry.resetForTests();
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> ok(HttpResponse<String> response) {
        check(response.statusCode() >= 200 && response.statusCode() < 300,
                "HTTP " + response.statusCode() + " " + response.body());
        return JsonCodec.parseObject(response.body());
    }

    private static HttpResponse<String> send(
            HttpClient client, URI uri, String method, String body, String token) throws Exception {
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

    private static String text(Map<String, Object> map, String key) {
        Object value = map.get(key);
        check(value != null && !String.valueOf(value).isBlank(), key + " present");
        return String.valueOf(value);
    }

    private static String escape(String path) {
        return path.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void verifyDefaultsAndTestOnly(Path root, Path jar) throws Exception {
        ArtifactRegistry registry = new ArtifactRegistry(root);
        ArtifactDescriptor descriptor = registry.register(jar);
        PreAnalysisInput input = ArtifactMetadataReader.read(descriptor);
        PreAnalysisResult pre = new PreAnalysisService().analyze(input);

        ProviderContext context = ProviderContext.of(
                "proj-spi", descriptor.sha256(), "scan-spi", descriptor, pre);

        ProviderBundle baseline = ProviderRegistry.collect(context);
        check(ProviderRegistry.providerIds().contains(DefaultJvmProviders.ENTRY_ID),
                "default spring entry provider registered");
        check(ProviderRegistry.providerIds().contains(DefaultJvmProviders.EFFECT_ID),
                "default sink effect provider registered");
        check(ProviderRegistry.providerIds().contains(DefaultJvmProviders.GUARD_ID),
                "default AuthCoverage guard provider registered");
        check(!baseline.entries().isEmpty(), "default providers emit entries from PreAnalysis");
        check(baseline.effects().stream().anyMatch(e -> !e.custom()),
                "default providers emit non-custom sink effects");
        check(baseline.guards().stream().anyMatch(g ->
                        "AUTH_GAP".equals(g.node().guardKind())
                                || "DECLARED_ROLE".equals(g.node().guardKind())),
                "default AuthCoverage emits guards");
        int baselineEntries = baseline.entries().size();
        int baselineEffects = baseline.effects().size();
        int baselineGuards = baseline.guards().size();
        int baselineDetectors = baseline.detectors().size();

        TestOnlyProvider testOnly = new TestOnlyProvider(context);
        ProviderRegistry.register(testOnly);
        try {
            ProviderBundle withTest = ProviderRegistry.collect(context);
            check(withTest.entriesFromScope(TEST_SCOPE).size() == 1,
                    "TestOnly adds one entry in its scope");
            check(withTest.effectsFromScope(TEST_SCOPE).stream().anyMatch(ProviderContribution.Effect::custom),
                    "TestOnly adds custom effect in its scope");
            check(withTest.guardsFromScope(TEST_SCOPE).size() == 1,
                    "TestOnly adds guard in its scope");
            check(withTest.detectorsFromScope(TEST_SCOPE).size() == 1,
                    "TestOnly adds detector in its scope");
            check(withTest.entries().size() == baselineEntries + 1,
                    "TestOnly entry is additive");
            check(withTest.effects().size() == baselineEffects + 1,
                    "TestOnly effect is additive");
            check(withTest.guards().size() == baselineGuards + 1,
                    "TestOnly guard is additive");
            check(withTest.detectors().size() == baselineDetectors + 1,
                    "TestOnly detector is additive");
            check(withTest.detectorsFromScope(TEST_SCOPE).get(0).hypothesis().lifecycle()
                            == HypothesisLifecycle.CANDIDATE,
                    "TestOnly detector lifecycle clamped to CANDIDATE");
        } finally {
            check(ProviderRegistry.unregister(testOnly), "TestOnly unregistered");
        }

        ProviderBundle afterUnload = ProviderRegistry.collect(context);
        check(afterUnload.entriesFromScope(TEST_SCOPE).isEmpty(),
                "unload removes TestOnly entries only");
        check(afterUnload.effectsFromScope(TEST_SCOPE).isEmpty(),
                "unload removes TestOnly effects only");
        check(afterUnload.guardsFromScope(TEST_SCOPE).isEmpty(),
                "unload removes TestOnly guards only");
        check(afterUnload.detectorsFromScope(TEST_SCOPE).isEmpty(),
                "unload removes TestOnly detectors only");
        check(afterUnload.entries().size() == baselineEntries,
                "default entries unchanged after unload");
        check(afterUnload.effects().size() == baselineEffects,
                "default effects unchanged after unload");
        check(afterUnload.guards().size() == baselineGuards,
                "default guards unchanged after unload");
        check(afterUnload.detectors().size() == baselineDetectors,
                "default detectors unchanged after unload");
    }

    private static void verifyGateRejectsFindingAndStatusElevation() {
        ProviderContext context = new ProviderContext(
                "proj-gate", "digest-gate", "scan-gate", null, null, List.of(), null);
        ProviderOutputGate gate = new ProviderOutputGate(context);
        gate.rejectForbidden("finding-write-attempt");
        gate.acceptEntry(new ProviderContribution.Entry(
                "evil", "evil", AnalysisProvider.SCHEMA_VERSION,
                "proj-gate", "digest-gate", "scan-gate",
                new EntryNode(StableNodeIds.entry("e1"), "HTTP", "GET", "/x", "X",
                        List.of(), List.of("ev"), "FACT", "VERIFIED")));
        gate.acceptDetector(new ProviderContribution.Detector(
                "evil", "evil", AnalysisProvider.SCHEMA_VERSION,
                "proj-gate", "digest-gate", "scan-gate",
                new SecurityHypothesis(
                        SecurityHypothesis.SCHEMA_VERSION,
                        "hyp-evil",
                        "scan-gate",
                        "CUSTOM",
                        HypothesisFamily.CONFIG,
                        HypothesisLifecycle.SUPPORTED,
                        "evil/1",
                        List.of(), List.of(), List.of(),
                        "", "")));
        // 错误 scope 须 fail-closed。
        gate.acceptEffect(new ProviderContribution.Effect(
                "evil", "evil", AnalysisProvider.SCHEMA_VERSION,
                "wrong-project", "digest-gate", "scan-gate",
                new EffectNode(StableNodeIds.effect("fx"), "CUSTOM", "x", "src",
                        List.of(), "INFERENCE", "STATIC_INFERRED"),
                true));

        ProviderBundle bundle = gate.build();
        check(bundle.rejected().stream().anyMatch(r -> r.contains("finding-write")),
                "gate records Finding write rejection");
        check(bundle.rejected().stream().anyMatch(r -> r.contains("status-elevation")),
                "gate rejects VERIFIED elevation");
        check(bundle.entries().size() == 1
                        && "STATIC_INFERRED".equals(bundle.entries().get(0).node().verificationStatus()),
                "elevated entry status clamped to STATIC_INFERRED");
        check(bundle.detectors().size() == 1
                        && bundle.detectors().get(0).hypothesis().lifecycle()
                        == HypothesisLifecycle.CANDIDATE,
                "detector lifecycle elevation clamped to CANDIDATE");
        check(bundle.effects().isEmpty()
                        && bundle.rejected().stream().anyMatch(r -> r.startsWith("scope:")),
                "wrong-scope contribution rejected");
    }

    /** Multi-kind TestOnly provider used for register/unload isolation. */
    private static final class TestOnlyProvider
            implements EntryProvider, EffectModelProvider, GuardModelProvider, DetectorProvider {
        private TestOnlyProvider(ProviderContext ignored) {
        }

        @Override public String id() { return TEST_PROVIDER_ID; }
        @Override public String providerVersion() { return "test-only/0.1"; }
        @Override public String declaredScope() { return TEST_SCOPE; }
        @Override public Set<ProviderKind> kinds() {
            return EnumSet.of(ProviderKind.ENTRY, ProviderKind.EFFECT_MODEL,
                    ProviderKind.GUARD_MODEL, ProviderKind.DETECTOR);
        }

        @Override
        public List<ProviderContribution.Entry> contributeEntries(ProviderContext context) {
            return List.of(new ProviderContribution.Entry(
                    id(), declaredScope(), schemaVersion(),
                    context.projectId(), context.artifactDigest(), context.scanId(),
                    new EntryNode(StableNodeIds.entry("test-only-entry"),
                            "CUSTOM", "HANDLE", "/test-only/hook",
                            "com.example.TestOnlyHook", List.of("payload"),
                            List.of("ev-test-only-entry"), "INFERENCE", "STATIC_INFERRED")));
        }

        @Override
        public List<ProviderContribution.Effect> contributeEffects(ProviderContext context) {
            return List.of(new ProviderContribution.Effect(
                    id(), declaredScope(), schemaVersion(),
                    context.projectId(), context.artifactDigest(), context.scanId(),
                    new EffectNode(StableNodeIds.effect("test-only-effect"),
                            "CUSTOM_EFFECT", "com.example.TestOnly#sideEffect",
                            "test-only custom effect", List.of("ev-test-only-effect"),
                            "INFERENCE", "STATIC_INFERRED"),
                    true));
        }

        @Override
        public List<ProviderContribution.Guard> contributeGuards(ProviderContext context) {
            return List.of(new ProviderContribution.Guard(
                    id(), declaredScope(), schemaVersion(),
                    context.projectId(), context.artifactDigest(), context.scanId(),
                    new GuardNode(StableNodeIds.guard("test-only-guard"),
                            "CUSTOM_GUARD", "hasRole('TEST')",
                            StableNodeIds.entry("test-only-entry"),
                            List.of("ev-test-only-guard"), "INFERENCE")));
        }

        @Override
        public List<ProviderContribution.Detector> contributeDetectors(ProviderContext context) {
            return List.of(new ProviderContribution.Detector(
                    id(), declaredScope(), schemaVersion(),
                    context.projectId(), context.artifactDigest(), context.scanId(),
                    new SecurityHypothesis(
                            SecurityHypothesis.SCHEMA_VERSION,
                            "hyp-test-only-1",
                            context.scanId(),
                            "CUSTOM_GUARD",
                            HypothesisFamily.GUARD_COVERAGE,
                            HypothesisLifecycle.SUPPORTED, // gate must clamp
                            providerVersion(),
                            List.of("ev-test-only-guard"),
                            List.of(),
                            List.of(),
                            "",
                            "")));
        }
    }

    private static Path buildFixture(Path root) throws Exception {
        Path src = root.resolve("src");
        Path classes = root.resolve("classes");
        Files.createDirectories(src);
        Files.createDirectories(classes);
        Files.writeString(src.resolve("SpiController.java"), """
                package com.example;
                import org.springframework.web.bind.annotation.*;
                import java.sql.Connection;
                import java.sql.DriverManager;
                import java.sql.Statement;
                @RestController
                public class SpiController {
                    @GetMapping("/spi/search")
                    public String search(@RequestParam("q") String q) {
                        try {
                            Connection c = DriverManager.getConnection("jdbc:h2:mem:x");
                            Statement s = c.createStatement();
                            s.execute("SELECT * FROM t WHERE q='" + q + "'");
                            return "ok";
                        } catch (Exception e) {
                            return "err";
                        }
                    }
                }
                """, StandardCharsets.UTF_8);
        writeStub(src, "org/springframework/web/bind/annotation/RestController.java", """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE)
                public @interface RestController {}
                """);
        writeStub(src, "org/springframework/web/bind/annotation/GetMapping.java", """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
                public @interface GetMapping { String value() default ""; }
                """);
        writeStub(src, "org/springframework/web/bind/annotation/RequestParam.java", """
                package org.springframework.web.bind.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.PARAMETER)
                public @interface RequestParam { String value() default ""; }
                """);

        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        check(compiler != null, "JDK compiler available");
        List<Path> sourceFiles;
        try (Stream<Path> walk = Files.walk(src)) {
            sourceFiles = walk.filter(p -> p.toString().endsWith(".java")).toList();
        }
        try (StandardJavaFileManager fm =
                     compiler.getStandardFileManager(null, null, StandardCharsets.UTF_8)) {
            boolean ok = compiler.getTask(null, fm, null,
                    List.of("--release", "17", "-parameters", "-d", classes.toString()), null,
                    fm.getJavaFileObjectsFromPaths(sourceFiles)).call();
            check(ok, "fixture compiled");
        }

        Path jar = root.resolve("spi-fixture.jar");
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(jar));
             Stream<Path> walk = Files.walk(classes)) {
            for (Path file : walk.filter(Files::isRegularFile).toList()) {
                String name = "BOOT-INF/classes/"
                        + classes.relativize(file).toString().replace('\\', '/');
                zos.putNextEntry(new ZipEntry(name));
                Files.copy(file, zos);
                zos.closeEntry();
            }
        }
        return jar;
    }

    private static void writeStub(Path srcRoot, String relative, String source) throws Exception {
        Path file = srcRoot.resolve(relative);
        Files.createDirectories(file.getParent());
        Files.writeString(file, source, StandardCharsets.UTF_8);
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }

    private static void deleteTree(Path root) throws Exception {
        if (root == null || !Files.exists(root)) return;
        try (Stream<Path> walk = Files.walk(root)) {
            walk.sorted((a, b) -> b.compareTo(a)).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (Exception ignored) {
                }
            });
        }
    }
}
