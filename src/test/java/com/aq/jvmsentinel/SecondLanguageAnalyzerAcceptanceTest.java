package com.aq.jvmsentinel;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.domain.analyzer.AnalyzerCapability;
import com.aq.jvmsentinel.domain.analyzer.AnalyzerIngress;
import com.aq.jvmsentinel.domain.analyzer.AnalyzerScope;
import com.aq.jvmsentinel.domain.analyzer.AnalyzerSessionSpec;
import com.aq.jvmsentinel.domain.analyzer.AnalyzerBudget;
import com.aq.jvmsentinel.domain.analyzer.AnalyzerSchemaRange;
import com.aq.jvmsentinel.domain.analyzer.InMemoryAnalyzerEvidenceStore;
import com.aq.jvmsentinel.domain.analyzer.IrChunk;
import com.aq.jvmsentinel.domain.analyzer.TestJsLanguageAnalyzer;
import com.aq.jvmsentinel.domain.coverage.CoverageMatrix;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.domain.ir.EntryNode;
import com.aq.jvmsentinel.domain.ir.EvidenceGraph;
import com.aq.jvmsentinel.domain.ir.IrNode;
import com.aq.jvmsentinel.domain.ir.ProgramNode;
import com.aq.jvmsentinel.domain.runtime.JsRuntimeAdapter;
import com.aq.jvmsentinel.domain.runtime.RuntimeRunProfile;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

/**
 * P2：第二语言静态 LanguageAnalyzer + RuntimeAdapter 骨架。
 * 证明 non-JVM IR 复用相同 store/hypothesis/coverage/GUI degrade path，
 * 且 static analyzer 支持不授予 dynamic RuntimeAdapter capability。
 */
public final class SecondLanguageAnalyzerAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();
    private static final String ARTIFACT = "c".repeat(64);
    private static final String POLICY = "d".repeat(64);

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);

        publishNonJvmProgramViaAnalyzerContract();
        reuseControlPlaneHypothesisCoverageGuiPath();
        staticSupportDoesNotGrantDynamicRuntime();
        analyzerPackageDoesNotCopyControlPlane();

        System.out.println("SecondLanguageAnalyzerAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void publishNonJvmProgramViaAnalyzerContract() {
        InMemoryAnalyzerEvidenceStore store = new InMemoryAnalyzerEvidenceStore();
        AnalyzerIngress ingress = new AnalyzerIngress(store);
        AnalyzerScope scope = new AnalyzerScope("proj-js", ARTIFACT, "scan-js-1", "analysis-js-1");
        TestJsLanguageAnalyzer analyzer = new TestJsLanguageAnalyzer(scope, ARTIFACT, POLICY);

        Set<AnalyzerCapability> accepted = ingress.negotiate(
                analyzer.offer(), TestJsLanguageAnalyzer.STATIC_CAPABILITIES);
        check(accepted.equals(TestJsLanguageAnalyzer.STATIC_CAPABILITIES),
                "JS analyzer capabilities negotiated");

        String sessionId = ingress.openSession(new AnalyzerSessionSpec(
                scope, ARTIFACT, POLICY, TestJsLanguageAnalyzer.STATIC_CAPABILITIES,
                AnalyzerSchemaRange.v1Only(), AnalyzerBudget.defaults(),
                Instant.now().plusSeconds(120)));
        List<IrChunk> chunks = analyzer.minimalStaticChunks();
        for (IrChunk chunk : chunks) {
            ingress.stageChunk(sessionId, chunk);
        }
        AnalyzerIngress.CommitResult result = ingress.commit(
                sessionId, analyzer.successSubmission(chunks, "sub-js-1"));
        check(result.published(), "JS analyzer commit publishes");
        check(result.evidence().nodes().stream().anyMatch(n -> n instanceof ProgramNode pn
                        && TestJsLanguageAnalyzer.LANGUAGE.equals(pn.language())
                        && "MODULE".equals(pn.elementKind())
                        && !"JVM".equals(pn.language())),
                "published non-JVM javascript ProgramNode");
        check(result.evidence().nodes().stream().anyMatch(n -> n instanceof ProgramNode pn
                        && pn.extensions().containsKey("javascript")),
                "namespaced javascript extension preserved through ingress");
        check(result.evidence().nodes().stream().anyMatch(n -> n instanceof EntryNode),
                "published EntrySurface from JS analyzer");
        check(result.evidence().coverageGaps().size() == 1, "published CoverageGap");
        check(store.findByScanId(scope.scanId()).size() == 1, "evidence in shared store");
    }

    private static void reuseControlPlaneHypothesisCoverageGuiPath() throws Exception {
        Path root = Files.createTempDirectory("js-lang-cp");
        try (ControlPlaneServer server = new ControlPlaneServer(root, 0, "js-lang-token").start()) {
            String now = Instant.now().toString();
            ControlPlaneStore store = server.store();
            ControlPlaneStore.ProjectRecord project = store.createProject(
                    "proj-js-cp", "JS Lang", now, "local-admin");
            String scanId = "scan-js-cp-1";
            ApiDtos.ScanDto scan = new ApiDtos.ScanDto(
                    ApiDtos.SCHEMA_VERSION, project.projectId(), ARTIFACT, scanId,
                    "COMPLETED", ApiDtos.STATIC_INFERRED, ApiDtos.MOCK, now, now,
                    List.of("ev-js-1"), List.of(), List.of(), List.of(), List.of(), List.of());
            store.saveScan(new ControlPlaneStore.ScanRecord(scan, Map.of(), List.of(), List.of()),
                    "local-admin");
            store.saveHypotheses(scanId, List.of(
                    new SecurityHypothesis(
                            SecurityHypothesis.SCHEMA_VERSION, "hyp-js-config-1", scanId,
                            "CONFIG", HypothesisFamily.CONFIG,
                            HypothesisLifecycle.CANDIDATE, "test-js-language-analyzer/0.1",
                            List.of("ev-js-1"), List.of(), List.of(), "", "")), "local-admin");

            ProgramNode jsNode = new ProgramNode(
                    "program:module:javascript:routes/users",
                    "MODULE",
                    TestJsLanguageAnalyzer.LANGUAGE,
                    "routes/users",
                    "src/routes/users.js:12",
                    List.of("ev-js-1"),
                    "FACT",
                    Map.of("javascript", Map.of("moduleKind", "esm", "exportName", "listUsers")));
            server.analyzerIrIngestPort().ingestProgramNodes(scanId, List.of(jsNode));

            List<ProgramNode> stored = server.analyzerIrIngestPort().supplementalProgramNodes(scanId);
            check(stored.size() == 1 && TestJsLanguageAnalyzer.LANGUAGE.equals(stored.get(0).language()),
                    "JS ProgramNode on shared ingest port");

            Optional<EvidenceGraph> graph = server.evidenceGraphQueryPort().evidenceGraph(scanId);
            check(graph.isPresent(), "evidence-graph query port works for JS scan");
            Optional<IrNode> found = graph.get().findById(jsNode.id());
            check(found.isPresent() && found.get() instanceof ProgramNode pn
                            && TestJsLanguageAnalyzer.LANGUAGE.equals(pn.language()),
                    "JS node queryable without Control Plane fork");

            check(server.hypothesisQueryPort().hypotheses(scanId).size() == 1,
                    "hypothesis path reused for JS scan");
            Optional<CoverageMatrix> coverage = server.coverageQueryPort().coverage(scanId);
            check(coverage.isPresent(), "coverage path reused for JS scan");

            Path frontend = SchemaContractAcceptanceTest.projectRoot()
                    .resolve("frontend/src/components/CapabilityEvidencePanels.tsx");
            String gui = Files.readString(frontend, StandardCharsets.UTF_8);
            check(gui.contains("UnknownExtensionView"), "GUI unknown-extension degrade component");
            check(gui.contains("unknown/other language") || gui.contains("未知/其他语言"),
                    "GUI degrades unknown/other language without page fork");
            check(!gui.contains("if (language === 'javascript')")
                            && !gui.contains("language === \"javascript\""),
                    "GUI has no javascript-specific main-flow branch");
        } finally {
            deleteTree(root);
        }
    }

    private static void staticSupportDoesNotGrantDynamicRuntime() {
        JsRuntimeAdapter adapter = new JsRuntimeAdapter();
        check(adapter.declaredCapabilities().isEmpty(), "default JS RuntimeAdapter has no caps");
        check(!adapter.supportsDynamicExecution(), "static ≠ dynamic by default");

        String image = "e".repeat(64);
        RuntimeRunProfile profile = RuntimeRunProfile.serverFixed(
                JsRuntimeAdapter.RUNTIME_KIND,
                JsRuntimeAdapter.RUNTIME_VERSION,
                image,
                List.of("node", "/artifact/app.js"),
                List.of(new RuntimeRunProfile.ReadOnlyMount(ARTIFACT, "/artifact/app.js", true)),
                65534,
                RuntimeRunProfile.NetworkMode.DENY,
                new RuntimeRunProfile.RuntimeBudget(60, 30_000, 512_000_000, 100_000_000, 1_000_000),
                List.of("HTTP_PROBE"),
                "DYNAMIC_SUSPECTED");
        try {
            adapter.bindProfile(profile);
            throw new AssertionError("static-only JS RuntimeAdapter must reject dynamic bind");
        } catch (SecurityException ex) {
            check(ex.getMessage().startsWith("RUNTIME_CAPABILITY_DENIED"),
                    "dynamic capability denied without audited caps");
        }

        // 即使显式 capability-bearing adapter 仍拒绝不可信 override。
        JsRuntimeAdapter withObserve = new JsRuntimeAdapter("20", Set.of("OBSERVE"));
        check(withObserve.supportsDynamicExecution(), "explicit OBSERVE is dynamic");
        try {
            withObserve.bindProfile(profile);
            throw new AssertionError("HTTP_PROBE without declared capability must fail");
        } catch (SecurityException ex) {
            check(ex.getMessage().contains("HTTP_PROBE") || ex.getMessage().contains("DENIED"),
                    "observation kind still gated by declared capabilities");
        }
    }

    private static void analyzerPackageDoesNotCopyControlPlane() throws Exception {
        Path root = SchemaContractAcceptanceTest.projectRoot();
        Path analyzer = root.resolve("src/main/java/com/aq/jvmsentinel/domain/analyzer/TestJsLanguageAnalyzer.java");
        check(Files.isRegularFile(analyzer), "TestJsLanguageAnalyzer source exists");
        String text = Files.readString(analyzer, StandardCharsets.UTF_8);
        check(!text.contains("import com.aq.jvmsentinel.control."),
                "JS LanguageAnalyzer must not import Control Plane");
        check(!text.contains("ControlPlaneServer") && !text.contains("ControlPlaneStore"),
                "JS LanguageAnalyzer must not copy control-plane types");

        Path domainRuntime = root.resolve("src/main/java/com/aq/jvmsentinel/domain/runtime");
        try (Stream<Path> stream = Files.walk(domainRuntime)) {
            boolean sawJs = stream.anyMatch(p -> p.getFileName().toString().equals("JsRuntimeAdapter.java"));
            check(sawJs, "JsRuntimeAdapter skeleton present under domain.runtime");
        }
    }

    private static void deleteTree(Path root) throws Exception {
        if (root == null || !Files.exists(root)) {
            return;
        }
        try (var stream = Files.walk(root)) {
            stream.sorted((a, b) -> b.compareTo(a)).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (Exception ignored) {
                    // 尽力而为
                }
            });
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
