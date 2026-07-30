package com.aq.jvmsentinel;

import com.aq.jvmsentinel.domain.analyzer.AnalyzerBudget;
import com.aq.jvmsentinel.domain.analyzer.AnalyzerCapability;
import com.aq.jvmsentinel.domain.analyzer.AnalyzerCoverageGapDto;
import com.aq.jvmsentinel.domain.analyzer.AnalyzerDiagnostic;
import com.aq.jvmsentinel.domain.analyzer.AnalyzerIngress;
import com.aq.jvmsentinel.domain.analyzer.AnalyzerRejectException;
import com.aq.jvmsentinel.domain.analyzer.AnalyzerRejectReason;
import com.aq.jvmsentinel.domain.analyzer.AnalyzerResourceUsage;
import com.aq.jvmsentinel.domain.analyzer.AnalyzerSchemaRange;
import com.aq.jvmsentinel.domain.analyzer.AnalyzerScope;
import com.aq.jvmsentinel.domain.analyzer.AnalyzerSessionSpec;
import com.aq.jvmsentinel.domain.analyzer.AnalyzerSubmission;
import com.aq.jvmsentinel.domain.analyzer.AnalyzerTerminalState;
import com.aq.jvmsentinel.domain.analyzer.CapabilityNegotiation;
import com.aq.jvmsentinel.domain.analyzer.InMemoryAnalyzerEvidenceStore;
import com.aq.jvmsentinel.domain.analyzer.IrChunk;
import com.aq.jvmsentinel.domain.analyzer.IrChunkManifest;
import com.aq.jvmsentinel.domain.analyzer.TestAnalyzerProcessMain;
import com.aq.jvmsentinel.domain.ir.EntryNode;
import com.aq.jvmsentinel.domain.ir.ProgramNode;
import com.aq.jvmsentinel.domain.ir.StableNodeIds;
import com.aq.jvmsentinel.domain.runtime.RuntimeAdapterGuard;
import com.aq.jvmsentinel.domain.runtime.RuntimeAdapterOverrideAttempt;
import com.aq.jvmsentinel.domain.runtime.RuntimeRunProfile;
import com.aq.jvmsentinel.domain.runtime.SkeletonRuntimeAdapter;
import com.aq.jvmsentinel.domain.universe.CoverageGap;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

/**
 * P1-07：进程外 Analyzer / Runtime contract — 同进程 Fake regression 加
 * 真实 {@link ProcessBuilder} 子进程 {@link com.aq.jvmsentinel.domain.analyzer.TestAnalyzerProcessMain}
 * 经 {@link AnalyzerIngress} 提交最小 IR。
 */
public final class TestAnalyzerAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();
    private static final String ARTIFACT = "a".repeat(64);
    private static final String POLICY = "b".repeat(64);
    private static final Set<AnalyzerCapability> ALLOWED = EnumSet.of(
            AnalyzerCapability.PROGRAM_IR,
            AnalyzerCapability.ENTRY_SURFACE,
            AnalyzerCapability.COVERAGE_GAP,
            AnalyzerCapability.DIAGNOSTIC);

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);

        successMinimalProgramEntryGap();
        subprocessAnalyzerPublishesMinimalIr();
        rejectWrongScope();
        rejectWrongArtifactDigest();
        rejectWrongPolicyDigest();
        rejectIncompatibleSchema();
        rejectUnknownCapability();
        rejectMissingChunk();
        rejectDuplicateChunk();
        rejectOverBudget();
        rejectCancelled();
        rejectLate();
        replayIdempotent();
        rejectCrossScopeReplay();
        analyzerHasNoPrivilegedImports();
        runtimeAdapterRejectsOverrides();
        historicalEvidenceSurvivesWithoutAnalyzer();

        System.out.println("TestAnalyzerAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    /** In-process Test Analyzer that speaks the out-of-process protocol. */
    private static final class TestAnalyzer {
        private final AnalyzerScope scope;
        private final Set<AnalyzerCapability> capabilities;

        private TestAnalyzer(AnalyzerScope scope, Set<AnalyzerCapability> capabilities) {
            this.scope = scope;
            this.capabilities = capabilities;
        }

        CapabilityNegotiation offer() {
            return new CapabilityNegotiation(
                    1, "test-analyzer", "0.1.0",
                    List.of("testlang"), List.of("application/x-veyrion-test"),
                    capabilities, AnalyzerSchemaRange.v1Only(),
                    ARTIFACT, POLICY, scope, List.of("PROGRAM_IR", "ENTRY_SURFACE"));
        }

        List<IrChunk> minimalChunks() {
            Map<String, Object> program = new LinkedHashMap<>();
            program.put("id", StableNodeIds.programClass("test.App"));
            program.put("elementKind", "CLASS");
            program.put("language", "testlang");
            program.put("symbol", "test.App");
            program.put("location", "test/App.class");

            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("id", StableNodeIds.entry("entry-test-1"));
            entry.put("protocol", "HTTP");
            entry.put("operation", "GET");
            entry.put("address", "/api/test");
            entry.put("declaringSymbol", "test.App#handle");

            Map<String, Object> gap = new LinkedHashMap<>();
            gap.put("id", "gap-unresolved-1");
            gap.put("kind", CoverageGap.KIND_UNRESOLVED_CALL);
            gap.put("detail", "call to unknown.symbol");
            gap.put("stopReason", "STATIC_LIMIT");

            return List.of(
                    IrChunk.create(scope, 0, IrChunk.KIND_PROGRAM_NODE, program),
                    IrChunk.create(scope, 1, IrChunk.KIND_ENTRY, entry),
                    IrChunk.create(scope, 2, IrChunk.KIND_COVERAGE_GAP, gap));
        }

        AnalyzerSubmission successSubmission(List<IrChunk> chunks) {
            IrChunkManifest manifest = IrChunkManifest.of(chunks);
            AnalyzerResourceUsage usage = new AnalyzerResourceUsage(
                    chunks.size(), manifest.totalPayloadBytes(), 25, 2);
            return new AnalyzerSubmission(
                    1, "sub-success-1", scope, ARTIFACT, POLICY, capabilities, manifest,
                    List.of(AnalyzerDiagnostic.info("ANALYSIS_COMPLETE", "test analyzer ok")),
                    List.of(new AnalyzerCoverageGapDto(
                            "gap-unresolved-1", CoverageGap.KIND_UNRESOLVED_CALL,
                            "call to unknown.symbol", "STATIC_LIMIT", "ev-gap-1")),
                    usage, AnalyzerTerminalState.SUCCESS, "COMPLETED", null);
        }
    }

    private static void successMinimalProgramEntryGap() {
        InMemoryAnalyzerEvidenceStore store = new InMemoryAnalyzerEvidenceStore();
        AnalyzerIngress ingress = new AnalyzerIngress(store);
        AnalyzerScope scope = scope("analysis-ok");
        TestAnalyzer analyzer = new TestAnalyzer(scope, ALLOWED);

        Set<AnalyzerCapability> accepted = ingress.negotiate(analyzer.offer(), ALLOWED);
        check(accepted.equals(ALLOWED), "capability negotiation accepts known set");

        String sessionId = ingress.openSession(session(scope, ALLOWED, Instant.now().plusSeconds(60)));
        List<IrChunk> chunks = analyzer.minimalChunks();
        for (IrChunk chunk : chunks) {
            ingress.stageChunk(sessionId, chunk);
        }
        AnalyzerIngress.CommitResult result = ingress.commit(sessionId, analyzer.successSubmission(chunks));
        check(result.published(), "success commit publishes evidence");
        check(!result.idempotentReplay(), "first commit is not replay");
        check(result.evidence().nodes().stream().anyMatch(n -> n instanceof ProgramNode),
                "published ProgramNode");
        check(result.evidence().nodes().stream().anyMatch(n -> n instanceof EntryNode),
                "published EntryNode");
        check(result.evidence().coverageGaps().size() == 1, "published CoverageGap");
        check(store.findByScanId(scope.scanId()).size() == 1, "evidence readable from store");
    }

    /**
     * 真实子进程：ProcessBuilder launch {@link TestAnalyzerProcessMain}；父进程 ingest
     * 经 AnalyzerIngress 的 written chunk envelope（进程外 contract 证明）。
     */
    @SuppressWarnings("unchecked")
    private static void subprocessAnalyzerPublishesMinimalIr() throws Exception {
        Path out = Files.createTempFile("veyrion-analyzer-process-", ".json");
        try {
            String javaBin = ProcessHandle.current().info().command()
                    .orElse(Path.of(System.getProperty("java.home"), "bin", "java").toString());
            String classpath = System.getProperty("java.class.path");
            check(classpath != null && !classpath.isBlank(), "java.class.path present for subprocess");
            AnalyzerScope scope = new AnalyzerScope(
                    "proj-analyzer-proc", ARTIFACT, "scan-analyzer-proc", "analysis-process");
            String submissionId = "sub-process-1";
            ProcessBuilder pb = new ProcessBuilder(
                    javaBin, "-cp", classpath,
                    TestAnalyzerProcessMain.class.getName(),
                    out.toString(),
                    scope.projectId(),
                    scope.artifactDigest(),
                    scope.scanId(),
                    scope.analysisId(),
                    POLICY,
                    submissionId);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            String stdout = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            int exit = process.waitFor();
            check(exit == 0, "subprocess TestAnalyzer exit 0, stdout=" + stdout);
            check(stdout.contains(TestAnalyzerProcessMain.MARKER),
                    "subprocess prints process marker");
            check(Files.isRegularFile(out), "subprocess wrote IR envelope");

            String envelope = Files.readString(out, StandardCharsets.UTF_8);
            check(envelope.contains(TestAnalyzerProcessMain.MARKER), "envelope carries marker");
            check(envelope.contains("\"pid\":"), "envelope records child pid");
            ObjectMapper json = new ObjectMapper();
            Map<String, Object> root = json.readValue(envelope, Map.class);
            long childPid = ((Number) root.get("pid")).longValue();
            check(childPid > 0 && childPid != ProcessHandle.current().pid(),
                    "IR produced by distinct child PID");

            AnalyzerScope parsedScope = AnalyzerScope.fromMap((Map<String, ?>) root.get("scope"));
            check(parsedScope.equals(scope), "subprocess scope matches parent session");
            List<Map<String, Object>> chunkMaps = (List<Map<String, Object>>) root.get("chunks");
            check(chunkMaps != null && chunkMaps.size() == 3, "subprocess emitted 3 IR chunks");

            List<IrChunk> chunks = new java.util.ArrayList<>();
            for (Map<String, Object> chunkMap : chunkMaps) {
                AnalyzerScope chunkScope = AnalyzerScope.fromMap((Map<String, ?>) chunkMap.get("scope"));
                long sequence = ((Number) chunkMap.get("sequence")).longValue();
                String kind = String.valueOf(chunkMap.get("kind"));
                Map<String, Object> payload = (Map<String, Object>) chunkMap.get("payload");
                chunks.add(IrChunk.create(chunkScope, sequence, kind, payload));
            }

            InMemoryAnalyzerEvidenceStore store = new InMemoryAnalyzerEvidenceStore();
            AnalyzerIngress ingress = new AnalyzerIngress(store);
            Set<AnalyzerCapability> caps = EnumSet.copyOf(ALLOWED);
            CapabilityNegotiation offer = new CapabilityNegotiation(
                    1, TestAnalyzerProcessMain.ANALYZER_ID, TestAnalyzerProcessMain.ANALYZER_VERSION,
                    List.of(TestAnalyzerProcessMain.LANGUAGE),
                    List.of("application/x-veyrion-test"),
                    caps, AnalyzerSchemaRange.v1Only(),
                    ARTIFACT, POLICY, scope, List.of("PROGRAM_IR", "ENTRY_SURFACE"));
            check(ingress.negotiate(offer, ALLOWED).equals(ALLOWED),
                    "subprocess analyzer capabilities negotiated");
            String sessionId = ingress.openSession(session(scope, ALLOWED, Instant.now().plusSeconds(60)));
            for (IrChunk chunk : chunks) {
                ingress.stageChunk(sessionId, chunk);
            }
            AnalyzerSubmission submission = new AnalyzerSubmission(
                    1, submissionId, scope, ARTIFACT, POLICY, caps,
                    IrChunkManifest.of(chunks),
                    List.of(AnalyzerDiagnostic.info("ANALYSIS_COMPLETE", "subprocess ingest")),
                    List.of(new AnalyzerCoverageGapDto(
                            "gap-process-unresolved-1", CoverageGap.KIND_UNRESOLVED_CALL,
                            "call to unknown.symbol", "STATIC_LIMIT", "ev-gap-process-1")),
                    new AnalyzerResourceUsage(chunks.size(), IrChunkManifest.of(chunks).totalPayloadBytes(),
                            20, 2),
                    AnalyzerTerminalState.SUCCESS, "COMPLETED", null);
            AnalyzerIngress.CommitResult result = ingress.commit(sessionId, submission);
            check(result.published(), "subprocess IR commit publishes");
            check(result.evidence().nodes().stream().anyMatch(n -> n instanceof ProgramNode),
                    "subprocess published ProgramNode");
            check(result.evidence().nodes().stream().anyMatch(n -> n instanceof EntryNode),
                    "subprocess published EntryNode");
            check(result.evidence().coverageGaps().size() == 1,
                    "subprocess published CoverageGap");
            check(store.findByScanId(scope.scanId()).size() == 1,
                    "subprocess evidence readable without Analyzer process");
        } finally {
            Files.deleteIfExists(out);
        }
    }

    private static void rejectWrongScope() {
        expectReject(AnalyzerRejectReason.SCOPE_MISMATCH, ingress -> {
            AnalyzerScope scope = scope("analysis-scope");
            String sessionId = ingress.openSession(session(scope, ALLOWED, Instant.now().plusSeconds(60)));
            AnalyzerScope other = new AnalyzerScope("proj-other", ARTIFACT, "scan-analyzer", "analysis-scope");
            ingress.stageChunk(sessionId, IrChunk.create(other, 0, IrChunk.KIND_PROGRAM_NODE,
                    Map.of("symbol", "x")));
        });
    }

    private static void rejectWrongArtifactDigest() {
        AnalyzerScope scope = scope("analysis-art");
        try {
            new CapabilityNegotiation(
                    1, "test-analyzer", "0.1.0", List.of("testlang"),
                    List.of("application/x-veyrion-test"), ALLOWED, AnalyzerSchemaRange.v1Only(),
                    "c".repeat(64), POLICY, scope, List.of());
            throw new AssertionError("artifact digest mismatch must fail");
        } catch (AnalyzerRejectException ex) {
            check(ex.reason() == AnalyzerRejectReason.ARTIFACT_DIGEST_MISMATCH,
                    "offer artifactDigest must match scope");
        }
        // Commit path：错误 scope identity（含 artifact）fail-closed 为 SCOPE_MISMATCH。
        expectReject(AnalyzerRejectReason.SCOPE_MISMATCH, ingress -> {
            String sessionId = ingress.openSession(session(scope, ALLOWED, Instant.now().plusSeconds(60)));
            AnalyzerScope otherArtifact = new AnalyzerScope(
                    "proj-analyzer", "c".repeat(64), "scan-analyzer", "analysis-art");
            ingress.stageChunk(sessionId, IrChunk.create(otherArtifact, 0, IrChunk.KIND_PROGRAM_NODE,
                    Map.of("symbol", "x")));
        });
    }

    private static void rejectWrongPolicyDigest() {
        expectReject(AnalyzerRejectReason.POLICY_DIGEST_MISMATCH, ingress -> {
            AnalyzerScope scope = scope("analysis-pol");
            String sessionId = ingress.openSession(session(scope, ALLOWED, Instant.now().plusSeconds(60)));
            IrChunk chunk = IrChunk.create(scope, 0, IrChunk.KIND_PROGRAM_NODE, Map.of("symbol", "p"));
            ingress.stageChunk(sessionId, chunk);
            AnalyzerSubmission submission = new AnalyzerSubmission(
                    1, "sub-pol", scope, ARTIFACT, "f".repeat(64), ALLOWED,
                    IrChunkManifest.of(List.of(chunk)), List.of(), List.of(),
                    new AnalyzerResourceUsage(1, chunk.payloadBytes(), 1, 1),
                    AnalyzerTerminalState.SUCCESS, "COMPLETED", null);
            ingress.commit(sessionId, submission);
        });
    }

    private static void rejectIncompatibleSchema() {
        expectReject(AnalyzerRejectReason.SCHEMA_INCOMPATIBLE, ingress -> {
            AnalyzerScope scope = scope("analysis-schema");
            String sessionId = ingress.openSession(session(scope, ALLOWED, Instant.now().plusSeconds(60)));
            IrChunk bad = new IrChunk(99, scope, 0, IrChunk.KIND_PROGRAM_NODE, "NONE",
                    null, 0, Map.of("symbol", "s"));
            ingress.stageChunk(sessionId, bad);
        });
    }

    private static void rejectUnknownCapability() {
        try {
            CapabilityNegotiation.parseOffered(List.of("PROGRAM_IR", "SHELL_EXEC"));
            throw new AssertionError("unknown capability must fail");
        } catch (AnalyzerRejectException ex) {
            check(ex.reason() == AnalyzerRejectReason.UNKNOWN_CAPABILITY,
                    "unknown capability rejected at parse");
        }
        expectReject(AnalyzerRejectReason.UNKNOWN_CAPABILITY, ingress -> {
            AnalyzerScope scope = scope("analysis-cap");
            Set<AnalyzerCapability> offered = EnumSet.of(AnalyzerCapability.PROGRAM_IR);
            CapabilityNegotiation negotiation = new CapabilityNegotiation(
                    1, "test-analyzer", "0.1.0", List.of("testlang"),
                    List.of("application/x-veyrion-test"), offered, AnalyzerSchemaRange.v1Only(),
                    ARTIFACT, POLICY, scope, List.of());
            // 本场景服务端不允许 PROGRAM_IR
            ingress.negotiate(negotiation, EnumSet.of(AnalyzerCapability.DIAGNOSTIC));
        });
    }

    private static void rejectMissingChunk() {
        expectReject(AnalyzerRejectReason.MISSING_CHUNK, ingress -> {
            AnalyzerScope scope = scope("analysis-miss");
            String sessionId = ingress.openSession(session(scope, ALLOWED, Instant.now().plusSeconds(60)));
            IrChunk chunk0 = IrChunk.create(scope, 0, IrChunk.KIND_PROGRAM_NODE, Map.of("symbol", "a"));
            IrChunk chunk1 = IrChunk.create(scope, 1, IrChunk.KIND_ENTRY, Map.of(
                    "id", StableNodeIds.entry("e1"), "protocol", "HTTP", "address", "/x"));
            ingress.stageChunk(sessionId, chunk0);
            // Manifest 声称两 chunk 但仅 chunk0 staged
            IrChunkManifest forged = new IrChunkManifest(
                    List.of(chunk0.toRef(), chunk1.toRef()),
                    chunk0.payloadBytes() + chunk1.payloadBytes(),
                    chunk1.payloadDigest());
            AnalyzerSubmission submission = new AnalyzerSubmission(
                    1, "sub-miss", scope, ARTIFACT, POLICY, ALLOWED, forged,
                    List.of(), List.of(),
                    new AnalyzerResourceUsage(1, chunk0.payloadBytes(), 1, 1),
                    AnalyzerTerminalState.SUCCESS, "COMPLETED", null);
            ingress.commit(sessionId, submission);
        });
    }

    private static void rejectDuplicateChunk() {
        expectReject(AnalyzerRejectReason.DUPLICATE_CHUNK, ingress -> {
            AnalyzerScope scope = scope("analysis-dup");
            String sessionId = ingress.openSession(session(scope, ALLOWED, Instant.now().plusSeconds(60)));
            IrChunk chunk = IrChunk.create(scope, 0, IrChunk.KIND_PROGRAM_NODE, Map.of("symbol", "d"));
            ingress.stageChunk(sessionId, chunk);
            IrChunk chunk1 = IrChunk.create(scope, 1, IrChunk.KIND_ENTRY, Map.of(
                    "id", StableNodeIds.entry("dup-e"), "protocol", "HTTP", "address", "/d"));
            ingress.stageChunk(sessionId, chunk1);
            // 说明：Re-stage sequence 1→DUPLICATE_CHUNK（contiguous check 前 containsKey）。
            ingress.stageChunk(sessionId, chunk1);
        });
    }

    private static void rejectOverBudget() {
        expectReject(AnalyzerRejectReason.BUDGET_EXCEEDED, ingress -> {
            AnalyzerScope scope = scope("analysis-budget");
            AnalyzerBudget tiny = new AnalyzerBudget(1, 64, 64, 1, 1000);
            String sessionId = ingress.openSession(new AnalyzerSessionSpec(
                    scope, ARTIFACT, POLICY, ALLOWED, AnalyzerSchemaRange.v1Only(),
                    tiny, Instant.now().plusSeconds(60)));
            IrChunk chunk0 = IrChunk.create(scope, 0, IrChunk.KIND_PROGRAM_NODE,
                    Map.of("symbol", "budget0"));
            ingress.stageChunk(sessionId, chunk0);
            IrChunk chunk1 = IrChunk.create(scope, 1, IrChunk.KIND_ENTRY, Map.of(
                    "id", StableNodeIds.entry("budget-e"), "protocol", "HTTP", "address", "/b"));
            ingress.stageChunk(sessionId, chunk1);
        });
    }

    private static void rejectCancelled() {
        expectReject(AnalyzerRejectReason.SESSION_CANCELLED, ingress -> {
            AnalyzerScope scope = scope("analysis-cancel");
            String sessionId = ingress.openSession(session(scope, ALLOWED, Instant.now().plusSeconds(60)));
            ingress.cancel(sessionId);
            ingress.stageChunk(sessionId, IrChunk.create(scope, 0, IrChunk.KIND_PROGRAM_NODE,
                    Map.of("symbol", "c")));
        });
    }

    private static void rejectLate() {
        Clock fixed = Clock.fixed(Instant.parse("2026-07-28T00:00:00Z"), ZoneOffset.UTC);
        InMemoryAnalyzerEvidenceStore store = new InMemoryAnalyzerEvidenceStore();
        AnalyzerIngress ingress = new AnalyzerIngress(store, fixed);
        AnalyzerScope scope = scope("analysis-late");
        String sessionId = ingress.openSession(session(scope, ALLOWED,
                Instant.parse("2026-07-27T23:59:00Z")));
        try {
            ingress.stageChunk(sessionId, IrChunk.create(scope, 0, IrChunk.KIND_PROGRAM_NODE,
                    Map.of("symbol", "late")));
            throw new AssertionError("late session must fail");
        } catch (AnalyzerRejectException ex) {
            check(ex.reason() == AnalyzerRejectReason.SESSION_LATE, "late session rejected");
        }
    }

    private static void replayIdempotent() {
        InMemoryAnalyzerEvidenceStore store = new InMemoryAnalyzerEvidenceStore();
        AnalyzerIngress ingress = new AnalyzerIngress(store);
        AnalyzerScope scope = scope("analysis-replay");
        TestAnalyzer analyzer = new TestAnalyzer(scope, ALLOWED);
        String sessionId = ingress.openSession(session(scope, ALLOWED, Instant.now().plusSeconds(60)));
        List<IrChunk> chunks = analyzer.minimalChunks();
        for (IrChunk chunk : chunks) {
            ingress.stageChunk(sessionId, chunk);
        }
        AnalyzerSubmission submission = analyzer.successSubmission(chunks);
        AnalyzerIngress.CommitResult first = ingress.commit(sessionId, submission);
        check(first.published() && !first.idempotentReplay(), "first publish ok");

        // 先前 publish 后新 session replay — 相同 submissionId
        String session2 = ingress.openSession(session(scope, ALLOWED, Instant.now().plusSeconds(60)));
        for (IrChunk chunk : chunks) {
            ingress.stageChunk(session2, chunk);
        }
        AnalyzerIngress.CommitResult second = ingress.commit(session2, submission);
        check(second.idempotentReplay(), "replay is idempotent");
        check(store.size() == 1, "replay does not double-publish");
    }

    private static void rejectCrossScopeReplay() {
        InMemoryAnalyzerEvidenceStore store = new InMemoryAnalyzerEvidenceStore();
        AnalyzerIngress ingress = new AnalyzerIngress(store);
        AnalyzerScope ownerScope = scope("analysis-replay-owner");
        TestAnalyzer owner = new TestAnalyzer(ownerScope, ALLOWED);
        String ownerSession = ingress.openSession(
                session(ownerScope, ALLOWED, Instant.now().plusSeconds(60)));
        List<IrChunk> chunks = owner.minimalChunks();
        for (IrChunk chunk : chunks) {
            ingress.stageChunk(ownerSession, chunk);
        }
        AnalyzerSubmission submission = owner.successSubmission(chunks);
        ingress.commit(ownerSession, submission);

        AnalyzerScope otherScope = new AnalyzerScope(
                "proj-analyzer-other", ARTIFACT, "scan-analyzer-other", "analysis-replay-other");
        String otherSession = ingress.openSession(
                session(otherScope, ALLOWED, Instant.now().plusSeconds(60)));
        try {
            ingress.commit(otherSession, submission);
            throw new AssertionError("cross-scope submission replay must fail");
        } catch (AnalyzerRejectException ex) {
            check(ex.reason() == AnalyzerRejectReason.SCOPE_MISMATCH,
                    "cross-scope submission replay is denied before idempotency lookup");
        }
        check(store.size() == 1, "cross-scope replay cannot publish or expose another scan");
    }

    private static void analyzerHasNoPrivilegedImports() throws Exception {
        Path root = SchemaContractAcceptanceTest.projectRoot();
        Path analyzerPkg = root.resolve("src/main/java/com/aq/jvmsentinel/domain/analyzer");
        check(Files.isDirectory(analyzerPkg), "domain.analyzer package exists");
        String[] forbidden = {
                "com.aq.jvmsentinel.control.persistence",
                "com.aq.jvmsentinel.ai.",
                "java.sql.",
                "org.sqlite",
                "com.aq.jvmsentinel.worker.LocalArtifactWorkerLoop",
                "com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor",
                "com.aq.jvmsentinel.control.ControlPlaneStore"
        };
        try (Stream<Path> stream = Files.walk(analyzerPkg)) {
            List<Path> sources = stream.filter(p -> p.toString().endsWith(".java")).toList();
            check(!sources.isEmpty(), "analyzer sources present");
            for (Path source : sources) {
                String text = Files.readString(source, StandardCharsets.UTF_8);
                for (String token : forbidden) {
                    check(!text.contains("import " + token)
                                    && !text.contains("import static " + token),
                            source.getFileName() + " must not import " + token);
                }
            }
        }
    }

    private static void runtimeAdapterRejectsOverrides() {
        String image = "e".repeat(64);
        RuntimeRunProfile profile = RuntimeRunProfile.serverFixed(
                "JVM", "17", image,
                List.of("java", "-jar", "/artifact/app.jar"),
                List.of(new RuntimeRunProfile.ReadOnlyMount(ARTIFACT, "/artifact/app.jar", true)),
                65534,
                RuntimeRunProfile.NetworkMode.DENY,
                new RuntimeRunProfile.RuntimeBudget(60, 30_000, 512_000_000, 100_000_000, 1_000_000),
                List.of("HTTP_PROBE"),
                "DYNAMIC_SUSPECTED");
        SkeletonRuntimeAdapter adapter = new SkeletonRuntimeAdapter("JVM", "17", Set.of("OBSERVE"));
        RuntimeRunProfile bound = adapter.bindProfile(profile);
        check(bound.commandTemplate().equals(List.of("java", "-jar", "/artifact/app.jar")),
                "server-fixed command retained");
        check(bound.imageDigest().equals(image), "server-fixed image retained");

        try {
            RuntimeAdapterGuard.requireServerFixed(profile,
                    new RuntimeAdapterOverrideAttempt(
                            Optional.of("rm -rf /"), Optional.empty(), Optional.empty(),
                            Optional.empty(), Optional.empty(), Optional.empty()));
            throw new AssertionError("command override must fail");
        } catch (SecurityException ex) {
            check(ex.getMessage().startsWith("RUNTIME_OVERRIDE_REJECTED"),
                    "command override rejected");
        }
        try {
            adapter.bindProfile(profile, new RuntimeAdapterOverrideAttempt(
                    Optional.empty(), Optional.of("evil".repeat(16)), Optional.empty(),
                    Optional.empty(), Optional.empty(), Optional.empty()));
            throw new AssertionError("image override must fail");
        } catch (SecurityException ex) {
            check(ex.getMessage().contains("image"), "image override rejected");
        }
        try {
            new RuntimeRunProfile(
                    1, "JVM", "17", image, List.of("java"),
                    List.of(new RuntimeRunProfile.ReadOnlyMount(ARTIFACT, "/x", true)),
                    65534, RuntimeRunProfile.NetworkMode.DENY,
                    new RuntimeRunProfile.RuntimeBudget(1, 1, 1, 1, 1),
                    List.of(), "VERIFIED");
            throw new AssertionError("VERIFIED max status must fail");
        } catch (IllegalArgumentException ex) {
            check(ex.getMessage().contains("VERIFIED"), "VERIFIED banned on run profile");
        }
    }

    private static void historicalEvidenceSurvivesWithoutAnalyzer() {
        InMemoryAnalyzerEvidenceStore store = new InMemoryAnalyzerEvidenceStore();
        AnalyzerIngress ingress = new AnalyzerIngress(store);
        AnalyzerScope scope = scope("analysis-hist");
        TestAnalyzer analyzer = new TestAnalyzer(scope, ALLOWED);
        String sessionId = ingress.openSession(session(scope, ALLOWED, Instant.now().plusSeconds(60)));
        List<IrChunk> chunks = analyzer.minimalChunks();
        for (IrChunk chunk : chunks) {
            ingress.stageChunk(sessionId, chunk);
        }
        ingress.commit(sessionId, analyzer.successSubmission(chunks));
        // 丢弃 ingress/analyzer；store 仍服务 history
        check(store.findByScanId(scope.scanId()).size() == 1,
                "removing Analyzer does not erase published evidence");
    }

    private static AnalyzerScope scope(String analysisId) {
        return new AnalyzerScope("proj-analyzer", ARTIFACT, "scan-analyzer", analysisId);
    }

    private static AnalyzerSessionSpec session(
            AnalyzerScope scope,
            Set<AnalyzerCapability> capabilities,
            Instant deadline
    ) {
        return new AnalyzerSessionSpec(
                scope, ARTIFACT, POLICY, capabilities,
                AnalyzerSchemaRange.v1Only(), AnalyzerBudget.defaults(), deadline);
    }

    @FunctionalInterface
    private interface IngressAction {
        void run(AnalyzerIngress ingress);
    }

    private static void expectReject(AnalyzerRejectReason expected, IngressAction action) {
        InMemoryAnalyzerEvidenceStore store = new InMemoryAnalyzerEvidenceStore();
        AnalyzerIngress ingress = new AnalyzerIngress(store);
        try {
            action.run(ingress);
            throw new AssertionError("expected reject " + expected);
        } catch (AnalyzerRejectException ex) {
            check(ex.reason() == expected,
                    "expected " + expected + " but was " + ex.reason() + ": " + ex.getMessage());
        }
        check(store.size() == 0, "rejected submission must not publish evidence");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}
