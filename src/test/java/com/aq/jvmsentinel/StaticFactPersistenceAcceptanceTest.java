package com.aq.jvmsentinel;

import com.aq.jvmsentinel.analysis.contrast.ContrastLedger;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.ArtifactType;
import com.aq.jvmsentinel.model.BytecodeFactIndex;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/** P0-10 PARTIAL: StaticFactSnapshot schema v2 IR round-trip via taint_graphs (V017). */
public final class StaticFactPersistenceAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        roundTripPersistedTaintPaths();
        roundTripFullIrFacts();
        schemaVersion1StillLoads();
        persistenceBoundsTruncate();
        missingFactsUseLegacyFallback();
        factsRowNeverMergesSinkStubs();
        emptyPersistedPathsStayAuthoritative();
        System.out.println("StaticFactPersistenceAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void roundTripPersistedTaintPaths() throws Exception {
        Path root = Files.createTempDirectory("veyrion-static-facts");
        Path database = root.resolve("state.db");
        String now = Instant.now().toString();
        String digest = "f".repeat(64);
        String scanId = "scan-static-facts";

        ControlPlaneStore first = ControlPlaneStore.sqlite(database, root);
        first.bootstrapOperator("bootstrap-token", now);
        var project = first.createProject("project-static-facts", "Static facts", now, "local-admin");
        Path artifact = root.resolve("Fixture.class");
        Files.writeString(artifact, "fixture");
        first.registerArtifact(project, new ArtifactDescriptor("artifact-static-facts", ArtifactType.CLASS,
                artifact, Files.size(artifact), digest, true, Instant.parse(now), "Fixture.class"),
                "local-admin");

        var evidenceEntry = new ApiDtos.EvidenceDto(ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                "evidence-entry", "FACT", "classfile-annotation:com.example.ExecController#handle",
                1.0, "Spring MVC mapping", now, "test", "none", "artifact:" + digest, ApiDtos.MOCK);
        var entry = new ApiDtos.EntryDto(ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                "entry-1", "HTTP", "GET", "/api/exec", "com.example.ExecController", "example",
                List.of(), List.of(), ApiDtos.STATIC_INFERRED, 0.9, 0,
                List.of("evidence-entry"));
        var sink = new ApiDtos.SinkDto(ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                "sink-1", "COMMAND", "com.example.Service#run(Ljava/lang/String;)V",
                "bounded static inference; taint-path=tp-persist-1", ApiDtos.STATIC_INFERRED, 0.82,
                List.of("evidence-flow"));
        var scan = new ApiDtos.ScanDto(ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                "COMPLETED", ApiDtos.STATIC_INFERRED, ApiDtos.MOCK, now, now,
                List.of("evidence-entry", "evidence-flow"),
                List.of(entry), List.of(), List.of(sink), List.of(), List.of());
        first.saveScan(new ControlPlaneStore.ScanRecord(scan, Map.of("evidence-entry", evidenceEntry),
                List.of(), List.of()), "local-admin");

        BytecodeFactIndex.TaintPath path = new BytecodeFactIndex.TaintPath(
                "tp-persist-1",
                "com/example/ExecController", "handle", "(Ljava/lang/String;)V", 0,
                "com.example.Service", "run", "(Ljava/lang/String;)V", "COMMAND",
                List.of(
                        new BytecodeFactIndex.TaintStep(
                                "PARAM", "com.example.ExecController#handle", "DIRECT",
                                "evidence-entry", "entry parameter"),
                        new BytecodeFactIndex.TaintStep(
                                "CALL", "com.example.Service#run", "DIRECT",
                                "evidence-flow", "cross-method call")),
                "STATIC_INFERRED");
        BytecodeFactIndex.AnalysisCoverage coverage = new BytecodeFactIndex.AnalysisCoverage(
                512, 256, 12, 8, true, List.of());
        StaticFactSnapshot snapshot = new StaticFactSnapshot(
                StaticFactSnapshot.COMPLETE, List.of(path), coverage);
        first.saveStaticFacts(scanId, snapshot, "local-admin");

        check(first.staticFacts(scanId).isPresent(), "in-memory static facts present");
        check(first.staticFacts(scanId).get().coverageStatus().equals(StaticFactSnapshot.COMPLETE),
                "coverageStatus COMPLETE");
        check(first.staticFacts(scanId).get().taintPaths().size() == 1, "one persisted path");
        check(first.staticFacts(scanId).get().taintPaths().get(0).steps().size() == 2,
                "two persisted steps");
        check(first.staticFacts(scanId).get().classes().isEmpty(), "3-arg ctor leaves IR empty");
        check(StaticFactSnapshot.SCHEMA_VERSION == 4, "write schemaVersion is 4");

        ControlPlaneStore reopened = ControlPlaneStore.sqlite(database, root);
        check(reopened.staticFacts(scanId).isPresent(), "static facts survive restart");
        StaticFactSnapshot restored = reopened.staticFacts(scanId).orElseThrow();
        check(restored.coverageStatus().equals(StaticFactSnapshot.COMPLETE), "restored coverageStatus");
        check(restored.analysisCoverage().complete(), "restored analysisCoverage.complete");
        check(restored.analysisCoverage().taintStatesVisited() == 8, "restored taintStatesVisited");
        BytecodeFactIndex.TaintPath restoredPath = restored.taintPaths().get(0);
        check("tp-persist-1".equals(restoredPath.id()), "restored path id");
        check(restoredPath.steps().size() == 2, "restored step count");
        check("CALL".equals(restoredPath.steps().get(1).kind()), "restored second step kind");

        ApiDtos.EntryDto bound = StaticFactSnapshot.findEntryForTaintSource(
                scan.entries(), Map.of("evidence-entry", evidenceEntry), restoredPath);
        check(bound != null && "entry-1".equals(bound.id()), "taint source binds entry across slash/dot");
    }

    private static void roundTripFullIrFacts() throws Exception {
        Path root = Files.createTempDirectory("veyrion-static-facts-ir");
        Path database = root.resolve("state.db");
        String now = Instant.now().toString();
        String digest = "b".repeat(64);
        String scanId = "scan-full-ir";

        ControlPlaneStore store = ControlPlaneStore.sqlite(database, root);
        store.bootstrapOperator("bootstrap-token", now);
        var project = store.createProject("project-full-ir", "Full IR", now, "local-admin");
        Path artifact = root.resolve("FullIr.class");
        Files.writeString(artifact, "fixture");
        store.registerArtifact(project, new ArtifactDescriptor("artifact-full-ir", ArtifactType.CLASS,
                artifact, Files.size(artifact), digest, true, Instant.parse(now), "FullIr.class"),
                "local-admin");
        var scan = new ApiDtos.ScanDto(ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                "COMPLETED", ApiDtos.STATIC_INFERRED, ApiDtos.MOCK, now, now, List.of(),
                List.of(), List.of(), List.of(), List.of(), List.of());
        store.saveScan(new ControlPlaneStore.ScanRecord(scan, Map.of(), List.of(), List.of()), "local-admin");

        BytecodeFactIndex.InstructionEvidence evidence = new BytecodeFactIndex.InstructionEvidence(
                "com/example/Service", "run", "(Ljava/lang/String;)V", 4, 0);
        BytecodeFactIndex index = new BytecodeFactIndex(
                List.of(new BytecodeFactIndex.ClassFact(
                        "com/example/Service", "java/lang/Object", List.of(), 1, "class-ev")),
                List.of(new BytecodeFactIndex.FieldFact(
                        "com/example/Service", "cmd", "Ljava/lang/String;", 2, "field-ev")),
                List.of(new BytecodeFactIndex.MethodFact(
                        "com/example/Service", "run", "(Ljava/lang/String;)V", 1, "method-ev")),
                List.of(new BytecodeFactIndex.MemberAccessFact(
                        BytecodeFactIndex.AccessKind.FIELD_READ,
                        "com/example/Service", "cmd", "Ljava/lang/String;", evidence)),
                List.of(new BytecodeFactIndex.CallEdge(
                        "com/example/ExecController", "handle", "(Ljava/lang/String;)V",
                        "com/example/Service", "run", "(Ljava/lang/String;)V",
                        BytecodeFactIndex.EdgeKind.DIRECT, "none", evidence)),
                List.of(new BytecodeFactIndex.UnresolvedDynamicFact(
                        "INVOKE_DYNAMIC", "bootstrap unresolved", evidence)),
                List.of(new BytecodeFactIndex.ResolvedCallEdge(
                        "com/example/ExecController", "handle", "(Ljava/lang/String;)V",
                        "com/example/Service", "com/example/Service", "run", "(Ljava/lang/String;)V",
                        BytecodeFactIndex.EdgeKind.DIRECT, "none", evidence)),
                List.of(new BytecodeFactIndex.TaintPath(
                        "tp-ir-1",
                        "com/example/ExecController", "handle", "(Ljava/lang/String;)V", 0,
                        "com/example/Service", "run", "(Ljava/lang/String;)V", "COMMAND",
                        List.of(new BytecodeFactIndex.TaintStep(
                                "CALL", "com.example.Service#run", "DIRECT", "ev-1", "call")),
                        "STATIC_INFERRED")),
                new BytecodeFactIndex.AnalysisCoverage(100, 50, 1, 1, true, List.of()));

        StaticFactSnapshot snapshot = StaticFactSnapshot.fromBytecodeIndex(index);
        check(StaticFactSnapshot.COMPLETE.equals(snapshot.coverageStatus()), "full IR COMPLETE");
        check(snapshot.truncateReasons().isEmpty(), "no truncateReasons under caps");
        check(snapshot.methods().size() == 1, "methods copied");
        check(snapshot.callEdges().size() == 1, "callEdges copied");
        check(snapshot.unresolvedDynamics().size() == 1, "unresolvedDynamics copied");
        check(snapshot.artifactCallGraph().size() == 1, "artifactCallGraph copied");

        BytecodeFactIndex rebuilt = snapshot.toBytecodeIndex();
        check(rebuilt.methods().size() == 1, "toBytecodeIndex methods");
        check(rebuilt.callEdges().get(0).kind() == BytecodeFactIndex.EdgeKind.DIRECT,
                "toBytecodeIndex callEdges kind");
        check(rebuilt.unresolvedDynamics().get(0).mechanism().equals("INVOKE_DYNAMIC"),
                "toBytecodeIndex unresolved");
        check(rebuilt.artifactCallGraph().get(0).targetName().equals("run"),
                "toBytecodeIndex artifactCallGraph");

        store.saveStaticFacts(scanId, snapshot, "local-admin");
        ControlPlaneStore reopened = ControlPlaneStore.sqlite(database, root);
        StaticFactSnapshot restored = reopened.staticFacts(scanId).orElseThrow();
        check(restored.classes().size() == 1, "restored classes");
        check("com/example/Service".equals(restored.classes().get(0).className()), "restored className");
        check(restored.fields().size() == 1, "restored fields");
        check(restored.methods().size() == 1, "restored methods");
        check(restored.memberAccesses().size() == 1, "restored memberAccesses");
        check(restored.callEdges().size() == 1, "restored callEdges");
        check(BytecodeFactIndex.EdgeKind.DIRECT.equals(restored.callEdges().get(0).kind()),
                "restored callEdges kind");
        check(restored.unresolvedDynamics().size() == 1, "restored unresolvedDynamics");
        check("INVOKE_DYNAMIC".equals(restored.unresolvedDynamics().get(0).mechanism()),
                "restored unresolved mechanism");
        check(restored.artifactCallGraph().size() == 1, "restored artifactCallGraph");
        check("run".equals(restored.artifactCallGraph().get(0).targetName()),
                "restored artifactCallGraph target");
        check(restored.taintPaths().size() == 1, "restored IR taintPaths");
        check(restored.truncateReasons().isEmpty(), "restored empty truncateReasons");

        String json = restored.toJson();
        check(json.contains("\"schemaVersion\":4"), "toJson writes schemaVersion 4");
        StaticFactSnapshot fromJson = StaticFactSnapshot.fromJson(json);
        check(fromJson.methods().size() == 1, "fromJson methods");
        check(fromJson.callEdges().size() == 1, "fromJson callEdges");
        check(fromJson.unresolvedDynamics().size() == 1, "fromJson unresolvedDynamics");
        check(fromJson.artifactCallGraph().size() == 1, "fromJson artifactCallGraph");
    }

    private static void schemaVersion1StillLoads() {
        String v1 = """
                {
                  "schemaVersion": 1,
                  "coverageStatus": "COMPLETE",
                  "taintPaths": [],
                  "analysisCoverage": {
                    "callGraphEdgeBudget": 1,
                    "taintStateBudget": 1,
                    "callGraphEdgesProduced": 0,
                    "taintStatesVisited": 0,
                    "complete": true,
                    "stopReasons": []
                  }
                }
                """;
        StaticFactSnapshot loaded = StaticFactSnapshot.fromJson(v1);
        check(StaticFactSnapshot.COMPLETE.equals(loaded.coverageStatus()), "v1 coverageStatus");
        check(loaded.classes().isEmpty(), "v1 classes empty");
        check(loaded.methods().isEmpty(), "v1 methods empty");
        check(loaded.callEdges().isEmpty(), "v1 callEdges empty");
        check(loaded.unresolvedDynamics().isEmpty(), "v1 unresolved empty");
        check(loaded.artifactCallGraph().isEmpty(), "v1 artifactCallGraph empty");
        check(loaded.truncateReasons().isEmpty(), "v1 truncateReasons empty");
        check(loaded.toBytecodeIndex().methods().isEmpty(), "v1 toBytecodeIndex empty methods");
    }

    private static void persistenceBoundsTruncate() {
        List<BytecodeFactIndex.ClassFact> classes = new ArrayList<>();
        for (int i = 0; i < StaticFactSnapshot.MAX_CLASSES + 3; i++) {
            classes.add(new BytecodeFactIndex.ClassFact(
                    "com/example/C" + i, "java/lang/Object", List.of(), 1, "ev-" + i));
        }
        BytecodeFactIndex index = new BytecodeFactIndex(
                classes, List.of(), List.of(), List.of(), List.of(), List.of(),
                List.of(), List.of(),
                new BytecodeFactIndex.AnalysisCoverage(10, 10, 0, 0, true, List.of()));
        StaticFactSnapshot snapshot = StaticFactSnapshot.fromBytecodeIndex(index);
        check(StaticFactSnapshot.TRUNCATED.equals(snapshot.coverageStatus()),
                "over-cap classes -> TRUNCATED");
        check(snapshot.classes().size() == StaticFactSnapshot.MAX_CLASSES, "classes capped");
        check(!snapshot.truncateReasons().isEmpty(), "truncateReasons present");
        check(snapshot.truncateReasons().stream().anyMatch(r -> r.contains("classes")),
                "truncateReasons mention classes");
    }

    private static void missingFactsUseLegacyFallback() throws Exception {
        Path root = Files.createTempDirectory("veyrion-static-facts-legacy");
        ControlPlaneStore store = ControlPlaneStore.sqlite(root.resolve("legacy.db"), root);
        String now = Instant.now().toString();
        store.bootstrapOperator("bootstrap-token", now);
        var project = store.createProject("project-legacy", "Legacy", now, "local-admin");
        Path artifact = root.resolve("Legacy.class");
        Files.writeString(artifact, "fixture");
        String digest = "a".repeat(64);
        store.registerArtifact(project, new ArtifactDescriptor("artifact-legacy", ArtifactType.CLASS,
                artifact, Files.size(artifact), digest, true, Instant.parse(now), "Legacy.class"),
                "local-admin");
        var sink = new ApiDtos.SinkDto(ApiDtos.SCHEMA_VERSION, project.projectId(), digest, "scan-legacy",
                "sink-legacy", "SQL", "com.example.Dao#query()V",
                "taint-path=tp-legacy-stub", ApiDtos.STATIC_INFERRED, 0.7, List.of());
        var sinkNoToken = new ApiDtos.SinkDto(ApiDtos.SCHEMA_VERSION, project.projectId(), digest, "scan-legacy",
                "sink-no-token", "SQL", "com.example.Dao#other()V",
                "bounded static inference", ApiDtos.STATIC_INFERRED, 0.6, List.of());
        var scan = new ApiDtos.ScanDto(ApiDtos.SCHEMA_VERSION, project.projectId(), digest, "scan-legacy",
                "COMPLETED", ApiDtos.STATIC_INFERRED, ApiDtos.MOCK, now, now, List.of(),
                List.of(), List.of(), List.of(sink, sinkNoToken), List.of(), List.of());
        store.saveScan(new ControlPlaneStore.ScanRecord(scan, Map.of(), List.of(), List.of()), "local-admin");

        check(store.staticFacts("scan-legacy").isEmpty(), "missing static facts -> Optional.empty");
        check(StaticFactSnapshot.LEGACY_INCOMPLETE.equals(
                        StaticFactSnapshot.resolveContrastCoverageStatus(store.staticFacts("scan-legacy"))),
                "no facts row -> contrast coverage LEGACY_INCOMPLETE");
        List<BytecodeFactIndex.TaintPath> resolved = StaticFactSnapshot.resolveContrastTaintPaths(
                store.staticFacts("scan-legacy"), scan.sinks());
        check(!resolved.isEmpty(), "legacy scan falls back to sink stubs");
        check(resolved.stream().allMatch(path -> path.steps().isEmpty()),
                "legacy stub paths have empty steps");
        check(resolved.stream().anyMatch(path -> "tp-legacy-stub".equals(path.id())),
                "legacy stub preserves taint-path id");
        check(resolved.stream().anyMatch(path -> path.id().startsWith("tp-sink-")),
                "no-token sink still yields tp-sink-* stub when facts absent");
        check(!ContrastLedger.taintPathsFromSinks(scan.sinks()).isEmpty(),
                "ContrastLedger stub path still available for legacy scans");
    }

    /** Facts row present: contrast must not invent tp-sink-* stubs for uncovered sinks. */
    private static void factsRowNeverMergesSinkStubs() throws Exception {
        Path root = Files.createTempDirectory("veyrion-static-facts-no-stub");
        ControlPlaneStore store = ControlPlaneStore.sqlite(root.resolve("no-stub.db"), root);
        String now = Instant.now().toString();
        store.bootstrapOperator("bootstrap-token", now);
        var project = store.createProject("project-no-stub", "No stub", now, "local-admin");
        Path artifact = root.resolve("NoStub.class");
        Files.writeString(artifact, "fixture");
        String digest = "c".repeat(64);
        String scanId = "scan-no-stub-merge";
        store.registerArtifact(project, new ArtifactDescriptor("artifact-no-stub", ArtifactType.CLASS,
                artifact, Files.size(artifact), digest, true, Instant.parse(now), "NoStub.class"),
                "local-admin");
        var covered = new ApiDtos.SinkDto(ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                "sink-covered", "SQL", "com.example.Dao#query()V",
                "taint-path=tp-authoritative", ApiDtos.STATIC_INFERRED, 0.8, List.of());
        var uncovered = new ApiDtos.SinkDto(ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                "sink-uncovered", "COMMAND", "com.example.Service#run(Ljava/lang/String;)V",
                "no taint token", ApiDtos.STATIC_INFERRED, 0.7, List.of());
        var scan = new ApiDtos.ScanDto(ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                "COMPLETED", ApiDtos.STATIC_INFERRED, ApiDtos.MOCK, now, now, List.of(),
                List.of(), List.of(), List.of(covered, uncovered), List.of(), List.of());
        store.saveScan(new ControlPlaneStore.ScanRecord(scan, Map.of(), List.of(), List.of()), "local-admin");

        BytecodeFactIndex.TaintPath emptyStepPath = new BytecodeFactIndex.TaintPath(
                "tp-authoritative",
                "com/example/Controller", "handle", "(Ljava/lang/String;)V", 0,
                "com.example.Dao", "query", "()V", "SQL",
                List.of(), "STATIC_INFERRED");
        store.saveStaticFacts(scanId, new StaticFactSnapshot(
                StaticFactSnapshot.COMPLETE, List.of(emptyStepPath),
                new BytecodeFactIndex.AnalysisCoverage(1, 1, 0, 0, true, List.of())), "local-admin");

        check(store.staticFacts(scanId).isPresent(), "facts row present");
        check(StaticFactSnapshot.COMPLETE.equals(
                        StaticFactSnapshot.resolveContrastCoverageStatus(store.staticFacts(scanId))),
                "facts row -> contrast coverage from snapshot");
        List<BytecodeFactIndex.TaintPath> contrast = StaticFactSnapshot.resolveContrastTaintPaths(
                store.staticFacts(scanId), scan.sinks());
        check(contrast.size() == 1, "only persisted path returned when facts exist");
        check("tp-authoritative".equals(contrast.get(0).id()), "persisted id authoritative");
        check(contrast.get(0).steps().isEmpty(),
                "empty steps under COMPLETE still authoritative (no stub fill)");
        check(contrast.stream().noneMatch(path -> path.id().startsWith("tp-sink-")),
                "facts row present -> contrast paths must not include tp-sink-* stubs");
        check(ContrastLedger.taintPathsFromSinks(scan.sinks()).stream()
                        .anyMatch(path -> path.id().startsWith("tp-sink-")),
                "raw stub helper still produces tp-sink-* (LEGACY only)");
    }

    /** Empty persisted taintPaths with facts row must not fall back to sink stubs. */
    private static void emptyPersistedPathsStayAuthoritative() throws Exception {
        Path root = Files.createTempDirectory("veyrion-static-facts-empty-paths");
        ControlPlaneStore store = ControlPlaneStore.sqlite(root.resolve("empty-paths.db"), root);
        String now = Instant.now().toString();
        store.bootstrapOperator("bootstrap-token", now);
        var project = store.createProject("project-empty-paths", "Empty paths", now, "local-admin");
        Path artifact = root.resolve("EmptyPaths.class");
        Files.writeString(artifact, "fixture");
        String digest = "d".repeat(64);
        String scanId = "scan-empty-persisted-paths";
        store.registerArtifact(project, new ArtifactDescriptor("artifact-empty-paths", ArtifactType.CLASS,
                artifact, Files.size(artifact), digest, true, Instant.parse(now), "EmptyPaths.class"),
                "local-admin");
        var sink = new ApiDtos.SinkDto(ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                "sink-alone", "SQL", "com.example.Dao#query()V",
                "no path token", ApiDtos.STATIC_INFERRED, 0.7, List.of());
        var scan = new ApiDtos.ScanDto(ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                "COMPLETED", ApiDtos.STATIC_INFERRED, ApiDtos.MOCK, now, now, List.of(),
                List.of(), List.of(), List.of(sink), List.of(), List.of());
        store.saveScan(new ControlPlaneStore.ScanRecord(scan, Map.of(), List.of(), List.of()), "local-admin");
        store.saveStaticFacts(scanId, new StaticFactSnapshot(
                StaticFactSnapshot.TRUNCATED, List.of(),
                new BytecodeFactIndex.AnalysisCoverage(0, 0, 0, 0, false, List.of("taintPaths empty"))),
                "local-admin");

        List<BytecodeFactIndex.TaintPath> contrast = StaticFactSnapshot.resolveContrastTaintPaths(
                store.staticFacts(scanId), scan.sinks());
        check(contrast.isEmpty(),
                "facts row with empty taintPaths -> empty contrast paths (not stub)");
        check(contrast.stream().noneMatch(path -> path.id().startsWith("tp-sink-")),
                "TRUNCATED empty paths must not invent tp-sink-* stubs");
        check(StaticFactSnapshot.TRUNCATED.equals(
                        StaticFactSnapshot.resolveContrastCoverageStatus(store.staticFacts(scanId))),
                "empty persisted paths keep TRUNCATED coverage");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}
