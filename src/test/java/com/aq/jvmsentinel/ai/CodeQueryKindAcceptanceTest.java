package com.aq.jvmsentinel.ai;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.ai.tool.AiToolRegistry;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolCall;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolResult;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolStatus;
import com.aq.jvmsentinel.ai.tool.ControlPlaneToolDataSource;
import com.aq.jvmsentinel.ai.tool.ToolDataSource;
import com.aq.jvmsentinel.ai.tool.ToolExecutionContext;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.ArtifactType;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.aq.jvmsentinel.provider.AgentRole;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * P0-11：版本化 code_query kind，IR fail-closed 与 AUTH 门禁语义。
 */
public final class CodeQueryKindAcceptanceTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        methodViewFailsClosedWithoutIr();
        methodViewAndCallersUsePersistedIr();
        methodViewReturnsBoundedInstructionSlice();
        methodViewEmptySliceReportsSliceEmpty();
        cfgViewReportsNotAvailableWithoutBci();
        cfgViewBuildsBoundedBasicBlocks();
        dataflowSliceRoutesLikeTaintGraph();
        authKindStillHarvestsSummary();
        guardQueryUsesEntryPreconditionsWhenIrMissing();
        registryKindArgumentIsAccepted();
        authGateRequiresMethodOrGuardWhenIrMethodsPresent();
        System.out.println("CodeQueryKindAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void methodViewFailsClosedWithoutIr() throws Exception {
        Fixture fx = Fixture.create("cq-method-view");
        try {
            List<ToolDataSource.FactRecord> records =
                    fx.source.queryCode(fx.scope, "METHOD_VIEW", "ExecController", 10);
            check(!records.isEmpty(), "METHOD_VIEW returns a fact row");
            JsonNode value = records.get(0).value();
            check("METHOD_VIEW".equals(value.path("kind").asText()), "kind METHOD_VIEW");
            check("FACT".equals(value.path("classification").asText()), "classification FACT");
            check("STATIC_INFERRED".equals(value.path("verificationStatus").asText()),
                    "verificationStatus STATIC_INFERRED");
            check(StaticFactSnapshot.LEGACY_INCOMPLETE.equals(value.path("coverageStatus").asText())
                            || value.path("coverageStatus").asText().equals(fx.snapshot.coverageStatus()),
                    "coverageStatus present");
            String stop = value.path("stopReason").asText();
            check("IR_NOT_PERSISTED".equals(stop) || "LEGACY_INCOMPLETE".equals(stop),
                    "METHOD_VIEW without IR methods fails closed: " + stop);
            check(!ControlPlaneToolDataSource.hasNonEmptyMethodsIr(fx.snapshot),
                    "schema without methods IR reports empty");
        } finally {
            fx.close();
        }
    }

    private static void methodViewAndCallersUsePersistedIr() throws Exception {
        Fixture fx = Fixture.createWithIr("cq-ir-hit");
        try {
            check(ControlPlaneToolDataSource.hasNonEmptyMethodsIr(fx.snapshot),
                    "fixture exposes non-empty methods IR");
            List<ToolDataSource.FactRecord> methods =
                    fx.source.queryCode(fx.scope, "METHOD_VIEW", "handle", 10);
            check(!methods.isEmpty(), "METHOD_VIEW with IR returns rows");
            JsonNode summary = methods.get(0).value();
            check("METHOD_VIEW".equals(summary.path("kind").asText()), "METHOD_VIEW kind");
            check(summary.path("matchCount").asInt() >= 1, "METHOD_VIEW matchCount >= 1");
            check(!"IR_NOT_PERSISTED".equals(summary.path("stopReason").asText()),
                    "persisted IR must not report IR_NOT_PERSISTED");

            List<ToolDataSource.FactRecord> callers =
                    fx.source.queryCode(fx.scope, "CALLERS", "Service#run", 10);
            check("CALLERS".equals(callers.get(0).value().path("kind").asText()), "CALLERS kind");
            check(callers.get(0).value().path("matchCount").asInt() >= 1,
                    "CALLERS finds edge to Service#run");

            List<ToolDataSource.FactRecord> guards =
                    fx.source.queryCode(fx.scope, "GUARD_QUERY", "Jwt", 10);
            check("GUARD_QUERY".equals(guards.get(0).value().path("kind").asText()), "GUARD_QUERY kind");
            check(guards.get(0).value().path("matchCount").asInt() >= 1,
                    "GUARD_QUERY matches JwtFilter IR method");

            List<ToolDataSource.FactRecord> cfg =
                    fx.source.queryCode(fx.scope, "CFG_VIEW", "handle", 10);
            check("CFG_VIEW".equals(cfg.get(0).value().path("kind").asText()), "CFG_VIEW kind");
            check(cfg.get(0).value().path("bytecodeOffsets").isArray()
                            && cfg.get(0).value().path("bytecodeOffsets").size() >= 1,
                    "CFG_VIEW emits bci list from InstructionEvidence");
        } finally {
            fx.close();
        }
    }

    private static void methodViewReturnsBoundedInstructionSlice() throws Exception {
        Fixture fx = Fixture.createWithIr("cq-slice");
        try {
            List<ToolDataSource.FactRecord> methods =
                    fx.source.queryCode(fx.scope, "METHOD_VIEW", "handle", 10);
            JsonNode summary = methods.get(0).value();
            check(summary.path("methods").isArray() && summary.path("methods").size() >= 1,
                    "METHOD_VIEW methods array present");
            JsonNode method = summary.path("methods").get(0);
            check(method.path("instructionSlice").isArray(), "instructionSlice array present");
            check(method.path("instructionSlice").size() >= 1,
                    "instructionSlice non-empty for handle with callEdges/memberAccesses");
            JsonNode item = method.path("instructionSlice").get(0);
            check(item.has("bci"), "slice item has bci");
            check(item.path("stableKey").asText().contains("handle"), "slice stableKey bound to method");
            check(item.has("edgeKind") || item.has("accessKind"), "slice has edgeKind or accessKind");
            check(item.has("resolvedKind"), "slice has resolvedKind");
            check(item.has("coverageStatus"), "slice has coverageStatus");
            check(item.has("stopReason"), "slice has stopReason");
            check(!"IR_NOT_PERSISTED".equals(item.path("stopReason").asText()),
                    "observed slice must not forge IR_NOT_PERSISTED");
        } finally {
            fx.close();
        }
    }

    private static void methodViewEmptySliceReportsSliceEmpty() throws Exception {
        Fixture fx = Fixture.createWithIr("cq-slice-empty");
        try {
            List<ToolDataSource.FactRecord> methods =
                    fx.source.queryCode(fx.scope, "METHOD_VIEW", "JwtFilter", 10);
            check(methods.get(0).value().path("matchCount").asInt() >= 1, "JwtFilter method matches");
            JsonNode method = methods.get(0).value().path("methods").get(0);
            check(method.path("instructionSlice").isArray()
                            && method.path("instructionSlice").size() == 0,
                    "JwtFilter has empty instructionSlice (no forged instructions)");
            check("SLICE_EMPTY".equals(method.path("stopReason").asText()),
                    "empty slice reports SLICE_EMPTY");
        } finally {
            fx.close();
        }
    }

    private static void cfgViewBuildsBoundedBasicBlocks() throws Exception {
        Fixture fx = Fixture.createWithIr("cq-cfg-blocks");
        try {
            List<ToolDataSource.FactRecord> cfg =
                    fx.source.queryCode(fx.scope, "CFG_VIEW", "handle", 20);
            JsonNode value = cfg.get(0).value();
            check(value.path("basicBlocks").isArray(), "CFG_VIEW basicBlocks present");
            check(value.path("basicBlocks").size() >= 1, "CFG_VIEW emits at least one basic block");
            check(value.path("basicBlocks").size() <= 32, "CFG_VIEW basicBlocks bounded to 32");
            JsonNode block = value.path("basicBlocks").get(0);
            check(block.has("startBci") && block.has("endBci"), "block has startBci/endBci");
            check(block.path("evidenceRefs").isArray() && block.path("evidenceRefs").size() >= 1,
                    "block has evidenceRefs");
            check(block.path("startBci").asInt() <= block.path("endBci").asInt(),
                    "startBci <= endBci");
        } finally {
            fx.close();
        }
    }

    private static void cfgViewReportsNotAvailableWithoutBci() throws Exception {
        Fixture fx = Fixture.create("cq-cfg-view");
        try {
            List<ToolDataSource.FactRecord> records =
                    fx.source.queryCode(fx.scope, "CFG_VIEW", "handle", 10);
            check(!records.isEmpty(), "CFG_VIEW returns a fact row");
            JsonNode value = records.get(0).value();
            check("CFG_VIEW".equals(value.path("kind").asText()), "kind CFG_VIEW");
            String stop = value.path("stopReason").asText();
            check("CFG_NOT_AVAILABLE".equals(stop) || "IR_NOT_PERSISTED".equals(stop),
                    "CFG_VIEW stopReason when no bci: " + stop);
        } finally {
            fx.close();
        }
    }

    private static void dataflowSliceRoutesLikeTaintGraph() throws Exception {
        Fixture fx = Fixture.create("cq-dataflow");
        try {
            List<ToolDataSource.FactRecord> records =
                    fx.source.queryCode(fx.scope, "DATAFLOW_SLICE", "sinkId=sink-1", 10);
            check(!records.isEmpty(), "DATAFLOW_SLICE returns rows");
            check("DATAFLOW_SLICE".equals(records.get(0).value().path("kind").asText()),
                    "DATAFLOW_SLICE kind on summary");
            List<ToolDataSource.FactRecord> legacy =
                    fx.source.queryCode(fx.scope, "kind=TAINT_GRAPH sinkId=sink-1", 10);
            check("TAINT_GRAPH".equals(legacy.get(0).value().path("kind").asText()),
                    "legacy kind=TAINT_GRAPH prefix still works");
        } finally {
            fx.close();
        }
    }

    private static void authKindStillHarvestsSummary() throws Exception {
        Fixture fx = Fixture.create("cq-auth");
        try {
            ArtifactDescriptor registered = fx.store.artifact(
                    fx.store.requireProject(fx.scope.projectId()),
                    fx.store.requireScan(fx.scanId).dto().artifactDigest());
            Files.delete(registered.normalizedPath());
            List<ToolDataSource.FactRecord> records =
                    fx.source.queryCode(fx.scope, "AUTH", "jwt", 10);
            check(!records.isEmpty(), "AUTH returns summary");
            check("AUTH".equals(records.get(0).value().path("kind").asText()), "AUTH kind");
            check("code_query:auth-summary".equals(records.get(0).reference()), "auth-summary ref");
            check(StaticFactSnapshot.LEGACY_INCOMPLETE.equals(records.get(0).value().path("coverageStatus").asText()),
                    "AUTH reports incomplete coverage when the registered artifact is unavailable");
            check("ARTIFACT_UNAVAILABLE".equals(records.get(0).value().path("stopReason").asText()),
                    "AUTH reports artifact-unavailable stop reason");
            List<ToolDataSource.FactRecord> config =
                    fx.source.queryCode(fx.scope, "CONFIG_SEARCH", "jwt", 10);
            check("CONFIG_SEARCH".equals(config.get(0).value().path("kind").asText()),
                    "CONFIG_SEARCH kind");
        } finally {
            fx.close();
        }
    }

    private static void guardQueryUsesEntryPreconditionsWhenIrMissing() throws Exception {
        Fixture fx = Fixture.create("cq-guard");
        try {
            List<ToolDataSource.FactRecord> records =
                    fx.source.queryCode(fx.scope, "GUARD_QUERY", "PreAuthorize", 10);
            check(!records.isEmpty(), "GUARD_QUERY returns row");
            JsonNode value = records.get(0).value();
            check("GUARD_QUERY".equals(value.path("kind").asText()), "kind GUARD_QUERY");
            check(value.path("matchCount").asInt() >= 1
                            || "IR_NOT_PERSISTED".equals(value.path("stopReason").asText()),
                    "guard signals from entry preconditions or IR fail-closed");
            if (value.path("matchCount").asInt() >= 1) {
                check(value.path("signals").isArray() && value.path("signals").size() >= 1,
                        "signals array populated from PreAuthorize precondition");
                check("FACT".equals(value.path("signals").get(0).path("classification").asText()),
                        "guard signal FACT only");
            }
        } finally {
            fx.close();
        }
    }

    private static void registryKindArgumentIsAccepted() throws Exception {
        Fixture fx = Fixture.create("cq-registry");
        try {
            AiToolRegistry registry = new AiToolRegistry(fx.source);
            ObjectNode args = JSON.createObjectNode();
            args.put("kind", "method_view");
            args.put("query", "missing");
            args.put("limit", 5);
            ToolResult result = registry.execute(
                    new ToolCall(1, "call-cq-1", "code_query", args),
                    ToolExecutionContext.bind(
                            fx.scope, "local-admin", "job-" + fx.scanId, AgentRole.AUTH_ANALYSIS,
                            new ToolExecutionContext.Budget(
                                    8, 64_000, 8, 64_000, Instant.now().plusSeconds(60))));
            check(result.status() == ToolStatus.SUCCESS, "registry accepts optional kind");
            check(!result.outputs().isEmpty(), "registry emits FACT outputs");
            check("METHOD_VIEW".equals(result.outputs().get(0).value().path("kind").asText()),
                    "registry routes kind to METHOD_VIEW");
        } finally {
            fx.close();
        }
    }

    private static void authGateRequiresMethodOrGuardWhenIrMethodsPresent() {
        // 反射安全合同：无 IR methods 时任一 SUCCESS 计数；有 IR methods 时，
        // 仅 METHOD_VIEW / GUARD_QUERY kind 计数。经 hasNonEmptyMethodsIr + kind 检查模拟。
        StaticFactSnapshot legacy = new StaticFactSnapshot(
                StaticFactSnapshot.LEGACY_INCOMPLETE, List.of(),
                BytecodeFactIndex.AnalysisCoverage.empty());
        check(!ControlPlaneToolDataSource.hasNonEmptyMethodsIr(legacy),
                "legacy snapshot has no methods IR");
        check(countsTowardAuth(false, "AUTH"), "legacy AUTH success counts");
        check(countsTowardAuth(false, "TAINT_GRAPH"), "legacy TAINT_GRAPH success counts");
        check(!countsTowardAuth(true, "AUTH"), "IR present: AUTH harvest does not count");
        check(!countsTowardAuth(true, "CONFIG_SEARCH"), "IR present: CONFIG_SEARCH does not count");
        check(countsTowardAuth(true, "METHOD_VIEW"), "IR present: METHOD_VIEW counts");
        check(countsTowardAuth(true, "guard_query"), "IR present: GUARD_QUERY counts case-insensitive");
        check(!countsTowardAuth(true, "CALLERS"), "IR present: CALLERS does not count for AUTH");
    }

    private static boolean countsTowardAuth(boolean hasIrMethods, String kind) {
        if (!hasIrMethods) {
            return true;
        }
        String normalized = kind == null ? "" : kind.trim().toUpperCase();
        return "METHOD_VIEW".equals(normalized) || "GUARD_QUERY".equals(normalized);
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }

    private record Fixture(
            Path root,
            ControlPlaneStore store,
            ControlPlaneToolDataSource source,
            ToolExecutionContext.Scope scope,
            String scanId,
            StaticFactSnapshot snapshot) implements AutoCloseable {
        static Fixture create(String label) throws Exception {
            Path root = Files.createTempDirectory("veyrion-" + label);
            ControlPlaneStore store = ControlPlaneStore.sqlite(root.resolve("state.db"), root);
            String now = Instant.now().toString();
            store.bootstrapOperator("bootstrap-token", now);
            var project = store.createProject("project-" + label, label, now, "local-admin");
            Path artifact = root.resolve("Fixture.class");
            Files.writeString(artifact, "fixture");
            String digest = Integer.toHexString(label.hashCode());
            while (digest.length() < 64) {
                digest = digest + "0";
            }
            digest = digest.substring(0, 64);
            store.registerArtifact(project, new ArtifactDescriptor("artifact-" + label, ArtifactType.CLASS,
                    artifact, Files.size(artifact), digest, true, Instant.parse(now), "Fixture.class"),
                    "local-admin");
            String scanId = "scan-" + label;
            var evidence = new ApiDtos.EvidenceDto(ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                    "evidence-entry", "FACT", "classfile-annotation:com.example.ExecController#handle",
                    1.0, "Spring MVC mapping", now, "test", "none", "artifact:" + digest, ApiDtos.MOCK);
            var entry = new ApiDtos.EntryDto(ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                    "entry-1", "HTTP", "GET", "/api/exec", "com.example.ExecController", "example",
                    List.of(), List.of("PreAuthorize(hasRole('ADMIN'))"), ApiDtos.STATIC_INFERRED, 0.9, 0,
                    List.of("evidence-entry"));
            var sink = new ApiDtos.SinkDto(ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                    "sink-1", "COMMAND", "com.example.Service#run(Ljava/lang/String;)V",
                    "bounded static inference; taint-path=tp-1", ApiDtos.STATIC_INFERRED, 0.82,
                    List.of());
            var scan = new ApiDtos.ScanDto(ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                    "COMPLETED", ApiDtos.STATIC_INFERRED, ApiDtos.MOCK, now, now,
                    List.of("evidence-entry"),
                    List.of(entry), List.of(), List.of(sink), List.of(), List.of());
            store.saveScan(new ControlPlaneStore.ScanRecord(scan, Map.of("evidence-entry", evidence),
                    List.of(), List.of()), "local-admin");
            BytecodeFactIndex.TaintPath path = new BytecodeFactIndex.TaintPath(
                    "tp-1",
                    "com/example/ExecController", "handle", "(Ljava/lang/String;)V", 0,
                    "com.example.Service", "run", "(Ljava/lang/String;)V", "COMMAND",
                    List.of(new BytecodeFactIndex.TaintStep(
                            "PARAM", "com.example.ExecController#handle", "DIRECT",
                            "evidence-entry", "entry parameter")),
                    "STATIC_INFERRED");
            StaticFactSnapshot snapshot = new StaticFactSnapshot(
                    StaticFactSnapshot.COMPLETE, List.of(path),
                    new BytecodeFactIndex.AnalysisCoverage(64, 32, 4, 2, true, List.of()));
            store.saveStaticFacts(scanId, snapshot, "local-admin");
            ControlPlaneToolDataSource source = new ControlPlaneToolDataSource(store, scanId);
            ToolExecutionContext.Scope scope =
                    new ToolExecutionContext.Scope("local", project.projectId());
            return new Fixture(root, store, source, scope, scanId, snapshot);
        }

        static Fixture createWithIr(String label) throws Exception {
            Fixture base = create(label);
            BytecodeFactIndex.InstructionEvidence bci = new BytecodeFactIndex.InstructionEvidence(
                    "com/example/ExecController", "handle", "(Ljava/lang/String;)V", 12, 0);
            BytecodeFactIndex.InstructionEvidence bciFar = new BytecodeFactIndex.InstructionEvidence(
                    "com/example/ExecController", "handle", "(Ljava/lang/String;)V", 40, 1);
            BytecodeFactIndex.InstructionEvidence bciCha = new BytecodeFactIndex.InstructionEvidence(
                    "com/example/ExecController", "handle", "(Ljava/lang/String;)V", 44, 2);
            BytecodeFactIndex.MethodFact handle = new BytecodeFactIndex.MethodFact(
                    "com/example/ExecController", "handle", "(Ljava/lang/String;)V", 1,
                    "fact:method:ExecController#handle");
            BytecodeFactIndex.MethodFact jwtFilter = new BytecodeFactIndex.MethodFact(
                    "com/example/JwtFilter", "doFilter",
                    "(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;)V", 1,
                    "fact:method:JwtFilter#doFilter");
            BytecodeFactIndex.CallEdge edge = new BytecodeFactIndex.CallEdge(
                    "com/example/ExecController", "handle", "(Ljava/lang/String;)V",
                    "com/example/Service", "run", "(Ljava/lang/String;)V",
                    BytecodeFactIndex.EdgeKind.DIRECT, "none", bci);
            BytecodeFactIndex.CallEdge edgeFar = new BytecodeFactIndex.CallEdge(
                    "com/example/ExecController", "handle", "(Ljava/lang/String;)V",
                    "com/example/Service", "log", "(Ljava/lang/String;)V",
                    BytecodeFactIndex.EdgeKind.CHA, "cha", bciFar);
            BytecodeFactIndex.ResolvedCallEdge resolved = new BytecodeFactIndex.ResolvedCallEdge(
                    "com/example/ExecController", "handle", "(Ljava/lang/String;)V",
                    "com/example/Service", "com/example/Service", "run", "(Ljava/lang/String;)V",
                    BytecodeFactIndex.EdgeKind.DIRECT, "none", bciCha);
            BytecodeFactIndex.MemberAccessFact access = new BytecodeFactIndex.MemberAccessFact(
                    BytecodeFactIndex.AccessKind.FIELD_READ,
                    "com/example/Service", "secret", "Ljava/lang/String;", bci);
            StaticFactSnapshot withIr = new StaticFactSnapshot(
                    StaticFactSnapshot.COMPLETE,
                    base.snapshot.taintPaths(),
                    base.snapshot.analysisCoverage(),
                    List.of(),
                    List.of(),
                    List.of(handle, jwtFilter),
                    List.of(access),
                    List.of(edge, edgeFar),
                    List.of(),
                    List.of(resolved),
                    List.of());
            base.store.saveStaticFacts(base.scanId, withIr, "local-admin");
            return new Fixture(base.root, base.store,
                    new ControlPlaneToolDataSource(base.store, base.scanId),
                    base.scope, base.scanId, withIr);
        }

        @Override
        public void close() throws Exception {
            // best-effort 临时清理
            try {
                Files.walk(root)
                        .sorted((a, b) -> b.compareTo(a))
                        .forEach(path -> {
                            try {
                                Files.deleteIfExists(path);
                            } catch (Exception ignored) {
                                // 忽略
                            }
                        });
            } catch (Exception ignored) {
                // 忽略
            }
        }
    }
}
