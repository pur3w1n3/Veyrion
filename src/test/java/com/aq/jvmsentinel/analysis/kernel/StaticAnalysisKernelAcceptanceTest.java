package com.aq.jvmsentinel.analysis.kernel;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.ai.tool.ControlPlaneToolDataSource;
import com.aq.jvmsentinel.ai.tool.ToolDataSource;
import com.aq.jvmsentinel.ai.tool.ToolExecutionContext;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.ArtifactType;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * P1-04 gate：可序列化 CFG、MethodSummary bottom-up、field/return/sanitizer hook，
 * 与优先 CfgBuilder 的 CFG_VIEW。
 */
public final class StaticAnalysisKernelAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();
    private static final ObjectMapper JSON = new ObjectMapper();

    public static void main(String[] args) throws Exception {
        ASSERTIONS.set(0);
        AcceptanceAssertions.reset();
        cfgBuilderProducesSerializableGraph();
        cfgBuilderNegativeAndBudgetStopReasons();
        methodSummaryBottomUpPropagatesCustomEffect();
        methodSummaryNegativeAndPropagationBudget();
        methodSummaryAndSanitizerHeuristicNonEmpty();
        fieldReturnTaintEnhancerMarksSanitizerAndField();
        fieldReturnNegativeAndStepBudget();
        declareLightweightKernelScope();
        cfgViewPrefersKernelProducer();
        methodViewEmitsBoundedPseudoDecompile();
        System.out.println("StaticAnalysisKernelAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void cfgBuilderProducesSerializableGraph() throws Exception {
        BytecodeFactIndex.MethodFact method = new BytecodeFactIndex.MethodFact(
                "app/Handler", "handle", "(Ljava/lang/String;)V", 1, "fact:method:handle");
        BytecodeFactIndex.InstructionEvidence a =
                new BytecodeFactIndex.InstructionEvidence("app/Handler", "handle", "(Ljava/lang/String;)V", 4, 0);
        BytecodeFactIndex.InstructionEvidence b =
                new BytecodeFactIndex.InstructionEvidence("app/Handler", "handle", "(Ljava/lang/String;)V", 20, 1);
        BytecodeFactIndex.CallEdge edge = new BytecodeFactIndex.CallEdge(
                "app/Handler", "handle", "(Ljava/lang/String;)V",
                "java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;",
                BytecodeFactIndex.EdgeKind.DIRECT, "none", a);
        BytecodeFactIndex.MemberAccessFact access = new BytecodeFactIndex.MemberAccessFact(
                BytecodeFactIndex.AccessKind.FIELD_WRITE,
                "app/Handler", "last", "Ljava/lang/String;", b);
        CfgGraph cfg = CfgBuilder.build(method, List.of(edge), List.of(access), List.of());
        check(!cfg.blocks().isEmpty(), "CfgBuilder emits at least one block");
        check(cfg.blocks().size() <= CfgGraph.MAX_BLOCKS, "CfgBuilder respects block budget");
        check(cfg.blocks().get(0).startBci() <= cfg.blocks().get(0).endBci(), "block bci range ordered");
        JsonNode json = cfg.toJson(JSON);
        check("cfg-v1".equals(json.path("schemaVersion").asText()), "CFG JSON schemaVersion");
        check(json.path("blocks").isArray() && json.path("blocks").size() >= 1, "CFG JSON blocks");
        check(json.path("edges").isArray(), "CFG JSON edges array");
        check("analysis.kernel.CfgBuilder".equals(json.path("producer").asText()), "CFG producer");
        String serialized = JSON.writeValueAsString(json);
        check(serialized.contains("startBci") && serialized.contains("evidenceRefs"),
                "CFG JSON remains round-trippable text");
        check(cfg.stopReasons().isEmpty() || "COMPLETE".equals(cfg.coverageStatus())
                        || "PARTIAL".equals(cfg.coverageStatus()),
                "CFG exposes coverageStatus with optional stopReasons");
    }

    private static void cfgBuilderNegativeAndBudgetStopReasons() {
        BytecodeFactIndex.MethodFact emptyMethod = new BytecodeFactIndex.MethodFact(
                "app/Empty", "noop", "()V", 1, "fact:empty");
        CfgGraph empty = CfgBuilder.build(emptyMethod, List.of(), List.of(), List.of());
        check(empty.blocks().isEmpty(), "negative: no IR sites → empty CFG blocks");
        check(empty.stopReasons().contains("CFG_NOT_AVAILABLE"),
                "negative: CFG_NOT_AVAILABLE stopReason");
        check("PARTIAL".equals(empty.coverageStatus()), "negative: empty CFG is PARTIAL");

        BytecodeFactIndex.MethodFact budgetMethod = new BytecodeFactIndex.MethodFact(
                "app/Wide", "wide", "()V", 1, "fact:wide");
        List<BytecodeFactIndex.CallEdge> spaced = new java.util.ArrayList<>();
        for (int i = 0; i < CfgGraph.MAX_BLOCKS + 4; i++) {
            int bci = i * (CfgBuilder.GAP_THRESHOLD + 2);
            BytecodeFactIndex.InstructionEvidence site =
                    new BytecodeFactIndex.InstructionEvidence("app/Wide", "wide", "()V", bci, i);
            spaced.add(new BytecodeFactIndex.CallEdge(
                    "app/Wide", "wide", "()V",
                    "java/lang/Object", "hashCode", "()I",
                    BytecodeFactIndex.EdgeKind.DIRECT, "none", site));
        }
        CfgGraph budgeted = CfgBuilder.build(budgetMethod, spaced, List.of(), List.of());
        check(budgeted.blocks().size() <= CfgGraph.MAX_BLOCKS, "budget: blocks capped at MAX_BLOCKS");
        check(budgeted.stopReasons().contains("CFG_BLOCK_BUDGET"),
                "budget: CFG_BLOCK_BUDGET stopReason when sites exceed block capacity");
        check("PARTIAL".equals(budgeted.coverageStatus()), "budget: truncated CFG is PARTIAL");
    }

    private static void methodSummaryBottomUpPropagatesCustomEffect() {
        BytecodeFactIndex.MethodFact wrapper = new BytecodeFactIndex.MethodFact(
                "app/Wrapper", "finish", "(Ljava/lang/String;)V", 1, "fact:wrapper");
        BytecodeFactIndex.MethodFact controller = new BytecodeFactIndex.MethodFact(
                "app/Controller", "danger", "(Ljava/lang/String;)V", 1, "fact:controller");
        BytecodeFactIndex.InstructionEvidence wrapBci =
                new BytecodeFactIndex.InstructionEvidence("app/Wrapper", "finish", "(Ljava/lang/String;)V", 8, 0);
        BytecodeFactIndex.InstructionEvidence ctrlBci =
                new BytecodeFactIndex.InstructionEvidence("app/Controller", "danger", "(Ljava/lang/String;)V", 10, 0);
        BytecodeFactIndex.CallEdge primitive = new BytecodeFactIndex.CallEdge(
                "app/Wrapper", "finish", "(Ljava/lang/String;)V",
                "java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;",
                BytecodeFactIndex.EdgeKind.DIRECT, "none", wrapBci);
        BytecodeFactIndex.CallEdge wrapperCall = new BytecodeFactIndex.CallEdge(
                "app/Controller", "danger", "(Ljava/lang/String;)V",
                "app/Wrapper", "finish", "(Ljava/lang/String;)V",
                BytecodeFactIndex.EdgeKind.DIRECT, "none", ctrlBci);
        BytecodeFactIndex.MemberAccessFact fieldWrite = new BytecodeFactIndex.MemberAccessFact(
                BytecodeFactIndex.AccessKind.FIELD_WRITE,
                "app/Wrapper", "buf", "Ljava/lang/String;", wrapBci);
        Map<String, MethodSummary> summaries = MethodSummaryBuilder.build(
                List.of(wrapper, controller),
                List.of(primitive, wrapperCall),
                List.of(fieldWrite),
                List.of());
        MethodSummary wrapSummary = summaries.get(CfgBuilder.methodIdentity(
                "app/Wrapper", "finish", "(Ljava/lang/String;)V"));
        MethodSummary ctrlSummary = summaries.get(CfgBuilder.methodIdentity(
                "app/Controller", "danger", "(Ljava/lang/String;)V"));
        check(wrapSummary != null && wrapSummary.effects().contains("EFFECT:COMMAND"),
                "wrapper summary seeds primitive COMMAND effect");
        check(ctrlSummary != null && ctrlSummary.effects().stream().anyMatch(e -> e.startsWith("CUSTOM:")),
                "caller of effectful wrapper gains CUSTOM effect");
        check(wrapSummary.fieldWrites().stream().anyMatch(f -> f.contains("#buf")),
                "summary records field write");
        check(!MethodSummaryBuilder.wrappersWithCustomEffects(summaries).isEmpty(),
                "bottom-up reports wrappers with custom effects");
    }

    private static void methodSummaryNegativeAndPropagationBudget() {
        BytecodeFactIndex.MethodFact benign = new BytecodeFactIndex.MethodFact(
                "app/Safe", "ok", "()V", 1, "fact:safe");
        Map<String, MethodSummary> negative = MethodSummaryBuilder.build(
                List.of(benign), List.of(), List.of(), List.of());
        MethodSummary safe = negative.get(CfgBuilder.methodIdentity("app/Safe", "ok", "()V"));
        check(safe != null && safe.effects().isEmpty(),
                "negative: method without primitive/wrapper effects has empty effects");
        check(safe.stopReasons().isEmpty() && safe.complete(),
                "negative: complete summary without budget stopReasons");

        List<BytecodeFactIndex.MethodFact> chainMethods = new java.util.ArrayList<>();
        List<BytecodeFactIndex.CallEdge> chainEdges = new java.util.ArrayList<>();
        // Chain 长于 MAX round 使末轮仍变化 → budget stop reason。
        int depth = MethodSummaryBuilder.MAX_PROPAGATION_ROUNDS * 3;
        for (int i = 0; i <= depth; i++) {
            String owner = "app/L" + i;
            chainMethods.add(new BytecodeFactIndex.MethodFact(
                    owner, "run", "(Ljava/lang/String;)V", 1, "fact:L" + i));
        }
        for (int i = 0; i < depth; i++) {
            BytecodeFactIndex.InstructionEvidence bci =
                    new BytecodeFactIndex.InstructionEvidence(
                            "app/L" + i, "run", "(Ljava/lang/String;)V", 4, 0);
            chainEdges.add(new BytecodeFactIndex.CallEdge(
                    "app/L" + i, "run", "(Ljava/lang/String;)V",
                    "app/L" + (i + 1), "run", "(Ljava/lang/String;)V",
                    BytecodeFactIndex.EdgeKind.DIRECT, "none", bci));
        }
        BytecodeFactIndex.InstructionEvidence leaf =
                new BytecodeFactIndex.InstructionEvidence(
                        "app/L" + depth, "run", "(Ljava/lang/String;)V", 8, 0);
        chainEdges.add(new BytecodeFactIndex.CallEdge(
                "app/L" + depth, "run", "(Ljava/lang/String;)V",
                "java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;",
                BytecodeFactIndex.EdgeKind.DIRECT, "none", leaf));
        Map<String, MethodSummary> deep = MethodSummaryBuilder.build(
                chainMethods, chainEdges, List.of(), List.of());
        boolean budgetSeen = deep.values().stream()
                .anyMatch(summary -> summary.stopReasons().contains("SUMMARY_PROPAGATION_BUDGET"));
        check(budgetSeen, "budget: deep wrapper chain emits SUMMARY_PROPAGATION_BUDGET");
        MethodSummary leafSummary = deep.get(CfgBuilder.methodIdentity(
                "app/L" + depth, "run", "(Ljava/lang/String;)V"));
        check(leafSummary != null && leafSummary.effects().contains("EFFECT:COMMAND"),
                "budget fixture still seeds leaf COMMAND effect");
    }

    private static void fieldReturnTaintEnhancerMarksSanitizerAndField() {
        BytecodeFactIndex.InstructionEvidence bci =
                new BytecodeFactIndex.InstructionEvidence(
                        "app/Controller", "handle", "(Ljava/lang/String;)Ljava/lang/String;", 6, 0);
        BytecodeFactIndex.TaintPath path = new BytecodeFactIndex.TaintPath(
                "tp-kernel-1",
                "app/Controller", "handle", "(Ljava/lang/String;)Ljava/lang/String;", 0,
                "java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;",
                "COMMAND",
                List.of(new BytecodeFactIndex.TaintStep(
                        "SOURCE", "app/Controller#handle", "SOURCE",
                        "evidence-source", "entry parameter")),
                "STATIC_INFERRED");
        BytecodeFactIndex.MemberAccessFact write = new BytecodeFactIndex.MemberAccessFact(
                BytecodeFactIndex.AccessKind.FIELD_WRITE,
                "app/Controller", "cached", "Ljava/lang/String;", bci);
        BytecodeFactIndex.CallEdge sanitize = new BytecodeFactIndex.CallEdge(
                "app/Controller", "handle", "(Ljava/lang/String;)Ljava/lang/String;",
                "org/springframework/web/util/HtmlUtils", "htmlEscape",
                "(Ljava/lang/String;)Ljava/lang/String;",
                BytecodeFactIndex.EdgeKind.DIRECT, "none", bci);
        FieldReturnTaintEnhancer.Enhancement enhancement = FieldReturnTaintEnhancer.enhance(
                List.of(path), List.of(write), List.of(sanitize));
        check(!enhancement.enhancedPaths().isEmpty(), "enhancer keeps path");
        BytecodeFactIndex.TaintPath enhanced = enhancement.enhancedPaths().get(0);
        check(enhanced.steps().stream().anyMatch(step -> "FIELD_STORE".equals(step.kind())),
                "enhancer adds FIELD_STORE step");
        check(enhanced.steps().stream().anyMatch(step -> "SANITIZER".equals(step.kind())),
                "enhancer adds SANITIZER marker");
        check(enhanced.steps().stream().anyMatch(step -> "RETURN_PROP".equals(step.kind())),
                "enhancer adds RETURN_PROP for value-returning sanitizer call");
        check(!enhancement.sanitizerHits().isEmpty(), "sanitizerHits recorded");
        check(!enhancement.fieldFlows().isEmpty(), "fieldFlows recorded");
        check("STATIC_INFERRED".equals(enhanced.status()), "enhancer does not upgrade verification status");
        check(enhancement.stopReasons().isEmpty()
                        || enhancement.stopReasons().stream().allMatch(r -> r.contains("BUDGET")),
                "enhancer stopReasons only report budget when hit");
    }

    private static void fieldReturnNegativeAndStepBudget() {
        BytecodeFactIndex.TaintPath plain = new BytecodeFactIndex.TaintPath(
                "tp-neg-1",
                "app/Plain", "go", "(Ljava/lang/String;)V", 0,
                "java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;",
                "COMMAND",
                List.of(new BytecodeFactIndex.TaintStep(
                        "SOURCE", "app/Plain#go", "SOURCE", "ev-src", "entry")),
                "STATIC_INFERRED");
        FieldReturnTaintEnhancer.Enhancement negative = FieldReturnTaintEnhancer.enhance(
                List.of(plain), List.of(), List.of());
        BytecodeFactIndex.TaintPath unchanged = negative.enhancedPaths().get(0);
        check(unchanged.steps().stream().noneMatch(step ->
                        "FIELD_STORE".equals(step.kind()) || "SANITIZER".equals(step.kind())
                                || "RETURN_PROP".equals(step.kind())),
                "negative: no field/sanitizer/return steps without IR hooks");
        check(negative.fieldFlows().isEmpty() && negative.sanitizerHits().isEmpty(),
                "negative: no fieldFlows/sanitizerHits");

        List<BytecodeFactIndex.MemberAccessFact> manyWrites = new java.util.ArrayList<>();
        BytecodeFactIndex.InstructionEvidence bci =
                new BytecodeFactIndex.InstructionEvidence(
                        "app/Plain", "go", "(Ljava/lang/String;)V", 2, 0);
        for (int i = 0; i < FieldReturnTaintEnhancer.STEP_BUDGET + 8; i++) {
            manyWrites.add(new BytecodeFactIndex.MemberAccessFact(
                    BytecodeFactIndex.AccessKind.FIELD_WRITE,
                    "app/Plain", "f" + i, "Ljava/lang/String;", bci));
        }
        FieldReturnTaintEnhancer.Enhancement budgeted = FieldReturnTaintEnhancer.enhance(
                List.of(plain), manyWrites, List.of());
        check(budgeted.stopReasons().contains("FIELD_RETURN_STEP_BUDGET"),
                "budget: FIELD_RETURN_STEP_BUDGET when steps exceed STEP_BUDGET");
        check(budgeted.enhancedPaths().get(0).steps().size() <= FieldReturnTaintEnhancer.STEP_BUDGET
                        + plain.steps().size(),
                "budget: step growth remains bounded");
        check("STATIC_INFERRED".equals(budgeted.enhancedPaths().get(0).status()),
                "budget path does not elevate verification status");
    }

    private static void methodSummaryAndSanitizerHeuristicNonEmpty() {
        BytecodeFactIndex.MethodFact sanitize = new BytecodeFactIndex.MethodFact(
                "app/Safe", "sanitizeInput", "(Ljava/lang/String;)Ljava/lang/String;", 1, "fact:sanitize");
        BytecodeFactIndex.MethodFact guard = new BytecodeFactIndex.MethodFact(
                "app/Auth", "checkPermission", "(Ljava/lang/String;)V", 1, "fact:guard");
        BytecodeFactIndex.MethodFact sql = new BytecodeFactIndex.MethodFact(
                "app/Dao", "executeQuery", "(Ljava/lang/String;)V", 1, "fact:sql");
        Map<String, MethodSummary> summaries = MethodSummaryBuilder.build(
                List.of(sanitize, guard, sql), List.of(), List.of(), List.of());
        MethodSummary sanitizeSummary = summaries.get(CfgBuilder.methodIdentity(
                "app/Safe", "sanitizeInput", "(Ljava/lang/String;)Ljava/lang/String;"));
        MethodSummary guardSummary = summaries.get(CfgBuilder.methodIdentity(
                "app/Auth", "checkPermission", "(Ljava/lang/String;)V"));
        MethodSummary sqlSummary = summaries.get(CfgBuilder.methodIdentity(
                "app/Dao", "executeQuery", "(Ljava/lang/String;)V"));
        check(sanitizeSummary != null && !sanitizeSummary.sanitizers().isEmpty(),
                "heuristic: sanitize* method summary sanitizers non-empty");
        check(guardSummary != null && !guardSummary.guards().isEmpty(),
                "heuristic: checkPermission method summary guards non-empty");
        check(sqlSummary != null && !sqlSummary.effects().isEmpty(),
                "heuristic: executeQuery method summary effects non-empty");

        BytecodeFactIndex index = new BytecodeFactIndex(
                List.of(), List.of(), List.of(sanitize, guard, sql), List.of(), List.of(), List.of());
        check(!KernelSummaryProjector.sanitizerSeeds(index, List.of()).isEmpty(),
                "projector sanitizer seeds non-empty from IR heuristics");
        check(!KernelSummaryProjector.methodSummarySeeds(index, List.of()).isEmpty(),
                "projector method summary seeds non-empty from IR heuristics");
    }

    private static void declareLightweightKernelScope() {
        // P1-04 声明 AUDITED scope：轻量 analysis.kernel（CfgBuilder /
        // 说明：MethodSummary/FieldReturn 含 stopReason/budget 诚实 — 非完整 SSA/IFDS/points-to。
        // ADR-0002 仍为 PROPOSED；建议 ACCEPTED = 继续轻 kernel + 深化自研。
        check(CfgGraph.MAX_BLOCKS > 0 && MethodSummaryBuilder.MAX_PROPAGATION_ROUNDS > 0
                        && FieldReturnTaintEnhancer.PATH_BUDGET > 0,
                "lightweight kernel declares finite budgets (not unbounded IFDS)");
        check(!"IFDS".equalsIgnoreCase(CfgGraph.SCHEMA_VERSION),
                "CFG schema is cfg-v1 lightweight, not IFDS engine");
    }

    private static void methodViewEmitsBoundedPseudoDecompile() throws Exception {
        Path root = Files.createTempDirectory("veyrion-kernel-method-view");
        try {
            ControlPlaneStore store = ControlPlaneStore.sqlite(root.resolve("state.db"), root);
            String now = Instant.now().toString();
            store.bootstrapOperator("bootstrap-token", now);
            var project = store.createProject("project-method-view", "method-view", now, "local-admin");
            Path artifact = root.resolve("Fixture.class");
            Files.writeString(artifact, "fixture");
            String digest = "b".repeat(64);
            store.registerArtifact(project, new ArtifactDescriptor("artifact-method-view", ArtifactType.CLASS,
                    artifact, Files.size(artifact), digest, true, Instant.parse(now), "Fixture.class"),
                    "local-admin");
            String scanId = "scan-kernel-method-view";
            var evidence = new ApiDtos.EvidenceDto(ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                    "evidence-entry-mv", "FACT", "classfile-annotation:app.Handler#handle",
                    1.0, "fixture", now, "test", "none", "artifact:" + digest, ApiDtos.MOCK);
            var entry = new ApiDtos.EntryDto(ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                    "entry-mv", "HTTP", "GET", "/api", "app.Handler", "example",
                    List.of(), List.of(), ApiDtos.STATIC_INFERRED, 0.9, 0, List.of("evidence-entry-mv"));
            var scan = new ApiDtos.ScanDto(ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                    "COMPLETED", ApiDtos.STATIC_INFERRED, ApiDtos.MOCK, now, now,
                    List.of("evidence-entry-mv"), List.of(entry), List.of(), List.of(), List.of(), List.of());
            store.saveScan(new ControlPlaneStore.ScanRecord(scan, Map.of("evidence-entry-mv", evidence),
                    List.of(), List.of()), "local-admin");

            BytecodeFactIndex.MethodFact method = new BytecodeFactIndex.MethodFact(
                    "app/Handler", "handle", "(Ljava/lang/String;)V", 1, "fact:handle");
            BytecodeFactIndex.InstructionEvidence bci =
                    new BytecodeFactIndex.InstructionEvidence(
                            "app/Handler", "handle", "(Ljava/lang/String;)V", 12, 0);
            BytecodeFactIndex.CallEdge edge = new BytecodeFactIndex.CallEdge(
                    "app/Handler", "handle", "(Ljava/lang/String;)V",
                    "java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;",
                    BytecodeFactIndex.EdgeKind.DIRECT, "none", bci);
            StaticFactSnapshot facts = new StaticFactSnapshot(
                    StaticFactSnapshot.COMPLETE, List.of(),
                    new BytecodeFactIndex.AnalysisCoverage(64, 32, 1, 1, true, List.of()),
                    List.of(), List.of(), List.of(method), List.of(), List.of(edge),
                    List.of(), List.of(), List.of());
            store.saveStaticFacts(scanId, facts, "local-admin");

            ControlPlaneToolDataSource source = new ControlPlaneToolDataSource(store, scanId);
            ToolExecutionContext.Scope scope =
                    new ToolExecutionContext.Scope("local", project.projectId());
            List<ToolDataSource.FactRecord> rows = source.queryCode(scope, "METHOD_VIEW", "handle", 10);
            check(!rows.isEmpty(), "METHOD_VIEW returns rows");
            boolean sawPseudo = false;
            for (ToolDataSource.FactRecord row : rows) {
                JsonNode value = row.value();
                if (value.has("pseudoDecompile") && value.path("pseudoDecompile").isArray()
                        && value.path("pseudoDecompile").size() >= 2) {
                    sawPseudo = true;
                    String line = value.path("pseudoDecompile").get(1).asText("");
                    check(line.contains("bci=") && line.contains("INVOKE"),
                            "pseudoDecompile line carries bci and opcode label");
                    check("KERNEL_INFERENCE".equals(value.path("pseudoDecompileProvenance").asText()),
                            "pseudoDecompile provenance is KERNEL_INFERENCE");
                }
            }
            check(sawPseudo, "METHOD_VIEW emits bounded pseudoDecompile lines");
        } finally {
            try {
                Files.walk(root)
                        .sorted((a, b) -> b.compareTo(a))
                        .forEach(path -> {
                            try {
                                Files.deleteIfExists(path);
                            } catch (Exception ignored) {
                                // ignore
                            }
                        });
            } catch (Exception ignored) {
                // ignore
            }
        }
    }

    private static void cfgViewPrefersKernelProducer() throws Exception {
        Path root = Files.createTempDirectory("veyrion-kernel-cfg");
        try {
            ControlPlaneStore store = ControlPlaneStore.sqlite(root.resolve("state.db"), root);
            String now = Instant.now().toString();
            store.bootstrapOperator("bootstrap-token", now);
            var project = store.createProject("project-kernel", "kernel", now, "local-admin");
            Path artifact = root.resolve("Fixture.class");
            Files.writeString(artifact, "fixture");
            String digest = "a".repeat(64);
            store.registerArtifact(project, new ArtifactDescriptor("artifact-kernel", ArtifactType.CLASS,
                    artifact, Files.size(artifact), digest, true, Instant.parse(now), "Fixture.class"),
                    "local-admin");
            String scanId = "scan-kernel-cfg";
            var evidence = new ApiDtos.EvidenceDto(ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                    "evidence-entry", "FACT", "classfile-annotation:app.Handler#handle",
                    1.0, "fixture", now, "test", "none", "artifact:" + digest, ApiDtos.MOCK);
            var entry = new ApiDtos.EntryDto(ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                    "entry-1", "HTTP", "GET", "/api", "app.Handler", "example",
                    List.of(), List.of(), ApiDtos.STATIC_INFERRED, 0.9, 0, List.of("evidence-entry"));
            var scan = new ApiDtos.ScanDto(ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                    "COMPLETED", ApiDtos.STATIC_INFERRED, ApiDtos.MOCK, now, now,
                    List.of("evidence-entry"), List.of(entry), List.of(), List.of(), List.of(), List.of());
            store.saveScan(new ControlPlaneStore.ScanRecord(scan, Map.of("evidence-entry", evidence),
                    List.of(), List.of()), "local-admin");

            BytecodeFactIndex.InstructionEvidence bci =
                    new BytecodeFactIndex.InstructionEvidence("app/Handler", "handle", "(Ljava/lang/String;)V", 12, 0);
            BytecodeFactIndex.InstructionEvidence bciFar =
                    new BytecodeFactIndex.InstructionEvidence("app/Handler", "handle", "(Ljava/lang/String;)V", 40, 1);
            BytecodeFactIndex.MethodFact handle = new BytecodeFactIndex.MethodFact(
                    "app/Handler", "handle", "(Ljava/lang/String;)V", 1, "fact:method:handle");
            BytecodeFactIndex.CallEdge edge = new BytecodeFactIndex.CallEdge(
                    "app/Handler", "handle", "(Ljava/lang/String;)V",
                    "app/Service", "run", "(Ljava/lang/String;)V",
                    BytecodeFactIndex.EdgeKind.DIRECT, "none", bci);
            BytecodeFactIndex.CallEdge edgeFar = new BytecodeFactIndex.CallEdge(
                    "app/Handler", "handle", "(Ljava/lang/String;)V",
                    "app/Service", "log", "(Ljava/lang/String;)V",
                    BytecodeFactIndex.EdgeKind.CHA, "cha", bciFar);
            StaticFactSnapshot snapshot = new StaticFactSnapshot(
                    StaticFactSnapshot.COMPLETE,
                    List.of(),
                    new BytecodeFactIndex.AnalysisCoverage(64, 32, 2, 1, true, List.of()),
                    List.of(),
                    List.of(),
                    List.of(handle),
                    List.of(),
                    List.of(edge, edgeFar),
                    List.of(),
                    List.of(),
                    List.of());
            store.saveStaticFacts(scanId, snapshot, "local-admin");

            ControlPlaneToolDataSource source = new ControlPlaneToolDataSource(store, scanId);
            ToolExecutionContext.Scope scope =
                    new ToolExecutionContext.Scope("local", project.projectId());
            List<ToolDataSource.FactRecord> cfg = source.queryCode(scope, "CFG_VIEW", "handle", 20);
            check(!cfg.isEmpty(), "CFG_VIEW returns a row");
            JsonNode value = cfg.get(0).value();
            check("analysis.kernel.CfgBuilder".equals(value.path("cfgProducer").asText()),
                    "CFG_VIEW prefers CfgBuilder producer");
            check(value.path("basicBlocks").isArray() && value.path("basicBlocks").size() >= 1,
                    "CFG_VIEW basicBlocks present from kernel");
            check(value.path("cfg").isObject() && value.path("cfg").path("blocks").isArray(),
                    "CFG_VIEW includes serializable cfg object");
            check(value.path("basicBlocks").get(0).has("startBci"),
                    "compatibility startBci retained");
        } finally {
            try {
                Files.walk(root)
                        .sorted((a, b) -> b.compareTo(a))
                        .forEach(path -> {
                            try {
                                Files.deleteIfExists(path);
                            } catch (Exception ignored) {
                                // ignore
                            }
                        });
            } catch (Exception ignored) {
                // ignore
            }
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
