package com.aq.jvmsentinel.ai.tool.datasource;

import com.aq.jvmsentinel.analysis.TaintGraph;
import com.aq.jvmsentinel.analysis.TaintGraphProjector;
import com.aq.jvmsentinel.analysis.identity.AuthCodeQueryService;
import com.aq.jvmsentinel.analysis.kernel.CfgBuilder;
import com.aq.jvmsentinel.analysis.kernel.CfgGraph;
import com.aq.jvmsentinel.ai.tool.ToolDataSource.FactRecord;
import com.aq.jvmsentinel.ai.tool.ToolExecutionContext;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * queryCode 各类查询：METHOD_VIEW、CALLERS/CALLEES、FIELD_USES、CFG_VIEW、
 * GUARD、AUTH/CONFIG、TAINT_GRAPH 等。
 */
public final class CodeQuerySupport {
    private static final int MAX_INSTRUCTION_SLICE = 64;
    /** METHOD_VIEW 伪反编译行数上限（仅 bci/opcode/标签/evidence）。 */
    private static final int MAX_PSEUDO_DECOMPILE_LINES = 48;
    private static final int CFG_GAP_THRESHOLD = 8;
    private static final int CFG_BLOCK_CAPACITY = 8;
    private static final int CFG_MAX_BLOCKS = 32;

    private final ControlPlaneStore store;
    private final String scanId;
    private final IrProjectionSupport irProjection;

    public CodeQuerySupport(ControlPlaneStore store, String scanId, IrProjectionSupport irProjection) {
        this.store = Objects.requireNonNull(store, "store");
        this.scanId = Objects.requireNonNull(scanId, "scanId");
        this.irProjection = Objects.requireNonNull(irProjection, "irProjection");
    }

    public List<FactRecord> queryCode(ToolExecutionContext.Scope scope, String kind,
                                      String query, int limit) {
        ControlPlaneStore.ScanRecord scan = store.requireScan(scanId);
        int capped = Math.max(1, Math.min(50, limit));
        String resolvedKind = resolveCodeQueryKind(kind, query);
        String strippedQuery = stripKindPrefix(query);
        return switch (resolvedKind) {
            case "TAINT_GRAPH", "DATAFLOW_SLICE" ->
                    queryTaintGraph(scope, scan, strippedQuery, capped, resolvedKind);
            case "METHOD_VIEW" -> queryMethodView(scope, strippedQuery, capped);
            case "CALLERS" -> queryCallersOrCallees(scope, strippedQuery, capped, true);
            case "CALLEES" -> queryCallersOrCallees(scope, strippedQuery, capped, false);
            case "GUARD_QUERY" -> queryGuard(scope, scan, strippedQuery, capped);
            case "FIELD_USES" -> queryFieldUses(scope, strippedQuery, capped);
            case "CFG_VIEW" -> queryCfgView(scope, strippedQuery, capped);
            case "CONFIG_SEARCH", "AUTH" -> queryAuthOrConfig(scope, scan, strippedQuery, capped, resolvedKind);
            default -> queryAuthOrConfig(scope, scan, strippedQuery, capped, "AUTH");
        };
    }

    private List<FactRecord> queryAuthOrConfig(ToolExecutionContext.Scope scope,
                                               ControlPlaneStore.ScanRecord scan,
                                               String query, int limit, String kind) {
        Path artifactPath = null;
        try {
            ControlPlaneStore.ProjectRecord project = store.requireProject(scan.dto().projectId());
            ArtifactDescriptor artifact = store.artifact(project, scan.dto().artifactDigest());
            if (artifact != null) {
                artifactPath = artifact.normalizedPath();
            }
        } catch (RuntimeException ignored) {
            artifactPath = null;
        }
        AuthCodeQueryService.AuthCodeQueryResult result =
                new AuthCodeQueryService().query(artifactPath, query, Math.max(1, limit - 1));
        ObjectNode summary = DatasourceJson.JSON.valueToTree(AuthCodeQueryService.toToolMap(result));
        summary.put("kind", kind);
        summary.put("classification", "FACT");
        summary.put("verificationStatus", "STATIC_INFERRED");
        boolean artifactUnavailable = artifactPath == null || !Files.isRegularFile(artifactPath);
        boolean scanFailed = result.facts().stream().anyMatch(fact -> "ERROR".equals(fact.category()));
        if (artifactUnavailable || scanFailed) {
            summary.put("coverageStatus", StaticFactSnapshot.LEGACY_INCOMPLETE);
            summary.put("stopReason", artifactUnavailable ? "ARTIFACT_UNAVAILABLE" : "AUTH_CODE_SCAN_FAILED");
        } else {
            summary.put("coverageStatus", "COMPLETE");
        }
        List<FactRecord> records = new ArrayList<>();
        records.add(new FactRecord(scope, "code_query:auth-summary", summary));
        for (AuthCodeQueryService.AuthCodeFact fact : result.facts()) {
            if (records.size() >= limit) {
                break;
            }
            ObjectNode node = DatasourceJson.JSON.createObjectNode();
            node.put("id", fact.id());
            node.put("kind", kind);
            node.put("category", fact.category());
            node.put("summary", fact.summary());
            node.put("sourcePath", fact.sourcePath());
            node.put("classification", "FACT");
            node.put("verificationStatus", "STATIC_INFERRED");
            node.set("attributes", DatasourceJson.JSON.valueToTree(fact.attributes()));
            records.add(new FactRecord(scope, "code_query:" + fact.id(), node));
        }
        return List.copyOf(records);
    }

    private List<FactRecord> queryMethodView(ToolExecutionContext.Scope scope, String query, int limit) {
        Optional<IrProjectionSupport.IrProjection> ir = irProjection.resolveIrProjection();
        if (ir.isEmpty() || ir.get().methods().isEmpty()) {
            return irProjection.incompleteIr(scope, "METHOD_VIEW",
                    IrProjectionSupport.irStopReason(ir), IrProjectionSupport.irCoverage(ir));
        }
        String needle = query == null ? "" : query.toLowerCase(Locale.ROOT).trim();
        List<BytecodeFactIndex.MethodFact> matches = new ArrayList<>();
        for (BytecodeFactIndex.MethodFact method : ir.get().methods()) {
            String hay = IrProjectionSupport.methodKey(method.owner(), method.name(), method.descriptor())
                    .toLowerCase(Locale.ROOT);
            if (needle.isEmpty() || hay.contains(needle)
                    || method.evidence().toLowerCase(Locale.ROOT).contains(needle)) {
                matches.add(method);
            }
        }
        ObjectNode summary = IrProjectionSupport.baseIrSummary("METHOD_VIEW", ir.get().coverageStatus(), null);
        summary.put("matchCount", matches.size());
        if (matches.isEmpty()) {
            summary.put("stopReason", "NO_MATCH");
            summary.put("coverageStatus", ir.get().coverageStatus());
        }
        ArrayNode methods = summary.putArray("methods");
        int emitted = 0;
        boolean anySlice = false;
        for (BytecodeFactIndex.MethodFact method : matches) {
            if (emitted >= Math.max(0, limit - 1)) {
                break;
            }
            ObjectNode row = methods.addObject();
            IrProjectionSupport.putMethod(row, method);
            ArrayNode slice = putInstructionSlice(row, method, ir.get());
            putPseudoDecompile(row, method, slice);
            if (slice.size() > 0) {
                anySlice = true;
            } else {
                row.put("stopReason", "SLICE_EMPTY");
            }
            emitted++;
        }
        if (!matches.isEmpty() && !anySlice && !summary.has("stopReason")) {
            summary.put("stopReason", "SLICE_EMPTY");
        }
        List<FactRecord> records = new ArrayList<>();
        records.add(new FactRecord(scope, "code_query:method-view", summary));
        for (BytecodeFactIndex.MethodFact method : matches) {
            if (records.size() >= limit) {
                break;
            }
            ObjectNode row = IrProjectionSupport.baseIrSummary("METHOD_VIEW", ir.get().coverageStatus(), null);
            IrProjectionSupport.putMethod(row, method);
            ArrayNode slice = putInstructionSlice(row, method, ir.get());
            putPseudoDecompile(row, method, slice);
            if (slice.isEmpty()) {
                row.put("stopReason", "SLICE_EMPTY");
            }
            records.add(new FactRecord(scope, "code_query:method:"
                    + IrProjectionSupport.methodKey(method.owner(), method.name(), method.descriptor()), row));
        }
        return List.copyOf(records);
    }

    private List<FactRecord> queryCallersOrCallees(ToolExecutionContext.Scope scope, String query,
                                                   int limit, boolean callers) {
        String kind = callers ? "CALLERS" : "CALLEES";
        Optional<IrProjectionSupport.IrProjection> ir = irProjection.resolveIrProjection();
        if (ir.isEmpty() || (ir.get().callEdges().isEmpty() && ir.get().artifactCallGraph().isEmpty())) {
            String stop = IrProjectionSupport.irStopReason(ir);
            if (ir.isPresent() && !ir.get().methods().isEmpty()) {
                stop = "CALL_GRAPH_EMPTY";
            }
            return irProjection.incompleteIr(scope, kind, stop, IrProjectionSupport.irCoverage(ir));
        }
        String needle = query == null ? "" : query.toLowerCase(Locale.ROOT).trim();
        ObjectNode summary = IrProjectionSupport.baseIrSummary(kind, ir.get().coverageStatus(), null);
        ArrayNode edges = summary.putArray("edges");
        int emitted = 0;
        if (!ir.get().artifactCallGraph().isEmpty()) {
            for (BytecodeFactIndex.ResolvedCallEdge edge : ir.get().artifactCallGraph()) {
                String target = IrProjectionSupport.methodKey(edge.targetOwner(), edge.targetName(), edge.targetDescriptor())
                        .toLowerCase(Locale.ROOT);
                String caller = IrProjectionSupport.methodKey(edge.callerOwner(), edge.callerName(), edge.callerDescriptor())
                        .toLowerCase(Locale.ROOT);
                boolean hit = callers
                        ? (needle.isEmpty() || target.contains(needle))
                        : (needle.isEmpty() || caller.contains(needle));
                if (!hit) {
                    continue;
                }
                if (emitted >= Math.max(0, limit - 1)) {
                    break;
                }
                ObjectNode row = edges.addObject();
                row.put("caller", IrProjectionSupport.methodKey(edge.callerOwner(), edge.callerName(), edge.callerDescriptor()));
                row.put("callee", IrProjectionSupport.methodKey(edge.targetOwner(), edge.targetName(), edge.targetDescriptor()));
                row.put("edgeKind", edge.kind().name());
                row.put("evidence", edge.evidence().stableKey());
                emitted++;
            }
        } else {
            for (BytecodeFactIndex.CallEdge edge : ir.get().callEdges()) {
                String target = IrProjectionSupport.methodKey(edge.targetOwner(), edge.targetName(), edge.targetDescriptor())
                        .toLowerCase(Locale.ROOT);
                String caller = IrProjectionSupport.methodKey(edge.callerOwner(), edge.callerName(), edge.callerDescriptor())
                        .toLowerCase(Locale.ROOT);
                boolean hit = callers
                        ? (needle.isEmpty() || target.contains(needle))
                        : (needle.isEmpty() || caller.contains(needle));
                if (!hit) {
                    continue;
                }
                if (emitted >= Math.max(0, limit - 1)) {
                    break;
                }
                ObjectNode row = edges.addObject();
                row.put("caller", IrProjectionSupport.methodKey(edge.callerOwner(), edge.callerName(), edge.callerDescriptor()));
                row.put("callee", IrProjectionSupport.methodKey(edge.targetOwner(), edge.targetName(), edge.targetDescriptor()));
                row.put("edgeKind", edge.kind().name());
                row.put("evidence", edge.evidence().stableKey());
                emitted++;
            }
        }
        summary.put("matchCount", emitted);
        if (emitted == 0) {
            summary.put("stopReason", "NO_MATCH");
        }
        return List.of(new FactRecord(scope, "code_query:" + kind.toLowerCase(Locale.ROOT), summary));
    }

    private List<FactRecord> queryFieldUses(ToolExecutionContext.Scope scope, String query, int limit) {
        Optional<IrProjectionSupport.IrProjection> ir = irProjection.resolveIrProjection();
        if (ir.isEmpty() || ir.get().memberAccesses().isEmpty()) {
            String stop = IrProjectionSupport.irStopReason(ir);
            if (ir.isPresent() && !ir.get().methods().isEmpty()) {
                stop = "MEMBER_ACCESSES_EMPTY";
            }
            return irProjection.incompleteIr(scope, "FIELD_USES", stop, IrProjectionSupport.irCoverage(ir));
        }
        String needle = query == null ? "" : query.toLowerCase(Locale.ROOT).trim();
        ObjectNode summary = IrProjectionSupport.baseIrSummary("FIELD_USES", ir.get().coverageStatus(), null);
        ArrayNode uses = summary.putArray("uses");
        int emitted = 0;
        for (BytecodeFactIndex.MemberAccessFact access : ir.get().memberAccesses()) {
            String hay = (access.targetOwner() + "#" + access.targetName() + access.targetDescriptor()
                    + " " + access.kind().name()).toLowerCase(Locale.ROOT);
            if (!needle.isEmpty() && !hay.contains(needle)) {
                continue;
            }
            if (emitted >= Math.max(0, limit - 1)) {
                break;
            }
            ObjectNode row = uses.addObject();
            row.put("accessKind", access.kind().name());
            row.put("targetOwner", access.targetOwner());
            row.put("targetName", access.targetName());
            row.put("targetDescriptor", access.targetDescriptor());
            row.put("evidence", access.evidence().stableKey());
            emitted++;
        }
        summary.put("matchCount", emitted);
        if (emitted == 0) {
            summary.put("stopReason", "NO_MATCH");
        }
        return List.of(new FactRecord(scope, "code_query:field-uses", summary));
    }

    private List<FactRecord> queryCfgView(ToolExecutionContext.Scope scope, String query, int limit) {
        Optional<IrProjectionSupport.IrProjection> ir = irProjection.resolveIrProjection();
        if (ir.isEmpty()) {
            return irProjection.incompleteIr(scope, "CFG_VIEW", "IR_NOT_PERSISTED", StaticFactSnapshot.LEGACY_INCOMPLETE);
        }
        String needle = query == null ? "" : query.toLowerCase(Locale.ROOT).trim();
        Optional<CfgGraph> kernelCfg = CfgBuilder.buildForQuery(
                query,
                ir.get().methods(),
                ir.get().callEdges(),
                ir.get().memberAccesses(),
                ir.get().artifactCallGraph());
        if (kernelCfg.isPresent() && !kernelCfg.get().blocks().isEmpty()) {
            CfgGraph cfg = kernelCfg.get();
            ObjectNode summary = IrProjectionSupport.baseIrSummary("CFG_VIEW", ir.get().coverageStatus(), null);
            summary.put("cfgProducer", "analysis.kernel.CfgBuilder");
            summary.put("matchCount", cfg.blocks().stream().mapToInt(block -> block.evidenceRefs().size()).sum());
            ArrayNode offsets = summary.putArray("bytecodeOffsets");
            ArrayNode keys = summary.putArray("evidenceKeys");
            int emitted = 0;
            for (var block : cfg.blocks()) {
                for (String ref : block.evidenceRefs()) {
                    if (emitted >= Math.max(1, limit)) {
                        break;
                    }
                    int at = ref.lastIndexOf("@bci-");
                    if (at >= 0) {
                        int end = ref.indexOf(':', at);
                        String raw = end > at ? ref.substring(at + 5, end) : ref.substring(at + 5);
                        try {
                            offsets.add(Integer.parseInt(raw));
                        } catch (NumberFormatException ignored) {
                            offsets.add(block.startBci());
                        }
                    } else {
                        offsets.add(block.startBci());
                    }
                    keys.add(ref);
                    emitted++;
                }
                if (emitted >= Math.max(1, limit)) {
                    break;
                }
            }
            summary.set("basicBlocks", cfg.toBasicBlocksArray(DatasourceJson.JSON));
            summary.set("cfg", cfg.toJson(DatasourceJson.JSON));
            if (!cfg.stopReasons().isEmpty()) {
                summary.put("stopReason", cfg.stopReasons().get(0));
            }
            return List.of(new FactRecord(scope, "code_query:cfg-view", summary));
        }
        List<CfgSite> sites = new ArrayList<>();
        for (BytecodeFactIndex.CallEdge edge : ir.get().callEdges()) {
            collectCfgSite(needle, edge.evidence(), sites);
        }
        for (BytecodeFactIndex.MemberAccessFact access : ir.get().memberAccesses()) {
            collectCfgSite(needle, access.evidence(), sites);
        }
        for (BytecodeFactIndex.ResolvedCallEdge edge : ir.get().artifactCallGraph()) {
            collectCfgSite(needle, edge.evidence(), sites);
        }
        if (sites.isEmpty()) {
            return irProjection.incompleteIr(scope, "CFG_VIEW", "CFG_NOT_AVAILABLE", ir.get().coverageStatus());
        }
        sites.sort((a, b) -> Integer.compare(a.bci(), b.bci()));
        ObjectNode summary = IrProjectionSupport.baseIrSummary("CFG_VIEW", ir.get().coverageStatus(), null);
        summary.put("cfgProducer", "legacy-bci-gap");
        summary.put("matchCount", sites.size());
        ArrayNode offsets = summary.putArray("bytecodeOffsets");
        ArrayNode keys = summary.putArray("evidenceKeys");
        int emitted = 0;
        for (CfgSite site : sites) {
            if (emitted >= Math.max(1, limit)) {
                break;
            }
            offsets.add(site.bci());
            keys.add(site.evidenceKey());
            emitted++;
        }
        summary.set("basicBlocks", buildBasicBlocks(sites));
        return List.of(new FactRecord(scope, "code_query:cfg-view", summary));
    }

    private List<FactRecord> queryGuard(ToolExecutionContext.Scope scope,
                                        ControlPlaneStore.ScanRecord scan,
                                        String query, int limit) {
        Optional<IrProjectionSupport.IrProjection> ir = irProjection.resolveIrProjection();
        String needle = query == null ? "" : query.toLowerCase(Locale.ROOT).trim();
        ObjectNode summary = IrProjectionSupport.baseIrSummary("GUARD_QUERY",
                ir.map(IrProjectionSupport.IrProjection::coverageStatus)
                        .orElse(StaticFactSnapshot.LEGACY_INCOMPLETE), null);
        ArrayNode signals = summary.putArray("signals");
        int emitted = 0;
        if (ir.isPresent()) {
            for (BytecodeFactIndex.MethodFact method : ir.get().methods()) {
                String hay = IrProjectionSupport.methodKey(method.owner(), method.name(), method.descriptor())
                        + " " + method.evidence();
                if (!isGuardSignal(hay)) {
                    continue;
                }
                if (!needle.isEmpty() && !hay.toLowerCase(Locale.ROOT).contains(needle)) {
                    continue;
                }
                if (emitted >= Math.max(0, limit - 1)) {
                    break;
                }
                ObjectNode row = signals.addObject();
                row.put("source", "IR_METHOD");
                IrProjectionSupport.putMethod(row, method);
                row.put("classification", "FACT");
                emitted++;
            }
        }
        for (ApiDtos.EntryDto entry : scan.dto().entries()) {
            for (String precondition : entry.preconditions()) {
                if (!isGuardSignal(precondition)) {
                    continue;
                }
                if (!needle.isEmpty() && !precondition.toLowerCase(Locale.ROOT).contains(needle)
                        && !(entry.declaringClass() != null
                        && entry.declaringClass().toLowerCase(Locale.ROOT).contains(needle))) {
                    continue;
                }
                if (emitted >= Math.max(0, limit - 1)) {
                    break;
                }
                ObjectNode row = signals.addObject();
                row.put("source", "ENTRY_PRECONDITION");
                row.put("entryId", entry.id());
                row.put("declaringClass", entry.declaringClass() == null ? "" : entry.declaringClass());
                row.put("precondition", precondition);
                row.put("classification", "FACT");
                emitted++;
            }
        }
        summary.put("matchCount", emitted);
        if (ir.isEmpty() || ir.get().methods().isEmpty()) {
            if (emitted == 0) {
                return irProjection.incompleteIr(scope, "GUARD_QUERY",
                        IrProjectionSupport.irStopReason(ir), IrProjectionSupport.irCoverage(ir));
            }
            summary.put("stopReason", "LEGACY_ENTRY_PRECONDITIONS_ONLY");
            summary.put("coverageStatus", StaticFactSnapshot.LEGACY_INCOMPLETE);
        } else if (emitted == 0) {
            summary.put("stopReason", "NO_MATCH");
        }
        return List.of(new FactRecord(scope, "code_query:guard-query", summary));
    }

    private List<FactRecord> queryTaintGraph(ToolExecutionContext.Scope scope,
                                             ControlPlaneStore.ScanRecord scan,
                                             String query, int limit, String kind) {
        Optional<StaticFactSnapshot> facts = store.staticFacts(scanId);
        List<BytecodeFactIndex.TaintPath> paths =
                StaticFactSnapshot.resolveTaintPaths(facts, scan.dto().sinks());
        List<BytecodeFactIndex.TaintPath> enriched = new ArrayList<>();
        if (StaticFactSnapshot.hasPersistedSteps(facts)) {
            enriched.addAll(paths);
        } else {
            for (BytecodeFactIndex.TaintPath path : paths) {
                if (path.steps().isEmpty()) {
                    enriched.add(new BytecodeFactIndex.TaintPath(
                            path.id(), path.sourceOwner(), path.sourceMethod(), path.sourceDescriptor(),
                            path.sourceParameter(), path.sinkOwner(), path.sinkMethod(), path.sinkDescriptor(),
                            path.category(),
                            List.of(new BytecodeFactIndex.TaintStep(
                                    "TRANSFORM", path.sinkOwner() + "#bridge", "DIRECT",
                                    "fact:taint-bridge", "synthetic bridge for graph projection")),
                            path.status()));
                } else {
                    enriched.add(path);
                }
            }
        }
        TaintGraph full = TaintGraphProjector.project(enriched);
        String filter = extractQueryToken(query, "sinkId");
        if (filter.isBlank()) {
            filter = extractQueryToken(query, "entryId");
        }
        if (filter.isBlank()) {
            filter = extractQueryToken(query, "nodeId");
        }
        TaintGraph graph = TaintGraphProjector.subgraph(full, filter);
        ObjectNode summary = DatasourceJson.JSON.createObjectNode();
        summary.put("kind", kind);
        summary.put("nodeCount", graph.nodes().size());
        summary.put("edgeCount", graph.edges().size());
        summary.put("truncated", graph.truncated());
        summary.put("verificationStatus", "STATIC_INFERRED");
        summary.put("classification", "FACT");
        summary.put("coverageStatus", facts.map(StaticFactSnapshot::coverageStatus)
                .orElse(StaticFactSnapshot.LEGACY_INCOMPLETE));
        ArrayNode nodes = summary.putArray("nodes");
        for (TaintGraph.TaintNode node : graph.nodes()) {
            ObjectNode n = nodes.addObject();
            n.put("id", node.id());
            n.put("kind", node.kind().name());
            n.put("classname", node.classname());
            n.put("methodDesc", node.methodDesc());
            n.put("paramIdx", node.paramIdx());
        }
        ArrayNode edges = summary.putArray("edges");
        for (TaintGraph.TaintEdge edge : graph.edges()) {
            ObjectNode e = edges.addObject();
            e.put("from", edge.from());
            e.put("to", edge.to());
            e.put("edgeKind", edge.edgeKind().name());
            e.put("callSite", edge.callSite());
        }
        List<FactRecord> records = new ArrayList<>();
        records.add(new FactRecord(scope, "code_query:taint-graph", summary));
        int emitted = 1;
        for (TaintGraph.TaintNode node : graph.nodes()) {
            if (emitted >= limit) {
                break;
            }
            ObjectNode n = DatasourceJson.JSON.createObjectNode();
            n.put("id", node.id());
            n.put("kind", kind);
            n.put("nodeKind", node.kind().name());
            n.put("classname", node.classname());
            n.put("classification", "FACT");
            n.put("verificationStatus", "STATIC_INFERRED");
            records.add(new FactRecord(scope, "code_query:taint-node:" + node.id(), n));
            emitted++;
        }
        return List.copyOf(records);
    }

    private static ArrayNode putInstructionSlice(ObjectNode row, BytecodeFactIndex.MethodFact method,
                                                 IrProjectionSupport.IrProjection ir) {
        ArrayNode slice = row.putArray("instructionSlice");
        String identity = methodIdentity(method.owner(), method.name(), method.descriptor());
        Set<String> seen = new LinkedHashSet<>();
        for (BytecodeFactIndex.CallEdge edge : ir.callEdges()) {
            if (!callerMatches(identity, edge.callerOwner(), edge.callerName(), edge.callerDescriptor(),
                    edge.evidence())) {
                continue;
            }
            String target = IrProjectionSupport.methodKey(edge.targetOwner(), edge.targetName(), edge.targetDescriptor());
            appendSliceItem(slice, seen, edge.evidence(), "edgeKind", edge.kind().name(),
                    edge.kind().name(), ir.coverageStatus(), "INVOKE", target);
        }
        for (BytecodeFactIndex.ResolvedCallEdge edge : ir.artifactCallGraph()) {
            if (!callerMatches(identity, edge.callerOwner(), edge.callerName(), edge.callerDescriptor(),
                    edge.evidence())) {
                continue;
            }
            String target = IrProjectionSupport.methodKey(edge.targetOwner(), edge.targetName(), edge.targetDescriptor());
            appendSliceItem(slice, seen, edge.evidence(), "edgeKind", edge.kind().name(),
                    edge.kind().name(), ir.coverageStatus(), "INVOKE", target);
        }
        for (BytecodeFactIndex.MemberAccessFact access : ir.memberAccesses()) {
            if (!evidenceMatchesMethod(identity, access.evidence())) {
                continue;
            }
            String opcode = access.kind() == BytecodeFactIndex.AccessKind.FIELD_WRITE
                    ? "PUTFIELD" : "GETFIELD";
            String target = (access.targetOwner() == null ? "" : access.targetOwner().replace('/', '.'))
                    + "#" + (access.targetName() == null ? "" : access.targetName())
                    + (access.targetDescriptor() == null ? "" : access.targetDescriptor());
            appendSliceItem(slice, seen, access.evidence(), "accessKind", access.kind().name(),
                    "DIRECT", ir.coverageStatus(), opcode, target);
        }
        return slice;
    }

    private static void appendSliceItem(ArrayNode slice, Set<String> seen,
                                        BytecodeFactIndex.InstructionEvidence evidence,
                                        String kindField, String kindValue, String resolvedKind,
                                        String coverageStatus, String opcode, String target) {
        if (evidence == null || evidence.bytecodeOffset() < 0) {
            return;
        }
        if (slice.size() >= MAX_INSTRUCTION_SLICE) {
            return;
        }
        String key = evidence.stableKey();
        if (!seen.add(key)) {
            return;
        }
        ObjectNode item = slice.addObject();
        item.put("bci", evidence.bytecodeOffset());
        item.put("stableKey", key);
        item.put(kindField, kindValue == null ? "" : kindValue);
        item.put("resolvedKind", resolvedKind == null ? "UNRESOLVED" : resolvedKind);
        item.put("opcode", opcode == null ? "UNKNOWN" : opcode);
        item.put("target", target == null ? "" : target);
        item.put("coverageStatus", coverageStatus == null
                ? StaticFactSnapshot.LEGACY_INCOMPLETE : coverageStatus);
        item.put("stopReason", "OBSERVED");
    }

    /** 从 instructionSlice 生成有界伪反编译文本（bci/opcode/evidence），不读取宿主文件。 */
    private static void putPseudoDecompile(ObjectNode row, BytecodeFactIndex.MethodFact method,
                                           ArrayNode slice) {
        ArrayNode lines = row.putArray("pseudoDecompile");
        ArrayNode sourceLines = row.putArray("pseudoSourceLines");
        String owner = method.owner() == null ? "" : method.owner().replace('/', '.');
        String header = "// method " + owner + "#" + method.name()
                + (method.descriptor() == null ? "" : method.descriptor())
                + "  provenance=KERNEL_INFERENCE";
        lines.add(header);
        sourceLines.add(header);
        if (slice == null || slice.isEmpty()) {
            String empty = "// no instruction evidence; SLICE_EMPTY";
            lines.add(empty);
            sourceLines.add(empty);
            row.put("pseudoDecompileTruncated", false);
            return;
        }
        boolean truncated = false;
        int emitted = 0;
        for (JsonNode item : slice) {
            if (emitted >= MAX_PSEUDO_DECOMPILE_LINES) {
                truncated = true;
                break;
            }
            int bci = item.path("bci").asInt(-1);
            String opcode = item.path("opcode").asText("UNKNOWN");
            String target = item.path("target").asText("");
            String evidence = item.path("stableKey").asText("");
            String line = String.format(Locale.ROOT,
                    "  // bci=%d  %s  %s  evidence=%s",
                    bci, opcode, target, evidence);
            lines.add(line);
            sourceLines.add(line);
            emitted++;
        }
        if (truncated) {
            String marker = "// truncated at " + MAX_PSEUDO_DECOMPILE_LINES + " lines";
            lines.add(marker);
            sourceLines.add(marker);
        }
        row.put("pseudoDecompileTruncated", truncated);
        row.put("pseudoDecompileProvenance", "KERNEL_INFERENCE");
    }

    private static boolean callerMatches(String identity, String owner, String name, String descriptor,
                                         BytecodeFactIndex.InstructionEvidence evidence) {
        if (methodIdentity(owner, name, descriptor).equals(identity)) {
            return true;
        }
        return evidenceMatchesMethod(identity, evidence);
    }

    private static boolean evidenceMatchesMethod(String identity,
                                                 BytecodeFactIndex.InstructionEvidence evidence) {
        if (evidence == null) {
            return false;
        }
        return methodIdentity(evidence.className(), evidence.methodName(), evidence.methodDescriptor())
                .equals(identity);
    }

    private static String methodIdentity(String owner, String name, String descriptor) {
        return (owner == null ? "" : owner.replace('.', '/'))
                + "#" + (name == null ? "" : name)
                + (descriptor == null ? "" : descriptor);
    }

    private static void collectCfgSite(String needle, BytecodeFactIndex.InstructionEvidence evidence,
                                       List<CfgSite> sites) {
        if (evidence == null || evidence.bytecodeOffset() < 0) {
            return;
        }
        String hay = evidence.stableKey().toLowerCase(Locale.ROOT);
        if (!needle.isEmpty() && !hay.contains(needle)) {
            return;
        }
        sites.add(new CfgSite(evidence.bytecodeOffset(), evidence.stableKey()));
    }

    private static ArrayNode buildBasicBlocks(List<CfgSite> sortedSites) {
        ArrayNode blocks = DatasourceJson.JSON.createArrayNode();
        if (sortedSites == null || sortedSites.isEmpty()) {
            return blocks;
        }
        int blockStart = sortedSites.get(0).bci();
        int blockEnd = blockStart;
        List<String> refs = new ArrayList<>();
        refs.add(sortedSites.get(0).evidenceKey());
        int countInBlock = 1;
        for (int i = 1; i < sortedSites.size(); i++) {
            CfgSite site = sortedSites.get(i);
            boolean gapSplit = site.bci() - blockEnd > CFG_GAP_THRESHOLD;
            boolean sizeSplit = countInBlock >= CFG_BLOCK_CAPACITY;
            if ((gapSplit || sizeSplit) && blocks.size() < CFG_MAX_BLOCKS) {
                ObjectNode block = blocks.addObject();
                block.put("startBci", blockStart);
                block.put("endBci", blockEnd);
                ArrayNode evidenceRefs = block.putArray("evidenceRefs");
                for (String ref : refs) {
                    evidenceRefs.add(ref);
                }
                if (blocks.size() >= CFG_MAX_BLOCKS) {
                    return blocks;
                }
                blockStart = site.bci();
                blockEnd = site.bci();
                refs = new ArrayList<>();
                refs.add(site.evidenceKey());
                countInBlock = 1;
            } else {
                blockEnd = site.bci();
                refs.add(site.evidenceKey());
                countInBlock++;
            }
        }
        if (blocks.size() < CFG_MAX_BLOCKS) {
            ObjectNode block = blocks.addObject();
            block.put("startBci", blockStart);
            block.put("endBci", blockEnd);
            ArrayNode evidenceRefs = block.putArray("evidenceRefs");
            for (String ref : refs) {
                evidenceRefs.add(ref);
            }
        }
        return blocks;
    }

    private record CfgSite(int bci, String evidenceKey) {
        private CfgSite {
            evidenceKey = evidenceKey == null ? "" : evidenceKey;
        }
    }

    private static boolean isGuardSignal(String text) {
        if (text == null || text.isBlank()) {
            return false;
        }
        String upper = text.toUpperCase(Locale.ROOT);
        return upper.contains("PREAUTHORIZE")
                || upper.contains("PREAUTH")
                || upper.contains("FILTER")
                || upper.contains("INTERCEPTOR")
                || upper.contains("JWT")
                || upper.contains("HASROLE")
                || upper.contains("HAS_ROLE")
                || upper.contains("HASAUTHORITY")
                || upper.contains("SECURED")
                || upper.contains("ROLESALLOWED");
    }

    static String resolveCodeQueryKind(String kindArg, String query) {
        if (kindArg != null && !kindArg.isBlank()) {
            return normalizeKind(kindArg);
        }
        String fromQuery = extractQueryToken(query, "kind");
        if (!fromQuery.isBlank()) {
            return normalizeKind(fromQuery);
        }
        if (query != null && !query.isBlank()) {
            String upper = query.trim().toUpperCase(Locale.ROOT);
            if (upper.startsWith("TAINT_GRAPH")) return "TAINT_GRAPH";
            if (upper.startsWith("DATAFLOW_SLICE")) return "DATAFLOW_SLICE";
            if (upper.startsWith("METHOD_VIEW")) return "METHOD_VIEW";
            if (upper.startsWith("CALLERS")) return "CALLERS";
            if (upper.startsWith("CALLEES")) return "CALLEES";
            if (upper.startsWith("CFG_VIEW")) return "CFG_VIEW";
            if (upper.startsWith("GUARD_QUERY")) return "GUARD_QUERY";
            if (upper.startsWith("FIELD_USES")) return "FIELD_USES";
            if (upper.startsWith("CONFIG_SEARCH")) return "CONFIG_SEARCH";
            if (upper.startsWith("AUTH")) return "AUTH";
        }
        return "AUTH";
    }

    private static String normalizeKind(String raw) {
        String kind = raw == null ? "" : raw.trim().toUpperCase(Locale.ROOT).replace('-', '_');
        return switch (kind) {
            case "METHOD_VIEW", "CALLERS", "CALLEES", "CFG_VIEW", "DATAFLOW_SLICE",
                    "GUARD_QUERY", "FIELD_USES", "CONFIG_SEARCH", "AUTH", "TAINT_GRAPH" -> kind;
            default -> kind.isBlank() ? "AUTH" : kind;
        };
    }

    private static String stripKindPrefix(String query) {
        if (query == null || query.isBlank()) {
            return "";
        }
        String trimmed = query.trim();
        String lower = trimmed.toLowerCase(Locale.ROOT);
        if (lower.startsWith("kind=")) {
            int space = trimmed.indexOf(' ');
            return space < 0 ? "" : trimmed.substring(space + 1).trim();
        }
        for (String prefix : List.of(
                "TAINT_GRAPH", "DATAFLOW_SLICE", "METHOD_VIEW", "CALLERS", "CALLEES",
                "CFG_VIEW", "GUARD_QUERY", "FIELD_USES", "CONFIG_SEARCH", "AUTH")) {
            if (trimmed.regionMatches(true, 0, prefix, 0, prefix.length())) {
                String rest = trimmed.substring(prefix.length()).trim();
                if (rest.startsWith(":") || rest.startsWith("=")) {
                    rest = rest.substring(1).trim();
                }
                return rest;
            }
        }
        return trimmed;
    }

    static String extractQueryToken(String query, String key) {
        if (query == null || key == null) {
            return "";
        }
        String needle = key + "=";
        int at = query.indexOf(needle);
        if (at < 0) {
            at = query.toLowerCase(Locale.ROOT).indexOf(key.toLowerCase(Locale.ROOT) + "=");
            if (at < 0) {
                return "";
            }
            needle = query.substring(at, at + key.length() + 1);
        }
        String rest = query.substring(at + needle.length());
        int end = rest.length();
        for (int i = 0; i < rest.length(); i++) {
            char c = rest.charAt(i);
            if (c == ' ' || c == '&' || c == ',' || c == ';') {
                end = i;
                break;
            }
        }
        return rest.substring(0, end).trim();
    }
}
