package com.aq.jvmsentinel.ai.tool;

import com.aq.jvmsentinel.analysis.TaintGraph;
import com.aq.jvmsentinel.analysis.TaintGraphProjector;
import com.aq.jvmsentinel.analysis.contrast.ContrastLedger;
import com.aq.jvmsentinel.analysis.identity.AuthCodeQueryService;
import com.aq.jvmsentinel.analysis.kernel.CfgBuilder;
import com.aq.jvmsentinel.analysis.kernel.CfgGraph;
import com.aq.jvmsentinel.analysis.experiment.PathDebugWireHelper;
import com.aq.jvmsentinel.analysis.experiment.RuntimePostureOrchestrator;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.aq.jvmsentinel.model.ExperimentPlan;
import com.aq.jvmsentinel.domain.experiment.ExperimentPlanKind;
import com.aq.jvmsentinel.domain.experiment.HypothesisExperimentPlan;
import com.aq.jvmsentinel.worker.HypothesisExperimentPlanValidator;
import com.aq.jvmsentinel.model.StaticContrastRow;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Read-only projection of an already persisted scan. Default path never executes
 * artifacts; {@link #queryCode} may perform a bounded ZIP string/config scan of
 * the already-registered artifact (same trust boundary as synthetic identity harvest).
 */
public final class ControlPlaneToolDataSource implements ToolDataSource {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final int MAX_SQL_EVENTS_IN_FACT = 8;
    private static final int MAX_SQL_TEXT = 240;
    private static final int MAX_INSTRUCTION_SLICE = 64;
    /** Bounded pseudo-decompile lines for METHOD_VIEW (bci/opcode labels/evidence only). */
    private static final int MAX_PSEUDO_DECOMPILE_LINES = 48;
    private static final int CFG_GAP_THRESHOLD = 8;
    private static final int CFG_BLOCK_CAPACITY = 8;
    private static final int CFG_MAX_BLOCKS = 32;

    private final ControlPlaneStore store;
    private final String scanId;
    private final DynamicEvidenceSource dynamicEvidenceSource;
    private final DynamicProbeExecutor dynamicProbeExecutor;
    private final PathRunSource pathRunSource;
    private final ExperimentPlanAcceptor experimentPlanAcceptor;

    public ControlPlaneToolDataSource(ControlPlaneStore store, String scanId) {
        this(store, scanId, (projectId, artifactDigest, scopedScanId) -> List.of());
    }

    public ControlPlaneToolDataSource(ControlPlaneStore store, String scanId,
                                      DynamicEvidenceSource dynamicEvidenceSource) {
        this(store, scanId, dynamicEvidenceSource, (scopedScanId, scope, principalId, jobId, toolCallId,
                entrypointRef, candidateInputs, maxRequests, techniqueId, authorizationHeader, bladeAuthHeader,
                experimentPlanId) -> Optional.empty());
    }

    public ControlPlaneToolDataSource(ControlPlaneStore store, String scanId,
                                      DynamicEvidenceSource dynamicEvidenceSource,
                                      DynamicProbeExecutor dynamicProbeExecutor) {
        this(store, scanId, dynamicEvidenceSource, dynamicProbeExecutor,
                (projectId, artifactDigest, scopedScanId) -> List.of());
    }

    public ControlPlaneToolDataSource(ControlPlaneStore store, String scanId,
                                      DynamicEvidenceSource dynamicEvidenceSource,
                                      DynamicProbeExecutor dynamicProbeExecutor,
                                      PathRunSource pathRunSource) {
        this(store, scanId, dynamicEvidenceSource, dynamicProbeExecutor, pathRunSource,
                (scopedScanId, plan) -> { });
    }

    public ControlPlaneToolDataSource(ControlPlaneStore store, String scanId,
                                      DynamicEvidenceSource dynamicEvidenceSource,
                                      DynamicProbeExecutor dynamicProbeExecutor,
                                      PathRunSource pathRunSource,
                                      ExperimentPlanAcceptor experimentPlanAcceptor) {
        this.store = Objects.requireNonNull(store, "store");
        this.scanId = Objects.requireNonNull(scanId, "scanId");
        this.dynamicEvidenceSource = Objects.requireNonNull(dynamicEvidenceSource, "dynamicEvidenceSource");
        this.dynamicProbeExecutor = Objects.requireNonNull(dynamicProbeExecutor, "dynamicProbeExecutor");
        this.pathRunSource = Objects.requireNonNull(pathRunSource, "pathRunSource");
        this.experimentPlanAcceptor = Objects.requireNonNull(experimentPlanAcceptor, "experimentPlanAcceptor");
    }

    @Override
    public List<FactRecord> queryCode(ToolExecutionContext.Scope scope, String query, int limit) {
        return queryCode(scope, "", query, limit);
    }

    @Override
    public List<FactRecord> queryCode(ToolExecutionContext.Scope scope, String kind,
                                      String query, int limit) {
        ControlPlaneStore.ScanRecord scan = scopedScan(scope);
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
        ObjectNode summary = JSON.valueToTree(AuthCodeQueryService.toToolMap(result));
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
            if (records.size() >= limit) break;
            ObjectNode node = JSON.createObjectNode();
            node.put("id", fact.id());
            node.put("kind", kind);
            node.put("category", fact.category());
            node.put("summary", fact.summary());
            node.put("sourcePath", fact.sourcePath());
            node.put("classification", "FACT");
            node.put("verificationStatus", "STATIC_INFERRED");
            node.set("attributes", JSON.valueToTree(fact.attributes()));
            records.add(new FactRecord(scope, "code_query:" + fact.id(), node));
        }
        return List.copyOf(records);
    }

    private List<FactRecord> queryMethodView(ToolExecutionContext.Scope scope, String query, int limit) {
        Optional<IrProjection> ir = resolveIrProjection();
        if (ir.isEmpty() || ir.get().methods().isEmpty()) {
            return incompleteIr(scope, "METHOD_VIEW", irStopReason(ir), irCoverage(ir));
        }
        String needle = query == null ? "" : query.toLowerCase(Locale.ROOT).trim();
        List<BytecodeFactIndex.MethodFact> matches = new ArrayList<>();
        for (BytecodeFactIndex.MethodFact method : ir.get().methods()) {
            String hay = methodKey(method.owner(), method.name(), method.descriptor()).toLowerCase(Locale.ROOT);
            if (needle.isEmpty() || hay.contains(needle) || method.evidence().toLowerCase(Locale.ROOT).contains(needle)) {
                matches.add(method);
            }
        }
        ObjectNode summary = baseIrSummary("METHOD_VIEW", ir.get().coverageStatus(), null);
        summary.put("matchCount", matches.size());
        if (matches.isEmpty()) {
            summary.put("stopReason", "NO_MATCH");
            summary.put("coverageStatus", ir.get().coverageStatus());
        }
        ArrayNode methods = summary.putArray("methods");
        int emitted = 0;
        boolean anySlice = false;
        for (BytecodeFactIndex.MethodFact method : matches) {
            if (emitted >= Math.max(0, limit - 1)) break;
            ObjectNode row = methods.addObject();
            putMethod(row, method);
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
            if (records.size() >= limit) break;
            ObjectNode row = baseIrSummary("METHOD_VIEW", ir.get().coverageStatus(), null);
            putMethod(row, method);
            ArrayNode slice = putInstructionSlice(row, method, ir.get());
            putPseudoDecompile(row, method, slice);
            if (slice.isEmpty()) {
                row.put("stopReason", "SLICE_EMPTY");
            }
            records.add(new FactRecord(scope, "code_query:method:"
                    + methodKey(method.owner(), method.name(), method.descriptor()), row));
        }
        return List.copyOf(records);
    }

    private List<FactRecord> queryCallersOrCallees(ToolExecutionContext.Scope scope, String query,
                                                   int limit, boolean callers) {
        String kind = callers ? "CALLERS" : "CALLEES";
        Optional<IrProjection> ir = resolveIrProjection();
        if (ir.isEmpty() || (ir.get().callEdges().isEmpty() && ir.get().artifactCallGraph().isEmpty())) {
            String stop = irStopReason(ir);
            if (ir.isPresent() && !ir.get().methods().isEmpty()) {
                stop = "CALL_GRAPH_EMPTY";
            }
            return incompleteIr(scope, kind, stop, irCoverage(ir));
        }
        String needle = query == null ? "" : query.toLowerCase(Locale.ROOT).trim();
        ObjectNode summary = baseIrSummary(kind, ir.get().coverageStatus(), null);
        ArrayNode edges = summary.putArray("edges");
        int emitted = 0;
        if (!ir.get().artifactCallGraph().isEmpty()) {
            for (BytecodeFactIndex.ResolvedCallEdge edge : ir.get().artifactCallGraph()) {
                String target = methodKey(edge.targetOwner(), edge.targetName(), edge.targetDescriptor())
                        .toLowerCase(Locale.ROOT);
                String caller = methodKey(edge.callerOwner(), edge.callerName(), edge.callerDescriptor())
                        .toLowerCase(Locale.ROOT);
                boolean hit = callers
                        ? (needle.isEmpty() || target.contains(needle))
                        : (needle.isEmpty() || caller.contains(needle));
                if (!hit) continue;
                if (emitted >= Math.max(0, limit - 1)) break;
                ObjectNode row = edges.addObject();
                row.put("caller", methodKey(edge.callerOwner(), edge.callerName(), edge.callerDescriptor()));
                row.put("callee", methodKey(edge.targetOwner(), edge.targetName(), edge.targetDescriptor()));
                row.put("edgeKind", edge.kind().name());
                row.put("evidence", edge.evidence().stableKey());
                emitted++;
            }
        } else {
            for (BytecodeFactIndex.CallEdge edge : ir.get().callEdges()) {
                String target = methodKey(edge.targetOwner(), edge.targetName(), edge.targetDescriptor())
                        .toLowerCase(Locale.ROOT);
                String caller = methodKey(edge.callerOwner(), edge.callerName(), edge.callerDescriptor())
                        .toLowerCase(Locale.ROOT);
                boolean hit = callers
                        ? (needle.isEmpty() || target.contains(needle))
                        : (needle.isEmpty() || caller.contains(needle));
                if (!hit) continue;
                if (emitted >= Math.max(0, limit - 1)) break;
                ObjectNode row = edges.addObject();
                row.put("caller", methodKey(edge.callerOwner(), edge.callerName(), edge.callerDescriptor()));
                row.put("callee", methodKey(edge.targetOwner(), edge.targetName(), edge.targetDescriptor()));
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
        Optional<IrProjection> ir = resolveIrProjection();
        if (ir.isEmpty() || ir.get().memberAccesses().isEmpty()) {
            String stop = irStopReason(ir);
            if (ir.isPresent() && !ir.get().methods().isEmpty()) {
                stop = "MEMBER_ACCESSES_EMPTY";
            }
            return incompleteIr(scope, "FIELD_USES", stop, irCoverage(ir));
        }
        String needle = query == null ? "" : query.toLowerCase(Locale.ROOT).trim();
        ObjectNode summary = baseIrSummary("FIELD_USES", ir.get().coverageStatus(), null);
        ArrayNode uses = summary.putArray("uses");
        int emitted = 0;
        for (BytecodeFactIndex.MemberAccessFact access : ir.get().memberAccesses()) {
            String hay = (access.targetOwner() + "#" + access.targetName() + access.targetDescriptor()
                    + " " + access.kind().name()).toLowerCase(Locale.ROOT);
            if (!needle.isEmpty() && !hay.contains(needle)) continue;
            if (emitted >= Math.max(0, limit - 1)) break;
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
        Optional<IrProjection> ir = resolveIrProjection();
        if (ir.isEmpty()) {
            return incompleteIr(scope, "CFG_VIEW", "IR_NOT_PERSISTED", StaticFactSnapshot.LEGACY_INCOMPLETE);
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
            ObjectNode summary = baseIrSummary("CFG_VIEW", ir.get().coverageStatus(), null);
            summary.put("cfgProducer", "analysis.kernel.CfgBuilder");
            summary.put("matchCount", cfg.blocks().stream().mapToInt(block -> block.evidenceRefs().size()).sum());
            ArrayNode offsets = summary.putArray("bytecodeOffsets");
            ArrayNode keys = summary.putArray("evidenceKeys");
            int emitted = 0;
            for (var block : cfg.blocks()) {
                for (String ref : block.evidenceRefs()) {
                    if (emitted >= Math.max(1, limit)) break;
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
                if (emitted >= Math.max(1, limit)) break;
            }
            summary.set("basicBlocks", cfg.toBasicBlocksArray(JSON));
            summary.set("cfg", cfg.toJson(JSON));
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
            return incompleteIr(scope, "CFG_VIEW", "CFG_NOT_AVAILABLE", ir.get().coverageStatus());
        }
        sites.sort((a, b) -> Integer.compare(a.bci(), b.bci()));
        ObjectNode summary = baseIrSummary("CFG_VIEW", ir.get().coverageStatus(), null);
        summary.put("cfgProducer", "legacy-bci-gap");
        summary.put("matchCount", sites.size());
        ArrayNode offsets = summary.putArray("bytecodeOffsets");
        ArrayNode keys = summary.putArray("evidenceKeys");
        int emitted = 0;
        for (CfgSite site : sites) {
            if (emitted >= Math.max(1, limit)) break;
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
        Optional<IrProjection> ir = resolveIrProjection();
        String needle = query == null ? "" : query.toLowerCase(Locale.ROOT).trim();
        ObjectNode summary = baseIrSummary("GUARD_QUERY",
                ir.map(IrProjection::coverageStatus).orElse(StaticFactSnapshot.LEGACY_INCOMPLETE), null);
        ArrayNode signals = summary.putArray("signals");
        int emitted = 0;
        if (ir.isPresent()) {
            for (BytecodeFactIndex.MethodFact method : ir.get().methods()) {
                String hay = methodKey(method.owner(), method.name(), method.descriptor())
                        + " " + method.evidence();
                if (!isGuardSignal(hay)) continue;
                if (!needle.isEmpty() && !hay.toLowerCase(Locale.ROOT).contains(needle)) continue;
                if (emitted >= Math.max(0, limit - 1)) break;
                ObjectNode row = signals.addObject();
                row.put("source", "IR_METHOD");
                putMethod(row, method);
                row.put("classification", "FACT");
                emitted++;
            }
        }
        for (ApiDtos.EntryDto entry : scan.dto().entries()) {
            for (String precondition : entry.preconditions()) {
                if (!isGuardSignal(precondition)) continue;
                if (!needle.isEmpty() && !precondition.toLowerCase(Locale.ROOT).contains(needle)
                        && !(entry.declaringClass() != null
                        && entry.declaringClass().toLowerCase(Locale.ROOT).contains(needle))) {
                    continue;
                }
                if (emitted >= Math.max(0, limit - 1)) break;
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
                return incompleteIr(scope, "GUARD_QUERY", irStopReason(ir), irCoverage(ir));
            }
            summary.put("stopReason", "LEGACY_ENTRY_PRECONDITIONS_ONLY");
            summary.put("coverageStatus", StaticFactSnapshot.LEGACY_INCOMPLETE);
        } else if (emitted == 0) {
            summary.put("stopReason", "NO_MATCH");
        }
        return List.of(new FactRecord(scope, "code_query:guard-query", summary));
    }

    private static ArrayNode putInstructionSlice(ObjectNode row, BytecodeFactIndex.MethodFact method,
                                                 IrProjection ir) {
        ArrayNode slice = row.putArray("instructionSlice");
        String identity = methodIdentity(method.owner(), method.name(), method.descriptor());
        Set<String> seen = new LinkedHashSet<>();
        for (BytecodeFactIndex.CallEdge edge : ir.callEdges()) {
            if (!callerMatches(identity, edge.callerOwner(), edge.callerName(), edge.callerDescriptor(),
                    edge.evidence())) {
                continue;
            }
            String target = methodKey(edge.targetOwner(), edge.targetName(), edge.targetDescriptor());
            appendSliceItem(slice, seen, edge.evidence(), "edgeKind", edge.kind().name(),
                    edge.kind().name(), ir.coverageStatus(), "INVOKE", target);
        }
        for (BytecodeFactIndex.ResolvedCallEdge edge : ir.artifactCallGraph()) {
            if (!callerMatches(identity, edge.callerOwner(), edge.callerName(), edge.callerDescriptor(),
                    edge.evidence())) {
                continue;
            }
            String target = methodKey(edge.targetOwner(), edge.targetName(), edge.targetDescriptor());
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
        if (evidence == null || evidence.bytecodeOffset() < 0) return;
        if (slice.size() >= MAX_INSTRUCTION_SLICE) return;
        String key = evidence.stableKey();
        if (!seen.add(key)) return;
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

    /**
     * Bounded pseudo-decompile text from instructionSlice (bci/opcode/evidence).
     * Never reads host filesystem paths.
     */
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
        if (evidence == null) return false;
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
        if (evidence == null || evidence.bytecodeOffset() < 0) return;
        String hay = evidence.stableKey().toLowerCase(Locale.ROOT);
        if (!needle.isEmpty() && !hay.contains(needle)) return;
        sites.add(new CfgSite(evidence.bytecodeOffset(), evidence.stableKey()));
    }

    private static ArrayNode buildBasicBlocks(List<CfgSite> sortedSites) {
        ArrayNode blocks = JSON.createArrayNode();
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
        if (text == null || text.isBlank()) return false;
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

    private List<FactRecord> incompleteIr(ToolExecutionContext.Scope scope, String kind,
                                          String stopReason, String coverageStatus) {
        ObjectNode summary = baseIrSummary(kind, coverageStatus, stopReason);
        summary.put("matchCount", 0);
        return List.of(new FactRecord(scope,
                "code_query:" + kind.toLowerCase(Locale.ROOT), summary));
    }

    private static ObjectNode baseIrSummary(String kind, String coverageStatus, String stopReason) {
        ObjectNode summary = JSON.createObjectNode();
        summary.put("kind", kind);
        summary.put("classification", "FACT");
        summary.put("verificationStatus", "STATIC_INFERRED");
        summary.put("coverageStatus", coverageStatus == null
                ? StaticFactSnapshot.LEGACY_INCOMPLETE : coverageStatus);
        if (stopReason != null && !stopReason.isBlank()) {
            summary.put("stopReason", stopReason);
        }
        return summary;
    }

    private static void putMethod(ObjectNode row, BytecodeFactIndex.MethodFact method) {
        row.put("owner", method.owner());
        row.put("name", method.name());
        row.put("descriptor", method.descriptor());
        row.put("accessFlags", method.accessFlags());
        row.put("evidence", method.evidence());
        row.put("classification", "FACT");
        row.put("verificationStatus", "STATIC_INFERRED");
    }

    private static String methodKey(String owner, String name, String descriptor) {
        return (owner == null ? "" : owner.replace('/', '.'))
                + "#" + (name == null ? "" : name)
                + (descriptor == null ? "" : descriptor);
    }

    private static String resolveCodeQueryKind(String kindArg, String query) {
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
        if (query == null || query.isBlank()) return "";
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

    private Optional<IrProjection> resolveIrProjection() {
        Optional<StaticFactSnapshot> facts = store.staticFacts(scanId);
        if (facts.isEmpty()) {
            return Optional.empty();
        }
        StaticFactSnapshot snapshot = facts.get();
        BytecodeFactIndex index = snapshot.toBytecodeIndex();
        if (index.methods().isEmpty()
                && index.callEdges().isEmpty()
                && index.artifactCallGraph().isEmpty()
                && index.memberAccesses().isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new IrProjection(
                snapshot.coverageStatus(),
                index.methods(),
                index.callEdges(),
                index.artifactCallGraph(),
                index.memberAccesses()));
    }

    /** Used by AUTH gate: true when persisted facts expose a non-empty methods IR list. */
    public static boolean hasNonEmptyMethodsIr(StaticFactSnapshot snapshot) {
        return StaticFactSnapshot.hasNonEmptyMethodsIr(snapshot);
    }

    private static String irStopReason(Optional<IrProjection> ir) {
        if (ir.isEmpty()) return "IR_NOT_PERSISTED";
        if (ir.get().methods().isEmpty()) return "IR_NOT_PERSISTED";
        return "LEGACY_INCOMPLETE";
    }

    private static String irCoverage(Optional<IrProjection> ir) {
        return ir.map(IrProjection::coverageStatus).orElse(StaticFactSnapshot.LEGACY_INCOMPLETE);
    }

    private record IrProjection(
            String coverageStatus,
            List<BytecodeFactIndex.MethodFact> methods,
            List<BytecodeFactIndex.CallEdge> callEdges,
            List<BytecodeFactIndex.ResolvedCallEdge> artifactCallGraph,
            List<BytecodeFactIndex.MemberAccessFact> memberAccesses) {
        private IrProjection {
            coverageStatus = coverageStatus == null
                    ? StaticFactSnapshot.LEGACY_INCOMPLETE : coverageStatus;
            methods = List.copyOf(methods == null ? List.of() : methods);
            callEdges = List.copyOf(callEdges == null ? List.of() : callEdges);
            artifactCallGraph = List.copyOf(artifactCallGraph == null ? List.of() : artifactCallGraph);
            memberAccesses = List.copyOf(memberAccesses == null ? List.of() : memberAccesses);
        }
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
        if (filter.isBlank()) filter = extractQueryToken(query, "entryId");
        if (filter.isBlank()) filter = extractQueryToken(query, "nodeId");
        TaintGraph graph = TaintGraphProjector.subgraph(full, filter);
        ObjectNode summary = JSON.createObjectNode();
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
            if (emitted >= limit) break;
            ObjectNode n = JSON.createObjectNode();
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

    private static String extractQueryToken(String query, String key) {
        if (query == null || key == null) return "";
        String needle = key + "=";
        int at = query.indexOf(needle);
        if (at < 0) {
            at = query.toLowerCase(Locale.ROOT).indexOf(key.toLowerCase(Locale.ROOT) + "=");
            if (at < 0) return "";
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

    @Override
    public List<FactRecord> searchFacts(ToolExecutionContext.Scope scope, String kind,
                                        String query, int limit) {
        rejectPathTracePolicyOverrides(query);
        ControlPlaneStore.ScanRecord scan = scopedScan(scope);
        String requested = kind.toUpperCase(Locale.ROOT);
        String needle = query == null ? "" : query.toLowerCase(Locale.ROOT);
        List<FactRecord> result = new ArrayList<>();
        if ("SCAN".equals(requested) || "METADATA".equals(requested) || "ANY".equals(requested)) {
            addIfMatching(result, scope, "scan:" + scan.dto().scanId(),
                    JSON.valueToTree(scan.dto()), needle, limit);
        }
        if ("ENTRY".equals(requested) || "ENTRYPOINT".equals(requested) || "ANY".equals(requested)) {
            for (ApiDtos.EntryDto value : scan.dto().entries()) {
                addIfMatching(result, scope, "entry:" + value.id(), JSON.valueToTree(value), needle, limit);
            }
        }
        if ("DEPENDENCY".equals(requested) || "ANY".equals(requested)) {
            for (ApiDtos.DependencyDto value : scan.dto().dependencies()) {
                addIfMatching(result, scope, "dependency:" + value.id(), JSON.valueToTree(value), needle, limit);
            }
        }
        if ("SINK".equals(requested) || "ANY".equals(requested)) {
            for (ApiDtos.SinkDto value : scan.dto().sinks()) {
                addIfMatching(result, scope, "sink:" + value.id(), JSON.valueToTree(value), needle, limit);
            }
        }
        if ("PATH_RUN".equals(requested) || "PATHRUN".equals(requested) || "ANY".equals(requested)) {
            for (ApiDtos.PathRunDto value : pathRuns(scan)) {
                addIfMatching(result, scope, "pathrun:" + value.pathRunId(), pathRunFact(value), needle, limit);
            }
        }
        if ("PATH_TRACE".equals(requested) || "PATHTRACE".equals(requested) || "ANY".equals(requested)) {
            for (PathTrace trace : pathTraces(scan)) {
                addIfMatching(result, scope, "pathtrace:" + trace.pathTraceId(),
                        pathTraceFact(trace), needle, limit);
            }
        }
        if ("STATIC_CONTRAST".equals(requested) || "CONTRAST".equals(requested) || "ANY".equals(requested)) {
            ContrastLedger.Ledger ledger = ContrastLedger.build(
                    scan.dto().entries(), scan.dto().sinks(), scan.evidence(), pathRuns(scan),
                    StaticFactSnapshot.resolveContrastTaintPaths(
                            store.staticFacts(scanId), scan.dto().sinks()));
            for (StaticContrastRow row : ledger.rows()) {
                addIfMatching(result, scope, "contrast:" + row.rowId(),
                        ContrastLedger.toFactNode(row), needle, limit);
            }
        }
        if ("EVIDENCE".equals(requested) || "FACT".equals(requested) || "ANY".equals(requested)) {
            for (ApiDtos.EvidenceDto value : scan.evidence().values()) {
                addIfMatching(result, scope, value.evidenceId(), safeEvidence(value), needle, limit);
            }
            for (ApiDtos.EvidenceDto value : dynamicEvidence(scan)) {
                addIfMatching(result, scope, value.evidenceId(), safeEvidence(value), needle, limit);
            }
        }
        if ("DYNAMIC_EVIDENCE".equals(requested) || "RUNTIME_EVIDENCE".equals(requested)) {
            for (ApiDtos.EvidenceDto value : dynamicEvidence(scan)) {
                addIfMatching(result, scope, value.evidenceId(), safeEvidence(value), needle, limit);
            }
        }
        return List.copyOf(result);
    }

    @Override
    public Optional<FactRecord> findEvidence(ToolExecutionContext.Scope scope, String evidenceRef) {
        ControlPlaneStore.ScanRecord scan = scopedScan(scope);
        ApiDtos.EvidenceDto value = scan.evidence().get(evidenceRef);
        if (value != null) {
            return Optional.of(new FactRecord(scope, value.evidenceId(), safeEvidence(value)));
        }
        Optional<ApiDtos.EvidenceDto> dynamic = dynamicEvidence(scan).stream()
                .filter(item -> item.evidenceId().equals(evidenceRef)).findFirst();
        if (dynamic.isPresent()) {
            return Optional.of(new FactRecord(scope, evidenceRef, safeEvidence(dynamic.get())));
        }
        EntryRefResolver.Resolution resolution = EntryRefResolver.resolve(scan.dto().entries(), evidenceRef);
        if (resolution.resolved()) {
            return Optional.of(new FactRecord(scope, resolution.canonicalRef(),
                    JSON.valueToTree(resolution.entry())));
        }
        if (evidenceRef != null && evidenceRef.startsWith("pathrun:")) {
            String id = evidenceRef.substring("pathrun:".length());
            return pathRuns(scan).stream().filter(run -> run.pathRunId().equals(id)).findFirst()
                    .map(run -> new FactRecord(scope, evidenceRef, pathRunFact(run)));
        }
        if (evidenceRef != null && evidenceRef.startsWith("pathtrace:")) {
            String id = evidenceRef.substring("pathtrace:".length());
            return pathTraces(scan).stream().filter(trace -> trace.pathTraceId().equals(id)).findFirst()
                    .map(trace -> new FactRecord(scope, evidenceRef, pathTraceFact(trace)));
        }
        return Optional.empty();
    }

    @Override
    public Optional<FactRecord> resolveEntrypoint(ToolExecutionContext.Scope scope, String entrypointRef) {
        ControlPlaneStore.ScanRecord scan = scopedScan(scope);
        EntryRefResolver.Resolution resolution = EntryRefResolver.resolve(scan.dto().entries(), entrypointRef);
        if (!resolution.resolved()) {
            if (resolution.status() == EntryRefResolver.Status.AMBIGUOUS) {
                throw new IllegalArgumentException(EntryRefResolver.CODE_AMBIGUOUS);
            }
            if (resolution.status() == EntryRefResolver.Status.MUST_BE_ENTRY) {
                throw new IllegalArgumentException(EntryRefResolver.CODE_MUST_BE_ENTRY);
            }
            return Optional.empty();
        }
        return Optional.of(new FactRecord(scope, resolution.canonicalRef(),
                JSON.valueToTree(resolution.entry())));
    }

    @Override
    public Optional<FactRecord> requestSandboxProbe(ToolExecutionContext.Scope scope,
                                                    String principalId, String jobId,
                                                    String toolCallId,
                                                    String entrypointRef,
                                                    List<String> candidateInputs,
                                                    int maxRequests,
                                                    String techniqueId,
                                                    String authorizationHeader,
                                                    String bladeAuthHeader,
                                                    String experimentPlanId) throws Exception {
        ControlPlaneStore.ScanRecord scan = scopedScan(scope);
        ApiDtos.EntryDto entry = requireProbeEntry(scan, entrypointRef);
        if (!"HTTP".equalsIgnoreCase(entry.protocol()) || entry.route() == null || entry.method() == null) {
            throw new IllegalArgumentException("sandbox probe entry is not an eligible HTTP endpoint");
        }
        String canonical = EntryRefResolver.canonicalRef(entry);
        return dynamicProbeExecutor.request(scanId, scope, principalId, jobId, toolCallId, canonical,
                candidateInputs == null ? List.of() : List.copyOf(candidateInputs), maxRequests,
                techniqueId, authorizationHeader, bladeAuthHeader, experimentPlanId);
    }

    @Override
    public List<String> coverageGapIds(ToolExecutionContext.Scope scope) {
        ControlPlaneStore.ScanRecord scan = scopedScan(scope);
        List<ApiDtos.PathRunDto> pathRuns;
        try {
            pathRuns = pathRunSource.pathRunsForScan(
                    scan.dto().projectId(), scan.dto().artifactDigest(), scanId);
        } catch (RuntimeException ignored) {
            pathRuns = List.of();
        }
        ContrastLedger.Ledger ledger = ContrastLedger.build(
                scan.dto().entries(),
                scan.dto().sinks(),
                scan.evidence(),
                pathRuns,
                StaticFactSnapshot.resolveTaintPaths(store.staticFacts(scanId), scan.dto().sinks()));
        List<com.aq.jvmsentinel.analysis.CoverageGapProjector.CoverageGap> gaps =
                com.aq.jvmsentinel.analysis.CoverageGapProjector.project(
                        StaticFactSnapshot.resolveTaintPaths(store.staticFacts(scanId), scan.dto().sinks()),
                        ledger.rows(), scan.dto().entries());
        List<String> ids = new ArrayList<>();
        for (var gap : gaps) {
            if (gap.taintPathId() != null && !gap.taintPathId().isBlank()) {
                ids.add(gap.taintPathId());
            }
        }
        return List.copyOf(ids);
    }

    @Override
    public void validateHypothesisBinding(ToolExecutionContext.Scope scope,
                                           String hypothesisId,
                                           String planKind,
                                           String experimentPlanId,
                                           String entrypointRef) {
        ControlPlaneStore.ScanRecord scan = scopedScan(scope);
        String requestedHypothesis = hypothesisId == null ? "" : hypothesisId.trim();
        String requestedPlan = experimentPlanId == null ? "" : experimentPlanId.trim();
        String requestedKind = planKind == null ? "" : planKind.trim();
        if (requestedHypothesis.isBlank() && requestedPlan.isBlank()) return;
        if (requestedHypothesis.isBlank() || requestedKind.isBlank()) {
            throw new SecurityException("HYPOTHESIS_BINDING_INCOMPLETE");
        }
        var hypothesis = store.hypothesis(requestedHypothesis);
        if (hypothesis == null || !scan.dto().scanId().equals(hypothesis.scanId())) {
            throw new SecurityException("HYPOTHESIS_SCOPE_MISMATCH");
        }
        ExperimentPlanKind kind = HypothesisExperimentPlanValidator.requirePlanKind(requestedKind);
        if (!requestedPlan.isBlank()) {
            HypothesisExperimentPlan plan = store.hypothesisExperimentPlan(requestedPlan);
            if (plan == null || !scan.dto().scanId().equals(plan.scanId())
                    || !requestedHypothesis.equals(plan.hypothesisId())
                    || plan.planKind() != kind) {
                throw new SecurityException("EXPERIMENT_PLAN_SCOPE_MISMATCH");
            }
            if (!plan.entrypointRef().isBlank()) {
                EntryRefResolver.Resolution planned = EntryRefResolver.resolve(scan.dto().entries(), plan.entrypointRef());
                EntryRefResolver.Resolution requested = EntryRefResolver.resolve(scan.dto().entries(), entrypointRef);
                if (!planned.resolved() || !requested.resolved()
                        || !planned.canonicalRef().equals(requested.canonicalRef())) {
                    throw new SecurityException("EXPERIMENT_PLAN_ENTRYPOINT_MISMATCH");
                }
            }
        }
    }
    @Override
    public void acceptExperimentPlan(ToolExecutionContext.Scope scope, ExperimentPlan plan) {
        scopedScan(scope);
        experimentPlanAcceptor.accept(scanId, plan);
    }

    private ControlPlaneStore.ScanRecord scopedScan(ToolExecutionContext.Scope scope) {
        if (!"local".equals(scope.workspaceId())) throw new SecurityException("workspace scope mismatch");
        ControlPlaneStore.ScanRecord scan = store.requireScan(scanId);
        if (!scope.projectId().equals(scan.dto().projectId())) {
            throw new SecurityException("project scope mismatch");
        }
        return scan;
    }

    private List<ApiDtos.EvidenceDto> dynamicEvidence(ControlPlaneStore.ScanRecord scan) {
        ApiDtos.ScanDto dto = scan.dto();
        List<ApiDtos.EvidenceDto> values = List.copyOf(dynamicEvidenceSource.evidenceForScan(
                dto.projectId(), dto.artifactDigest(), dto.scanId()));
        if (values.size() > 10_000 || values.stream().anyMatch(value ->
                !dto.projectId().equals(value.projectId())
                        || !dto.artifactDigest().equals(value.artifactDigest())
                        || !dto.scanId().equals(value.scanId()))) {
            throw new SecurityException("dynamic evidence scope mismatch");
        }
        return values;
    }

    private List<ApiDtos.PathRunDto> pathRuns(ControlPlaneStore.ScanRecord scan) {
        ApiDtos.ScanDto dto = scan.dto();
        List<ApiDtos.PathRunDto> values = List.copyOf(pathRunSource.pathRunsForScan(
                dto.projectId(), dto.artifactDigest(), dto.scanId()));
        if (values.size() > 50_000 || values.stream().anyMatch(value -> !dto.scanId().equals(value.scanId()))) {
            throw new SecurityException("path run scope mismatch");
        }
        return values;
    }

    private List<PathTrace> pathTraces(ControlPlaneStore.ScanRecord scan) {
        ApiDtos.ScanDto dto = scan.dto();
        List<PathTrace> traces = new ArrayList<>();
        for (SQLiteControlPlanePersistence.PathTraceData row : store.loadPathTracesForScan(
                dto.projectId(), dto.artifactDigest(), dto.scanId())) {
            PathTrace cached = store.pathTraceForPathRun(row.pathRunId());
            if (cached != null) {
                traces.add(cached);
                continue;
            }
            try {
                traces.add(PathTrace.fromMap(JsonCodec.parseObject(row.payloadJson())));
            } catch (RuntimeException ignored) {
                // skip malformed rows
            }
        }
        return List.copyOf(traces);
    }

    private static void rejectPathTracePolicyOverrides(String query) {
        if (query == null || query.isBlank()) {
            return;
        }
        Map<String, String> probe = new LinkedHashMap<>();
        for (String token : query.split("[;&]")) {
            int eq = token.indexOf('=');
            if (eq <= 0) continue;
            probe.put(token.substring(0, eq).trim(), token.substring(eq + 1).trim());
        }
        try {
            RuntimePostureOrchestrator.authorizeForcedReachability(true, false, probe);
        } catch (SecurityException denied) {
            throw denied;
        }
        String lower = query.toLowerCase(Locale.ROOT);
        for (String forbidden : List.of("forcedreachability", "forcedguardrefs", "command=", "image=",
                "mount=", "network=", "uid=", "budget=")) {
            if (lower.contains(forbidden)) {
                throw new SecurityException("CLIENT_POLICY_OVERRIDE_DENIED:" + forbidden);
            }
        }
    }

    private static JsonNode pathTraceFact(PathTrace trace) {
        ObjectNode node = JSON.createObjectNode();
        node.put("kind", "PATH_TRACE");
        node.put("pathTraceId", trace.pathTraceId());
        node.put("pathRunId", trace.pathRunId());
        node.put("entryRef", trace.entryRef());
        node.put("track", trace.track());
        node.put("postureKind", trace.posture().postureKind().name());
        node.put("postureProvenance", trace.posture().postureProvenance());
        node.put("exitReason", trace.exitReason().name());
        node.put("lastBusinessHop", trace.lastBusinessHop());
        node.put("legacyIncomplete", trace.legacyIncomplete());
        node.put("authRequirement", com.aq.jvmsentinel.analysis.experiment.PathTraceProjector
                .authRequirementFor(trace, -1));
        ArrayNode effects = node.putArray("effectRefs");
        for (String ref : trace.effectRefs()) effects.add(ref);
        ArrayNode flow = node.putArray("parameterFlow");
        for (PathTrace.ParameterFlowStep step : trace.parameterFlow()) {
            ObjectNode row = flow.addObject();
            row.put("source", step.source());
            row.put("boundTo", step.boundTo());
            row.put("flowedTo", step.flowedTo());
            row.put("effectRef", step.effectRef());
        }
        return node;
    }

    private static ApiDtos.EntryDto requireProbeEntry(ControlPlaneStore.ScanRecord scan, String entrypointRef) {
        EntryRefResolver.Resolution resolution = EntryRefResolver.resolve(scan.dto().entries(), entrypointRef);
        if (resolution.resolved()) {
            return resolution.entry();
        }
        throw new IllegalArgumentException(resolution.code());
    }

    private static JsonNode pathRunFact(ApiDtos.PathRunDto value) {
        ObjectNode node = JSON.createObjectNode();
        node.put("kind", "PATH_RUN");
        node.put("pathRunId", value.pathRunId());
        node.put("scanId", value.scanId());
        node.put("entrypointRef", value.entrypointRef());
        node.put("track", value.track());
        node.put("attemptId", value.attemptId());
        if (value.experimentPlanId() != null && !value.experimentPlanId().isBlank()) {
            node.put("experimentPlanId", value.experimentPlanId());
        }
        node.put("method", value.method());
        node.put("contentType", value.contentType());
        node.put("requestSummary", value.requestSummary());
        node.put("outcomeClass", value.outcomeClass());
        node.put("httpStatus", value.httpStatus());
        if (value.entryHit() != null) node.put("entryHit", value.entryHit());
        if (value.parameterBound() != null) node.put("parameterBound", value.parameterBound());
        node.put("stopReason", value.stopReason());
        node.put("verificationStatus", value.verificationStatus());
        node.put("identityProvenance", value.identityProvenance());
        node.put("identityPrecondition", value.identityPrecondition());
        ArrayNode evidenceRefs = node.putArray("evidenceRefs");
        for (String ref : value.evidenceRefs()) evidenceRefs.add(ref);
        ArrayNode sqlEvents = node.putArray("sqlEvents");
        int emitted = 0;
        for (ApiDtos.SqlEventDto sql : value.sqlEvents()) {
            if (emitted >= MAX_SQL_EVENTS_IN_FACT) break;
            ObjectNode row = sqlEvents.addObject();
            String sqlText = sql.sqlText() == null ? "" : sql.sqlText();
            if (sqlText.length() > MAX_SQL_TEXT) sqlText = sqlText.substring(0, MAX_SQL_TEXT);
            row.put("sqlText", sqlText);
            row.put("parameterSummary", sql.parameterSummary() == null ? "" : sql.parameterSummary());
            row.put("readWrite", sql.readWrite());
            row.put("parameterized", sql.parameterized());
            row.put("maliciousFragmentPresent", sql.maliciousFragmentPresent());
            row.put("captureMode", sql.captureMode());
            emitted++;
        }
        node.put("sqlEventCount", value.sqlEvents().size());
        node.put("sqlEventsTruncated", value.sqlEvents().size() > MAX_SQL_EVENTS_IN_FACT);
        return node;
    }

    private static JsonNode safeEvidence(ApiDtos.EvidenceDto value) {
        // Only the bounded evidence summary and provenance metadata cross the tool boundary.
        return JSON.createObjectNode()
                .put("evidenceId", value.evidenceId())
                .put("projectId", value.projectId())
                .put("artifactDigest", value.artifactDigest())
                .put("scanId", value.scanId())
                .put("provenanceKind", value.provenanceKind())
                .put("source", value.source())
                .put("summary", value.summary())
                .put("verificationStatus", value.verificationStatus())
                .put("dependencyMode", value.dependencyMode());
    }

    private static void addIfMatching(List<FactRecord> result, ToolExecutionContext.Scope scope,
                                      String reference, JsonNode value, String needle, int limit) {
        if (result.size() >= limit) return;
        String searchable = value.toString().toLowerCase(Locale.ROOT);
        if (needle.isEmpty() || searchable.contains(needle)) {
            result.add(new FactRecord(scope, reference, value));
        }
    }

    /** Compact HTTP/SQL digest used when injecting PathRuns into AI prompts. */
    public static Map<String, Object> pathRunPromptSummary(ApiDtos.PathRunDto value) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("pathRunId", value.pathRunId());
        row.put("entrypointRef", value.entrypointRef());
        row.put("track", value.track());
        row.put("method", value.method());
        row.put("httpStatus", value.httpStatus());
        row.put("outcomeClass", value.outcomeClass());
        row.put("verificationStatus", value.verificationStatus());
        row.put("requestSummary", truncate(value.requestSummary(), 160));
        row.put("sqlEventCount", value.sqlEvents().size());
        List<Map<String, Object>> sql = new ArrayList<>();
        int emitted = 0;
        for (ApiDtos.SqlEventDto event : value.sqlEvents()) {
            if (emitted >= 3) break;
            Map<String, Object> sqlRow = new LinkedHashMap<>();
            sqlRow.put("readWrite", event.readWrite());
            sqlRow.put("captureMode", event.captureMode());
            sqlRow.put("maliciousFragmentPresent", event.maliciousFragmentPresent());
            sqlRow.put("sqlText", truncate(event.sqlText(), 120));
            sql.add(sqlRow);
            emitted++;
        }
        row.put("sqlEvents", sql);
        return row;
    }

    private static String truncate(String value, int max) {
        if (value == null) return "";
        return value.length() <= max ? value : value.substring(0, max);
    }

    @FunctionalInterface
    public interface DynamicEvidenceSource {
        List<ApiDtos.EvidenceDto> evidenceForScan(
                String projectId, String artifactDigest, String scanId);
    }

    @FunctionalInterface
    public interface DynamicProbeExecutor {
        Optional<FactRecord> request(String scanId, ToolExecutionContext.Scope scope, String principalId,
                                     String jobId, String toolCallId,
                                     String entrypointRef, List<String> candidateInputs, int maxRequests,
                                     String techniqueId, String authorizationHeader, String bladeAuthHeader,
                                     String experimentPlanId)
                throws Exception;
    }

    @FunctionalInterface
    public interface PathRunSource {
        List<ApiDtos.PathRunDto> pathRunsForScan(
                String projectId, String artifactDigest, String scanId);
    }

    @FunctionalInterface
    public interface ExperimentPlanAcceptor {
        void accept(String scanId, ExperimentPlan plan);
    }
}
