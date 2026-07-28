package com.aq.jvmsentinel.analysis.ir;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.domain.ir.EdgeKind;
import com.aq.jvmsentinel.domain.ir.EffectNode;
import com.aq.jvmsentinel.domain.ir.EntryNode;
import com.aq.jvmsentinel.domain.ir.EvidenceGraph;
import com.aq.jvmsentinel.domain.ir.GuardNode;
import com.aq.jvmsentinel.domain.ir.IrEdge;
import com.aq.jvmsentinel.domain.ir.IrNode;
import com.aq.jvmsentinel.domain.ir.ProgramNode;
import com.aq.jvmsentinel.domain.ir.ResourceNode;
import com.aq.jvmsentinel.domain.ir.RuntimeObservationNode;
import com.aq.jvmsentinel.domain.ir.StableNodeIds;
import com.aq.jvmsentinel.domain.ir.StateNode;
import com.aq.jvmsentinel.domain.ir.TrustBoundaryNode;
import com.aq.jvmsentinel.model.BytecodeFactIndex;

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
 * Compatible projection of existing scan facts into a minimal {@link EvidenceGraph}.
 * Does not mutate {@link StaticFactSnapshot} persistence; reads only.
 */
public final class EvidenceGraphProjector {
    private EvidenceGraphProjector() {
    }

    public static EvidenceGraph fromScan(
            String scanId,
            Optional<StaticFactSnapshot> facts,
            List<ApiDtos.EntryDto> entries,
            List<ApiDtos.SinkDto> sinks,
            List<ApiDtos.DependencyDto> dependencies,
            List<SecurityHypothesis> hypotheses,
            List<ApiDtos.FindingDto> findings,
            List<ApiDtos.PathRunDto> pathRuns) {
        return fromScan(
                scanId, facts, entries, sinks, dependencies, hypotheses, findings, pathRuns,
                EvidenceGraph.DEFAULT_MAX_NODES, EvidenceGraph.DEFAULT_MAX_EDGES);
    }

    public static EvidenceGraph fromScan(
            String scanId,
            Optional<StaticFactSnapshot> facts,
            List<ApiDtos.EntryDto> entries,
            List<ApiDtos.SinkDto> sinks,
            List<ApiDtos.DependencyDto> dependencies,
            List<SecurityHypothesis> hypotheses,
            List<ApiDtos.FindingDto> findings,
            List<ApiDtos.PathRunDto> pathRuns,
            int maxNodes,
            int maxEdges) {
        Objects.requireNonNull(scanId, "scanId");
        if (scanId.isBlank()) throw new IllegalArgumentException("scanId must not be blank");
        int nodeCap = Math.max(1, maxNodes);
        int edgeCap = Math.max(1, maxEdges);

        Builder builder = new Builder(nodeCap, edgeCap);
        List<ApiDtos.EntryDto> entryList = entries == null ? List.of() : entries;
        List<ApiDtos.SinkDto> sinkList = sinks == null ? List.of() : sinks;
        List<ApiDtos.DependencyDto> depList = dependencies == null ? List.of() : dependencies;
        List<SecurityHypothesis> hypList = hypotheses == null ? List.of() : hypotheses;
        List<ApiDtos.FindingDto> findingList = findings == null ? List.of() : findings;
        List<ApiDtos.PathRunDto> runList = pathRuns == null ? List.of() : pathRuns;
        StaticFactSnapshot snapshot = facts == null ? null : facts.orElse(null);

        List<String> filteredAuthEntries = new ArrayList<>();
        List<String> gapNotes = new ArrayList<>();
        int entryNodeCount = 0;

        for (ApiDtos.EntryDto entry : entryList) {
            if (entry == null) continue;
            if (isAuthFilterEntry(entry)) {
                filteredAuthEntries.add(entry.id());
                String guardId = StableNodeIds.guard("auth-entry:" + entry.id());
                builder.addNode(new GuardNode(
                        guardId, "AUTH_ENTRY", entry.route(),
                        "", entry.evidenceRefs(), "FACT"));
                continue;
            }
            String entryNodeId = StableNodeIds.entry(entry.id());
            if (builder.addNode(new EntryNode(
                    entryNodeId, entry.protocol(), entry.method(), entry.route(),
                    entry.declaringClass(), entry.parameters(), entry.evidenceRefs(),
                    "FACT", entry.verificationStatus()))) {
                entryNodeCount++;
            }
            projectEntryAttachments(builder, entry, entryNodeId);
            if (entry.declaringClass() != null && !entry.declaringClass().isBlank()) {
                String classId = StableNodeIds.programClass(entry.declaringClass());
                builder.addNode(new ProgramNode(
                        classId, "CLASS", "JVM", entry.declaringClass(), "",
                        entry.evidenceRefs(), "FACT", Map.of()));
                builder.addEdge(EdgeKind.CALL, entryNodeId, classId, entry.evidenceRefs(), "FACT");
            }
        }

        if (!filteredAuthEntries.isEmpty()) {
            gapNotes.add("AUTH EntryDto rows projected as GuardNode, not EntryNode");
        }

        Map<String, String> sinkEffectIds = new LinkedHashMap<>();
        for (ApiDtos.SinkDto sink : sinkList) {
            if (sink == null) continue;
            boolean authGap = sink.category() != null
                    && ("AUTH_GAP".equalsIgnoreCase(sink.category())
                    || "AUTH".equalsIgnoreCase(sink.category()));
            String effectId = StableNodeIds.effect(sink.id());
            sinkEffectIds.put(sink.id(), effectId);
            builder.addNode(new EffectNode(
                    effectId, sink.category(), sink.symbol(), sink.source(),
                    sink.evidenceRefs(), authGap ? "INFERENCE" : "FACT",
                    sink.verificationStatus()));
            if (authGap) {
                String guardId = StableNodeIds.guard("missing:" + sink.id());
                builder.addNode(new GuardNode(
                        guardId, "AUTH_GAP", "missing-auth-guard", effectId,
                        sink.evidenceRefs(), "INFERENCE"));
                builder.addEdge(EdgeKind.GUARD, effectId, guardId, sink.evidenceRefs(), "INFERENCE");
            }
            linkSourceToEffect(builder, entryList, sink, effectId);
        }

        for (ApiDtos.DependencyDto dep : depList) {
            if (dep == null) continue;
            builder.addNode(new ResourceNode(
                    StableNodeIds.resource(dep.id()), dep.kind(), dep.target(),
                    dep.accessType(), dep.evidenceRefs(), "FACT"));
        }

        projectStaticFacts(builder, snapshot);
        projectHypotheses(builder, hypList, sinkEffectIds);
        projectFindings(builder, findingList, sinkEffectIds);
        projectPathRuns(builder, runList);

        if (builder.truncated) {
            gapNotes.add("graph truncated at maxNodes=" + nodeCap + " maxEdges=" + edgeCap);
        }

        EvidenceGraph.CompatibilityGap gap = new EvidenceGraph.CompatibilityGap(
                entryList.size(),
                entryNodeCount,
                filteredAuthEntries,
                gapNotes);

        return new EvidenceGraph(
                EvidenceGraph.SCHEMA_VERSION,
                scanId,
                builder.nodes(),
                builder.edges(),
                builder.truncated,
                nodeCap,
                edgeCap,
                builder.truncated ? "NODE_OR_EDGE_BUDGET" : "",
                gap);
    }

    private static void projectEntryAttachments(Builder builder, ApiDtos.EntryDto entry, String entryNodeId) {
        for (String param : entry.parameters() == null ? List.<String>of() : entry.parameters()) {
            if (param == null || param.isBlank()) continue;
            String trustId = StableNodeIds.trust(entry.id(), param);
            builder.addNode(new TrustBoundaryNode(
                    trustId, "PARAMETER", param, entryNodeId, entry.evidenceRefs(), "FACT"));
            builder.addEdge(EdgeKind.DATA, trustId, entryNodeId, entry.evidenceRefs(), "FACT");
        }
        for (String precondition : entry.preconditions() == null ? List.<String>of() : entry.preconditions()) {
            if (precondition == null || precondition.isBlank()) continue;
            String upper = precondition.trim().toUpperCase(Locale.ROOT);
            if (upper.startsWith("ROLE=") || upper.startsWith("TENANT=") || upper.startsWith("AUTH")) {
                String guardId = StableNodeIds.guard(entry.id() + ":" + StableNodeIds.fingerprint(precondition));
                builder.addNode(new GuardNode(
                        guardId, upper.startsWith("TENANT=") ? "TENANT" : "AUTH",
                        precondition, entryNodeId, entry.evidenceRefs(), "FACT"));
                builder.addEdge(EdgeKind.GUARD, entryNodeId, guardId, entry.evidenceRefs(), "FACT");
            } else if (upper.startsWith("STATE=")) {
                String stateKey = precondition.substring(precondition.indexOf('=') + 1).trim();
                String stateId = StableNodeIds.state(entry.id(), stateKey.isBlank() ? "state" : stateKey);
                builder.addNode(new StateNode(
                        stateId, stateKey, entryNodeId, entry.evidenceRefs(), "FACT"));
                builder.addEdge(EdgeKind.STATE, entryNodeId, stateId, entry.evidenceRefs(), "FACT");
            }
        }
    }

    private static void linkSourceToEffect(
            Builder builder, List<ApiDtos.EntryDto> entries, ApiDtos.SinkDto sink, String effectId) {
        String source = sink.source() == null ? "" : sink.source().trim();
        if (source.isBlank()) return;
        for (ApiDtos.EntryDto entry : entries) {
            if (entry == null || isAuthFilterEntry(entry)) continue;
            boolean match = source.equals(entry.id())
                    || source.equals(entry.route())
                    || (entry.route() != null && source.contains(entry.route()))
                    || source.contains(entry.declaringClass() == null ? "\0" : entry.declaringClass());
            if (!match) continue;
            String entryNodeId = StableNodeIds.entry(entry.id());
            Set<String> refs = new LinkedHashSet<>(sink.evidenceRefs());
            refs.addAll(entry.evidenceRefs());
            builder.addEdge(EdgeKind.DATA, entryNodeId, effectId, List.copyOf(refs), "INFERENCE");
            for (String param : entry.parameters() == null ? List.<String>of() : entry.parameters()) {
                if (param == null || param.isBlank()) continue;
                builder.addEdge(EdgeKind.DATA, StableNodeIds.trust(entry.id(), param), effectId,
                        List.copyOf(refs), "INFERENCE");
            }
            return;
        }
    }

    private static void projectStaticFacts(Builder builder, StaticFactSnapshot snapshot) {
        if (snapshot == null) return;
        int methodBudget = Math.min(200, snapshot.methods().size());
        for (int i = 0; i < methodBudget; i++) {
            BytecodeFactIndex.MethodFact method = snapshot.methods().get(i);
            if (method == null) continue;
            String id = StableNodeIds.programMethod(method.owner(), method.name(), method.descriptor());
            builder.addNode(new ProgramNode(
                    id, "METHOD", "JVM",
                    method.owner() + "#" + method.name() + method.descriptor(),
                    method.owner(),
                    List.of(), "FACT", Map.of()));
        }
        List<BytecodeFactIndex.ResolvedCallEdge> resolved = snapshot.artifactCallGraph();
        if (!resolved.isEmpty()) {
            int edgeBudget = Math.min(400, resolved.size());
            for (int i = 0; i < edgeBudget; i++) {
                BytecodeFactIndex.ResolvedCallEdge edge = resolved.get(i);
                if (edge == null) continue;
                String from = StableNodeIds.programMethod(
                        edge.callerOwner(), edge.callerName(), edge.callerDescriptor());
                String to = StableNodeIds.programMethod(
                        edge.targetOwner(), edge.targetName(), edge.targetDescriptor());
                builder.addNode(new ProgramNode(from, "METHOD", "JVM",
                        edge.callerOwner() + "#" + edge.callerName(), "", List.of(), "FACT", Map.of()));
                builder.addNode(new ProgramNode(to, "METHOD", "JVM",
                        edge.targetOwner() + "#" + edge.targetName(), "", List.of(), "FACT", Map.of()));
                builder.addEdge(EdgeKind.CALL, from, to, List.of(), "FACT");
            }
        } else {
            List<BytecodeFactIndex.CallEdge> callEdges = snapshot.callEdges();
            int edgeBudget = Math.min(400, callEdges.size());
            for (int i = 0; i < edgeBudget; i++) {
                BytecodeFactIndex.CallEdge edge = callEdges.get(i);
                if (edge == null) continue;
                String from = StableNodeIds.programMethod(
                        edge.callerOwner(), edge.callerName(), edge.callerDescriptor());
                String to = StableNodeIds.programMethod(
                        edge.targetOwner(), edge.targetName(), edge.targetDescriptor());
                builder.addNode(new ProgramNode(from, "METHOD", "JVM",
                        edge.callerOwner() + "#" + edge.callerName(), "", List.of(), "FACT", Map.of()));
                builder.addNode(new ProgramNode(to, "METHOD", "JVM",
                        edge.targetOwner() + "#" + edge.targetName(), "", List.of(), "FACT", Map.of()));
                builder.addEdge(EdgeKind.CALL, from, to, List.of(), "FACT");
            }
        }
        for (BytecodeFactIndex.TaintPath path : snapshot.taintPaths()) {
            if (path == null) continue;
            String sourceId = StableNodeIds.programMethod(
                    path.sourceOwner(), path.sourceMethod(), path.sourceDescriptor());
            String sinkId = StableNodeIds.programMethod(
                    path.sinkOwner(), path.sinkMethod(), path.sinkDescriptor());
            builder.addNode(new ProgramNode(sourceId, "METHOD", "JVM",
                    path.sourceOwner() + "#" + path.sourceMethod(), "", List.of(), "INFERENCE", Map.of()));
            builder.addNode(new ProgramNode(sinkId, "METHOD", "JVM",
                    path.sinkOwner() + "#" + path.sinkMethod(), "", List.of(), "INFERENCE", Map.of()));
            builder.addEdge(EdgeKind.DATA, sourceId, sinkId, List.of(), "INFERENCE");
            List<BytecodeFactIndex.TaintStep> steps = path.steps();
            if (steps == null || steps.size() < 2) continue;
            String previous = sourceId;
            for (BytecodeFactIndex.TaintStep step : steps) {
                if (step == null || step.symbol() == null || step.symbol().isBlank()) continue;
                String stepId = "program:step:" + StableNodeIds.fingerprint(path.id() + ":" + step.symbol());
                builder.addNode(new ProgramNode(stepId, "INSTRUCTION", "JVM", step.symbol(),
                        step.evidence(), List.of(), "INFERENCE", Map.of("edgeKind", step.edgeKind())));
                builder.addEdge(EdgeKind.DATA, previous, stepId, List.of(), "INFERENCE");
                previous = stepId;
            }
            builder.addEdge(EdgeKind.DATA, previous, sinkId, List.of(), "INFERENCE");
        }
    }

    private static void projectHypotheses(
            Builder builder, List<SecurityHypothesis> hypotheses, Map<String, String> sinkEffectIds) {
        for (SecurityHypothesis hypothesis : hypotheses) {
            if (hypothesis == null) continue;
            String effectHint = hypothesis.effect() == null ? "" : hypothesis.effect().trim();
            String linkedEffect = "";
            if (!effectHint.isBlank()) {
                for (Map.Entry<String, String> item : sinkEffectIds.entrySet()) {
                    if (effectHint.equals(item.getKey()) || effectHint.contains(item.getKey())) {
                        linkedEffect = item.getValue();
                        break;
                    }
                }
            }
            boolean needsCarrier = false;
            for (String ref : hypothesis.supportingEvidenceRefs()) {
                if (ref != null && !ref.isBlank() && !builder.nodesByEvidence.containsKey(ref)) {
                    needsCarrier = true;
                    break;
                }
            }
            if (!needsCarrier && linkedEffect.isBlank()) continue;
            String guardId = StableNodeIds.guard("hyp:" + hypothesis.hypothesisId());
            builder.addNode(new GuardNode(
                    guardId,
                    hypothesis.family() == null ? "HYPOTHESIS" : hypothesis.family().name(),
                    hypothesis.securityProperty(),
                    linkedEffect,
                    hypothesis.supportingEvidenceRefs(),
                    "INFERENCE"));
            if (!linkedEffect.isBlank()) {
                builder.addEdge(EdgeKind.GUARD, linkedEffect, guardId,
                        hypothesis.supportingEvidenceRefs(), "INFERENCE");
            }
        }
    }

    private static void projectFindings(
            Builder builder, List<ApiDtos.FindingDto> findings, Map<String, String> sinkEffectIds) {
        for (ApiDtos.FindingDto finding : findings) {
            if (finding == null) continue;
            if (finding.entrypointId() != null && !finding.entrypointId().isBlank()
                    && !"entry-unbound".equals(finding.entrypointId())) {
                String entryId = StableNodeIds.entry(finding.entrypointId());
                if (!builder.nodeIds.contains(entryId)) {
                    builder.addNode(new EntryNode(
                            entryId, "UNKNOWN", "", finding.entry(), "",
                            List.of(), finding.evidenceRefs(), "INFERENCE",
                            finding.verificationStatus()));
                } else {
                    builder.mergeEvidence(entryId, finding.evidenceRefs());
                }
            }
            String sinkId = finding.sinkId();
            if (sinkId != null && !sinkId.isBlank()) {
                if (sinkId.startsWith("guard:")) {
                    builder.addNode(new GuardNode(
                            StableNodeIds.guard(sinkId), "AUTH_GAP", finding.sink(),
                            finding.entrypointId() == null || finding.entrypointId().isBlank()
                                    ? "" : StableNodeIds.entry(finding.entrypointId()),
                            finding.evidenceRefs(), "INFERENCE"));
                } else {
                    String effectId = sinkEffectIds.getOrDefault(sinkId, StableNodeIds.effect(sinkId));
                    if (!builder.nodeIds.contains(effectId)) {
                        builder.addNode(new EffectNode(
                                effectId, "UNKNOWN", finding.sink(), finding.entry(),
                                finding.evidenceRefs(), "INFERENCE", finding.verificationStatus()));
                    } else {
                        builder.mergeEvidence(effectId, finding.evidenceRefs());
                    }
                    if (finding.entrypointId() != null && !finding.entrypointId().isBlank()
                            && !"entry-unbound".equals(finding.entrypointId())) {
                        builder.addEdge(
                                EdgeKind.DATA,
                                StableNodeIds.entry(finding.entrypointId()),
                                effectId,
                                finding.evidenceRefs(),
                                "INFERENCE");
                    }
                }
            }
            // Guarantee finding evidence refs are joinable on at least one node.
            for (String ref : finding.evidenceRefs()) {
                if (ref == null || ref.isBlank()) continue;
                if (builder.nodesByEvidence.containsKey(ref)) continue;
                String effectId = sinkId != null && !sinkId.isBlank() && !sinkId.startsWith("guard:")
                        ? sinkEffectIds.getOrDefault(sinkId, StableNodeIds.effect(sinkId))
                        : StableNodeIds.effect("finding:" + finding.findingId());
                if (builder.nodeIds.contains(effectId)) {
                    builder.mergeEvidence(effectId, List.of(ref));
                } else {
                    builder.addNode(new EffectNode(
                            effectId, "FINDING", finding.sink(), finding.entry(),
                            finding.evidenceRefs(), "INFERENCE", finding.verificationStatus()));
                }
            }
        }
    }

    private static void projectPathRuns(Builder builder, List<ApiDtos.PathRunDto> pathRuns) {
        ApiDtos.PathRunDto previous = null;
        for (ApiDtos.PathRunDto run : pathRuns) {
            if (run == null) continue;
            String runtimeId = StableNodeIds.runtime(run.pathRunId());
            String subject = "";
            if (run.entrypointRef() != null && !run.entrypointRef().isBlank()) {
                // entrypointRef may be id or route; prefer entry: prefix when it looks like an id.
                subject = run.entrypointRef().startsWith("entry:")
                        ? run.entrypointRef()
                        : StableNodeIds.entry(run.entrypointRef());
            }
            builder.addNode(new RuntimeObservationNode(
                    runtimeId, "PATH_RUN", run.attemptId(), subject, run.outcomeClass(),
                    run.evidenceRefs(),
                    run.identityProvenance() == null ? "RUNTIME_OBSERVED" : run.identityProvenance(),
                    run.verificationStatus()));
            if (!subject.isBlank() && builder.nodeIds.contains(subject)) {
                builder.addEdge(EdgeKind.OBSERVED, runtimeId, subject, run.evidenceRefs(),
                        "RUNTIME_OBSERVED");
            }
            if (previous != null) {
                builder.addEdge(
                        EdgeKind.HAPPENS_BEFORE,
                        StableNodeIds.runtime(previous.pathRunId()),
                        runtimeId,
                        run.evidenceRefs(),
                        "RUNTIME_OBSERVED");
            }
            previous = run;
        }
    }

    private static boolean isAuthFilterEntry(ApiDtos.EntryDto entry) {
        String protocol = entry.protocol() == null ? "" : entry.protocol().trim().toUpperCase(Locale.ROOT);
        return "AUTH".equals(protocol) || "AUTH_FILTER".equals(protocol) || "SECURITY_FILTER".equals(protocol);
    }

    private static final class Builder {
        private final int maxNodes;
        private final int maxEdges;
        private final Map<String, IrNode> nodeMap = new LinkedHashMap<>();
        private final Map<String, IrEdge> edgeMap = new LinkedHashMap<>();
        private final Set<String> nodeIds = new LinkedHashSet<>();
        private final Map<String, String> nodesByEvidence = new LinkedHashMap<>();
        private boolean truncated;

        private Builder(int maxNodes, int maxEdges) {
            this.maxNodes = maxNodes;
            this.maxEdges = maxEdges;
        }

        private boolean addNode(IrNode node) {
            if (node == null) return false;
            if (nodeMap.containsKey(node.id())) {
                mergeEvidence(node.id(), node.evidenceRefs());
                return false;
            }
            if (nodeMap.size() >= maxNodes) {
                truncated = true;
                return false;
            }
            nodeMap.put(node.id(), node);
            nodeIds.add(node.id());
            for (String ref : node.evidenceRefs()) {
                nodesByEvidence.putIfAbsent(ref, node.id());
            }
            return true;
        }

        private void mergeEvidence(String nodeId, List<String> refs) {
            IrNode existing = nodeMap.get(nodeId);
            if (existing == null || refs == null || refs.isEmpty()) return;
            Set<String> merged = new LinkedHashSet<>(existing.evidenceRefs());
            boolean changed = false;
            for (String ref : refs) {
                if (ref != null && !ref.isBlank() && merged.add(ref)) {
                    changed = true;
                    nodesByEvidence.putIfAbsent(ref, nodeId);
                }
            }
            if (!changed) return;
            nodeMap.put(nodeId, withEvidence(existing, List.copyOf(merged)));
        }

        private void addEdge(EdgeKind kind, String fromId, String toId, List<String> refs, String provenance) {
            if (fromId == null || toId == null || fromId.isBlank() || toId.isBlank()) return;
            if (!nodeIds.contains(fromId) || !nodeIds.contains(toId)) return;
            String id = StableNodeIds.edge(kind, fromId, toId);
            if (edgeMap.containsKey(id)) return;
            if (edgeMap.size() >= maxEdges) {
                truncated = true;
                return;
            }
            edgeMap.put(id, new IrEdge(id, kind, fromId, toId, refs, provenance));
        }

        private List<IrNode> nodes() {
            return List.copyOf(nodeMap.values());
        }

        private List<IrEdge> edges() {
            return List.copyOf(edgeMap.values());
        }
    }

    private static IrNode withEvidence(IrNode node, List<String> refs) {
        if (node instanceof EntryNode n) {
            return new EntryNode(n.id(), n.protocol(), n.operation(), n.address(), n.declaringSymbol(),
                    n.inputs(), refs, n.provenanceKind(), n.verificationStatus());
        }
        if (node instanceof EffectNode n) {
            return new EffectNode(n.id(), n.category(), n.symbol(), n.sourceLabel(),
                    refs, n.provenanceKind(), n.verificationStatus());
        }
        if (node instanceof GuardNode n) {
            return new GuardNode(n.id(), n.guardKind(), n.expression(), n.subjectNodeId(),
                    refs, n.provenanceKind());
        }
        if (node instanceof TrustBoundaryNode n) {
            return new TrustBoundaryNode(n.id(), n.boundaryKind(), n.name(), n.entryNodeId(),
                    refs, n.provenanceKind());
        }
        if (node instanceof ProgramNode n) {
            return new ProgramNode(n.id(), n.elementKind(), n.language(), n.symbol(), n.location(),
                    refs, n.provenanceKind(), n.extensions());
        }
        if (node instanceof ResourceNode n) {
            return new ResourceNode(n.id(), n.resourceKind(), n.target(), n.accessType(),
                    refs, n.provenanceKind());
        }
        if (node instanceof RuntimeObservationNode n) {
            return new RuntimeObservationNode(n.id(), n.eventKind(), n.correlation(), n.subjectNodeId(),
                    n.outcomeClass(), refs, n.provenanceKind(), n.verificationStatus());
        }
        if (node instanceof StateNode n) {
            return new StateNode(n.id(), n.stateKey(), n.subjectNodeId(), refs, n.provenanceKind());
        }
        return node;
    }
}
