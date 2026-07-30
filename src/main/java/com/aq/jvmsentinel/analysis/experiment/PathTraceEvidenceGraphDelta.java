package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.domain.ir.EdgeKind;
import com.aq.jvmsentinel.domain.ir.EvidenceGraph;
import com.aq.jvmsentinel.domain.ir.EvidenceGraphMerge;
import com.aq.jvmsentinel.domain.ir.IrEdge;
import com.aq.jvmsentinel.domain.ir.IrNode;
import com.aq.jvmsentinel.domain.ir.RuntimeObservationNode;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePosture;
import com.aq.jvmsentinel.domain.pathdebug.TraceEvent;
import com.aq.jvmsentinel.domain.pathdebug.TraceEventKind;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * P0-21：将 PathTrace event 转换为 Evidence Graph delta node/edge。
 * 仅 FORCED observation 保持有限（node 上 UNREACHED verification）。
 */
public final class PathTraceEvidenceGraphDelta {
    public static final String PRODUCER = "path-trace-evidence-delta/0.1";

    private PathTraceEvidenceGraphDelta() {
    }

    public record Delta(
            List<RuntimeObservationNode> nodes,
            List<IrEdge> edges,
            Map<String, Object> wireDelta
    ) {
        public Delta {
            nodes = nodes == null ? List.of() : List.copyOf(nodes);
            edges = edges == null ? List.of() : List.copyOf(edges);
            wireDelta = wireDelta == null ? Map.of() : Map.copyOf(wireDelta);
        }
    }

    public static Delta fromPathTrace(PathTrace trace, String scanId) {
        Objects.requireNonNull(trace, "trace");
        if (trace.legacyIncomplete() || trace.events().isEmpty()) {
            return new Delta(List.of(), List.of(), Map.of("producer", PRODUCER, "empty", true));
        }
        boolean forcedOnly = trace.posture().postureKind().name().equals("FORCED_REACHABILITY")
                || RuntimePosture.PROVENANCE_INSTRUMENTATION.equals(trace.posture().postureProvenance());
        String verification = forcedOnly ? "UNREACHED" : "DYNAMIC_SUSPECTED";
        List<RuntimeObservationNode> nodes = new ArrayList<>();
        List<IrEdge> edges = new ArrayList<>();
        String pathRef = "pathtrace:" + trace.pathTraceId();
        for (TraceEvent event : trace.events()) {
            if (event.kind() == TraceEventKind.TRACE_TRUNCATED) {
                continue;
            }
            String nodeId = "runtime:pathtrace:" + trace.pathTraceId() + ":" + event.sequence();
            String eventKind = mapEventKind(event.kind());
            List<String> refs = new ArrayList<>();
            refs.add(pathRef);
            if (event.kind() == TraceEventKind.EFFECT_TRIGGERED) {
                for (String effectRef : trace.effectRefs()) {
                    if (effectRef != null && !effectRef.isBlank()) {
                        refs.add(effectRef.startsWith("EFFECT:") ? effectRef : "EFFECT:" + effectRef);
                    }
                }
            }
            String nodeVerification = event.forced() || forcedOnly ? "UNREACHED" : verification;
            nodes.add(new RuntimeObservationNode(
                    nodeId,
                    eventKind,
                    trace.correlationId(),
                    event.subjectRef(),
                    trace.exitReason().name(),
                    List.copyOf(refs),
                    "RUNTIME_OBSERVED",
                    nodeVerification));
            if (!event.subjectRef().isBlank()) {
                edges.add(new IrEdge(
                        "edge:pathtrace:" + trace.pathTraceId() + ":" + event.sequence(),
                        EdgeKind.OBSERVED,
                        nodeId,
                        event.subjectRef(),
                        List.of(pathRef),
                        "RUNTIME_OBSERVED"));
            }
        }
        Map<String, Object> wire = new LinkedHashMap<>();
        wire.put("producer", PRODUCER);
        wire.put("scanId", scanId == null ? "" : scanId);
        wire.put("pathTraceId", trace.pathTraceId());
        wire.put("pathRunId", trace.pathRunId());
        wire.put("forcedOnly", forcedOnly);
        wire.put("nodeCount", nodes.size());
        wire.put("edgeCount", edges.size());
        wire.put("effectRefs", trace.effectRefs());
        if (!trace.posture().forcedGuardRefs().isEmpty()) {
            wire.put("forcedGuardRefs", trace.posture().forcedGuardRefs());
        }
        return new Delta(nodes, edges, Map.copyOf(wire));
    }

    public static EvidenceGraph mergeInto(EvidenceGraph base, Delta delta) {
        if (base == null || delta == null || delta.nodes().isEmpty()) {
            return base;
        }
        List<IrNode> extras = new ArrayList<>(delta.nodes());
        return EvidenceGraphMerge.withExtraNodes(base, extras);
    }

    public static Map<String, Object> toWireMap(Delta delta) {
        if (delta == null) {
            return Map.of();
        }
        Map<String, Object> map = new LinkedHashMap<>(delta.wireDelta());
        List<Map<String, Object>> nodeMaps = new ArrayList<>();
        for (RuntimeObservationNode node : delta.nodes()) {
            nodeMaps.add(node.toMap());
        }
        map.put("nodes", nodeMaps);
        List<Map<String, Object>> edgeMaps = new ArrayList<>();
        for (IrEdge edge : delta.edges()) {
            edgeMaps.add(edge.toMap());
        }
        map.put("edges", edgeMaps);
        return Map.copyOf(map);
    }

    private static String mapEventKind(TraceEventKind kind) {
        return switch (kind) {
            case ENTRY_HIT, PARAMETER_BOUND, METHOD_HOP -> "PATH_METHOD";
            case GUARD_DECISION -> "GUARD_DECISION";
            case EFFECT_TRIGGERED -> "EFFECT";
            case DEPENDENCY_FAILURE -> "DEPENDENCY";
            case EXCEPTION_THROWN, RETURN_EXIT -> "EXCEPTION";
            default -> kind.name();
        };
    }
}
