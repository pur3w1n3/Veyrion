package com.aq.jvmsentinel.analysis;

import com.aq.jvmsentinel.model.BytecodeFactIndex;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Pure projection of TaintPath lists into a bounded DAG. */
public final class TaintGraphProjector {
    public static final int MAX_NODES = 50;
    public static final int MAX_EDGES = 100;

    private TaintGraphProjector() {
    }

    public static TaintGraph project(List<BytecodeFactIndex.TaintPath> paths) {
        Map<String, TaintGraph.TaintNode> nodes = new LinkedHashMap<>();
        List<TaintGraph.TaintEdge> edges = new ArrayList<>();
        boolean truncated = false;
        List<BytecodeFactIndex.TaintPath> list = paths == null ? List.of() : paths;
        for (BytecodeFactIndex.TaintPath path : list) {
            String sourceId = nodeId(path.sourceOwner(), path.sourceMethod() + path.sourceDescriptor(),
                    TaintGraph.NodeKind.SOURCE);
            String sinkId = nodeId(path.sinkOwner(), path.sinkMethod() + path.sinkDescriptor(),
                    TaintGraph.NodeKind.SINK);
            putNode(nodes, sourceId, TaintGraph.NodeKind.SOURCE, path.sourceOwner(),
                    path.sourceMethod() + path.sourceDescriptor(), path.sourceParameter());
            putNode(nodes, sinkId, TaintGraph.NodeKind.SINK, path.sinkOwner(),
                    path.sinkMethod() + path.sinkDescriptor(), -1);
            String previous = sourceId;
            for (BytecodeFactIndex.TaintStep step : path.steps()) {
                String symbol = step.symbol() == null ? "" : step.symbol();
                int hash = symbol.indexOf('#');
                String owner = hash > 0 ? symbol.substring(0, hash) : symbol;
                String method = hash > 0 ? symbol.substring(hash + 1) : "";
                String transformId = nodeId(owner, method, TaintGraph.NodeKind.TRANSFORM);
                putNode(nodes, transformId, TaintGraph.NodeKind.TRANSFORM, owner, method, -1);
                if (edges.size() < MAX_EDGES) {
                    edges.add(new TaintGraph.TaintEdge(previous, transformId,
                            TaintGraph.EdgeKind.DIRECT, owner + "#" + method));
                } else truncated = true;
                previous = transformId;
                if (nodes.size() >= MAX_NODES) {
                    truncated = true;
                    break;
                }
            }
            if (edges.size() < MAX_EDGES) {
                edges.add(new TaintGraph.TaintEdge(previous, sinkId,
                        TaintGraph.EdgeKind.DIRECT, path.sinkOwner() + "#" + path.sinkMethod()));
            } else truncated = true;
            if (nodes.size() >= MAX_NODES) {
                truncated = true;
                break;
            }
        }
        List<TaintGraph.TaintNode> nodeList = new ArrayList<>(nodes.values());
        if (nodeList.size() > MAX_NODES) {
            nodeList = nodeList.subList(0, MAX_NODES);
            truncated = true;
        }
        if (edges.size() > MAX_EDGES) {
            edges = edges.subList(0, MAX_EDGES);
            truncated = true;
        }
        return new TaintGraph(nodeList, edges, truncated);
    }

    public static TaintGraph subgraph(TaintGraph graph, String sinkIdOrNodeId) {
        if (graph == null) return new TaintGraph(List.of(), List.of(), false);
        if (sinkIdOrNodeId == null || sinkIdOrNodeId.isBlank()) {
            return new TaintGraph(
                    graph.nodes().stream().limit(MAX_NODES).toList(),
                    graph.edges().stream().limit(MAX_EDGES).toList(),
                    graph.truncated() || graph.nodes().size() > MAX_NODES);
        }
        Set<String> keep = new LinkedHashSet<>();
        for (TaintGraph.TaintNode node : graph.nodes()) {
            if (node.id().contains(sinkIdOrNodeId) || node.classname().contains(sinkIdOrNodeId)) {
                keep.add(node.id());
            }
        }
        for (TaintGraph.TaintEdge edge : graph.edges()) {
            if (keep.contains(edge.from()) || keep.contains(edge.to())
                    || edge.callSite().contains(sinkIdOrNodeId)) {
                keep.add(edge.from());
                keep.add(edge.to());
            }
        }
        List<TaintGraph.TaintNode> nodes = graph.nodes().stream()
                .filter(n -> keep.contains(n.id())).limit(MAX_NODES).toList();
        Set<String> nodeIds = new LinkedHashSet<>();
        nodes.forEach(n -> nodeIds.add(n.id()));
        List<TaintGraph.TaintEdge> edges = graph.edges().stream()
                .filter(e -> nodeIds.contains(e.from()) && nodeIds.contains(e.to()))
                .limit(MAX_EDGES).toList();
        return new TaintGraph(nodes, edges, graph.truncated() || nodes.size() >= MAX_NODES);
    }

    private static void putNode(Map<String, TaintGraph.TaintNode> nodes, String id,
                                TaintGraph.NodeKind kind, String classname, String methodDesc, int paramIdx) {
        nodes.putIfAbsent(id, new TaintGraph.TaintNode(id, kind, classname, methodDesc, paramIdx));
    }

    private static String nodeId(String classname, String methodDesc, TaintGraph.NodeKind kind) {
        return (classname == null ? "_" : classname.replace('/', '.'))
                + "#" + (methodDesc == null ? "_" : methodDesc)
                + "#" + kind.name();
    }
}
