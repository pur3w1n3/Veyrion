package com.aq.jvmsentinel.analysis;

import java.util.List;
import java.util.Objects;

/** Projected data-flow graph over existing TaintPath facts. */
public record TaintGraph(List<TaintNode> nodes, List<TaintEdge> edges, boolean truncated) {
    public enum NodeKind { SOURCE, TRANSFORM, SINK }
    public enum EdgeKind { DIRECT, CHA, UNRESOLVED }

    public record TaintNode(String id, NodeKind kind, String classname, String methodDesc, int paramIdx) {
        public TaintNode {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(kind, "kind");
            classname = classname == null ? "" : classname;
            methodDesc = methodDesc == null ? "" : methodDesc;
        }
    }

    public record TaintEdge(String from, String to, EdgeKind edgeKind, String callSite) {
        public TaintEdge {
            Objects.requireNonNull(from, "from");
            Objects.requireNonNull(to, "to");
            Objects.requireNonNull(edgeKind, "edgeKind");
            callSite = callSite == null ? "" : callSite;
        }
    }

    public TaintGraph {
        nodes = List.copyOf(nodes == null ? List.of() : nodes);
        edges = List.copyOf(edges == null ? List.of() : edges);
    }
}
