package com.aq.jvmsentinel.domain.ir;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Merges supplemental IR nodes into an existing Evidence Graph without elevating status.
 */
public final class EvidenceGraphMerge {
    private EvidenceGraphMerge() {
    }

    public static EvidenceGraph withExtraNodes(EvidenceGraph base, List<? extends IrNode> extras) {
        Objects.requireNonNull(base, "base");
        if (extras == null || extras.isEmpty()) {
            return base;
        }
        Map<String, IrNode> nodes = new LinkedHashMap<>();
        for (IrNode node : base.nodes()) {
            nodes.put(node.id(), node);
        }
        boolean truncated = base.truncated();
        String stopReason = base.stopReason();
        for (IrNode extra : extras) {
            if (extra == null || extra.id() == null || extra.id().isBlank()) {
                continue;
            }
            if (nodes.containsKey(extra.id())) {
                continue;
            }
            if (nodes.size() >= base.maxNodes()) {
                truncated = true;
                if (stopReason == null || stopReason.isBlank()) {
                    stopReason = "NODE_BUDGET";
                }
                break;
            }
            nodes.put(extra.id(), extra);
        }
        List<String> notes = new ArrayList<>(base.compatibilityGap().notes());
        notes.add("supplemental analyzer/program nodes merged");
        EvidenceGraph.CompatibilityGap gap = new EvidenceGraph.CompatibilityGap(
                base.compatibilityGap().entryDtoCount(),
                base.compatibilityGap().entryNodeCount(),
                base.compatibilityGap().filteredEntryIds(),
                notes);
        return new EvidenceGraph(
                base.schemaVersion(),
                base.scanId(),
                List.copyOf(nodes.values()),
                base.edges(),
                truncated,
                base.maxNodes(),
                base.maxEdges(),
                stopReason == null ? "" : stopReason,
                gap);
    }
}
