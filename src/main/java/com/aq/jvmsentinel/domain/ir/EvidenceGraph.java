package com.aq.jvmsentinel.domain.ir;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * 有界 Security IR / Evidence Graph 容器（P1-02）。
 *
 * <p>投影只读且在 budget 上 fail-closed：达到 node/edge 上限时，
 * {@code truncated=true} 且 {@code stopReason} 说明 bound。永不提升
 * verification status 或发明 FACT provenance。
 */
public record EvidenceGraph(
        int schemaVersion,
        String scanId,
        List<IrNode> nodes,
        List<IrEdge> edges,
        boolean truncated,
        int maxNodes,
        int maxEdges,
        String stopReason,
        CompatibilityGap compatibilityGap
) {
    public static final int SCHEMA_VERSION = 1;
    public static final int DEFAULT_MAX_NODES = 2000;
    public static final int DEFAULT_MAX_EDGES = 4000;

    public EvidenceGraph {
        if (schemaVersion < 1) {
            throw new IllegalArgumentException("schemaVersion must be >= 1");
        }
        Objects.requireNonNull(scanId, "scanId");
        if (scanId.isBlank()) throw new IllegalArgumentException("scanId must not be blank");
        nodes = List.copyOf(nodes == null ? List.of() : nodes);
        edges = List.copyOf(edges == null ? List.of() : edges);
        if (maxNodes < 1) throw new IllegalArgumentException("maxNodes must be >= 1");
        if (maxEdges < 1) throw new IllegalArgumentException("maxEdges must be >= 1");
        stopReason = stopReason == null ? "" : stopReason;
        compatibilityGap = compatibilityGap == null ? CompatibilityGap.empty() : compatibilityGap;
    }

    public Optional<IrNode> findById(String nodeId) {
        if (nodeId == null || nodeId.isBlank()) return Optional.empty();
        for (IrNode node : nodes) {
            if (nodeId.equals(node.id())) return Optional.of(node);
        }
        return Optional.empty();
    }

    /** Nodes that carry the given evidence ref (finding ↔ graph join key). */
    public List<IrNode> nodesForEvidenceRef(String evidenceRef) {
        if (evidenceRef == null || evidenceRef.isBlank()) return List.of();
        List<IrNode> matches = new ArrayList<>();
        for (IrNode node : nodes) {
            if (node.evidenceRefs().contains(evidenceRef)) {
                matches.add(node);
            }
        }
        return List.copyOf(matches);
    }

    /**
     * evidenceRefs 与本 node ref 相交的 finding（node → finding 反向 join）。
     */
    public List<String> findingIdsForNode(
            String nodeId, List<Map<String, Object>> findingMaps) {
        Optional<IrNode> node = findById(nodeId);
        if (node.isEmpty() || findingMaps == null || findingMaps.isEmpty()) {
            return List.of();
        }
        List<String> nodeRefs = node.get().evidenceRefs();
        if (nodeRefs.isEmpty()) return List.of();
        List<String> matched = new ArrayList<>();
        for (Map<String, Object> finding : findingMaps) {
            if (finding == null) continue;
            Object idObj = finding.get("findingId");
            Object refsObj = finding.get("evidenceRefs");
            if (!(idObj instanceof String findingId) || findingId.isBlank()) continue;
            if (!(refsObj instanceof List<?> refs) || refs.isEmpty()) continue;
            for (Object ref : refs) {
                if (ref != null && nodeRefs.contains(String.valueOf(ref))) {
                    matched.add(findingId);
                    break;
                }
            }
        }
        return List.copyOf(matched);
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("schemaVersion", schemaVersion);
        map.put("scanId", scanId);
        List<Object> nodeMaps = new ArrayList<>(nodes.size());
        for (IrNode node : nodes) {
            nodeMaps.add(node.toMap());
        }
        map.put("nodes", nodeMaps);
        List<Object> edgeMaps = new ArrayList<>(edges.size());
        for (IrEdge edge : edges) {
            edgeMaps.add(edge.toMap());
        }
        map.put("edges", edgeMaps);
        map.put("truncated", truncated);
        map.put("maxNodes", maxNodes);
        map.put("maxEdges", maxEdges);
        map.put("nodeCount", nodes.size());
        map.put("edgeCount", edges.size());
        if (!stopReason.isBlank()) map.put("stopReason", stopReason);
        map.put("compatibilityGap", compatibilityGap.toMap());
        return map;
    }

    /**
     * Legacy EntryDto 与 EntryNode 计数 gap（AUTH filter 行、budget 截断、…）。
     */
    public record CompatibilityGap(
            int entryDtoCount,
            int entryNodeCount,
            List<String> filteredEntryIds,
            List<String> notes
    ) {
        public CompatibilityGap {
            filteredEntryIds = List.copyOf(filteredEntryIds == null ? List.of() : filteredEntryIds);
            notes = List.copyOf(notes == null ? List.of() : notes);
            if (entryDtoCount < 0 || entryNodeCount < 0) {
                throw new IllegalArgumentException("counts must not be negative");
            }
        }

        public static CompatibilityGap empty() {
            return new CompatibilityGap(0, 0, List.of(), List.of());
        }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("entryDtoCount", entryDtoCount);
            map.put("entryNodeCount", entryNodeCount);
            map.put("filteredEntryIds", filteredEntryIds);
            map.put("notes", notes);
            return map;
        }

        @SuppressWarnings("unchecked")
        static CompatibilityGap fromMap(Map<String, Object> map) {
            if (map == null || map.isEmpty()) return empty();
            int entryDtoCount = intVal(map.get("entryDtoCount"), 0);
            int entryNodeCount = intVal(map.get("entryNodeCount"), 0);
            List<String> filtered = stringList(map.get("filteredEntryIds"));
            List<String> notes = stringList(map.get("notes"));
            return new CompatibilityGap(entryDtoCount, entryNodeCount, filtered, notes);
        }
    }

    /**
     * 从 {@link #toMap()} wire 形式恢复权威 graph（StaticFactSnapshot persistence）。
     * 未知 node kind fail-closed 跳过（不发明为 FACT）。
     */
    @SuppressWarnings("unchecked")
    public static EvidenceGraph fromMap(Map<String, Object> map) {
        Objects.requireNonNull(map, "map");
        String scanId = stringVal(map.get("scanId"), "");
        if (scanId.isBlank()) {
            throw new IllegalArgumentException("evidence graph scanId required");
        }
        int schemaVersion = intVal(map.get("schemaVersion"), SCHEMA_VERSION);
        int maxNodes = intVal(map.get("maxNodes"), DEFAULT_MAX_NODES);
        int maxEdges = intVal(map.get("maxEdges"), DEFAULT_MAX_EDGES);
        boolean truncated = Boolean.TRUE.equals(map.get("truncated"));
        String stopReason = stringVal(map.get("stopReason"), "");
        List<IrNode> nodes = new ArrayList<>();
        Object nodesObj = map.get("nodes");
        if (nodesObj instanceof List<?> nodeList) {
            for (Object item : nodeList) {
                if (!(item instanceof Map<?, ?> raw)) continue;
                IrNode node = nodeFromMap((Map<String, Object>) raw);
                if (node != null) nodes.add(node);
            }
        }
        List<IrEdge> edges = new ArrayList<>();
        Object edgesObj = map.get("edges");
        if (edgesObj instanceof List<?> edgeList) {
            for (Object item : edgeList) {
                if (!(item instanceof Map<?, ?> raw)) continue;
                IrEdge edge = edgeFromMap((Map<String, Object>) raw);
                if (edge != null) edges.add(edge);
            }
        }
        CompatibilityGap gap = CompatibilityGap.empty();
        Object gapObj = map.get("compatibilityGap");
        if (gapObj instanceof Map<?, ?> rawGap) {
            gap = CompatibilityGap.fromMap((Map<String, Object>) rawGap);
        }
        return new EvidenceGraph(
                schemaVersion, scanId, nodes, edges, truncated, maxNodes, maxEdges, stopReason, gap);
    }

    @SuppressWarnings("unchecked")
    private static IrNode nodeFromMap(Map<String, Object> map) {
        String kind = stringVal(map.get("kind"), "").toUpperCase(Locale.ROOT);
        String id = stringVal(map.get("id"), "");
        if (id.isBlank() || kind.isBlank()) return null;
        List<String> refs = stringList(map.get("evidenceRefs"));
        String provenance = stringVal(map.get("provenanceKind"), "INFERENCE");
        return switch (kind) {
            case "PROGRAM" -> new ProgramNode(
                    id,
                    stringVal(map.get("elementKind"), "CLASS"),
                    stringVal(map.get("language"), "UNKNOWN"),
                    stringVal(map.get("symbol"), ""),
                    stringVal(map.get("location"), ""),
                    refs,
                    provenance,
                    map.get("extensions") instanceof Map<?, ?> ext
                            ? (Map<String, Object>) ext : Map.of());
            case "ENTRY" -> new EntryNode(
                    id,
                    stringVal(map.get("protocol"), "UNKNOWN"),
                    stringVal(map.get("operation"), ""),
                    stringVal(map.get("address"), ""),
                    stringVal(map.get("declaringSymbol"), ""),
                    stringList(map.get("inputs")),
                    refs,
                    provenance,
                    stringVal(map.get("verificationStatus"), "STATIC_INFERRED"));
            case "TRUST_BOUNDARY" -> new TrustBoundaryNode(
                    id,
                    stringVal(map.get("boundaryKind"), "PARAMETER"),
                    stringVal(map.get("name"), ""),
                    stringVal(map.get("entryNodeId"), ""),
                    refs,
                    provenance);
            case "EFFECT" -> new EffectNode(
                    id,
                    stringVal(map.get("category"), "UNKNOWN"),
                    stringVal(map.get("symbol"), ""),
                    stringVal(map.get("sourceLabel"), ""),
                    refs,
                    provenance,
                    stringVal(map.get("verificationStatus"), "STATIC_INFERRED"));
            case "GUARD" -> new GuardNode(
                    id,
                    stringVal(map.get("guardKind"), "UNKNOWN"),
                    stringVal(map.get("expression"), ""),
                    stringVal(map.get("subjectNodeId"), ""),
                    refs,
                    provenance);
            case "SANITIZER" -> new SanitizerNode(
                    id,
                    stringVal(map.get("sanitizerKind"), "UNKNOWN"),
                    stringVal(map.get("symbol"), ""),
                    refs,
                    provenance);
            case "STATE" -> new StateNode(
                    id,
                    stringVal(map.get("stateKey"), ""),
                    stringVal(map.get("subjectNodeId"), ""),
                    refs,
                    provenance);
            case "RESOURCE" -> new ResourceNode(
                    id,
                    stringVal(map.get("resourceKind"), "UNKNOWN"),
                    stringVal(map.get("target"), ""),
                    stringVal(map.get("accessType"), ""),
                    refs,
                    provenance);
            case "RUNTIME_OBSERVATION" -> new RuntimeObservationNode(
                    id,
                    stringVal(map.get("eventKind"), "PATH_RUN"),
                    stringVal(map.get("correlation"), ""),
                    stringVal(map.get("subjectNodeId"), ""),
                    stringVal(map.get("outcomeClass"), ""),
                    refs,
                    provenance,
                    stringVal(map.get("verificationStatus"), "UNREACHED"));
            default -> null;
        };
    }

    private static IrEdge edgeFromMap(Map<String, Object> map) {
        String id = stringVal(map.get("id"), "");
        String fromId = stringVal(map.get("fromId"), "");
        String toId = stringVal(map.get("toId"), "");
        String kindName = stringVal(map.get("kind"), "");
        if (id.isBlank() || fromId.isBlank() || toId.isBlank() || kindName.isBlank()) return null;
        EdgeKind kind;
        try {
            kind = EdgeKind.valueOf(kindName.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            return null;
        }
        return new IrEdge(
                id, kind, fromId, toId,
                stringList(map.get("evidenceRefs")),
                stringVal(map.get("provenanceKind"), "INFERENCE"));
    }

    private static int intVal(Object value, int fallback) {
        if (value instanceof Number number) return number.intValue();
        if (value instanceof String text) {
            try {
                return Integer.parseInt(text.trim());
            } catch (NumberFormatException ignored) {
                return fallback;
            }
        }
        return fallback;
    }

    private static String stringVal(Object value, String fallback) {
        if (value == null) return fallback;
        String text = String.valueOf(value);
        return text.isBlank() ? fallback : text;
    }

    private static List<String> stringList(Object value) {
        if (!(value instanceof List<?> list) || list.isEmpty()) return List.of();
        List<String> out = new ArrayList<>();
        for (Object item : list) {
            if (item == null) continue;
            String text = String.valueOf(item);
            if (!text.isBlank()) out.add(text);
        }
        return List.copyOf(out);
    }
}
