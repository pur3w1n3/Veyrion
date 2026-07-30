package com.aq.jvmsentinel.analysis.kernel;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.List;
import java.util.Objects;

/**
 * 从 persisted IR site 构建的可序列化 method CFG 投影。
 * 非完整 SSA；branch/exception edge 可能不完整。
 */
public record CfgGraph(
        String schemaVersion,
        String owner,
        String name,
        String descriptor,
        List<CfgBasicBlock> blocks,
        List<CfgEdge> edges,
        String coverageStatus,
        List<String> stopReasons) {

    public static final String SCHEMA_VERSION = "cfg-v1";
    public static final int MAX_BLOCKS = 32;

    public CfgGraph {
        schemaVersion = schemaVersion == null || schemaVersion.isBlank() ? SCHEMA_VERSION : schemaVersion;
        owner = owner == null ? "" : owner;
        name = name == null ? "" : name;
        descriptor = descriptor == null ? "" : descriptor;
        blocks = List.copyOf(blocks == null ? List.of() : blocks);
        edges = List.copyOf(edges == null ? List.of() : edges);
        coverageStatus = coverageStatus == null || coverageStatus.isBlank() ? "PARTIAL" : coverageStatus;
        stopReasons = List.copyOf(stopReasons == null ? List.of() : stopReasons);
    }

    public ObjectNode toJson(ObjectMapper mapper) {
        Objects.requireNonNull(mapper, "mapper");
        ObjectNode root = mapper.createObjectNode();
        root.put("schemaVersion", schemaVersion);
        root.put("owner", owner);
        root.put("name", name);
        root.put("descriptor", descriptor);
        root.put("coverageStatus", coverageStatus);
        root.put("producer", "analysis.kernel.CfgBuilder");
        root.put("provenance", "KERNEL_INFERENCE");
        ArrayNode stop = root.putArray("stopReasons");
        for (String reason : stopReasons) {
            stop.add(reason);
        }
        ArrayNode blockNodes = root.putArray("blocks");
        for (CfgBasicBlock block : blocks) {
            ObjectNode node = blockNodes.addObject();
            node.put("id", block.id());
            node.put("startBci", block.startBci());
            node.put("endBci", block.endBci());
            ArrayNode refs = node.putArray("evidenceRefs");
            for (String ref : block.evidenceRefs()) {
                refs.add(ref);
            }
            ArrayNode successors = node.putArray("successors");
            for (Integer id : block.successors()) {
                successors.add(id);
            }
        }
        ArrayNode edgeNodes = root.putArray("edges");
        for (CfgEdge edge : edges) {
            ObjectNode node = edgeNodes.addObject();
            node.put("from", edge.fromBlockId());
            node.put("to", edge.toBlockId());
            node.put("kind", edge.kind());
            node.put("evidenceRef", edge.evidenceRef());
        }
        return root;
    }

    /** Compatibility projection for existing CFG_VIEW consumers. */
    public ArrayNode toBasicBlocksArray(ObjectMapper mapper) {
        Objects.requireNonNull(mapper, "mapper");
        ArrayNode array = mapper.createArrayNode();
        for (CfgBasicBlock block : blocks) {
            if (array.size() >= MAX_BLOCKS) break;
            ObjectNode node = array.addObject();
            node.put("id", block.id());
            node.put("startBci", block.startBci());
            node.put("endBci", block.endBci());
            ArrayNode refs = node.putArray("evidenceRefs");
            for (String ref : block.evidenceRefs()) {
                refs.add(ref);
            }
            ArrayNode successors = node.putArray("successors");
            for (Integer id : block.successors()) {
                successors.add(id);
            }
        }
        return array;
    }
}
