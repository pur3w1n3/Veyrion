package com.aq.jvmsentinel.ai.tool.datasource;

import com.aq.jvmsentinel.ai.tool.ToolDataSource.FactRecord;
import com.aq.jvmsentinel.ai.tool.ToolExecutionContext;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * 从已持久化 static facts 解析 IR 投影及摘要辅助方法。
 */
public final class IrProjectionSupport {
    private final ControlPlaneStore store;
    private final String scanId;

    public IrProjectionSupport(ControlPlaneStore store, String scanId) {
        this.store = Objects.requireNonNull(store, "store");
        this.scanId = Objects.requireNonNull(scanId, "scanId");
    }

    /** AUTH 门禁：持久化 facts 是否暴露非空 methods IR 列表。 */
    public static boolean hasNonEmptyMethodsIr(StaticFactSnapshot snapshot) {
        return StaticFactSnapshot.hasNonEmptyMethodsIr(snapshot);
    }

    public Optional<IrProjection> resolveIrProjection() {
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

    public List<FactRecord> incompleteIr(ToolExecutionContext.Scope scope, String kind,
                                         String stopReason, String coverageStatus) {
        ObjectNode summary = baseIrSummary(kind, coverageStatus, stopReason);
        summary.put("matchCount", 0);
        return List.of(new FactRecord(scope,
                "code_query:" + kind.toLowerCase(java.util.Locale.ROOT), summary));
    }

    public static ObjectNode baseIrSummary(String kind, String coverageStatus, String stopReason) {
        ObjectNode summary = DatasourceJson.JSON.createObjectNode();
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

    public static void putMethod(ObjectNode row, BytecodeFactIndex.MethodFact method) {
        row.put("owner", method.owner());
        row.put("name", method.name());
        row.put("descriptor", method.descriptor());
        row.put("accessFlags", method.accessFlags());
        row.put("evidence", method.evidence());
        row.put("classification", "FACT");
        row.put("verificationStatus", "STATIC_INFERRED");
    }

    public static String methodKey(String owner, String name, String descriptor) {
        return (owner == null ? "" : owner.replace('/', '.'))
                + "#" + (name == null ? "" : name)
                + (descriptor == null ? "" : descriptor);
    }

    public static String irStopReason(Optional<IrProjection> ir) {
        if (ir.isEmpty()) return "IR_NOT_PERSISTED";
        if (ir.get().methods().isEmpty()) return "IR_NOT_PERSISTED";
        return "LEGACY_INCOMPLETE";
    }

    public static String irCoverage(Optional<IrProjection> ir) {
        return ir.map(IrProjection::coverageStatus).orElse(StaticFactSnapshot.LEGACY_INCOMPLETE);
    }

    public record IrProjection(
            String coverageStatus,
            List<BytecodeFactIndex.MethodFact> methods,
            List<BytecodeFactIndex.CallEdge> callEdges,
            List<BytecodeFactIndex.ResolvedCallEdge> artifactCallGraph,
            List<BytecodeFactIndex.MemberAccessFact> memberAccesses) {
        public IrProjection {
            coverageStatus = coverageStatus == null
                    ? StaticFactSnapshot.LEGACY_INCOMPLETE : coverageStatus;
            methods = List.copyOf(methods == null ? List.of() : methods);
            callEdges = List.copyOf(callEdges == null ? List.of() : callEdges);
            artifactCallGraph = List.copyOf(artifactCallGraph == null ? List.of() : artifactCallGraph);
            memberAccesses = List.copyOf(memberAccesses == null ? List.of() : memberAccesses);
        }
    }
}
