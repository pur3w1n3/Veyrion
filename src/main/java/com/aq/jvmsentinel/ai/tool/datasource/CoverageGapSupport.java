package com.aq.jvmsentinel.ai.tool.datasource;

import com.aq.jvmsentinel.analysis.experiment.TracePlanCompiler;
import com.aq.jvmsentinel.analysis.experiment.TracePlanObservationDiff;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.domain.pathdebug.TracePlan;
import com.aq.jvmsentinel.model.BytecodeFactIndex;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * coverageGapIds 所需的 TracePlan 缺失效应 entry 计算。
 */
public final class CoverageGapSupport {
    private final ControlPlaneStore store;

    public CoverageGapSupport(ControlPlaneStore store) {
        this.store = Objects.requireNonNull(store, "store");
    }

    public List<String> tracePlanMissingEffectEntries(
            ControlPlaneStore.ScanRecord scan,
            List<BytecodeFactIndex.TaintPath> taintPaths) {
        try {
            List<TracePlan> plans = new ArrayList<>();
            for (SQLiteControlPlanePersistence.TracePlanData row : store.loadTracePlansForScan(
                    scan.dto().scanId())) {
                if (row == null || row.payloadJson() == null || row.payloadJson().isBlank()) {
                    continue;
                }
                try {
                    plans.add(TracePlan.fromMap(JsonCodec.parseObject(row.payloadJson())));
                } catch (RuntimeException ignored) {
                    // 跳过格式错误的 plan
                }
            }
            if (plans.isEmpty()) {
                for (ApiDtos.EntryDto entry : scan.dto().entries()) {
                    if (entry == null || entry.route() == null || entry.route().isBlank()) {
                        continue;
                    }
                    if (!"HTTP".equalsIgnoreCase(entry.protocol())) {
                        continue;
                    }
                    plans.add(TracePlanCompiler.compileFromStaticIr(
                            entry, scan.dto().sinks(), scan.evidence(), taintPaths, List.of()));
                    if (plans.size() >= 48) {
                        break;
                    }
                }
            }
            List<PathTrace> traces = new ArrayList<>();
            for (SQLiteControlPlanePersistence.PathTraceData row : store.loadPathTracesForScan(
                    scan.dto().projectId(), scan.dto().artifactDigest(), scan.dto().scanId())) {
                if (row == null) {
                    continue;
                }
                PathTrace cached = store.pathTraceForPathRun(row.pathRunId());
                if (cached != null) {
                    traces.add(cached);
                    continue;
                }
                if (row.payloadJson() != null && !row.payloadJson().isBlank()) {
                    try {
                        traces.add(PathTrace.fromMap(JsonCodec.parseObject(row.payloadJson())));
                    } catch (RuntimeException ignored) {
                        // 跳过格式错误的 trace
                    }
                }
            }
            return TracePlanObservationDiff.entriesWithMissingEffects(
                    TracePlanObservationDiff.diffAll(plans, traces));
        } catch (RuntimeException ignored) {
            return List.of();
        }
    }
}
