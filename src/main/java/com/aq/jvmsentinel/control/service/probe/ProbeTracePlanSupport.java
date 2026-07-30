package com.aq.jvmsentinel.control.service.probe;

import com.aq.jvmsentinel.analysis.experiment.TracePlanCompiler;
import com.aq.jvmsentinel.analysis.experiment.TracePlanObservationDiff;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.domain.pathdebug.TracePlan;
import com.aq.jvmsentinel.model.BytecodeFactIndex;

import java.util.ArrayList;
import java.util.List;

/** TracePlan 加载、编译与缺口 entry 选择。 */
public final class ProbeTracePlanSupport {
    private final ControlPlaneStore store;

    public ProbeTracePlanSupport(ControlPlaneStore store) {
        this.store = store;
    }

    /** 持久化/已编译 TracePlan 相对 PathTrace 仍缺 expected effects 的 entry。 */
    public List<String> tracePlanGapEntryIds(ControlPlaneStore.ScanRecord scan) {
        try {
            List<TracePlan> plans = loadOrCompileTracePlans(scan);
            if (plans.isEmpty()) {
                return List.of();
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
                    } catch (Exception ignored) {
                        // 保持 flood 选择在异常时仍可继续
                    }
                }
            }
            return TracePlanObservationDiff.entriesWithMissingEffects(
                    TracePlanObservationDiff.prioritizeGaps(
                            TracePlanObservationDiff.diffAll(plans, traces)));
        } catch (RuntimeException ignored) {
            return List.of();
        }
    }

    public List<String> staticEffectEntryIds(
            ControlPlaneStore.ScanRecord scan, List<ApiDtos.EntryDto> httpEntries) {
        try {
            List<BytecodeFactIndex.TaintPath> taintPaths = StaticFactSnapshot.resolveTaintPaths(
                    store.staticFacts(scan.dto().scanId()), scan.dto().sinks());
            return TracePlanCompiler.entryIdsWithExpectedEffects(
                    httpEntries, scan.dto().sinks(), scan.evidence(), taintPaths);
        } catch (RuntimeException ignored) {
            return List.of();
        }
    }

    public List<TracePlan> loadOrCompileTracePlans(ControlPlaneStore.ScanRecord scan) {
        List<TracePlan> plans = new ArrayList<>();
        for (SQLiteControlPlanePersistence.TracePlanData row : store.loadTracePlansForScan(
                scan.dto().scanId())) {
            if (row == null || row.payloadJson() == null || row.payloadJson().isBlank()) {
                continue;
            }
            try {
                plans.add(TracePlan.fromMap(JsonCodec.parseObject(row.payloadJson())));
            } catch (Exception ignored) {
                // 下方回退为从 IR 编译
            }
        }
        if (!plans.isEmpty()) {
            return List.copyOf(plans);
        }
        List<BytecodeFactIndex.TaintPath> taintPaths = StaticFactSnapshot.resolveTaintPaths(
                store.staticFacts(scan.dto().scanId()), scan.dto().sinks());
        for (ApiDtos.EntryDto entry : scan.dto().entries()) {
            if (entry == null || entry.route() == null || entry.route().isBlank()) {
                continue;
            }
            if (!"HTTP".equalsIgnoreCase(entry.protocol())) {
                continue;
            }
            plans.add(TracePlanCompiler.compileFromStaticIr(
                    entry, scan.dto().sinks(), scan.evidence(), taintPaths, List.of()));
            if (plans.size() >= 64) {
                break;
            }
        }
        return List.copyOf(plans);
    }
}
