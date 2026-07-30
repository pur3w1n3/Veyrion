package com.aq.jvmsentinel.control.store;

import com.aq.jvmsentinel.analysis.experiment.PathTraceEvidenceGraphDelta;
import com.aq.jvmsentinel.analysis.experiment.PostureExperimentCompiler;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.domain.ir.EvidenceGraph;
import com.aq.jvmsentinel.domain.ir.EvidenceGraphMerge;
import com.aq.jvmsentinel.domain.ir.IrNode;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** Store 辅助类。 */
public final class ControlPlanePathRunTraceStore {
    private final ControlPlaneMemoryState state;
    private final SQLiteControlPlanePersistence persistence;

    public ControlPlanePathRunTraceStore(ControlPlaneMemoryState state,
                                  SQLiteControlPlanePersistence persistence) {
        this.state = Objects.requireNonNull(state, "state");
        this.persistence = persistence;
    }

    public void replacePathTracesForTask(String projectId, String artifactDigest, String scanId,
                                  String taskId, List<SQLiteControlPlanePersistence.PathTraceData> traces,
                                  String createdAt) {
        if (persistence != null) {
            persistence.replacePathTracesForTask(projectId, artifactDigest, scanId, taskId, traces, createdAt);
        }
        if (traces != null) {
            for (SQLiteControlPlanePersistence.PathTraceData row : traces) {
                if (row == null || row.pathRunId() == null || row.pathRunId().isBlank()) {
                    continue;
                }
                try {
                    PathTrace trace = PathTrace.fromMap(JsonCodec.parseObject(row.payloadJson()));
                    state.pathTracesByPathRunId.put(row.pathRunId(), trace);
                } catch (RuntimeException ignored) {
                    // 畸形 trace 负载不得阻断任务完成
                    }
            }
            applyPathTraceEvidenceGraphDelta(scanId, traces);
        }
    }

    private void applyPathTraceEvidenceGraphDelta(
            String scanId, List<SQLiteControlPlanePersistence.PathTraceData> traces) {
        if (scanId == null || scanId.isBlank() || traces == null || traces.isEmpty()) {
            return;
        }
        Optional<StaticFactSnapshot> facts = staticFacts(scanId);
        if (facts.isEmpty() || !facts.get().hasPersistedEvidenceGraph()) {
            return;
        }
        EvidenceGraph base = facts.get().evidenceGraph().orElse(null);
        if (base == null) {
            return;
        }
        List<IrNode> extras = new ArrayList<>();
        for (SQLiteControlPlanePersistence.PathTraceData row : traces) {
            if (row == null || row.payloadJson() == null || row.payloadJson().isBlank()) {
                continue;
            }
            try {
                PathTrace trace = PathTrace.fromMap(JsonCodec.parseObject(row.payloadJson()));
                PathTraceEvidenceGraphDelta.Delta delta =
                        PathTraceEvidenceGraphDelta.fromPathTrace(trace, scanId);
                extras.addAll(delta.nodes());
                state.pathTraceEvidenceDeltas.put(trace.pathTraceId(),
                        PathTraceEvidenceGraphDelta.toWireMap(delta));
            } catch (RuntimeException ignored) {
                // 畸形 trace 不得阻断 evidence graph 合并
                }
        }
        if (extras.isEmpty()) {
            return;
        }
        EvidenceGraph merged = EvidenceGraphMerge.withExtraNodes(base, extras);
        state.staticFacts.put(scanId, facts.get().withEvidenceGraph(merged));
    }

    public Map<String, Object> pathTraceEvidenceDelta(String pathTraceId) {
        if (pathTraceId == null || pathTraceId.isBlank()) {
            return Map.of();
        }
        Map<String, Object> delta = state.pathTraceEvidenceDeltas.get(pathTraceId);
        return delta == null ? Map.of() : Map.copyOf(delta);
    }

    public List<SQLiteControlPlanePersistence.PathTraceData> loadPathTracesForScan(
            String projectId, String artifactDigest, String scanId) {
        return persistence == null
                ? List.of()
                : persistence.loadPathTracesForScan(projectId, artifactDigest, scanId);
    }

    public PathTrace pathTraceForPathRun(String pathRunId) {
        if (pathRunId == null || pathRunId.isBlank()) {
            return null;
        }
        return state.pathTracesByPathRunId.get(pathRunId);
    }

    public void registerPostureExperiment(PostureExperimentCompiler.CompiledPostureExperiment plan) {
        if (plan == null || plan.experimentPlanId().isBlank()) {
            return;
        }
        state.postureExperimentsById.put(plan.experimentPlanId(), plan);
    }

    public PostureExperimentCompiler.CompiledPostureExperiment postureExperiment(String experimentPlanId) {
        if (experimentPlanId == null || experimentPlanId.isBlank()) {
            return null;
        }
        return state.postureExperimentsById.get(experimentPlanId);
    }

    public Map<String, PostureExperimentCompiler.CompiledPostureExperiment> postureExperimentsForScan(String scanId) {
        if (scanId == null || scanId.isBlank()) {
            return Map.of();
        }
        Map<String, PostureExperimentCompiler.CompiledPostureExperiment> result = new LinkedHashMap<>();
        for (PostureExperimentCompiler.CompiledPostureExperiment plan : state.postureExperimentsById.values()) {
            if (plan.experimentPlanId().contains(scanId) || plan.tracePlanId().contains(scanId)) {
                result.put(plan.experimentPlanId(), plan);
            }
        }
        return Map.copyOf(result);
    }

    public List<ApiDtos.PathRunDto> loadPathRunsForScan(String projectId, String artifactDigest, String scanId) {
        return persistence == null ? List.of() : persistence.loadPathRunsForScan(projectId, artifactDigest, scanId);
    }

    public List<ApiDtos.PathRunDto> loadPathRunsForTask(String taskId) {
        return persistence == null ? List.of() : persistence.loadPathRunsForTask(taskId);
    }

    public void replacePathRunsForTask(String projectId, String artifactDigest, String scanId,
                                String taskId, List<ApiDtos.PathRunDto> pathRuns, String createdAt) {
        if (persistence != null) {
            persistence.replacePathRunsForTask(projectId, artifactDigest, scanId, taskId, pathRuns, createdAt);
        }
    }

    public synchronized void saveStaticFacts(String scanId, StaticFactSnapshot snapshot, String actorId,
                                      Runnable requireScan) {
        Objects.requireNonNull(scanId, "scanId");
        Objects.requireNonNull(snapshot, "snapshot");
        requireScan.run();
        if (persistence != null) {
            persistence.insertTaintGraph(scanId, snapshot.toJson(), Instant.now().toString(), actorId);
        }
        state.staticFacts.put(scanId, snapshot);
    }

    public Optional<StaticFactSnapshot> staticFacts(String scanId) {
        if (scanId == null || scanId.isBlank()) {
            return Optional.empty();
        }
        StaticFactSnapshot cached = state.staticFacts.get(scanId);
        if (cached != null) {
            return Optional.of(cached);
        }
        if (persistence == null) {
            return Optional.empty();
        }
        Optional<StaticFactSnapshot> loaded = persistence.loadTaintGraph(scanId);
        loaded.ifPresent(snapshot -> state.staticFacts.putIfAbsent(scanId, snapshot));
        return Optional.ofNullable(state.staticFacts.get(scanId));
    }

    public void purgeScanScopedCaches(String scanId) {
        for (String experimentPlanId : postureExperimentsForScan(scanId).keySet()) {
            state.postureExperimentsById.remove(experimentPlanId);
        }
        state.pathTracesByPathRunId.entrySet().removeIf(entry -> {
            PathTrace trace = entry.getValue();
            if (trace == null) {
                return true;
            }
            return containsScanToken(trace.pathTraceId(), scanId)
                    || containsScanToken(trace.pathRunId(), scanId)
                    || containsScanToken(trace.experimentPlanId(), scanId)
                    || containsScanToken(trace.tracePlanId(), scanId);
        });
        state.pathTraceEvidenceDeltas.entrySet().removeIf(entry -> containsScanToken(entry.getKey(), scanId));
    }

    public static boolean containsScanToken(String value, String scanId) {
        return value != null && !value.isBlank() && scanId != null && value.contains(scanId);
    }
}
