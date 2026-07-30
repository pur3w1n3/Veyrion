package com.aq.jvmsentinel.control.service.probe;

import com.aq.jvmsentinel.analysis.entry.NonHttpEntryProtocol;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;
import com.aq.jvmsentinel.worker.TaskSnapshot;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.BiFunction;

/** 断网洪水探针基础选择：HTTP 入口过滤与优先级排序。 */
public final class ProbeFloodPlanBuilder {
    private ProbeFloodPlanBuilder() {
    }

    public record FloodSelection(
            ApiDtos.EntryDto primary,
            LinkedHashSet<String> selectedIds,
            List<ExternalArtifactTaskExecutor.ProbeTarget> effectiveProbes) {
    }

    public static List<ApiDtos.EntryDto> filterHttpProbeEntries(ControlPlaneStore.ScanRecord scan) {
        return scan.dto().entries().stream()
                .filter(entry -> NonHttpEntryProtocol.isHttpProbeEligible(entry.protocol()))
                .filter(entry -> entry.route() != null
                        && entry.route().matches("/[A-Za-z0-9_./{}:-]{0,1023}"))
                .filter(entry -> entry.method() != null
                        && (Set.of("GET", "POST", "PUT", "PATCH", "DELETE")
                        .contains(entry.method().toUpperCase(Locale.ROOT))
                        || "UNKNOWN".equalsIgnoreCase(entry.method())))
                .toList();
    }

    /**
     * 按 TracePlan 缺口、PATH_EXPLORATION 提示、静态 effect 与高价值路由选择基础洪水探针。
     */
    public static FloodSelection selectBaseProbes(
            ControlPlaneStore.ScanRecord scan,
            List<ApiDtos.EntryDto> httpEntries,
            String taskIdHint,
            String preferredEntryId,
            List<String> candidateInputs,
            int requestedMaxRequests,
            int maxProbes,
            BiFunction<String, String, List<TaskSnapshot>> workerSnapshots,
            ProbeTracePlanSupport traceSupport,
            String pathExplorationHint) {
        int maxBaseProbes = Math.min(httpEntries.size(), maxProbes);
        if (httpEntries.size() >= maxProbes) {
            maxBaseProbes = maxProbes * 3 / 4;
        }
        LinkedHashSet<String> selectedIds = new LinkedHashSet<>();
        List<ExternalArtifactTaskExecutor.ProbeTarget> probes = new ArrayList<>();
        if (preferredEntryId != null) {
            httpEntries.stream().filter(entry -> entry.id().equals(preferredEntryId)).findFirst()
                    .ifPresent(entry -> {
                        selectedIds.add(entry.id());
                        probes.add(ProbeWireHelpers.probeTargetFor(entry));
                    });
        }
        if (taskIdHint != null) {
            workerSnapshots.apply(scan.dto().projectId(), scan.dto().scanId()).stream()
                    .filter(snapshot -> snapshot.scope().taskId().equals(taskIdHint))
                    .map(snapshot -> snapshot.spec().targetEntryId())
                    .findFirst()
                    .flatMap(targetId -> httpEntries.stream().filter(entry -> entry.id().equals(targetId)).findFirst())
                    .ifPresent(entry -> {
                        if (selectedIds.add(entry.id())) probes.add(ProbeWireHelpers.probeTargetFor(entry));
                    });
        }
        for (String entryId : traceSupport.tracePlanGapEntryIds(scan)) {
            if (probes.size() >= maxBaseProbes) break;
            httpEntries.stream()
                    .filter(entry -> entry.id().equals(entryId))
                    .findFirst()
                    .ifPresent(entry -> {
                        if (selectedIds.add(entry.id())) {
                            probes.add(ProbeWireHelpers.probeTargetFor(entry));
                        }
                    });
        }
        if (pathExplorationHint != null && !pathExplorationHint.isBlank()) {
            for (ApiDtos.EntryDto entry : httpEntries) {
                if (probes.size() >= maxBaseProbes) break;
                if (!(pathExplorationHint.contains(entry.id()) || pathExplorationHint.contains(entry.route()))) {
                    continue;
                }
                if (!selectedIds.add(entry.id())) continue;
                probes.add(ProbeWireHelpers.probeTargetFor(entry));
            }
        }
        for (String entryId : traceSupport.staticEffectEntryIds(scan, httpEntries)) {
            if (probes.size() >= maxBaseProbes) break;
            httpEntries.stream()
                    .filter(entry -> entry.id().equals(entryId))
                    .findFirst()
                    .ifPresent(entry -> {
                        if (selectedIds.add(entry.id())) {
                            probes.add(ProbeWireHelpers.probeTargetFor(entry));
                        }
                    });
        }
        for (ApiDtos.EntryDto entry : httpEntries) {
            if (probes.size() >= maxBaseProbes) break;
            if (!ProbeWireHelpers.isHighValueRoute(entry.route())) continue;
            if (!selectedIds.add(entry.id())) continue;
            probes.add(ProbeWireHelpers.probeTargetFor(entry));
        }
        for (ApiDtos.EntryDto entry : httpEntries) {
            if (probes.size() >= maxBaseProbes) break;
            if (!selectedIds.add(entry.id())) continue;
            probes.add(ProbeWireHelpers.probeTargetFor(entry));
        }
        ApiDtos.EntryDto primary = httpEntries.stream()
                .filter(entry -> selectedIds.contains(entry.id()))
                .findFirst()
                .orElse(httpEntries.get(0));
        List<ExternalArtifactTaskExecutor.ProbeTarget> candidateProbes =
                ProbeFloodSelector.candidateProbeTargets(primary, candidateInputs, requestedMaxRequests);
        List<ExternalArtifactTaskExecutor.ProbeTarget> effectiveProbes = probes;
        if (!candidateProbes.isEmpty()) {
            effectiveProbes = candidateProbes;
            selectedIds.clear();
            selectedIds.add(primary.id());
        }
        return new FloodSelection(primary, selectedIds, effectiveProbes);
    }
}
