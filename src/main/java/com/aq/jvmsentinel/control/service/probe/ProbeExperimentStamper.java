package com.aq.jvmsentinel.control.service.probe;

import com.aq.jvmsentinel.analysis.experiment.EntryParameterExperimentCompiler;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.model.ExperimentPlan;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** 为洪水探针 stamp 服务端编译的 experimentPlanId（P0-18/P0-19）。 */
public final class ProbeExperimentStamper {
    private ProbeExperimentStamper() {
    }

    public static List<ExternalArtifactTaskExecutor.ProbeTarget> stampExperimentPlanIds(
            ControlPlaneStore store,
            ControlPlaneStore.ScanRecord scan,
            List<ApiDtos.EntryDto> httpEntries,
            List<ExternalArtifactTaskExecutor.ProbeTarget> probes) {
        if (probes == null || probes.isEmpty()) return List.of();
        List<EntryParameterExperimentCompiler.CompiledExperiment> compiled =
                EntryParameterExperimentCompiler.compileUnified(
                        httpEntries,
                        store.hypotheses(scan.dto().scanId()),
                        List.<ExperimentPlan>of(),
                        List.of(),
                        Math.max(probes.size(), 16));
        Map<String, String> planByKey = new LinkedHashMap<>();
        for (EntryParameterExperimentCompiler.CompiledExperiment item : compiled) {
            if (item == null) continue;
            String key = item.method().toUpperCase(Locale.ROOT) + " " + item.route();
            planByKey.putIfAbsent(key, item.experimentPlanId());
        }
        List<ExternalArtifactTaskExecutor.ProbeTarget> stamped = new ArrayList<>(probes.size());
        for (ExternalArtifactTaskExecutor.ProbeTarget probe : probes) {
            if (probe == null) continue;
            if (probe.experimentPlanId() != null && !probe.experimentPlanId().isBlank()) {
                stamped.add(probe);
                continue;
            }
            String key = probe.method().toUpperCase(Locale.ROOT) + " " + probe.route();
            String planId = planByKey.getOrDefault(key, "");
            stamped.add(probe.withExperimentPlanId(planId));
        }
        return List.copyOf(stamped);
    }
}
