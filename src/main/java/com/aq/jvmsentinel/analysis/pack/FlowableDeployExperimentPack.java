package com.aq.jvmsentinel.analysis.pack;

import com.aq.jvmsentinel.model.ExperimentPlan;
import com.aq.jvmsentinel.model.IdentityTrack;

import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * 说明：Flowable/BPMN deploy-upload 实验 shape。
 * Multipart deploy probe 保持非破坏性（无 process start / 无 memory shell）。
 */
public final class FlowableDeployExperimentPack implements AnalysisPack {
    @Override
    public String id() {
        return "flowable-deploy-multipart";
    }

    @Override
    public boolean matches(Path artifactPath, List<String> entryRoutes) {
        if (entryRoutes == null) return false;
        for (String route : entryRoutes) {
            String value = route == null ? "" : route.toLowerCase(Locale.ROOT);
            if (value.contains("flowable") || value.contains("activiti")
                    || value.contains("camunda") || value.contains("blade-flow")
                    || value.contains("deploy") || value.contains("bpmn")
                    || value.contains("process-definition") || value.contains("repository")) {
                return true;
            }
        }
        return false;
    }

    @Override
    public Optional<String> suggestJwtSecret(Path artifactPath) {
        return Optional.empty();
    }

    @Override
    public List<ExperimentPlan> experimentTemplates(String entrypointRef, IdentityTrack track) {
        return List.of(new ExperimentPlan(
                "plan-flowable-deploy-" + track.name().toLowerCase(Locale.ROOT),
                entrypointRef,
                track,
                "POST",
                "multipart/form-data",
                List.of("file", "deploymentName"),
                track != IdentityTrack.UNAUTH,
                "2xx",
                "$.id",
                2));
    }
}
