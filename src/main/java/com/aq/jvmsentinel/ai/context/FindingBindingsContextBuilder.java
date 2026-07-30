package com.aq.jvmsentinel.ai.context;

import com.aq.jvmsentinel.ai.prompt.AiPromptSanitizer;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.aq.jvmsentinel.ai.tool.ControlPlaneToolDataSource.PathRunSource;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.aq.jvmsentinel.ai.FindingBindings;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;


/** findingBindings 事实块与服务端装配。 */
public final class FindingBindingsContextBuilder {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final ControlPlaneStore store;
    private final PathRunSource pathRunSource;

    private final PathRunContextBuilder pathRuns;
    private final ContrastContextBuilder contrast;



    public FindingBindingsContextBuilder(ControlPlaneStore store, PathRunSource pathRunSource, PathRunContextBuilder pathRuns, ContrastContextBuilder contrast) {
        this.store = java.util.Objects.requireNonNull(store, "store");
        this.pathRunSource = java.util.Objects.requireNonNull(pathRunSource, "pathRunSource");
        this.contrast = java.util.Objects.requireNonNull(contrast, "contrast");
        this.pathRuns = java.util.Objects.requireNonNull(pathRuns, "pathRuns");
    }

    public String findingBindingsContext(
            SQLiteControlPlanePersistence.AiJobData job, AiOutputLanguage language) {
        if (job.scanId() == null) return "";
        if (job.role() != AgentRole.PATH_EXPLORATION
                && job.role() != AgentRole.REPORT_GENERATION
                && job.role() != AgentRole.VULNERABILITY_TRIAGE) {
            return "";
        }
        List<FindingBindings.Binding> bindings;
        if (job.role() == AgentRole.REPORT_GENERATION) {
            bindings = loadPathFindingBindings(job, language);
            if (bindings.isEmpty()) {
                bindings = assembleFindingBindings(job, language);
            }
        } else {
            bindings = assembleFindingBindings(job, language);
        }
        if (bindings.isEmpty()) return "";
        return FindingBindings.formatFactsBlock(bindings, language);
    }

    public List<FindingBindings.Binding> loadPathFindingBindings(
            SQLiteControlPlanePersistence.AiJobData job, AiOutputLanguage language) {
        if (job == null || job.scanId() == null) return List.of();
        try {
            Optional<SQLiteControlPlanePersistence.AiJobData> pathJob = store.aiJobs(job.projectId()).stream()
                    .filter(item -> job.scanId().equals(item.scanId())
                            && item.role() == AgentRole.PATH_EXPLORATION
                            && "COMPLETED".equals(item.status())
                            && item.conclusionJson() != null)
                    .sorted((left, right) -> right.createdAt().compareTo(left.createdAt()))
                    .findFirst();
            if (pathJob.isPresent()) {
                List<FindingBindings.Binding> parsed =
                        FindingBindings.parseFromConclusion(pathJob.get().conclusionJson());
                if (!parsed.isEmpty()) return parsed;
            }
        } catch (RuntimeException ignored) {
            // 继续走 assemble
        }
        return assembleFindingBindings(job, language);
    }

    public List<FindingBindings.Binding> assembleFindingBindings(
            SQLiteControlPlanePersistence.AiJobData job, AiOutputLanguage language) {
        if (job == null || job.scanId() == null) return List.of();
        try {
            ControlPlaneStore.ScanRecord scan = store.requireScan(job.scanId());
            List<ApiDtos.PathRunDto> runs = pathRuns.loadPathRuns(job);
            Map<String, com.aq.jvmsentinel.domain.pathdebug.PathTrace> traces =
                    contrast.loadPathTracesByPathRunId(job);
            return FindingBindings.assemble(
                    scan.dto().findings(),
                    scan.dto().entries(),
                    runs,
                    traces,
                    language);
        } catch (RuntimeException ignored) {
            return List.of();
        }
    }
}
