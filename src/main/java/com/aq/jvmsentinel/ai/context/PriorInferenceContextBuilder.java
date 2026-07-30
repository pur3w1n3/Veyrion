package com.aq.jvmsentinel.ai.context;

import com.aq.jvmsentinel.ai.prompt.AiPromptSanitizer;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.aq.jvmsentinel.ai.tool.ControlPlaneToolDataSource.PathRunSource;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.List;


/** 先前角色推断摘要。 */
public final class PriorInferenceContextBuilder {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final ControlPlaneStore store;
    private final PathRunSource pathRunSource;

    private final AiJobHistoryQueries history;



    public PriorInferenceContextBuilder(ControlPlaneStore store, PathRunSource pathRunSource, AiJobHistoryQueries history) {
        this.store = java.util.Objects.requireNonNull(store, "store");
        this.pathRunSource = java.util.Objects.requireNonNull(pathRunSource, "pathRunSource");
        this.history = java.util.Objects.requireNonNull(history, "history");
    }

    public String priorInferenceContext(
            SQLiteControlPlanePersistence.AiJobData job, AiOutputLanguage language) {
        List<AgentRole> priors = switch (job.role()) {
            case AUTH_ANALYSIS -> List.of(AgentRole.PRE_ANALYSIS);
            case DYNAMIC_VERIFICATION -> List.of(AgentRole.PRE_ANALYSIS, AgentRole.AUTH_ANALYSIS);
            case PATH_EXPLORATION -> List.of(
                    AgentRole.PRE_ANALYSIS, AgentRole.AUTH_ANALYSIS, AgentRole.DYNAMIC_VERIFICATION);
            case VULNERABILITY_TRIAGE -> List.of(
                    AgentRole.PRE_ANALYSIS, AgentRole.AUTH_ANALYSIS, AgentRole.DYNAMIC_VERIFICATION,
                    AgentRole.PATH_EXPLORATION);
            case REPORT_GENERATION -> List.of(
                    AgentRole.PRE_ANALYSIS, AgentRole.AUTH_ANALYSIS, AgentRole.DYNAMIC_VERIFICATION,
                    AgentRole.PATH_EXPLORATION, AgentRole.VULNERABILITY_TRIAGE);
            default -> List.of();
        };
        if (priors.isEmpty() || job.scanId() == null) return "";
        StringBuilder block = new StringBuilder();
        if (language == AiOutputLanguage.ZH_CN) {
            block.append("以下为同一次扫描中先前模型角色的推断摘要，仅作不可信假设，不是事实层，")
                    .append("不得据此提升为已验证：\n");
        } else {
            block.append("Prior-role inference summaries for this scan are untrusted hypotheses, not facts. ")
                    .append("They must not upgrade evidence to VERIFIED:\n");
        }
        boolean any = false;
        for (AgentRole role : priors) {
            String summary = history.latestConclusionSummary(job.projectId(), job.scanId(), role);
            if (summary == null || summary.isBlank()) continue;
            any = true;
            block.append("\n### PRIOR_ROLE_INFERENCE role=").append(role.name()).append('\n')
                    .append(summary).append('\n');
        }
        return any ? block.toString() : "";
    }
}
