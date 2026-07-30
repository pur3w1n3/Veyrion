package com.aq.jvmsentinel.ai.context;

import com.aq.jvmsentinel.ai.prompt.AiPromptSanitizer;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.provider.AgentRole;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/** 跨角色 job 历史查询。 */
public final class AiJobHistoryQueries {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final ControlPlaneStore store;

    public AiJobHistoryQueries(ControlPlaneStore store) {
        this.store = java.util.Objects.requireNonNull(store, "store");
    }

    public String latestRootCauseJson(String projectId, String scanId, AgentRole role) {
        return store.aiJobs(projectId).stream()
                .filter(job -> scanId.equals(job.scanId()) && job.role() == role
                        && "COMPLETED".equals(job.status()) && job.conclusionJson() != null)
                .sorted((left, right) -> right.createdAt().compareTo(left.createdAt()))
                .map(job -> {
                    try {
                        JsonNode root = JSON.readTree(job.conclusionJson()).path("rootCause");
                        if (root.isMissingNode() || root.isNull() || root.isEmpty()) return "";
                        String text = root.toString();
                        return text.length() <= 1_024 ? text : text.substring(0, 1_024);
                    } catch (Exception ignored) {
                        return "";
                    }
                })
                .filter(value -> !value.isBlank())
                .findFirst()
                .orElse("");
    }

    public String latestConclusionSummary(String projectId, String scanId, AgentRole role) {
        return store.aiJobs(projectId).stream()
                .filter(job -> scanId.equals(job.scanId()) && job.role() == role
                        && "COMPLETED".equals(job.status()) && job.conclusionJson() != null)
                .sorted((left, right) -> right.createdAt().compareTo(left.createdAt()))
                .map(job -> {
                    try {
                        return AiPromptSanitizer.sanitizeSummary(
                                JSON.readTree(job.conclusionJson()).path("summary").asText(""));
                    } catch (Exception ignored) {
                        return "";
                    }
                })
                .filter(value -> !value.isBlank())
                .findFirst()
                .map(value -> value.length() <= AiPromptLimits.PRIOR_ROLE_SUMMARY_CHARS
                        ? value : value.substring(0, AiPromptLimits.PRIOR_ROLE_SUMMARY_CHARS))
                .orElse("");
    }
}
