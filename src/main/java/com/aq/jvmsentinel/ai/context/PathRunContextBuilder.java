package com.aq.jvmsentinel.ai.context;

import com.aq.jvmsentinel.ai.prompt.AiPromptSanitizer;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.aq.jvmsentinel.ai.tool.ControlPlaneToolDataSource;
import com.aq.jvmsentinel.ai.tool.ControlPlaneToolDataSource.PathRunSource;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.List;

/** PathRun 事实块与加载。 */
public final class PathRunContextBuilder {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final ControlPlaneStore store;
    private final PathRunSource pathRunSource;


    public PathRunContextBuilder(ControlPlaneStore store, PathRunSource pathRunSource) {
        this.store = java.util.Objects.requireNonNull(store, "store");
        this.pathRunSource = java.util.Objects.requireNonNull(pathRunSource, "pathRunSource");
    }

    public List<ApiDtos.PathRunDto> loadPathRunsForScanSafe(ControlPlaneStore.ScanRecord scan) {
        try {
            return List.copyOf(pathRunSource.pathRunsForScan(
                    scan.dto().projectId(), scan.dto().artifactDigest(), scan.dto().scanId()));
        } catch (RuntimeException ignored) {
            return List.of();
        }
    }
    public List<ApiDtos.PathRunDto> loadPathRuns(SQLiteControlPlanePersistence.AiJobData job) {
        if (job == null || job.scanId() == null) return List.of();
        try {
            return List.copyOf(pathRunSource.pathRunsForScan(
                    job.projectId(), job.artifactDigest(), job.scanId()));
        } catch (RuntimeException ignored) {
            return List.of();
        }
    }
    public String pathRunFactsContext(
            SQLiteControlPlanePersistence.AiJobData job, AiOutputLanguage language) {
        if (job.role() == AgentRole.PRE_ANALYSIS || job.scanId() == null) return "";
        List<ApiDtos.PathRunDto> runs;
        try {
            runs = List.copyOf(pathRunSource.pathRunsForScan(
                    job.projectId(), job.artifactDigest(), job.scanId()));
        } catch (RuntimeException ignored) {
            runs = List.of();
        }
        StringBuilder block = new StringBuilder();
        if (language == AiOutputLanguage.ZH_CN) {
            block.append("PATH_RUN_FACTS（服务端持久化的 HTTP/SQL 路径会话；可用 facts_search kind=PATH_RUN 深挖）：\n");
        } else {
            block.append("PATH_RUN_FACTS (persisted HTTP/SQL path sessions; deepen with facts_search kind=PATH_RUN):\n");
        }
        if (runs.isEmpty()) {
            block.append(language == AiOutputLanguage.ZH_CN
                    ? "- 当前扫描尚无 PathRun；在获得动态探针结果前不得宣称绕过或 DYNAMIC_CONFIRMED。\n"
                    : "- No PathRuns yet for this scan; do not claim bypass or DYNAMIC_CONFIRMED without probe evidence.\n");
            return block.toString();
        }
        int emitted = 0;
        for (ApiDtos.PathRunDto run : runs) {
            if (emitted >= AiPromptLimits.MAX_PATH_RUN_PROMPT_ROWS) break;
            try {
                block.append("- ").append(JSON.writeValueAsString(
                        ControlPlaneToolDataSource.pathRunPromptSummary(run))).append('\n');
            } catch (Exception ignored) {
                block.append("- pathRunId=").append(run.pathRunId())
                        .append(" httpStatus=").append(run.httpStatus())
                        .append(" outcome=").append(run.outcomeClass()).append('\n');
            }
            emitted++;
        }
        if (runs.size() > AiPromptLimits.MAX_PATH_RUN_PROMPT_ROWS) {
            block.append(language == AiOutputLanguage.ZH_CN
                    ? "- …另有 " + (runs.size() - AiPromptLimits.MAX_PATH_RUN_PROMPT_ROWS) + " 条未内联，请用 facts_search kind=PATH_RUN 拉取。\n"
                    : "- …" + (runs.size() - AiPromptLimits.MAX_PATH_RUN_PROMPT_ROWS)
                    + " more omitted; fetch with facts_search kind=PATH_RUN.\n");
        }
        return block.toString();
    }
}
