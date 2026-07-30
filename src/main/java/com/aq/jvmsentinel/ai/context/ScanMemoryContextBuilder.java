package com.aq.jvmsentinel.ai.context;

import com.aq.jvmsentinel.ai.prompt.AiPromptSanitizer;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.aq.jvmsentinel.ai.tool.ControlPlaneToolDataSource.PathRunSource;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.aq.jvmsentinel.ai.memory.ScanMemoryBuilder;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;


/** SCAN_MEMORY_INDEX 上下文。 */
public final class ScanMemoryContextBuilder {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final ControlPlaneStore store;
    private final PathRunSource pathRunSource;

    private final AiJobHistoryQueries history;



    public ScanMemoryContextBuilder(ControlPlaneStore store, PathRunSource pathRunSource, AiJobHistoryQueries history) {
        this.store = java.util.Objects.requireNonNull(store, "store");
        this.pathRunSource = java.util.Objects.requireNonNull(pathRunSource, "pathRunSource");
        this.history = java.util.Objects.requireNonNull(history, "history");
    }

    public String scanMemoryIndexContext(
            SQLiteControlPlanePersistence.AiJobData job, AiOutputLanguage language) {
        if (job.scanId() == null) {
            return "";
        }
        try {
            ControlPlaneStore.ScanRecord scan = store.requireScan(job.scanId());
            List<ApiDtos.PathRunDto> runs;
            try {
                runs = List.copyOf(pathRunSource.pathRunsForScan(
                        job.projectId(), job.artifactDigest(), job.scanId()));
            } catch (RuntimeException ignored) {
                runs = List.of();
            }
            Map<String, String> priors = new LinkedHashMap<>();
            for (AgentRole role : AgentRole.values()) {
                String summary = history.latestConclusionSummary(job.projectId(), job.scanId(), role);
                if (summary != null && !summary.isBlank()) {
                    priors.put(role.name(), summary);
                }
            }
            Map<String, Object> full = com.aq.jvmsentinel.ai.memory.ScanMemoryBuilder.build(
                    store, job.scanId(), runs, priors);
            Map<String, Object> index = com.aq.jvmsentinel.ai.memory.ScanMemoryBuilder.indexOnly(full);
            Map<String, Object> slice = com.aq.jvmsentinel.ai.memory.ScanMemoryBuilder.roleSlice(full, job.role());
            StringBuilder block = new StringBuilder();
            if (language == AiOutputLanguage.ZH_CN) {
                block.append("SCAN_MEMORY_INDEX（同扫描共享记忆索引；细节用 scan_memory_get / facts_search 深挖；")
                        .append("INFERENCE 不可升 VERIFIED）：\n");
            } else {
                block.append("SCAN_MEMORY_INDEX (same-scan shared memory; deepen with scan_memory_get / ")
                        .append("facts_search; INFERENCE must not upgrade VERIFIED):\n");
            }
            block.append(JSON.writeValueAsString(Map.of(
                    "counts", index.get("counts"),
                    "knownEffects", index.getOrDefault("knownEffects", List.of()),
                    "staticOnlyGaps", index.getOrDefault("staticOnlyGaps", List.of()),
                    "howToDeepen", index.get("howToDeepen"),
                    "roleGuidance", slice.get("guidance"),
                    "scanId", scan.dto().scanId())));
            block.append('\n');
            return block.toString();
        } catch (Exception ignored) {
            return "";
        }
    }
}
