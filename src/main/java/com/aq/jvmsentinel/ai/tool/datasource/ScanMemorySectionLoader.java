package com.aq.jvmsentinel.ai.tool.datasource;

import com.aq.jvmsentinel.ai.tool.ControlPlaneToolDataSource;
import com.aq.jvmsentinel.ai.tool.ToolDataSource.FactRecord;
import com.aq.jvmsentinel.ai.tool.ToolExecutionContext;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * 加载 scan memory 分区切片（INDEX / FACTS / ROLE_SLICE 等）。
 */
public final class ScanMemorySectionLoader {
    private final ControlPlaneStore store;
    private final String scanId;
    private final ControlPlaneToolDataSource.PathRunSource pathRunSource;

    public ScanMemorySectionLoader(ControlPlaneStore store, String scanId,
                                     ControlPlaneToolDataSource.PathRunSource pathRunSource) {
        this.store = Objects.requireNonNull(store, "store");
        this.scanId = Objects.requireNonNull(scanId, "scanId");
        this.pathRunSource = Objects.requireNonNull(pathRunSource, "pathRunSource");
    }

    /**
     * @param scope  工具执行作用域
     * @param section 分区名，空则 INDEX
     * @param role   ROLE_SLICE 时指定 AgentRole
     */
    public Optional<FactRecord> load(ToolExecutionContext.Scope scope, String section, String role,
                                     DatasourceScope datasourceScope) {
        ControlPlaneStore.ScanRecord scan = datasourceScope.scopedScan(scope);
        List<ApiDtos.PathRunDto> runs = List.of();
        try {
            runs = List.copyOf(pathRunSource.pathRunsForScan(
                    scan.dto().projectId(), scan.dto().artifactDigest(), scan.dto().scanId()));
        } catch (RuntimeException ignored) {
            runs = List.of();
        }
        Map<String, String> priors = new LinkedHashMap<>();
        for (var job : store.aiJobs(scan.dto().projectId())) {
            if (job == null || !scan.dto().scanId().equals(job.scanId())
                    || !"COMPLETED".equals(job.status()) || job.conclusionJson() == null) {
                continue;
            }
            try {
                String summary = DatasourceJson.JSON.readTree(job.conclusionJson()).path("summary").asText("");
                if (!summary.isBlank()) {
                    priors.putIfAbsent(job.role().name(), summary.length() > 800
                            ? summary.substring(0, 800) : summary);
                }
            } catch (Exception ignored) {
                // 跳过格式错误的 conclusion
            }
        }
        Map<String, Object> full = com.aq.jvmsentinel.ai.memory.ScanMemoryBuilder.build(
                store, scan.dto().scanId(), runs, priors);
        String sec = section == null ? "INDEX" : section.trim();
        Map<String, Object> body;
        if ("ROLE_SLICE".equalsIgnoreCase(sec) && role != null && !role.isBlank()) {
            try {
                body = com.aq.jvmsentinel.ai.memory.ScanMemoryBuilder.roleSlice(
                        full, com.aq.jvmsentinel.provider.AgentRole.valueOf(role.trim().toUpperCase()));
            } catch (IllegalArgumentException badRole) {
                body = com.aq.jvmsentinel.ai.memory.ScanMemoryBuilder.section(full, "INDEX");
            }
        } else {
            body = com.aq.jvmsentinel.ai.memory.ScanMemoryBuilder.section(full, sec);
        }
        return Optional.of(new FactRecord(scope, "scan-memory:" + scan.dto().scanId() + ":" + sec.toUpperCase(),
                DatasourceJson.JSON.valueToTree(body)));
    }
}
