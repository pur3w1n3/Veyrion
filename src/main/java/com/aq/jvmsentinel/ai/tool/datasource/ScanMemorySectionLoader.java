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
        try {
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
        } catch (RuntimeException ignored) {
            // 与 pathRuns 一致：无 SQLite management / 瞬态失败时降级为空 INFERENCE，
            // 不得让整个 scan_memory_get 变成 TOOL_EXECUTION_FAILED。
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
                // 不得静默回落 INDEX：模型以为拿到 ROLE_SLICE，实际是另一分区。
                throw new IllegalArgumentException("SCAN_MEMORY_ROLE_INVALID");
            }
        } else if ("ROLE_SLICE".equalsIgnoreCase(sec)) {
            // role 空时仍按当前任务不可知；返回全量 roleSlices 目录而非假装 INDEX。
            body = com.aq.jvmsentinel.ai.memory.ScanMemoryBuilder.section(full, "ROLE_SLICE");
        } else {
            body = com.aq.jvmsentinel.ai.memory.ScanMemoryBuilder.section(full, sec);
        }
        return Optional.of(new FactRecord(scope, "scan-memory:" + scan.dto().scanId() + ":" + sec.toUpperCase(),
                DatasourceJson.JSON.valueToTree(body)));
    }
}
