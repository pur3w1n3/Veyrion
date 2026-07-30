package com.aq.jvmsentinel.ai.tool.datasource;

import com.aq.jvmsentinel.ai.tool.ControlPlaneToolDataSource;
import com.aq.jvmsentinel.ai.tool.ToolExecutionContext;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * 工具数据源共享作用域：校验 project/scan 边界并加载 path run、path trace、动态证据。
 */
public final class DatasourceScope {
    private final ControlPlaneStore store;
    private final String scanId;
    private final ControlPlaneToolDataSource.PathRunSource pathRunSource;
    private final ControlPlaneToolDataSource.DynamicEvidenceSource dynamicEvidenceSource;

    public DatasourceScope(ControlPlaneStore store, String scanId,
                           ControlPlaneToolDataSource.PathRunSource pathRunSource,
                           ControlPlaneToolDataSource.DynamicEvidenceSource dynamicEvidenceSource) {
        this.store = Objects.requireNonNull(store, "store");
        this.scanId = Objects.requireNonNull(scanId, "scanId");
        this.pathRunSource = Objects.requireNonNull(pathRunSource, "pathRunSource");
        this.dynamicEvidenceSource = Objects.requireNonNull(dynamicEvidenceSource, "dynamicEvidenceSource");
    }

    public ControlPlaneStore store() {
        return store;
    }

    public String scanId() {
        return scanId;
    }

    /** 校验 workspace/project 与 scan 绑定后返回 scan 记录。 */
    public ControlPlaneStore.ScanRecord scopedScan(ToolExecutionContext.Scope scope) {
        if (!"local".equals(scope.workspaceId())) {
            throw new SecurityException("workspace scope mismatch");
        }
        ControlPlaneStore.ScanRecord scan = store.requireScan(scanId);
        if (!scope.projectId().equals(scan.dto().projectId())) {
            throw new SecurityException("project scope mismatch");
        }
        return scan;
    }

    public List<ApiDtos.EvidenceDto> dynamicEvidence(ControlPlaneStore.ScanRecord scan) {
        ApiDtos.ScanDto dto = scan.dto();
        List<ApiDtos.EvidenceDto> values = List.copyOf(dynamicEvidenceSource.evidenceForScan(
                dto.projectId(), dto.artifactDigest(), dto.scanId()));
        if (values.size() > 10_000 || values.stream().anyMatch(value ->
                !dto.projectId().equals(value.projectId())
                        || !dto.artifactDigest().equals(value.artifactDigest())
                        || !dto.scanId().equals(value.scanId()))) {
            throw new SecurityException("dynamic evidence scope mismatch");
        }
        return values;
    }

    public List<ApiDtos.PathRunDto> pathRuns(ControlPlaneStore.ScanRecord scan) {
        ApiDtos.ScanDto dto = scan.dto();
        List<ApiDtos.PathRunDto> values = List.copyOf(pathRunSource.pathRunsForScan(
                dto.projectId(), dto.artifactDigest(), dto.scanId()));
        if (values.size() > 50_000 || values.stream().anyMatch(value -> !dto.scanId().equals(value.scanId()))) {
            throw new SecurityException("path run scope mismatch");
        }
        return values;
    }

    public List<PathTrace> pathTraces(ControlPlaneStore.ScanRecord scan) {
        ApiDtos.ScanDto dto = scan.dto();
        List<PathTrace> traces = new ArrayList<>();
        for (SQLiteControlPlanePersistence.PathTraceData row : store.loadPathTracesForScan(
                dto.projectId(), dto.artifactDigest(), dto.scanId())) {
            PathTrace cached = store.pathTraceForPathRun(row.pathRunId());
            if (cached != null) {
                traces.add(cached);
                continue;
            }
            try {
                traces.add(PathTrace.fromMap(JsonCodec.parseObject(row.payloadJson())));
            } catch (RuntimeException ignored) {
                // 跳过格式错误的行
            }
        }
        return List.copyOf(traces);
    }
}
