package com.aq.jvmsentinel.control.persistence;

import com.aq.jvmsentinel.artifact.ArtifactUploadService;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.event.VersionedEvent;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderKind;
import com.aq.jvmsentinel.security.ProviderSecretCipher.EncryptedSecret;
import com.aq.jvmsentinel.security.ProviderSecretCipher.SecretScope;
import com.aq.jvmsentinel.security.auth.OperatorRole;
import com.aq.jvmsentinel.worker.InMemoryTraceStore;
import com.aq.jvmsentinel.worker.TaskSnapshot;
import com.aq.jvmsentinel.worker.TraceChunk;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 控制面不可变快照的纯 JDBC SQLite 持久化门面。
 *
 * <p>仅存储制品元数据及其受控主机路径；制品字节仍由 {@code ArtifactRegistry} 所选内容源持有。</p>
 */
public final class SQLiteControlPlanePersistence {
    public static final String LOCAL_WORKSPACE = "local";

    private final PersistenceSupport support;
    private final ScanProjectArtifactPersistence scans;
    private final AiManagementPersistence aiManagement;
    private final PathExperimentPersistence paths;
    private final WorkerRuntimePersistence workerRuntime;

    public SQLiteControlPlanePersistence(Path databasePath, Path allowedRoot) {
        Path secured = PersistenceSupport.controlledDatabasePath(databasePath, allowedRoot);
        this.support = new PersistenceSupport(secured);
        new MigrationSupport(support).migrate();
        // 迁移后、业务流量前：有显著 freelist 时独占 VACUUM，失败不阻断启动。
        support.vacuumOnStartupIfNeeded();
        this.scans = new ScanProjectArtifactPersistence(support);
        this.aiManagement = new AiManagementPersistence(support);
        this.paths = new PathExperimentPersistence(support);
        this.workerRuntime = new WorkerRuntimePersistence(support);
    }

    public Path databasePath() {
        return support.databasePath();
    }

    public List<IdempotencyData> loadIdempotency() {
        return workerRuntime.loadIdempotency();
    }

    /** 插入不可变记录，或返回同一 scope/key 已提交的记录。 */
    public IdempotencyData putIdempotency(IdempotencyData candidate) {
        return workerRuntime.putIdempotency(candidate);
    }

    public List<PipelineRunData> loadPipelineRuns() {
        return workerRuntime.loadPipelineRuns();
    }

    public void savePipelineRun(PipelineRunData run) {
        workerRuntime.savePipelineRun(run);
    }

    /**
     * CAS 游标推进：仅 armed 且 scan/run/attempt 与 expected 资源匹配的行可前进。
     * 外来、过期、重复或迟到写入返回 false。
     */
    public boolean compareAndAdvancePipelineRun(PipelineRunData expected, PipelineRunData next) {
        return workerRuntime.compareAndAdvancePipelineRun(expected, next);
    }

    public List<ProbePlanData> loadProbePlans() {
        return workerRuntime.loadProbePlans();
    }

    public void saveProbePlan(ProbePlanData plan) {
        workerRuntime.saveProbePlan(plan);
    }

    public List<ExperimentPlanData> loadExperimentPlans() {
        return paths.loadExperimentPlans();
    }

    public List<ExperimentPlanData> loadExperimentPlansForScan(String scanId) {
        return paths.loadExperimentPlansForScan(scanId);
    }

    public void saveExperimentPlan(ExperimentPlanData plan) {
        paths.saveExperimentPlan(plan);
    }

    public List<com.aq.jvmsentinel.control.ApiDtos.PathRunDto> loadPathRunsForScan(
            String projectId, String artifactDigest, String scanId) {
        return paths.loadPathRunsForScan(projectId, artifactDigest, scanId);
    }

    public List<com.aq.jvmsentinel.control.ApiDtos.PathRunDto> loadPathRunsForTask(String taskId) {
        return paths.loadPathRunsForTask(taskId);
    }

    public void replacePathRunsForTask(String projectId, String artifactDigest, String scanId,
                                       String taskId, List<com.aq.jvmsentinel.control.ApiDtos.PathRunDto> pathRuns,
                                       String createdAt) {
        paths.replacePathRunsForTask(projectId, artifactDigest, scanId, taskId, pathRuns, createdAt);
    }

    public void saveTracePlan(TracePlanData plan) {
        paths.saveTracePlan(plan);
    }

    public List<TracePlanData> loadTracePlansForScan(String scanId) {
        return paths.loadTracePlansForScan(scanId);
    }

    public void saveWorldPack(WorldPackData pack) {
        paths.saveWorldPack(pack);
    }

    public List<WorldPackData> loadWorldPacksForScan(String scanId) {
        return paths.loadWorldPacksForScan(scanId);
    }

    public void savePathTrace(PathTraceData trace) {
        paths.savePathTrace(trace);
    }

    public List<PathTraceData> loadPathTracesForScan(String projectId, String artifactDigest, String scanId) {
        return paths.loadPathTracesForScan(projectId, artifactDigest, scanId);
    }

    public void replacePathTracesForTask(String projectId, String artifactDigest, String scanId,
                                         String taskId, List<PathTraceData> traces, String createdAt) {
        paths.replacePathTracesForTask(projectId, artifactDigest, scanId, taskId, traces, createdAt);
    }

    public List<ArtifactUploadService.PersistedSession> loadArtifactUploads() {
        return scans.loadArtifactUploads();
    }

    public void persistArtifactUpload(ArtifactUploadService.PersistedSession session) {
        scans.persistArtifactUpload(session);
    }

    public void deleteArtifactUpload(String uploadId) {
        scans.deleteArtifactUpload(uploadId);
    }

    public List<VersionedEvent> loadSseEvents() {
        return workerRuntime.loadSseEvents();
    }

    public void persistSseEvent(String scanId, VersionedEvent event) {
        workerRuntime.persistSseEvent(scanId, event);
    }

    public WorkerState loadWorkerState() {
        return workerRuntime.loadWorkerState();
    }

    public void persistWorkerTask(TaskSnapshot snapshot) {
        workerRuntime.persistWorkerTask(snapshot);
    }

    public void persistWorkerTrace(String idempotencyKey, TraceChunk chunk) {
        workerRuntime.persistWorkerTrace(idempotencyKey, chunk);
    }

    public Snapshot load() {
        return scans.load();
    }

    public void insertHypotheses(String scanId,
                                 List<com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis> hypotheses,
                                 String actorId) {
        scans.insertHypotheses(scanId, hypotheses, actorId);
    }

    /** 惰性加载单个扫描的 static facts IR；供 ControlPlaneStore.staticFacts 使用。 */
    public Optional<StaticFactSnapshot> loadTaintGraph(String scanId) {
        return scans.loadTaintGraph(scanId);
    }

    public void insertTaintGraph(String scanId, String graphJson, String createdAt, String actorId) {
        scans.insertTaintGraph(scanId, graphJson, createdAt, actorId);
    }

    public void insertProject(String id, String name, String status, String createdAt, String updatedAt,
                              String actorId) {
        scans.insertProject(id, name, status, createdAt, updatedAt, actorId);
    }

    public void updateProject(String id, String name, String status, String updatedAt, String actorId) {
        scans.updateProject(id, name, status, updatedAt, actorId);
    }

    public void softDeleteProject(String id, String deletedAt, String actorId) {
        scans.softDeleteProject(id, deletedAt, actorId);
    }

    public void insertArtifact(String projectId, ArtifactDescriptor descriptor, String actorId) {
        scans.insertArtifact(projectId, descriptor, actorId);
    }

    public void insertScan(ControlPlaneStore.ScanRecord record, String actorId) {
        scans.insertScan(record, actorId);
    }

    /**
     * 硬删除单个扫描及其 scan 作用域依赖项。无 ON DELETE CASCADE 的子表须显式先删，
     * 以保证 FK 检查 fail-closed 且不残留 worker lease。
     */
    public void deleteScan(ControlPlaneStore.ScanRecord record, String actorId, String now) {
        scans.deleteScan(record, actorId, now);
    }

    public void bootstrapOperator(String token, String now) {
        aiManagement.bootstrapOperator(token, now);
    }

    public Optional<OperatorData> authenticateOperator(String token) {
        return aiManagement.authenticateOperator(token);
    }

    public List<OperatorData> listOperators() {
        return aiManagement.listOperators();
    }

    public void createOperator(OperatorData operator, String tokenHash, String actorId) {
        aiManagement.createOperator(operator, tokenHash, actorId);
    }

    public void updateOperator(String operatorId, OperatorRole role, boolean revokeTokens,
                               String actorId, String now) {
        aiManagement.updateOperator(operatorId, role, revokeTokens, actorId, now);
    }

    public List<ProviderData> listProviders() {
        return aiManagement.listProviders();
    }

    public Optional<ProviderData> findProvider(String providerId) {
        return aiManagement.findProvider(providerId);
    }

    public void saveProvider(ProviderData provider, StoredSecret secret, String actorId) {
        aiManagement.saveProvider(provider, secret, actorId);
    }

    public Optional<StoredSecret> findProviderSecret(String providerId) {
        return aiManagement.findProviderSecret(providerId);
    }

    public void deleteProvider(String providerId, String actorId, String now) {
        aiManagement.deleteProvider(providerId, actorId, now);
    }

    public List<RoleBindingData> listRoleBindings(String projectId) {
        return aiManagement.listRoleBindings(projectId);
    }

    public Optional<RoleBindingData> findRoleBinding(String projectId, AgentRole role) {
        return aiManagement.findRoleBinding(projectId, role);
    }

    public void saveRoleBinding(RoleBindingData binding, String actorId) {
        aiManagement.saveRoleBinding(binding, actorId);
    }

    public void deleteRoleBinding(String projectId, AgentRole role, String actorId, String now) {
        aiManagement.deleteRoleBinding(projectId, role, actorId, now);
    }

    public void saveAiJob(AiJobData job, String actorId, String action) {
        aiManagement.saveAiJob(job, actorId, action);
    }

    public List<AiJobData> listAiJobs(String projectId) {
        return aiManagement.listAiJobs(projectId);
    }

    public Optional<AiJobData> findAiJob(String jobId) {
        return aiManagement.findAiJob(jobId);
    }

    public AiJobEventData appendAiJobEvent(AiJobEventData event) {
        return aiManagement.appendAiJobEvent(event);
    }

    public List<AiJobEventData> listAiJobEvents(String jobId) {
        return aiManagement.listAiJobEvents(jobId);
    }

    public void deleteAiJob(AiJobData job, String actorId, String now) {
        aiManagement.deleteAiJob(job, actorId, now);
    }

    public List<AuditData> listAudit(String projectId) {
        return aiManagement.listAudit(projectId);
    }

    public void recordAudit(String projectId, String operatorId, String action,
                            String targetType, String targetId, String detailsJson, String now) {
        aiManagement.recordAudit(projectId, operatorId, action, targetType, targetId, detailsJson, now);
    }

    /** 去除行注释后按分号拆分迁移 SQL（供测试与 MigrationSupport 使用）。 */
    static List<String> splitMigrationStatements(String migrationSql) {
        return MigrationSupport.splitMigrationStatements(migrationSql);
    }

    public record ProjectData(String projectId, String name, String status, String createdAt,
                              String updatedAt, String deletedAt) { }
    public record ArtifactData(String projectId, ArtifactDescriptor descriptor) { }
    public record ArtifactUploadData(String uploadId, String projectId, String fileName, long sizeBytes,
                                     String sha256, long nextOffset, String createdAt, String expiresAt) { }
    public record OperatorData(String operatorId, String username, OperatorRole role,
                               String createdAt, String updatedAt) { }
    public record ProviderData(String providerId, String name, ProviderKind kind, String baseUrl,
                               String model, boolean enabled, String createdAt, String updatedAt,
                               boolean hasCredential) { }
    public record StoredSecret(SecretScope scope, EncryptedSecret encrypted) { }
    public record RoleBindingData(String projectId, AgentRole role, String providerId,
                                  String model, String updatedAt, String promptZh, String promptEn) {
        public RoleBindingData(String projectId, AgentRole role, String providerId,
                               String model, String updatedAt) {
            this(projectId, role, providerId, model, updatedAt, null, null);
        }
    }
    public record AiJobData(String aiJobId, String workspaceId, String projectId, String scanId,
                            String artifactDigest, AgentRole role, String providerId, String model,
                            String policySnapshotJson, boolean authorized, String status,
                            String stopReason, String stagesJson, String providerRequestId,
                            long elapsedMillis, int rounds, String toolSummaryJson,
                            String conclusionJson, String createdAt, String updatedAt) { }
    public record AiJobEventData(String aiJobId, long sequence, String workspaceId, String projectId,
                                 String stage, String status, String providerRequestSummary,
                                 String providerResultSummary, String toolCallName,
                                 String toolArgumentsSummary, String toolResultStatus,
                                 String modelInferenceSummary, String failureDiagnostic,
                                 String createdAt) { }
    public record AuditData(String auditEventId, String projectId, String operatorId, String action,
                            String targetType, String targetId, String outcome, String detailsJson,
                            String createdAt) { }
    public record IdempotencyData(String scope, String key, String payloadHash, String resultRef,
                                  String resultJson, String createdAt) { }
    public record PipelineRunData(String scanId, String projectId, String actorId,
                                  String outputLanguage, boolean armed, String nextStage,
                                  String updatedAt, String pipelineRunId, String stageAttemptId,
                                  String expectedJobId, String expectedTaskId, String stopReason) {
        public PipelineRunData {
            if (expectedJobId != null && expectedJobId.isBlank()) {
                expectedJobId = null;
            }
            if (expectedTaskId != null && expectedTaskId.isBlank()) {
                expectedTaskId = null;
            }
            if (pipelineRunId != null && pipelineRunId.isBlank()) {
                pipelineRunId = null;
            }
            if (stageAttemptId != null && stageAttemptId.isBlank()) {
                stageAttemptId = null;
            }
            if (stopReason != null && stopReason.isBlank()) {
                stopReason = null;
            }
        }

        /** 身份字段引入前历史行及窄测试 fixture 的兼容构造器。 */
        public PipelineRunData(String scanId, String projectId, String actorId,
                               String outputLanguage, boolean armed, String nextStage,
                               String updatedAt) {
            this(scanId, projectId, actorId, outputLanguage, armed, nextStage, updatedAt,
                    null, null, null, null, null);
        }

        public boolean hasStageIdentity() {
            return pipelineRunId != null && stageAttemptId != null;
        }
    }
    public record ProbePlanData(String taskId, String projectId, String artifactDigest,
                                String scanId, String targetEntryId, String candidateInputsJson,
                                int maxRequests, String planHash, String createdAt,
                                String payloadJson) {
        /** V011 仅元数据形态（无编译 payload）。 */
        public ProbePlanData(String taskId, String projectId, String artifactDigest,
                             String scanId, String targetEntryId, String candidateInputsJson,
                             int maxRequests, String planHash, String createdAt) {
            this(taskId, projectId, artifactDigest, scanId, targetEntryId, candidateInputsJson,
                    maxRequests, planHash, createdAt, null);
        }
    }
    public record ExperimentPlanData(String planId, String scanId, String projectId,
                                     String artifactDigest, String payloadJson, String createdAt,
                                     String fuzzStrategyJson) {
        public ExperimentPlanData(String planId, String scanId, String projectId,
                                  String artifactDigest, String payloadJson, String createdAt) {
            this(planId, scanId, projectId, artifactDigest, payloadJson, createdAt, null);
        }
    }
    public record TracePlanData(String tracePlanId, String scanId, String projectId,
                                String artifactDigest, String entryRef, String payloadJson,
                                String createdAt) { }
    public record WorldPackData(String worldPackId, String scanId, String projectId,
                                String artifactDigest, String dependencyMode, String payloadJson,
                                String createdAt) { }
    public record PathTraceData(String pathTraceId, String pathRunId, String scanId, String projectId,
                                String artifactDigest, String taskId, String experimentPlanId,
                                String tracePlanId, String worldPackId, String postureKind,
                                String exitReason, boolean legacyIncomplete, String payloadJson,
                                String createdAt) { }
    public record Snapshot(List<ProjectData> projects, List<ArtifactData> artifacts,
                           List<ControlPlaneStore.ScanRecord> scans,
                           Map<String, StaticFactSnapshot> staticFacts,
                           Map<String, List<com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis>> hypotheses) {
        public Snapshot(List<ProjectData> projects, List<ArtifactData> artifacts,
                        List<ControlPlaneStore.ScanRecord> scans) {
            this(projects, artifacts, scans, Map.of(), Map.of());
        }

        public Snapshot(List<ProjectData> projects, List<ArtifactData> artifacts,
                        List<ControlPlaneStore.ScanRecord> scans,
                        Map<String, StaticFactSnapshot> staticFacts) {
            this(projects, artifacts, scans, staticFacts, Map.of());
        }

        public Snapshot {
            projects = List.copyOf(projects);
            artifacts = List.copyOf(artifacts);
            scans = List.copyOf(scans);
            staticFacts = staticFacts == null ? Map.of() : Map.copyOf(staticFacts);
            if (hypotheses == null) {
                hypotheses = Map.of();
            } else {
                Map<String, List<com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis>> copied =
                        new LinkedHashMap<>();
                for (Map.Entry<String, List<com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis>> item
                        : hypotheses.entrySet()) {
                    copied.put(item.getKey(), List.copyOf(item.getValue() == null ? List.of() : item.getValue()));
                }
                hypotheses = Map.copyOf(copied);
            }
        }
    }
    public record WorkerState(List<TaskSnapshot> tasks, List<InMemoryTraceStore.StoredTrace> traces) {
        public WorkerState {
            tasks = List.copyOf(tasks);
            traces = List.copyOf(traces);
        }
        public static WorkerState empty() { return new WorkerState(List.of(), List.of()); }
    }

    public static class PersistenceException extends RuntimeException {
        public PersistenceException(String message) { super(message); }
        public PersistenceException(String message, Throwable cause) { super(message, cause); }
    }

    public static final class MigrationException extends PersistenceException {
        public MigrationException(String message) { super(message); }
        public MigrationException(String message, Throwable cause) { super(message, cause); }
    }
}
