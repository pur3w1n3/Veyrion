package com.aq.jvmsentinel.control;

import com.aq.jvmsentinel.analysis.experiment.PostureExperimentCompiler;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.control.store.ControlPlaneAiJobStore;
import com.aq.jvmsentinel.control.store.ControlPlaneEntityAccess;
import com.aq.jvmsentinel.control.store.ControlPlaneHypothesisObservationStore;
import com.aq.jvmsentinel.control.store.ControlPlaneManagementStore;
import com.aq.jvmsentinel.control.store.ControlPlaneMemoryState;
import com.aq.jvmsentinel.control.store.ControlPlanePathRunTraceStore;
import com.aq.jvmsentinel.control.store.ControlPlanePipelinePersistence;
import com.aq.jvmsentinel.domain.experiment.ExperimentPlanKind;
import com.aq.jvmsentinel.domain.experiment.HypothesisExperimentGate;
import com.aq.jvmsentinel.domain.experiment.HypothesisExperimentPlan;
import com.aq.jvmsentinel.domain.experiment.RuntimeObservation;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.domain.ir.ProgramNode;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.event.VersionedEvent;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.aq.jvmsentinel.provider.ProviderContracts;
import com.aq.jvmsentinel.security.ProviderSecretCipher;
import com.aq.jvmsentinel.security.RootKeyStore;
import com.aq.jvmsentinel.security.auth.OperatorRole;
import com.aq.jvmsentinel.worker.TaskSnapshot;
import com.aq.jvmsentinel.worker.TraceChunk;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

/**
 * 有界控制面存储：可注入内存或 SQLite 持久化。
 *
 * <p>无参构造刻意保持进程内，供单元测试与 fixture 使用。
 * 需重启安全的本地持久化请使用 {@link #sqlite(Path, Path)}。</p>
 */
public final class ControlPlaneStore implements ControlPlaneEntityAccess {
    private static final int MAX_PROJECTS = 10_000;
    private static final int MAX_ARTIFACTS_PER_PROJECT = 1_000;
    private static final int MAX_SCANS = 20_000;
    private static final int MAX_EVIDENCE = 100_000;
    private static final int MAX_FINDINGS = 100_000;

    private final ControlPlaneMemoryState memory = new ControlPlaneMemoryState();
    private final SQLiteControlPlanePersistence persistence;
    private final SecretKey rootKey;
    private final ProviderSecretCipher providerCipher;
    private final ControlPlanePipelinePersistence pipeline;
    private final ControlPlanePathRunTraceStore pathRunTraceStore;
    private final ControlPlaneHypothesisObservationStore hypothesisStore;
    private final ControlPlaneManagementStore managementStore;
    private final ControlPlaneAiJobStore aiJobStore;

    public ControlPlaneStore() {
        this.persistence = null;
        this.rootKey = null;
        this.providerCipher = null;
        this.pipeline = new ControlPlanePipelinePersistence(null);
        this.pathRunTraceStore = new ControlPlanePathRunTraceStore(memory, null);
        this.hypothesisStore = new ControlPlaneHypothesisObservationStore(memory, null, this, pathRunTraceStore);
        this.managementStore = new ControlPlaneManagementStore(null, null, null, this);
        this.aiJobStore = new ControlPlaneAiJobStore(null, this);
    }

    private ControlPlaneStore(Path databasePath, Path allowedRoot) {
        this.persistence = new SQLiteControlPlanePersistence(databasePath, allowedRoot);
        try {
            Path keyPath = this.persistence.databasePath().getParent()
                    .resolve("security").resolve("provider-root.key");
            this.rootKey = new RootKeyStore(keyPath).loadOrCreate(
                    new RootKeyStore.DeploymentPolicy(true, false)).key();
        } catch (IOException failure) {
            throw new SQLiteControlPlanePersistence.PersistenceException(
                    "provider root key could not be loaded", failure);
        }
        this.providerCipher = new ProviderSecretCipher();
        this.pipeline = new ControlPlanePipelinePersistence(persistence);
        this.pathRunTraceStore = new ControlPlanePathRunTraceStore(memory, persistence);
        this.hypothesisStore = new ControlPlaneHypothesisObservationStore(memory, persistence, this, pathRunTraceStore);
        this.managementStore = new ControlPlaneManagementStore(persistence, rootKey, providerCipher, this);
        this.aiJobStore = new ControlPlaneAiJobStore(persistence, this);
        restore(this.persistence.load());
    }

    public static ControlPlaneStore sqlite(Path databasePath, Path allowedRoot) {
        return new ControlPlaneStore(databasePath, allowedRoot);
    }

    public String persistenceMode() {
        return persistence == null ? "IN_MEMORY_MVP" : "SQLITE";
    }

    public List<SQLiteControlPlanePersistence.IdempotencyData> loadIdempotency() {
        return pipeline.loadIdempotency();
    }

    public SQLiteControlPlanePersistence.IdempotencyData persistIdempotency(
            SQLiteControlPlanePersistence.IdempotencyData candidate) {
        return pipeline.persistIdempotency(candidate);
    }

    public List<SQLiteControlPlanePersistence.PipelineRunData> loadPipelineRuns() {
        return pipeline.loadPipelineRuns();
    }

    public void persistPipelineRun(SQLiteControlPlanePersistence.PipelineRunData run) {
        pipeline.persistPipelineRun(run);
    }

    public boolean compareAndAdvancePipelineRun(
            SQLiteControlPlanePersistence.PipelineRunData expected,
            SQLiteControlPlanePersistence.PipelineRunData next) {
        return pipeline.compareAndAdvancePipelineRun(expected, next);
    }

    public List<SQLiteControlPlanePersistence.ProbePlanData> loadProbePlans() {
        return pipeline.loadProbePlans();
    }

    public void persistProbePlan(SQLiteControlPlanePersistence.ProbePlanData plan) {
        pipeline.persistProbePlan(plan);
    }

    public List<SQLiteControlPlanePersistence.ExperimentPlanData> loadExperimentPlans() {
        return pipeline.loadExperimentPlans();
    }

    public List<SQLiteControlPlanePersistence.ExperimentPlanData> loadExperimentPlansForScan(String scanId) {
        return pipeline.loadExperimentPlansForScan(scanId);
    }

    public void persistExperimentPlan(SQLiteControlPlanePersistence.ExperimentPlanData plan) {
        pipeline.persistExperimentPlan(plan);
    }

    public void persistTracePlan(SQLiteControlPlanePersistence.TracePlanData plan) {
        pipeline.persistTracePlan(plan);
    }

    public List<SQLiteControlPlanePersistence.TracePlanData> loadTracePlansForScan(String scanId) {
        return pipeline.loadTracePlansForScan(scanId);
    }

    public void persistWorldPack(SQLiteControlPlanePersistence.WorldPackData pack) {
        pipeline.persistWorldPack(pack);
    }

    public List<SQLiteControlPlanePersistence.WorldPackData> loadWorldPacksForScan(String scanId) {
        return pipeline.loadWorldPacksForScan(scanId);
    }

    public void replacePathTracesForTask(String projectId, String artifactDigest, String scanId,
                                         String taskId, List<SQLiteControlPlanePersistence.PathTraceData> traces,
                                         String createdAt) {
        pathRunTraceStore.replacePathTracesForTask(projectId, artifactDigest, scanId, taskId, traces, createdAt);
    }

    public Map<String, Object> pathTraceEvidenceDelta(String pathTraceId) {
        return pathRunTraceStore.pathTraceEvidenceDelta(pathTraceId);
    }

    public List<SQLiteControlPlanePersistence.PathTraceData> loadPathTracesForScan(
            String projectId, String artifactDigest, String scanId) {
        return pathRunTraceStore.loadPathTracesForScan(projectId, artifactDigest, scanId);
    }

    public PathTrace pathTraceForPathRun(String pathRunId) {
        return pathRunTraceStore.pathTraceForPathRun(pathRunId);
    }

    public void registerPostureExperiment(PostureExperimentCompiler.CompiledPostureExperiment plan) {
        pathRunTraceStore.registerPostureExperiment(plan);
    }

    public PostureExperimentCompiler.CompiledPostureExperiment postureExperiment(String experimentPlanId) {
        return pathRunTraceStore.postureExperiment(experimentPlanId);
    }

    public Map<String, PostureExperimentCompiler.CompiledPostureExperiment> postureExperimentsForScan(String scanId) {
        return pathRunTraceStore.postureExperimentsForScan(scanId);
    }

    public List<ApiDtos.PathRunDto> loadPathRunsForScan(String projectId, String artifactDigest, String scanId) {
        return pathRunTraceStore.loadPathRunsForScan(projectId, artifactDigest, scanId);
    }

    public List<ApiDtos.PathRunDto> loadPathRunsForTask(String taskId) {
        return pathRunTraceStore.loadPathRunsForTask(taskId);
    }

    public void replacePathRunsForTask(String projectId, String artifactDigest, String scanId,
                                       String taskId, List<ApiDtos.PathRunDto> pathRuns, String createdAt) {
        pathRunTraceStore.replacePathRunsForTask(projectId, artifactDigest, scanId, taskId, pathRuns, createdAt);
        hypothesisStore.applyPathRunHypothesisObservations(pathRuns);
    }

    public void replacePathRunsAndTracesForTask(String projectId, String artifactDigest, String scanId,
                                                String taskId, List<ApiDtos.PathRunDto> pathRuns,
                                                List<SQLiteControlPlanePersistence.PathTraceData> traces,
                                                String createdAt) {
        replacePathTracesForTask(projectId, artifactDigest, scanId, taskId, traces, createdAt);
        replacePathRunsForTask(projectId, artifactDigest, scanId, taskId, pathRuns, createdAt);
    }

    public synchronized int recomputeDetectorsAfterObservation(String scanId) {
        return hypothesisStore.recomputeDetectorsAfterObservation(scanId);
    }

    public synchronized boolean hasPendingObservationLoopWork(String scanId) {
        return hypothesisStore.hasPendingObservationLoopWork(scanId);
    }

    public synchronized List<HypothesisExperimentGate.Decision> applyPathRunHypothesisObservations(
            List<ApiDtos.PathRunDto> pathRuns) {
        return hypothesisStore.applyPathRunHypothesisObservations(pathRuns);
    }

    public SQLiteControlPlanePersistence.WorkerState loadWorkerState() {
        return pipeline.loadWorkerState();
    }

    public void persistWorkerTask(TaskSnapshot snapshot) {
        pipeline.persistWorkerTask(snapshot);
    }

    public void persistWorkerTrace(String idempotencyKey, TraceChunk chunk) {
        pipeline.persistWorkerTrace(idempotencyKey, chunk);
    }

    public com.aq.jvmsentinel.artifact.ArtifactUploadService.UploadPersistence artifactUploadPersistence() {
        return pipeline.artifactUploadPersistence();
    }

    public List<VersionedEvent> loadSseEvents() {
        return pipeline.loadSseEvents();
    }

    public void persistSseEvent(String scanId, VersionedEvent event) {
        pipeline.persistSseEvent(scanId, event);
    }

    public void bootstrapOperator(String token, String now) {
        managementStore.bootstrapOperator(token, now);
    }

    public SQLiteControlPlanePersistence.OperatorData authenticateOperator(String token) {
        return managementStore.authenticateOperator(token);
    }

    public List<SQLiteControlPlanePersistence.OperatorData> operators() {
        return managementStore.operators();
    }

    public CreatedOperator createOperator(String username, OperatorRole role, String actorId, String now) {
        return managementStore.createOperator(username, role, actorId, now);
    }

    public void updateOperator(String operatorId, OperatorRole role, boolean revokeTokens,
                               String actorId, String now) {
        managementStore.updateOperator(operatorId, role, revokeTokens, actorId, now);
    }

    public List<SQLiteControlPlanePersistence.ProviderData> providers() {
        return managementStore.providers();
    }

    public SQLiteControlPlanePersistence.ProviderData requireProvider(String providerId) {
        return managementStore.requireProvider(providerId);
    }

    public SQLiteControlPlanePersistence.ProviderData saveProvider(
            String providerId, String name, ProviderContracts.ProviderKind kind, String baseUrl,
            String model, boolean enabled, String apiKey, String actorId, String now) {
        return managementStore.saveProvider(providerId, name, kind, baseUrl, model, enabled, apiKey, actorId, now);
    }

    public void verifyProviderCredential(String providerId) {
        managementStore.verifyProviderCredential(providerId);
    }

    public <T> T withProviderCredential(String providerId, Function<byte[], T> operation) {
        return managementStore.withProviderCredential(providerId, operation);
    }

    public void deleteProvider(String providerId, String actorId, String now) {
        managementStore.deleteProvider(providerId, actorId, now);
    }

    public List<SQLiteControlPlanePersistence.RoleBindingData> roleBindings(String projectId) {
        return managementStore.roleBindings(projectId);
    }

    public SQLiteControlPlanePersistence.RoleBindingData saveRoleBinding(
            String projectId, AgentRole role, String providerId, String model, String actorId, String now) {
        return managementStore.saveRoleBinding(projectId, role, providerId, model, null, null, actorId, now);
    }

    public SQLiteControlPlanePersistence.RoleBindingData saveRoleBinding(
            String projectId, AgentRole role, String providerId, String model,
            String promptZh, String promptEn, String actorId, String now) {
        return managementStore.saveRoleBinding(projectId, role, providerId, model, promptZh, promptEn, actorId, now);
    }

    public void deleteRoleBinding(String projectId, AgentRole role, String actorId, String now) {
        managementStore.deleteRoleBinding(projectId, role, actorId, now);
    }

    public SQLiteControlPlanePersistence.AiJobData createAiJob(
            String projectId, AgentRole requestedRole, boolean authorized, String actorId, String now) {
        return aiJobStore.createAiJob(projectId, requestedRole, null, AiOutputLanguage.ZH_CN, authorized, actorId, now);
    }

    public SQLiteControlPlanePersistence.AiJobData createAiJob(
            String projectId, AgentRole requestedRole, String requestedScanId,
            boolean authorized, String actorId, String now) {
        return aiJobStore.createAiJob(projectId, requestedRole, requestedScanId, AiOutputLanguage.ZH_CN,
                authorized, actorId, now);
    }

    public SQLiteControlPlanePersistence.AiJobData createAiJob(
            String projectId, AgentRole requestedRole, String requestedScanId,
            AiOutputLanguage outputLanguage, boolean authorized, String actorId, String now) {
        return aiJobStore.createAiJob(projectId, requestedRole, requestedScanId, outputLanguage,
                authorized, actorId, now);
    }

    public SQLiteControlPlanePersistence.AiJobData updateAiJob(
            SQLiteControlPlanePersistence.AiJobData existing, String status, String stopReason,
            String stagesJson, String providerRequestId, long elapsedMillis, int rounds,
            String toolSummaryJson, String conclusionJson, String actorId, String action, String now) {
        return aiJobStore.updateAiJob(existing, status, stopReason, stagesJson, providerRequestId,
                elapsedMillis, rounds, toolSummaryJson, conclusionJson, actorId, action, now);
    }

    public List<SQLiteControlPlanePersistence.AiJobData> aiJobs(String projectId) {
        return aiJobStore.aiJobs(projectId);
    }

    public SQLiteControlPlanePersistence.AiJobData requireAiJob(String jobId) {
        return aiJobStore.requireAiJob(jobId);
    }

    public SQLiteControlPlanePersistence.AiJobEventData appendAiJobEvent(
            SQLiteControlPlanePersistence.AiJobEventData event) {
        return aiJobStore.appendAiJobEvent(event);
    }

    public List<SQLiteControlPlanePersistence.AiJobEventData> aiJobEvents(String jobId) {
        return aiJobStore.aiJobEvents(jobId);
    }

    public SQLiteControlPlanePersistence.AiJobData cancelAiJob(String jobId, String actorId, String now) {
        return aiJobStore.cancelAiJob(jobId, actorId, now);
    }

    public void deleteAiJob(String jobId, String actorId, String now) {
        aiJobStore.deleteAiJob(jobId, actorId, now);
    }

    public List<SQLiteControlPlanePersistence.AuditData> auditEvents(String projectId) {
        return managementStore.auditEvents(projectId);
    }

    public void auditChange(String projectId, String actorId, String action,
                            String targetType, String targetId, String detailsJson, String now) {
        managementStore.auditChange(projectId, actorId, action, targetType, targetId, detailsJson, now);
    }

    public synchronized ProjectRecord createProject(String requestedId, String requestedName, String createdAt,
                                                    String actorId) {
        String id = requestedId == null || requestedId.isBlank()
                ? "project-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16)
                : requestedId;
        String name = requestedName == null || requestedName.isBlank() ? id : requestedName;
        validateId(id, "projectId");
        if (createdAt == null || createdAt.isBlank()) {
            throw new IllegalArgumentException("createdAt is required");
        }
        if (memory.projects.size() >= MAX_PROJECTS) {
            throw new StoreLimitException("project limit reached");
        }
        ProjectRecord candidate = new ProjectRecord(id, name, "ACTIVE", createdAt, createdAt, null);
        if (memory.projects.containsKey(id)) {
            throw new DuplicateRecordException("project already exists");
        }
        if (persistence != null) {
            persistence.insertProject(id, name, candidate.status, createdAt, createdAt, actorId);
        }
        ProjectRecord existing = memory.projects.putIfAbsent(id, candidate);
        if (existing != null) {
            throw new DuplicateRecordException("project already exists");
        }
        return candidate;
    }

    @Override
    public ProjectRecord requireProject(String projectId) {
        ProjectRecord result = project(projectId);
        if (result == null) {
            throw new MissingRecordException("project not found");
        }
        return result;
    }

    @Override
    public ProjectRecord project(String projectId) {
        ProjectRecord project = projectId == null ? null : memory.projects.get(projectId);
        return project == null || project.deleted() ? null : project;
    }

    public List<ProjectRecord> projects() {
        return memory.projects.values().stream().filter(project -> !project.deleted())
                .sorted(Comparator.comparing(ProjectRecord::createdAt).thenComparing(ProjectRecord::projectId))
                .toList();
    }

    public synchronized ProjectRecord updateProject(String projectId, String requestedName,
                                                    String requestedStatus, String updatedAt, String actorId) {
        ProjectRecord project = requireProject(projectId);
        String name = requestedName == null ? project.name : requestedName;
        String status = requestedStatus == null ? project.status : requestedStatus.toUpperCase(java.util.Locale.ROOT);
        if (name.isBlank() || name.length() > 512) {
            throw new IllegalArgumentException("name is invalid");
        }
        if (!status.equals("ACTIVE") && !status.equals("ARCHIVED")) {
            throw new IllegalArgumentException("status must be ACTIVE or ARCHIVED");
        }
        if (updatedAt == null || updatedAt.isBlank()) {
            throw new IllegalArgumentException("updatedAt is required");
        }
        if (persistence != null) {
            persistence.updateProject(projectId, name, status, updatedAt, actorId);
        }
        project.name = name;
        project.status = status;
        project.updatedAt = updatedAt;
        return project;
    }

    public synchronized void softDeleteProject(String projectId, String deletedAt, String actorId) {
        ProjectRecord project = requireProject(projectId);
        if (deletedAt == null || deletedAt.isBlank()) {
            throw new IllegalArgumentException("deletedAt is required");
        }
        if (persistence != null) {
            persistence.softDeleteProject(projectId, deletedAt, actorId);
        }
        project.status = "DELETED";
        project.updatedAt = deletedAt;
        project.deletedAt = deletedAt;
    }

    public synchronized void registerArtifact(ProjectRecord project, ArtifactDescriptor descriptor,
                                              String actorId) {
        Objects.requireNonNull(project, "project");
        Objects.requireNonNull(descriptor, "descriptor");
        synchronized (project) {
            if (project.artifacts.size() >= MAX_ARTIFACTS_PER_PROJECT
                    && !project.artifacts.containsKey(descriptor.sha256())) {
                throw new StoreLimitException("artifact limit reached for project");
            }
            if (project.deleted()) {
                throw new MissingRecordException("project not found");
            }
            if (persistence != null) {
                persistence.insertArtifact(project.projectId, descriptor, actorId);
            }
            project.artifacts.put(descriptor.sha256(), descriptor);
        }
    }

    public ArtifactDescriptor artifact(ProjectRecord project, String digestOrId) {
        if (project == null || digestOrId == null) {
            return null;
        }
        synchronized (project) {
            ArtifactDescriptor byDigest = project.artifacts.get(digestOrId);
            if (byDigest != null) {
                return byDigest;
            }
            for (ArtifactDescriptor descriptor : project.artifacts.values()) {
                if (descriptor.artifactId().equals(digestOrId)) {
                    return descriptor;
                }
            }
            return null;
        }
    }

    public List<ArtifactDescriptor> artifacts(ProjectRecord project) {
        if (project == null) {
            return List.of();
        }
        synchronized (project) {
            return List.copyOf(project.artifacts.values());
        }
    }

    public synchronized void saveScan(ScanRecord record, String actorId) {
        Objects.requireNonNull(record, "record");
        requireProject(record.dto().projectId());
        if (memory.scans.size() >= MAX_SCANS && !memory.scans.containsKey(record.dto().scanId())) {
            throw new StoreLimitException("scan limit reached");
        }
        if (memory.scans.containsKey(record.dto().scanId())) {
            throw new DuplicateRecordException("scan already exists");
        }
        int newEvidence = 0;
        for (ApiDtos.EvidenceDto item : record.evidence().values()) {
            if (!memory.evidence.containsKey(item.evidenceId())) {
                newEvidence++;
            }
        }
        if (memory.evidence.size() + newEvidence > MAX_EVIDENCE) {
            throw new StoreLimitException("evidence limit reached");
        }
        int newFindings = 0;
        for (ApiDtos.FindingDto item : record.findings()) {
            if (!memory.findings.containsKey(item.findingId())) {
                newFindings++;
            }
        }
        if (memory.findings.size() + newFindings > MAX_FINDINGS) {
            throw new StoreLimitException("finding limit reached");
        }
        if (persistence != null) {
            persistence.insertScan(record, actorId);
        }
        ScanRecord prior = memory.scans.putIfAbsent(record.dto().scanId(), record);
        if (prior != null) {
            throw new DuplicateRecordException("scan already exists");
        }
        ProjectRecord project = requireProject(record.dto().projectId());
        synchronized (project) {
            project.latestScanId = record.dto().scanId();
        }
        for (ApiDtos.EvidenceDto item : record.evidence().values()) {
            memory.evidence.putIfAbsent(item.evidenceId(), item);
        }
        for (ApiDtos.FindingDto item : record.findings()) {
            memory.findings.putIfAbsent(item.findingId(), item);
        }
        for (ApiDtos.AttackChainDto item : record.chains()) {
            memory.chains.putIfAbsent(item.chainId(), item);
        }
    }

    public synchronized void saveStaticFacts(String scanId, StaticFactSnapshot snapshot, String actorId) {
        pathRunTraceStore.saveStaticFacts(scanId, snapshot, actorId, () -> requireScan(scanId));
    }

    public synchronized void saveHypotheses(String scanId, List<SecurityHypothesis> hypotheses, String actorId) {
        hypothesisStore.saveHypotheses(scanId, hypotheses, actorId);
    }

    public List<SecurityHypothesis> hypotheses(String scanId) {
        return hypothesisStore.hypotheses(scanId);
    }

    public synchronized void saveAnalyzerProgramNodes(String scanId, List<ProgramNode> nodes) {
        hypothesisStore.saveAnalyzerProgramNodes(scanId, nodes);
    }

    public List<ProgramNode> analyzerProgramNodes(String scanId) {
        return hypothesisStore.analyzerProgramNodes(scanId);
    }

    public SecurityHypothesis hypothesis(String hypothesisId) {
        return hypothesisStore.hypothesis(hypothesisId);
    }

    public SecurityHypothesis hypothesis(String scanId, String hypothesisId) {
        return hypothesisStore.hypothesis(scanId, hypothesisId);
    }

    public synchronized List<HypothesisExperimentPlan> generateDefaultHypothesisExperimentPlans(String scanId) {
        return hypothesisStore.generateDefaultHypothesisExperimentPlans(scanId);
    }

    public synchronized List<HypothesisExperimentPlan> saveHypothesisExperimentPlans(
            String scanId, List<HypothesisExperimentPlan> plans) {
        return hypothesisStore.saveHypothesisExperimentPlans(scanId, plans);
    }

    public List<HypothesisExperimentPlan> hypothesisExperimentPlans(String scanId) {
        return hypothesisStore.hypothesisExperimentPlans(scanId);
    }

    public HypothesisExperimentPlan hypothesisExperimentPlan(String experimentPlanId) {
        return hypothesisStore.hypothesisExperimentPlan(experimentPlanId);
    }

    public void bindProbeHypothesis(String bindingKey,
                                    String hypothesisId,
                                    ExperimentPlanKind planKind,
                                    String stageAttemptId,
                                    String probeAttemptId) {
        hypothesisStore.bindProbeHypothesis(bindingKey, hypothesisId, planKind, stageAttemptId, probeAttemptId);
    }

    public ProbeHypothesisBinding probeHypothesisBinding(String bindingKey) {
        return hypothesisStore.probeHypothesisBinding(bindingKey);
    }

    public synchronized HypothesisExperimentGate.Decision applyHypothesisObservation(
            String experimentPlanId,
            RuntimeObservation observation) {
        return hypothesisStore.applyHypothesisObservation(experimentPlanId, observation);
    }

    public synchronized HypothesisLifecycle recordFailedHypothesisProjection(String hypothesisId) {
        return hypothesisStore.recordFailedHypothesisProjection(hypothesisId);
    }

    public synchronized List<ObservationKindRef> drainPendingIncrementalSubjects() {
        return hypothesisStore.drainPendingIncrementalSubjects();
    }

    public Optional<StaticFactSnapshot> staticFacts(String scanId) {
        return pathRunTraceStore.staticFacts(scanId);
    }

    public List<ScanRecord> scansForProject(String projectId) {
        requireProject(projectId);
        return memory.scans.values().stream()
                .filter(record -> record.dto().projectId().equals(projectId))
                .sorted(Comparator.comparing((ScanRecord record) -> record.dto().createdAt()).reversed()
                        .thenComparing(record -> record.dto().scanId()))
                .toList();
    }

    @Override
    public ScanRecord scan(String scanId) {
        ScanRecord result = scanId == null ? null : memory.scans.get(scanId);
        return result == null || project(result.dto().projectId()) == null ? null : result;
    }

    @Override
    public ScanRecord requireScan(String scanId) {
        ScanRecord result = scan(scanId);
        if (result == null) {
            throw new MissingRecordException("scan not found");
        }
        return result;
    }

    /**
     * 永久删除一条 scan 历史及其 scan 作用域依赖项。
     * 调用方须先取消活跃 AI job / worker 租约（audit-history UX：先 cancel 再 delete）；
     * 若仍有活跃项，本方法仍 fail-closed。
     */
    public synchronized void deleteScan(String scanId, String expectedProjectId, String actorId, String now) {
        Objects.requireNonNull(scanId, "scanId");
        Objects.requireNonNull(actorId, "actorId");
        Objects.requireNonNull(now, "now");
        ScanRecord existing = requireScan(scanId);
        String projectId = existing.dto().projectId();
        if (expectedProjectId != null && !expectedProjectId.equals(projectId)) {
            throw new MissingRecordException("scan not found");
        }
        ProjectRecord project = requireProject(projectId);
        if (persistence != null) {
            aiJobStore.assertNoActiveJobsForScan(projectId, scanId);
            persistence.deleteScan(existing, actorId, now);
        }
        memory.scans.remove(scanId, existing);
        for (ApiDtos.EvidenceDto item : existing.evidence().values()) {
            memory.evidence.remove(item.evidenceId(), item);
        }
        for (ApiDtos.FindingDto item : existing.findings()) {
            memory.findings.remove(item.findingId(), item);
        }
        for (ApiDtos.AttackChainDto item : existing.chains()) {
            memory.chains.remove(item.chainId(), item);
        }
        hypothesisStore.purgeScanScopedState(scanId);
        pathRunTraceStore.purgeScanScopedCaches(scanId);
        synchronized (project) {
            if (scanId.equals(project.latestScanId)) {
                project.latestScanId = memory.scans.values().stream()
                        .filter(record -> projectId.equals(record.dto().projectId()))
                        .max(Comparator.comparing((ScanRecord record) -> record.dto().createdAt())
                                .thenComparing(record -> record.dto().scanId()))
                        .map(record -> record.dto().scanId())
                        .orElse(null);
            }
        }
    }

    /**
     * 向现有内存 scan 快照追加 evidence（如 DYNAMIC_TAINT_UPDATE）。
     * 不重写 durable scan 负载；调用方可稍后单独持久化。
     */
    public synchronized ScanRecord appendScanEvidence(String scanId, List<ApiDtos.EvidenceDto> extras) {
        ScanRecord prior = requireScan(scanId);
        if (extras == null || extras.isEmpty()) {
            return prior;
        }
        Map<String, ApiDtos.EvidenceDto> merged = new LinkedHashMap<>(prior.evidence());
        List<String> refs = new ArrayList<>(prior.dto().evidenceRefs());
        for (ApiDtos.EvidenceDto item : extras) {
            if (item == null) {
                continue;
            }
            if (memory.evidence.size() >= MAX_EVIDENCE && !memory.evidence.containsKey(item.evidenceId())
                    && !merged.containsKey(item.evidenceId())) {
                throw new StoreLimitException("evidence limit reached");
            }
            merged.put(item.evidenceId(), item);
            memory.evidence.put(item.evidenceId(), item);
            if (!refs.contains(item.evidenceId())) {
                refs.add(item.evidenceId());
            }
        }
        ApiDtos.ScanDto dto = prior.dto();
        ApiDtos.ScanDto updated = new ApiDtos.ScanDto(
                dto.schemaVersion(), dto.projectId(), dto.artifactDigest(), dto.scanId(),
                dto.status(), dto.verificationStatus(), dto.dependencyMode(),
                dto.createdAt(), dto.completedAt(), List.copyOf(refs),
                dto.entries(), dto.dependencies(), dto.sinks(), dto.findings(), dto.paths());
        ScanRecord next = new ScanRecord(updated, merged, prior.findings(), prior.chains());
        memory.scans.put(scanId, next);
        return next;
    }

    public ApiDtos.FindingDto finding(String findingId) {
        ApiDtos.FindingDto result = findingId == null ? null : memory.findings.get(findingId);
        return result == null || project(result.projectId()) == null ? null : result;
    }

    public synchronized ApiDtos.FindingDto attachTriageFinding(String scanId, ApiDtos.FindingDto finding) {
        return hypothesisStore.attachTriageFinding(scanId, finding);
    }

    public ApiDtos.EvidenceDto evidence(String evidenceId) {
        ApiDtos.EvidenceDto result = evidenceId == null ? null : memory.evidence.get(evidenceId);
        return result == null || project(result.projectId()) == null ? null : result;
    }

    public List<ApiDtos.AttackChainDto> attackChains(String projectId) {
        List<ApiDtos.AttackChainDto> result = new ArrayList<>();
        for (ApiDtos.AttackChainDto chain : memory.chains.values()) {
            if (project(chain.projectId()) != null
                    && (projectId == null || projectId.equals(chain.projectId()))) {
                result.add(chain);
            }
        }
        return List.copyOf(result);
    }

    private void restore(SQLiteControlPlanePersistence.Snapshot snapshot) {
        for (SQLiteControlPlanePersistence.ProjectData item : snapshot.projects()) {
            memory.projects.put(item.projectId(), new ProjectRecord(item.projectId(), item.name(), item.status(),
                    item.createdAt(), item.updatedAt(), item.deletedAt()));
        }
        for (SQLiteControlPlanePersistence.ArtifactData item : snapshot.artifacts()) {
            ProjectRecord project = memory.projects.get(item.projectId());
            if (project == null) {
                throw new SQLiteControlPlanePersistence.PersistenceException(
                        "artifact references a missing project");
            }
            project.artifacts.put(item.descriptor().sha256(), item.descriptor());
        }
        for (ScanRecord record : snapshot.scans()) {
            ProjectRecord project = memory.projects.get(record.dto().projectId());
            if (project == null || !project.artifacts.containsKey(record.dto().artifactDigest())) {
                throw new SQLiteControlPlanePersistence.PersistenceException(
                        "scan references missing project or artifact");
            }
            memory.scans.put(record.dto().scanId(), record);
            project.latestScanId = record.dto().scanId();
            for (ApiDtos.EvidenceDto item : record.evidence().values()) {
                memory.evidence.put(item.evidenceId(), item);
            }
            for (ApiDtos.FindingDto item : record.findings()) {
                memory.findings.put(item.findingId(), item);
            }
            for (ApiDtos.AttackChainDto item : record.chains()) {
                memory.chains.put(item.chainId(), item);
            }
        }
        for (Map.Entry<String, StaticFactSnapshot> item : snapshot.staticFacts().entrySet()) {
            memory.staticFacts.put(item.getKey(), item.getValue());
        }
        hypothesisStore.restoreHypotheses(snapshot.hypotheses());
    }

    /** PathRun / probe 绑定：在 experimentPlanId 旁携带 hypothesisId+planKind。 */
    public record ProbeHypothesisBinding(
            String bindingKey,
            String hypothesisId,
            ExperimentPlanKind planKind,
            String stageAttemptId,
            String probeAttemptId
    ) {
        public ProbeHypothesisBinding {
            Objects.requireNonNull(bindingKey, "bindingKey");
            Objects.requireNonNull(hypothesisId, "hypothesisId");
            Objects.requireNonNull(planKind, "planKind");
            stageAttemptId = stageAttemptId == null ? "" : stageAttemptId;
            probeAttemptId = probeAttemptId == null ? "" : probeAttemptId;
        }
    }

    /** 成功观测后的最小增量重算提示。 */
    public record ObservationKindRef(String hypothesisId, String observationKind) {
        public ObservationKindRef {
            hypothesisId = hypothesisId == null ? "" : hypothesisId;
            observationKind = observationKind == null ? "" : observationKind;
        }
    }

    public static final class ProjectRecord {
        private final String projectId;
        private volatile String name;
        private final String createdAt;
        private volatile String status;
        private volatile String updatedAt;
        private volatile String deletedAt;
        private final Map<String, ArtifactDescriptor> artifacts = new LinkedHashMap<>();
        private volatile String latestScanId;

        private ProjectRecord(String projectId, String name, String status, String createdAt,
                              String updatedAt, String deletedAt) {
            this.projectId = projectId;
            this.name = name;
            this.status = status;
            this.createdAt = createdAt;
            this.updatedAt = updatedAt;
            this.deletedAt = deletedAt;
        }

        public String projectId() { return projectId; }
        public String name() { return name; }
        public String status() { return status; }
        public String createdAt() { return createdAt; }
        public String updatedAt() { return updatedAt; }
        public String deletedAt() { return deletedAt; }
        public boolean deleted() { return deletedAt != null; }
        public String latestScanId() { return latestScanId; }
    }

    /** 不可变 scan 快照及其 evidence 与关联记录。 */
    public record ScanRecord(ApiDtos.ScanDto dto, Map<String, ApiDtos.EvidenceDto> evidence,
                             List<ApiDtos.FindingDto> findings, List<ApiDtos.AttackChainDto> chains) {
        public ScanRecord {
            Objects.requireNonNull(dto, "dto");
            Map<String, ApiDtos.EvidenceDto> copiedEvidence = new LinkedHashMap<>();
            if (evidence != null) {
                copiedEvidence.putAll(evidence);
            }
            evidence = Collections.unmodifiableMap(copiedEvidence);
            findings = List.copyOf(findings == null ? List.of() : findings);
            chains = List.copyOf(chains == null ? List.of() : chains);
        }
    }

    public record CreatedOperator(SQLiteControlPlanePersistence.OperatorData operator, String personalAccessToken) { }

    public static final class MissingRecordException extends RuntimeException {
        public MissingRecordException(String message) { super(message); }
    }

    public static final class DuplicateRecordException extends RuntimeException {
        public DuplicateRecordException(String message) { super(message); }
    }

    public static final class StoreLimitException extends RuntimeException {
        public StoreLimitException(String message) { super(message); }
    }

    public static void validateId(String value, String name) {
        if (value == null || !value.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")) {
            throw new IllegalArgumentException(name + " contains invalid characters");
        }
    }
}
