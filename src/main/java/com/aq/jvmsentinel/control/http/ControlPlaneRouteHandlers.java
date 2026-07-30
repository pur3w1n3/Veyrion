package com.aq.jvmsentinel.control.http;

import com.aq.jvmsentinel.control.routing.ControlPlaneRouteActions;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.security.auth.Permission;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.net.URI;

/** 组合各域 HTTP 处理器，实现 {@link ControlPlaneRouteActions}。 */
public final class ControlPlaneRouteHandlers implements ControlPlaneRouteActions {
    private final OperatorProviderHttpHandlers operators;
    private final AiJobHttpHandlers aiJobs;
    private final PathFindingsHttpHandlers pathFindings;
    private final SandboxProbeHttpHandlers sandboxProbe;
    private final DynamicWorkerHttpHandlers dynamicWorker;
    private final ScanBuildHttpHandlers scanBuild;
    private final ScanAuditHttpHandlers scanAudit;

    public ControlPlaneRouteHandlers(ControlPlaneHandlerHost host) {
        this.operators = new OperatorProviderHttpHandlers(host);
        this.aiJobs = new AiJobHttpHandlers(host, operators);
        this.pathFindings = new PathFindingsHttpHandlers(host);
        this.scanBuild = new ScanBuildHttpHandlers(host);
        this.sandboxProbe = new SandboxProbeHttpHandlers(host, operators, pathFindings);
        this.dynamicWorker = new DynamicWorkerHttpHandlers(host, operators, pathFindings, sandboxProbe);
        this.scanAudit = new ScanAuditHttpHandlers(host, operators, aiJobs, sandboxProbe, pathFindings, scanBuild);
    }

    @Override public void requirePermission(HttpExchange e, Permission p) { operators.requirePermission(e, p); }
    @Override public AgentRole role(String v) { return operators.role(v); }
    @Override public String query(URI u, String k) { return ControlPlaneHttpSupport.query(u, k); }
    @Override public void sendHealth(HttpExchange e) throws IOException { operators.sendHealth(e); }

    @Override public void createProject(HttpExchange e) throws IOException { operators.createProject(e); }
    @Override public void sendProject(HttpExchange e, String id) throws IOException { operators.sendProject(e, id); }
    @Override public void listProjects(HttpExchange e) throws IOException { operators.listProjects(e); }
    @Override public void updateProject(HttpExchange e, String id) throws IOException { operators.updateProject(e, id); }
    @Override public void deleteProject(HttpExchange e, String id) throws IOException { operators.deleteProject(e, id); }
    @Override public void registerArtifact(HttpExchange e, String id) throws IOException { operators.registerArtifact(e, id); }
    @Override public void initializeArtifactUpload(HttpExchange e, String id) throws IOException { operators.initializeArtifactUpload(e, id); }
    @Override public void appendArtifactUpload(HttpExchange e, String p, String u) throws IOException { operators.appendArtifactUpload(e, p, u); }
    @Override public void completeArtifactUpload(HttpExchange e, String p, String u) throws IOException { operators.completeArtifactUpload(e, p, u); }
    @Override public void cancelArtifactUpload(HttpExchange e, String p, String u) throws IOException { operators.cancelArtifactUpload(e, p, u); }
    @Override public void listArtifacts(HttpExchange e, String id) throws IOException { operators.listArtifacts(e, id); }
    @Override public void listEntries(HttpExchange e, String id) throws IOException { operators.listEntries(e, id); }
    @Override public void listOperators(HttpExchange e) throws IOException { operators.listOperators(e); }
    @Override public void createOperator(HttpExchange e) throws IOException { operators.createOperator(e); }
    @Override public void updateOperator(HttpExchange e, String id) throws IOException { operators.updateOperator(e, id); }
    @Override public void listProviders(HttpExchange e) throws IOException { operators.listProviders(e); }
    @Override public void createProvider(HttpExchange e) throws IOException { operators.createProvider(e); }
    @Override public void updateProvider(HttpExchange e, String id) throws IOException { operators.updateProvider(e, id); }
    @Override public void deleteProvider(HttpExchange e, String id) throws IOException { operators.deleteProvider(e, id); }
    @Override public void detectProviderProtocol(HttpExchange e) throws IOException { operators.detectProviderProtocol(e); }
    @Override public void refreshProviderModels(HttpExchange e, String id) throws IOException { operators.refreshProviderModels(e, id); }
    @Override public void listRoleAssignments(HttpExchange e, String id) throws IOException { aiJobs.listRoleAssignments(e, id); }
    @Override public void sendRoleAssignment(HttpExchange e, String p, AgentRole r) throws IOException { aiJobs.sendRoleAssignment(e, p, r); }
    @Override public void saveRoleAssignment(HttpExchange e, String p, AgentRole r) throws IOException { aiJobs.saveRoleAssignment(e, p, r); }
    @Override public void deleteRoleAssignment(HttpExchange e, String p, AgentRole r) throws IOException { aiJobs.deleteRoleAssignment(e, p, r); }
    @Override public void listAiJobs(HttpExchange e, String id) throws IOException { aiJobs.listAiJobs(e, id); }
    @Override public void createAiJob(HttpExchange e, String id) throws IOException { aiJobs.createAiJob(e, id); }
    @Override public void sendAiJob(HttpExchange e, String id) throws IOException { aiJobs.sendAiJob(e, id); }
    @Override public void listAiJobEvents(HttpExchange e, String id) throws IOException { aiJobs.listAiJobEvents(e, id); }
    @Override public void updateAiJob(HttpExchange e, String id) throws IOException { aiJobs.updateAiJob(e, id); }
    @Override public void deleteAiJob(HttpExchange e, String id) throws IOException { aiJobs.deleteAiJob(e, id); }
    @Override public void listAudit(HttpExchange e, String id) throws IOException { operators.listAudit(e, id); }
    @Override public void startAudit(HttpExchange e, String id) throws IOException { scanAudit.startAudit(e, id); }
    @Override public void retryAuditStage(HttpExchange e, String id) throws IOException { scanAudit.retryAuditStage(e, id); }
    @Override public void createScan(HttpExchange e, String id) throws IOException { scanAudit.createScan(e, id); }
    @Override public void listScans(HttpExchange e, String id) throws IOException { scanAudit.listScans(e, id); }
    @Override public void updateScan(HttpExchange e, String id) throws IOException { scanAudit.updateScan(e, id); }
    @Override public void deleteScan(HttpExchange e, String p, String s) throws IOException { scanAudit.deleteScan(e, p, s); }
    @Override public void sendScan(HttpExchange e, String id) throws IOException { scanAudit.sendScan(e, id); }
    @Override public void sendScanCoverage(HttpExchange e, String id) throws IOException { pathFindings.sendScanCoverage(e, id); }
    @Override public void sendScanEvidenceGraph(HttpExchange e, String id) throws IOException { pathFindings.sendScanEvidenceGraph(e, id); }
    @Override public void sendScanHypotheses(HttpExchange e, String id) throws IOException { pathFindings.sendScanHypotheses(e, id); }
    @Override public void sendScanAiMemory(HttpExchange e, String id) throws IOException { pathFindings.sendScanAiMemory(e, id); }
    @Override public void createDynamicTask(HttpExchange e, String id) throws IOException { dynamicWorker.createDynamicTask(e, id); }
    @Override public void listDynamicTasks(HttpExchange e, String id) throws IOException { dynamicWorker.listDynamicTasks(e, id); }
    @Override public void replayFinding(HttpExchange e, String id) throws IOException { dynamicWorker.replayFinding(e, id); }
    @Override public void focusEntryProbe(HttpExchange e, String s, String entry) throws IOException { dynamicWorker.focusEntryProbe(e, s, entry); }
    @Override public void replaySqlExperimentCard(HttpExchange e, String s, String c) throws IOException { dynamicWorker.replaySqlExperimentCard(e, s, c); }
    @Override public void streamEvents(HttpExchange e, String id) throws IOException { pathFindings.streamEvents(e, id); }
    @Override public void listPaths(HttpExchange e, String id) throws IOException { pathFindings.listPaths(e, id); }
    @Override public void sendPath(HttpExchange e, String s, String p) throws IOException { pathFindings.sendPath(e, s, p); }
    @Override public void listScanEvidence(HttpExchange e, String id) throws IOException { pathFindings.listScanEvidence(e, id); }
    @Override public void listScanFindings(HttpExchange e, String id) throws IOException { pathFindings.listScanFindings(e, id); }
    @Override public void sendFinding(HttpExchange e, String id) throws IOException { pathFindings.sendFinding(e, id); }
    @Override public void sendEvidence(HttpExchange e, String id) throws IOException { pathFindings.sendEvidence(e, id); }
    @Override public void listEvidence(HttpExchange e, String id) throws IOException { pathFindings.listEvidence(e, id); }
    @Override public void listChains(HttpExchange e) throws IOException { pathFindings.listChains(e); }
    @Override public void dashboard(HttpExchange e, String id) throws IOException { scanAudit.dashboard(e, id); }

    public java.util.Optional<com.aq.jvmsentinel.ai.tool.ToolDataSource.FactRecord> requestSandboxProbe(
            String scanId, com.aq.jvmsentinel.ai.tool.ToolExecutionContext.Scope scope, String principalId,
            String jobId, String toolCallId, String entrypointRef, java.util.List<String> candidateInputs,
            int maxRequests, String techniqueId, String authorizationHeader, String bladeAuthHeader,
            String experimentPlanId) {
        return sandboxProbe.requestSandboxProbe(scanId, scope, principalId, jobId, toolCallId, entrypointRef,
                candidateInputs, maxRequests, techniqueId, authorizationHeader, bladeAuthHeader, experimentPlanId);
    }

    public synchronized com.aq.jvmsentinel.worker.TaskSnapshot enqueueDynamicForPipeline(String scanId, String actorId) {
        return sandboxProbe.enqueueDynamicForPipeline(scanId, actorId);
    }

    public java.util.List<com.aq.jvmsentinel.control.ApiDtos.PathRunDto> mergedPathRunsForScan(
            String projectId, String artifactDigest, String scanId) {
        return pathFindings.mergedPathRunsForScan(projectId, artifactDigest, scanId);
    }

    public synchronized void acceptExperimentPlan(String scanId, com.aq.jvmsentinel.model.ExperimentPlan plan) {
        dynamicWorker.acceptExperimentPlan(scanId, plan);
    }

    public java.util.Map<String, Object> scanViewForPort(String scanId) { return scanAudit.scanViewForPort(scanId); }
    public java.util.List<java.util.Map<String, Object>> pathRunViewsForPort(String scanId) { return pathFindings.pathRunViewsForPort(scanId); }
    public com.aq.jvmsentinel.domain.coverage.CoverageMatrix coverageMatrixForScan(String scanId) { return pathFindings.coverageMatrixForScan(scanId); }
    public com.aq.jvmsentinel.domain.coverage.CoverageMatrix coverageMatrixForScan(String scanId, com.aq.jvmsentinel.analysis.coverage.CoverageMatrixProjector.SuppressMode m) { return pathFindings.coverageMatrixForScan(scanId, m); }
    public com.aq.jvmsentinel.domain.ir.EvidenceGraph projectEvidenceGraphBase(String scanId) { return pathFindings.projectEvidenceGraphBase(scanId); }
    public java.util.Map<String, Object> enrichedFindingMap(com.aq.jvmsentinel.control.ApiDtos.FindingDto dto) { return pathFindings.enrichedFindingMap(dto); }
    public com.aq.jvmsentinel.control.service.ProbePlanService.ProbePlan restoredDynamicProbePlan(String taskId) { return sandboxProbe.restoredDynamicProbePlan(taskId); }
    public com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor.ArtifactRegistration requireLocalArtifact(com.aq.jvmsentinel.worker.TaskScope scope) { return sandboxProbe.requireLocalArtifact(scope); }
    public java.util.Map<String, Object> health() { return operators.health(); }
    public void mergeRuntimeLoadedClasses(String scanId, java.util.List<String> names, String actorId) { pathFindings.mergeRuntimeLoadedClasses(scanId, names, actorId); }
    public void restoreProbePlans() { sandboxProbe.restoreProbePlans(); }
    public void restoreExperimentPlans() { dynamicWorker.restoreExperimentPlans(); }

    public static String probeAttemptId(String jobId, String toolCallId) { return SandboxProbeHttpHandlers.probeAttemptId(jobId, toolCallId); }
    public static com.aq.jvmsentinel.control.service.ProbePlanService.AuthMaterialized materializeAiPocAuth(
            String techniqueId, String authorizationHeader, java.nio.file.Path artifactPath) {
        return SandboxProbeHttpHandlers.materializeAiPocAuth(techniqueId, authorizationHeader, artifactPath);
    }
    public static com.aq.jvmsentinel.control.service.ProbePlanService.AuthMaterialized materializeAiPocAuth(
            String techniqueId, String authorizationHeader, String bladeAuthHeader, java.nio.file.Path artifactPath) {
        return SandboxProbeHttpHandlers.materializeAiPocAuth(techniqueId, authorizationHeader, bladeAuthHeader, artifactPath);
    }
    public static java.util.List<com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor.ProbeTarget> expandProbesByIdentityTracks(
            java.nio.file.Path artifactPath, java.util.List<com.aq.jvmsentinel.control.ApiDtos.EntryDto> entries,
            java.util.List<com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor.ProbeTarget> base, int max) {
        return SandboxProbeHttpHandlers.expandProbesByIdentityTracks(artifactPath, entries, base, max);
    }

    public static java.util.Map<String, Object> providerMap(
            com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.ProviderData provider) {
        return OperatorProviderHttpHandlers.providerMap(provider);
    }
}
