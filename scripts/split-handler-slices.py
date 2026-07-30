#!/usr/bin/env python3
"""Split ControlPlaneRouteHandlers into domain collaborator classes."""
from __future__ import annotations

import pathlib
import re

HTTP = pathlib.Path(r"e:\ai\Veyrion\src\main\java\com\aq\jvmsentinel\control\http")
SRC = HTTP / "ControlPlaneRouteHandlers.java"

# public route + package-visible helpers owned by each slice
SLICES: dict[str, list[str]] = {
    "AuthOperatorProviderHttpHandlers": [
        "requirePermission", "actor", "role", "listOperators", "createOperator", "updateOperator",
        "listProviders", "createProvider", "updateProvider", "deleteProvider", "refreshProviderModels",
        "listRoleAssignments", "sendRoleAssignment", "saveRoleAssignment", "deleteRoleAssignment",
        "saveProviderBody", "operatorRole", "outputLanguage", "operatorMap", "providerMap",
        "inventoryMap", "roleBindingMap",
    ],
    "AiJobHttpHandlers": [
        "listAiJobs", "createAiJob", "sendAiJob", "listAiJobEvents", "updateAiJob", "deleteAiJob",
        "listAudit", "aiJobMap", "aiJobEventMap", "auditMap",
    ],
    "ProjectArtifactHttpHandlers": [
        "createProject", "sendProject", "listProjects", "updateProject", "deleteProject",
        "registerArtifact", "initializeArtifactUpload", "appendArtifactUpload", "completeArtifactUpload",
        "cancelArtifactUpload", "listArtifacts", "projectMap", "projectDto", "artifactMap", "artifactDto",
        "uploadSessionMap",
    ],
    "ScanAuditHttpHandlers": [
        "listEntries", "listScans", "deleteScan", "startAudit", "retryAuditStage", "updateScan",
        "createScan", "sendScan", "sendScanCoverage", "sendScanEvidenceGraph", "sendScanHypotheses",
        "sendScanAiMemory", "pauseAuditPipeline", "cancelAuditPipeline", "resumeAuditPipeline",
        "enqueueAuditStage", "pipelineRunForScan", "invalidateArmedPipelineForRetry",
        "requireRetryPrerequisite", "createOrReplayScan", "buildScan", "policyFrom", "buildFindings",
        "buildPaths", "buildChains", "publishEvent", "scanViewForPort", "attachPipelineProjection",
        "coverageMatrixForScan", "projectEvidenceGraphBase", "evidenceGraphForScan",
        "auditRunMap", "requireCompletedRole",
    ],
    "SandboxProbeHttpHandlers": [
        "requestSandboxProbe", "probeAttemptId", "probeExecutionFailureFact", "isActiveLifecycle",
        "probeState", "refreshTaskSnapshot", "awaitDynamicTaskTerminal", "probeFact",
        "enqueueDynamicForPipeline", "requireLocalArtifact", "resolveWorldPackDependencyMode",
        "restoreProbePlans", "restoredDynamicProbePlan", "persistedStringList", "probePlanHash",
        "buildProbePlan", "materializeAiPocAuth", "expandProbesByIdentityTracks",
        "hasExecutableMainClass", "dynamicBudgetForArtifact", "dynamicTaskMap", "dynamicTaskWithDiagnostic",
    ],
    "DynamicTaskHttpHandlers": [
        "createDynamicTask", "listDynamicTasks", "replayFinding", "focusEntryProbe",
        "replaySqlExperimentCard", "acceptExperimentPlan", "restoreExperimentPlans", "findAcceptedPlan",
        "findingReplayMap", "entryFocusProbeMap", "sqlExperimentCardMap", "experimentPlanMap",
    ],
    "PathRunQueryHttpHandlers": [
        "streamEvents", "listPaths", "sendPath", "listScanEvidence", "listScanFindings",
        "sendFinding", "sendEvidence", "listEvidence", "listChains", "dashboard", "sendHealth",
        "query", "health", "mergedPathRunsForScan", "mergedPathRunsForTask", "pathRunViewsForPort",
        "pathTracesByPathRunId", "dynamicPaths", "dynamicEvidence", "latestScan",
        "enrichedFindingMap", "mergeRuntimeLoadedClasses", "isAuthGapFinding",
    ],
}

SHARED = [
    "existingDurableIdempotency", "rememberDurableIdempotency",
    "envelope", "stringEnvelope", "entryMap", "dependencyMap", "sinkMap", "evidenceMap",
    "findingMap", "hypothesisMaps", "pathStepMap", "pathMap", "pathRunMap", "scanMap",
    "chainMap", "prefixRefs", "simpleName", "sinkCategoryLabel", "sinkBindingKey",
    "entryBindingKey", "staticSinkSeverity", "sinkDeclaringClass", "mergeProviderBundleIntoScan",
    "ensureProviderEvidence", "entryKey", "stripPrefix", "correlationIdFromPathRun",
    "readObjectOrEmpty", "safeMessage",
]


def parse_methods(text: str) -> dict[str, str]:
    lines = text.splitlines()
    pat = re.compile(
        r"^    ((?:public |synchronized |static )+)("
        r"(?:[\w<>,\s\[\]?]+\s+)?(\w+)|ControlPlaneHttpSupport\.readObject)"
        r"\s*\("
    )
    indices: list[tuple[int, str]] = []
    for i, ln in enumerate(lines):
        if ln.strip().startswith("@FunctionalInterface"):
            break
        m = re.match(r"^    ((?:public |synchronized |static )+(?:[\w<>,\s\[\]?]+\s+)?(\w+))\s*\(", ln)
        if m:
            indices.append((i, m.group(2)))
        elif ln.startswith("    ControlPlaneHttpSupport.readObject("):
            indices.append((i, "readObject_dup"))
        elif ln.startswith("    SQLiteControlPlanePersistence.IdempotencyData existingDurableIdempotency"):
            indices.append((i, "existingDurableIdempotency"))
        elif ln.startswith("    SQLiteControlPlanePersistence.IdempotencyData rememberDurableIdempotency"):
            indices.append((i, "rememberDurableIdempotency"))
    methods: dict[str, str] = {}
    for idx, (start, name) in enumerate(indices):
        end = indices[idx + 1][0] if idx + 1 < len(indices) else len(lines)
        body = "\n".join(lines[start:end]).rstrip()
        if name != "readObject_dup":
            methods[name] = body
    return methods


def write_support(methods: dict[str, str]) -> None:
    bodies = [methods[n] for n in SHARED if n in methods]
    content = f"""package com.aq.jvmsentinel.control.http;

/** 处理器共享辅助（wire map、幂等、投影工具）。 */
class ControlPlaneHandlerSupport {{
    protected final ControlPlaneHandlerHost host;

    ControlPlaneHandlerSupport(ControlPlaneHandlerHost host) {{
        this.host = host;
    }}

{chr(10).join(bodies)}
}}
"""
    (HTTP / "ControlPlaneHandlerSupport.java").write_text(content, encoding="utf-8", newline="\n")
    print("ControlPlaneHandlerSupport:", len(content.splitlines()))


def write_slice(name: str, method_names: list[str], methods: dict[str, str]) -> None:
    bodies = []
    missing = []
    for mn in method_names:
        if mn in methods:
            bodies.append(methods[mn])
        else:
            missing.append(mn)
    if missing:
        print(f"  {name} missing: {missing[:5]}{'...' if len(missing)>5 else ''}")
    content = f"""package com.aq.jvmsentinel.control.http;

import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;

/** 从 ControlPlaneServer 拆出的 HTTP 处理器：{name.replace('HttpHandlers','').replace('SandboxProbe','Sandbox/Probe ')}。 */
final class {name} extends ControlPlaneHandlerSupport {{
    {name}(ControlPlaneHandlerHost host) {{ super(host); }}

{chr(10).join(bodies)}
}}
"""
    (HTTP / f"{name}.java").write_text(content, encoding="utf-8", newline="\n")
    print(f"{name}:", len(content.splitlines()), "lines")


def write_facade() -> None:
    content = '''package com.aq.jvmsentinel.control.http;

import com.aq.jvmsentinel.control.routing.ControlPlaneRouteActions;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.security.auth.Permission;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.net.URI;

/** 组合各域 HTTP 处理器，实现 {@link ControlPlaneRouteActions}。 */
public final class ControlPlaneRouteHandlers implements ControlPlaneRouteActions {
    private final AuthOperatorProviderHttpHandlers auth;
    private final AiJobHttpHandlers aiJobs;
    private final ProjectArtifactHttpHandlers projects;
    private final ScanAuditHttpHandlers scanAudit;
    private final SandboxProbeHttpHandlers sandbox;
    private final DynamicTaskHttpHandlers dynamic;
    private final PathRunQueryHttpHandlers queries;

    public ControlPlaneRouteHandlers(ControlPlaneHandlerHost host) {
        var support = new ControlPlaneHandlerSupport(host) {};
        this.auth = new AuthOperatorProviderHttpHandlers(host);
        this.aiJobs = new AiJobHttpHandlers(host);
        this.projects = new ProjectArtifactHttpHandlers(host);
        this.scanAudit = new ScanAuditHttpHandlers(host);
        this.sandbox = new SandboxProbeHttpHandlers(host);
        this.dynamic = new DynamicTaskHttpHandlers(host);
        this.queries = new PathRunQueryHttpHandlers(host);
    }

    @Override public void requirePermission(HttpExchange e, Permission p) { auth.requirePermission(e, p); }
    @Override public AgentRole role(String v) { return auth.role(v); }
    @Override public String query(URI u, String k) { return ControlPlaneHttpSupport.query(u, k); }
    @Override public void sendHealth(HttpExchange e) throws IOException { queries.sendHealth(e); }

    @Override public void createProject(HttpExchange e) throws IOException { projects.createProject(e); }
    @Override public void sendProject(HttpExchange e, String id) throws IOException { projects.sendProject(e, id); }
    @Override public void listProjects(HttpExchange e) throws IOException { projects.listProjects(e); }
    @Override public void updateProject(HttpExchange e, String id) throws IOException { projects.updateProject(e, id); }
    @Override public void deleteProject(HttpExchange e, String id) throws IOException { projects.deleteProject(e, id); }
    @Override public void registerArtifact(HttpExchange e, String id) throws IOException { projects.registerArtifact(e, id); }
    @Override public void initializeArtifactUpload(HttpExchange e, String id) throws IOException { projects.initializeArtifactUpload(e, id); }
    @Override public void appendArtifactUpload(HttpExchange e, String p, String u) throws IOException { projects.appendArtifactUpload(e, p, u); }
    @Override public void completeArtifactUpload(HttpExchange e, String p, String u) throws IOException { projects.completeArtifactUpload(e, p, u); }
    @Override public void cancelArtifactUpload(HttpExchange e, String p, String u) throws IOException { projects.cancelArtifactUpload(e, p, u); }
    @Override public void listArtifacts(HttpExchange e, String id) throws IOException { projects.listArtifacts(e, id); }

    @Override public void listOperators(HttpExchange e) throws IOException { auth.listOperators(e); }
    @Override public void createOperator(HttpExchange e) throws IOException { auth.createOperator(e); }
    @Override public void updateOperator(HttpExchange e, String id) throws IOException { auth.updateOperator(e, id); }
    @Override public void listProviders(HttpExchange e) throws IOException { auth.listProviders(e); }
    @Override public void createProvider(HttpExchange e) throws IOException { auth.createProvider(e); }
    @Override public void updateProvider(HttpExchange e, String id) throws IOException { auth.updateProvider(e, id); }
    @Override public void deleteProvider(HttpExchange e, String id) throws IOException { auth.deleteProvider(e, id); }
    @Override public void refreshProviderModels(HttpExchange e, String id) throws IOException { auth.refreshProviderModels(e, id); }
    @Override public void listRoleAssignments(HttpExchange e, String id) throws IOException { auth.listRoleAssignments(e, id); }
    @Override public void sendRoleAssignment(HttpExchange e, String p, AgentRole r) throws IOException { auth.sendRoleAssignment(e, p, r); }
    @Override public void saveRoleAssignment(HttpExchange e, String p, AgentRole r) throws IOException { auth.saveRoleAssignment(e, p, r); }
    @Override public void deleteRoleAssignment(HttpExchange e, String p, AgentRole r) throws IOException { auth.deleteRoleAssignment(e, p, r); }

    @Override public void listAiJobs(HttpExchange e, String id) throws IOException { aiJobs.listAiJobs(e, id); }
    @Override public void createAiJob(HttpExchange e, String id) throws IOException { aiJobs.createAiJob(e, id); }
    @Override public void sendAiJob(HttpExchange e, String id) throws IOException { aiJobs.sendAiJob(e, id); }
    @Override public void listAiJobEvents(HttpExchange e, String id) throws IOException { aiJobs.listAiJobEvents(e, id); }
    @Override public void updateAiJob(HttpExchange e, String id) throws IOException { aiJobs.updateAiJob(e, id); }
    @Override public void deleteAiJob(HttpExchange e, String id) throws IOException { aiJobs.deleteAiJob(e, id); }
    @Override public void listAudit(HttpExchange e, String id) throws IOException { aiJobs.listAudit(e, id); }

    @Override public void listEntries(HttpExchange e, String id) throws IOException { scanAudit.listEntries(e, id); }
    @Override public void startAudit(HttpExchange e, String id) throws IOException { scanAudit.startAudit(e, id); }
    @Override public void retryAuditStage(HttpExchange e, String id) throws IOException { scanAudit.retryAuditStage(e, id); }
    @Override public void createScan(HttpExchange e, String id) throws IOException { scanAudit.createScan(e, id); }
    @Override public void listScans(HttpExchange e, String id) throws IOException { scanAudit.listScans(e, id); }
    @Override public void updateScan(HttpExchange e, String id) throws IOException { scanAudit.updateScan(e, id); }
    @Override public void deleteScan(HttpExchange e, String p, String s) throws IOException { scanAudit.deleteScan(e, p, s); }
    @Override public void sendScan(HttpExchange e, String id) throws IOException { scanAudit.sendScan(e, id); }
    @Override public void sendScanCoverage(HttpExchange e, String id) throws IOException { scanAudit.sendScanCoverage(e, id); }
    @Override public void sendScanEvidenceGraph(HttpExchange e, String id) throws IOException { scanAudit.sendScanEvidenceGraph(e, id); }
    @Override public void sendScanHypotheses(HttpExchange e, String id) throws IOException { scanAudit.sendScanHypotheses(e, id); }
    @Override public void sendScanAiMemory(HttpExchange e, String id) throws IOException { scanAudit.sendScanAiMemory(e, id); }

    @Override public void createDynamicTask(HttpExchange e, String id) throws IOException { dynamic.createDynamicTask(e, id); }
    @Override public void listDynamicTasks(HttpExchange e, String id) throws IOException { dynamic.listDynamicTasks(e, id); }
    @Override public void replayFinding(HttpExchange e, String id) throws IOException { dynamic.replayFinding(e, id); }
    @Override public void focusEntryProbe(HttpExchange e, String s, String entry) throws IOException { dynamic.focusEntryProbe(e, s, entry); }
    @Override public void replaySqlExperimentCard(HttpExchange e, String s, String c) throws IOException { dynamic.replaySqlExperimentCard(e, s, c); }

    @Override public void streamEvents(HttpExchange e, String id) throws IOException { queries.streamEvents(e, id); }
    @Override public void listPaths(HttpExchange e, String id) throws IOException { queries.listPaths(e, id); }
    @Override public void sendPath(HttpExchange e, String s, String p) throws IOException { queries.sendPath(e, s, p); }
    @Override public void listScanEvidence(HttpExchange e, String id) throws IOException { queries.listScanEvidence(e, id); }
    @Override public void listScanFindings(HttpExchange e, String id) throws IOException { queries.listScanFindings(e, id); }
    @Override public void sendFinding(HttpExchange e, String id) throws IOException { queries.sendFinding(e, id); }
    @Override public void sendEvidence(HttpExchange e, String id) throws IOException { queries.sendEvidence(e, id); }
    @Override public void listEvidence(HttpExchange e, String id) throws IOException { queries.listEvidence(e, id); }
    @Override public void listChains(HttpExchange e) throws IOException { queries.listChains(e); }
    @Override public void dashboard(HttpExchange e, String id) throws IOException { queries.dashboard(e, id); }

    // package-visible 桥接（ControlPlaneServer / orchestrator）
    public java.util.Optional<com.aq.jvmsentinel.ai.tool.ToolDataSource.FactRecord> requestSandboxProbe(
            String scanId, com.aq.jvmsentinel.ai.tool.ToolExecutionContext.Scope scope, String principalId,
            String jobId, String toolCallId, String entrypointRef, java.util.List<String> candidateInputs,
            int maxRequests, String techniqueId, String authorizationHeader, String bladeAuthHeader,
            String experimentPlanId) {
        return sandbox.requestSandboxProbe(scanId, scope, principalId, jobId, toolCallId, entrypointRef,
                candidateInputs, maxRequests, techniqueId, authorizationHeader, bladeAuthHeader, experimentPlanId);
    }

    public synchronized com.aq.jvmsentinel.worker.TaskSnapshot enqueueDynamicForPipeline(String scanId, String actorId) {
        return sandbox.enqueueDynamicForPipeline(scanId, actorId);
    }

    public java.util.List<com.aq.jvmsentinel.control.ApiDtos.PathRunDto> mergedPathRunsForScan(
            String projectId, String artifactDigest, String scanId) {
        return queries.mergedPathRunsForScan(projectId, artifactDigest, scanId);
    }

    public synchronized void acceptExperimentPlan(String scanId, com.aq.jvmsentinel.model.ExperimentPlan plan) {
        dynamic.acceptExperimentPlan(scanId, plan);
    }

    public java.util.Map<String, Object> scanViewForPort(String scanId) { return scanAudit.scanViewForPort(scanId); }
    public java.util.List<java.util.Map<String, Object>> pathRunViewsForPort(String scanId) { return queries.pathRunViewsForPort(scanId); }
    public com.aq.jvmsentinel.domain.coverage.CoverageMatrix coverageMatrixForScan(String scanId) { return scanAudit.coverageMatrixForScan(scanId); }
    public com.aq.jvmsentinel.domain.coverage.CoverageMatrix coverageMatrixForScan(String scanId, com.aq.jvmsentinel.analysis.coverage.CoverageMatrixProjector.SuppressMode m) { return scanAudit.coverageMatrixForScan(scanId, m); }
    public com.aq.jvmsentinel.domain.ir.EvidenceGraph projectEvidenceGraphBase(String scanId) { return scanAudit.projectEvidenceGraphBase(scanId); }
    public java.util.Map<String, Object> enrichedFindingMap(com.aq.jvmsentinel.control.ApiDtos.FindingDto dto) { return queries.enrichedFindingMap(dto); }
    public com.aq.jvmsentinel.control.service.ProbePlanService.ProbePlan restoredDynamicProbePlan(String taskId) { return sandbox.restoredDynamicProbePlan(taskId); }
    public com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor.ArtifactRegistration requireLocalArtifact(com.aq.jvmsentinel.worker.TaskScope scope) { return sandbox.requireLocalArtifact(scope); }
    public java.util.Map<String, Object> health() { return queries.health(); }
    public void mergeRuntimeLoadedClasses(String scanId, java.util.List<String> names, String actorId) { queries.mergeRuntimeLoadedClasses(scanId, names, actorId); }

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
}
'''
    (HTTP / "ControlPlaneRouteHandlers.java").write_text(content, encoding="utf-8", newline="\n")
    print("facade:", len(content.splitlines()))


def main() -> None:
    methods = parse_methods(SRC.read_text(encoding="utf-8"))
    print("parsed", len(methods), "methods")
    assigned = set(SHARED)
    for names in SLICES.values():
        assigned.update(names)
    write_support(methods)
    for slice_name, names in SLICES.items():
        write_slice(slice_name, names, methods)
    write_facade()
    # backup monolith
    monolith = SRC.read_text(encoding="utf-8")
    (HTTP / "ControlPlaneRouteHandlers.monolith.bak").write_text(monolith, encoding="utf-8")


if __name__ == "__main__":
    main()
