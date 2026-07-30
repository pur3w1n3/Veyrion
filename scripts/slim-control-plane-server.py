#!/usr/bin/env python3
"""Remove handler body from ControlPlaneServer; append delegations."""
from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(r"e:\ai\Veyrion")
SRC = ROOT / "src/main/java/com/aq/jvmsentinel/control/ControlPlaneServer.java"
HANDLERS = ROOT / "src/main/java/com/aq/jvmsentinel/control/http/ControlPlaneRouteHandlers.java"
ACTIONS = ROOT / "src/main/java/com/aq/jvmsentinel/control/routing/ControlPlaneRouteActions.java"

START = "@Override public synchronized void createProject"
END = "private record ScanBuild"


def extract_signatures() -> list[tuple[str, str, bool]]:
    src = HANDLERS.read_text(encoding="utf-8")
    out = []
    for m in re.finditer(
            r"(@Override\s+)?public (synchronized )?void (\w+)\(([^)]*)\) throws IOException",
            src):
        sync = m.group(2) is not None
        name = m.group(3)
        params = m.group(4)
        out.append((name, params, sync))
    # also role, query, sendHealth, requirePermission, AgentRole role
    for m in re.finditer(r"public (AgentRole role\(String value\)|String query\(URI uri, String key\)|void requirePermission\(HttpExchange exchange, Permission permission\))", src):
        pass
    for m in re.finditer(r"public AgentRole role\(String value\)", src):
        out.append(("role", "String value", False))
    for m in re.finditer(r"public String query\(URI uri, String key\)", src):
        out.append(("query", "URI uri, String key", False))
    for m in re.finditer(r"public void requirePermission\(HttpExchange exchange, Permission permission\)", src):
        out.append(("requirePermission", "HttpExchange exchange, Permission permission", False))
    for m in re.finditer(r"public void sendHealth\(HttpExchange exchange\) throws IOException", src):
        out.append(("sendHealth", "HttpExchange exchange", False))
    return out


def delegate_method(name: str, params: str, sync: bool) -> str:
    s = "synchronized " if sync else ""
    args = ", ".join(p.strip().split()[-1] for p in params.split(",") if p.strip()) if params.strip() else ""
    return f"""    @Override public {s}void {name}({params}) throws IOException {{
        routeHandlers.{name}({args});
    }}"""


def main() -> None:
    lines = SRC.read_text(encoding="utf-8").splitlines()
    start = next(i for i, ln in enumerate(lines) if START in ln)
    end = next(i for i, ln in enumerate(lines) if ln.strip().startswith(END))

    head = lines[:start]
    tail = lines[end:]

    imports = [
        "import com.aq.jvmsentinel.control.http.ControlPlaneHandlerHost;",
        "import com.aq.jvmsentinel.control.http.ControlPlaneRouteHandlers;",
        "import com.aq.jvmsentinel.control.http.ControlPlaneHttpSupport;",
        "import com.aq.jvmsentinel.control.http.ControlPlaneHttpLimits;",
        "import com.aq.jvmsentinel.control.http.ControlPlaneHandlerRecords;",
    ]
    pkg_idx = next(i for i, ln in enumerate(head) if ln.startswith("import "))
    for imp in reversed(imports):
        if imp not in head:
            head.insert(pkg_idx, imp)

    # 字段类型替换 + routeHandlers
    new_head = []
    inserted = False
    for ln in head:
        ln = ln.replace("AuditRunReplay", "ControlPlaneHandlerRecords.AuditRunReplay")
        ln = ln.replace("DynamicTaskReplay", "ControlPlaneHandlerRecords.DynamicTaskReplay")
        ln = ln.replace("FindingReplay", "ControlPlaneHandlerRecords.FindingReplay")
        ln = ln.replace("EntryFocusProbe", "ControlPlaneHandlerRecords.EntryFocusProbe")
        if not inserted and "private volatile ExecutorService executor" in ln:
            new_head.append(ln)
            new_head.append("    private final ControlPlaneHandlerHost handlerHost;")
            new_head.append("    private final ControlPlaneRouteHandlers routeHandlers;")
            inserted = True
            continue
        new_head.append(ln)
    head = new_head

    # 构造函数末尾注入 init（在 pipelineReaper schedule 块之后）
    for i in range(len(head) - 1, 0, -1):
        if head[i].strip() == "}" and "TimeUnit.SECONDS" in head[i - 1]:
            block = [
                "        this.handlerHost = new ControlPlaneHandlerHost(",
                "                JSON, bindAddress, artifactRegistry, artifactUploadService, analysis, store,",
                "                scanQueryPort, evidenceGraphQueryPort, coverageQueryPort, hypothesisQueryPort,",
                "                findingQueryPort, pathRunQueryPort, providerQueryPort, analyzerIrIngestPort,",
                "                scanQueryHttp, sseHub, idempotentProjects, idempotentArtifacts, idempotentScans,",
                "                idempotentAuditRuns, idempotentDynamicTasks, idempotentFindingReplays,",
                "                idempotentEntryFocusProbes, durableIdempotency, aiProbeTasks, dynamicProbePlans,",
                "                unreachedDynamicPaths, scanExperimentPlans, scanExpandedProbes,",
                "                idempotentExperimentCardReplays, mutationToken, workerToken, traceStore,",
                "                taskCoordinator, traceProjectionService, workerApi, probePlanService,",
                "                providerInventoryService, aiJobOrchestrator, auditPipeline, retainedSandboxRelease,",
                "                clock, authorizer);",
                "        this.routeHandlers = new ControlPlaneRouteHandlers(handlerHost);",
            ]
            head[i:i] = block
            break

    # 移除尾部 records（已迁移）
    tail = [ln for ln in tail if not ln.strip().startswith("private record ")]
    if tail and tail[0].strip() == "}":
        tail = tail[1:]

    sigs = extract_signatures()
    seen = set()
    delegations = ["", "    // ---- HTTP 路由委托 ----"]
    for name, params, sync in sigs:
        if name in seen:
            continue
        seen.add(name)
        if name == "requirePermission":
            delegations.append("    @Override public void requirePermission(HttpExchange exchange, Permission permission) {")
            delegations.append("        routeHandlers.requirePermission(exchange, permission);")
            delegations.append("    }")
            continue
        if name == "role":
            delegations.append("    @Override public AgentRole role(String value) { return routeHandlers.role(value); }")
            continue
        if name == "query":
            delegations.append("    @Override public String query(URI uri, String key) { return routeHandlers.query(uri, key); }")
            continue
        delegations.append(delegate_method(name, params, sync))

    bridge = """
    // ---- orchestrator / query port 桥接 ----
    Optional<ToolDataSource.FactRecord> requestSandboxProbe(
            String scanId, ToolExecutionContext.Scope scope, String principalId, String jobId,
            String toolCallId, String entrypointRef, List<String> candidateInputs, int maxRequests,
            String techniqueId, String authorizationHeader, String bladeAuthHeader,
            String experimentPlanId) {
        return routeHandlers.requestSandboxProbe(scanId, scope, principalId, jobId, toolCallId,
                entrypointRef, candidateInputs, maxRequests, techniqueId, authorizationHeader,
                bladeAuthHeader, experimentPlanId);
    }

    synchronized TaskSnapshot enqueueDynamicForPipeline(String scanId, String actorId) {
        return routeHandlers.enqueueDynamicForPipeline(scanId, actorId);
    }

    List<ApiDtos.PathRunDto> mergedPathRunsForScan(String projectId, String artifactDigest, String scanId) {
        return routeHandlers.mergedPathRunsForScan(projectId, artifactDigest, scanId);
    }

    synchronized void acceptExperimentPlan(String scanId, ExperimentPlan plan) {
        routeHandlers.acceptExperimentPlan(scanId, plan);
    }

    Map<String, Object> scanViewForPort(String scanId) {
        return routeHandlers.scanViewForPort(scanId);
    }

    List<Map<String, Object>> pathRunViewsForPort(String scanId) {
        return routeHandlers.pathRunViewsForPort(scanId);
    }

    CoverageMatrix coverageMatrixForScan(String scanId) {
        return routeHandlers.coverageMatrixForScan(scanId);
    }

    CoverageMatrix coverageMatrixForScan(String scanId, CoverageMatrixProjector.SuppressMode suppressMode) {
        return routeHandlers.coverageMatrixForScan(scanId, suppressMode);
    }

    EvidenceGraph projectEvidenceGraphBase(String scanId) {
        return routeHandlers.projectEvidenceGraphBase(scanId);
    }

    Map<String, Object> enrichedFindingMap(ApiDtos.FindingDto dto) {
        return routeHandlers.enrichedFindingMap(dto);
    }

    ProbePlanService.ProbePlan restoredDynamicProbePlan(String taskId) {
        return routeHandlers.restoredDynamicProbePlan(taskId);
    }

    public ExternalArtifactTaskExecutor.ArtifactRegistration requireLocalArtifact(TaskScope scope) {
        return routeHandlers.requireLocalArtifact(scope);
    }

    public Map<String, Object> health() {
        return routeHandlers.health();
    }

    public static String probeAttemptId(String jobId, String toolCallId) {
        return routeHandlers.probeAttemptId(jobId, toolCallId);
    }

    public static ProbePlanService.AuthMaterialized materializeAiPocAuth(
            String techniqueId, String authorizationHeader, Path artifactPath) {
        return ControlPlaneRouteHandlers.materializeAiPocAuth(techniqueId, authorizationHeader, artifactPath);
    }

    public static ProbePlanService.AuthMaterialized materializeAiPocAuth(
            String techniqueId, String authorizationHeader, String bladeAuthHeader, Path artifactPath) {
        return ControlPlaneRouteHandlers.materializeAiPocAuth(
                techniqueId, authorizationHeader, bladeAuthHeader, artifactPath);
    }

    static List<ExternalArtifactTaskExecutor.ProbeTarget> expandProbesByIdentityTracks(
            Path artifactPath,
            List<ApiDtos.EntryDto> httpEntries,
            List<ExternalArtifactTaskExecutor.ProbeTarget> base,
            int maxProbes) {
        return ControlPlaneRouteHandlers.expandProbesByIdentityTracks(
                artifactPath, httpEntries, base, maxProbes);
    }

    public void mergeRuntimeLoadedClasses(String scanId, List<String> loadedClassNames, String actorId) {
        routeHandlers.mergeRuntimeLoadedClasses(scanId, loadedClassNames, actorId);
    }
"""

    text = "\n".join(head) + "\n" + "\n".join(delegations) + bridge + "\n" + "\n".join(tail)
    text = text.replace("ControlPlaneHttpSupport.ApiException failure", "ControlPlaneHttpSupport.ApiException failure")
    text = text.replace("catch (ApiException failure)", "catch (ControlPlaneHttpSupport.ApiException failure)")
    SRC.write_text(text, encoding="utf-8", newline="\n")
    print("server lines:", len(text.splitlines()))


if __name__ == "__main__":
    main()
