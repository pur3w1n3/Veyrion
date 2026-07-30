#!/usr/bin/env python3
"""Generate ControlPlaneRouteHandlers + slim ControlPlaneServer delegation shell."""
from __future__ import annotations

import pathlib
import re
import textwrap

ROOT = pathlib.Path(r"e:\ai\Veyrion")
SRC = ROOT / "src/main/java/com/aq/jvmsentinel/control/ControlPlaneServer.java"
HTTP = ROOT / "src/main/java/com/aq/jvmsentinel/control/http"

# Method name -> handler class assignment for split files
GROUPS: dict[str, list[str]] = {
    "AuthOperatorProviderHttpHandlers": [
        "requirePermission", "listOperators", "createOperator", "updateOperator",
        "listProviders", "createProvider", "updateProvider", "deleteProvider",
        "refreshProviderModels", "listRoleAssignments", "sendRoleAssignment",
        "saveRoleAssignment", "deleteRoleAssignment", "role", "operatorRole",
        "saveProviderBody", "providerMap", "inventoryMap", "operatorMap", "roleBindingMap",
    ],
    "AiJobHttpHandlers": [
        "listAiJobs", "createAiJob", "sendAiJob", "listAiJobEvents", "updateAiJob",
        "deleteAiJob", "listAudit", "aiJobMap", "aiJobEventMap", "auditMap", "outputLanguage",
    ],
    "ProjectArtifactHttpHandlers": [
        "createProject", "sendProject", "listProjects", "updateProject", "deleteProject",
        "registerArtifact", "initializeArtifactUpload", "appendArtifactUpload",
        "completeArtifactUpload", "cancelArtifactUpload", "listArtifacts", "listEntries",
        "projectMap", "projectDto", "artifactMap", "artifactDto", "uploadSessionMap",
    ],
    "ScanAuditHttpHandlers": [
        "listScans", "deleteScan", "startAudit", "retryAuditStage", "updateScan",
        "createScan", "sendScan", "sendScanCoverage", "sendScanEvidenceGraph",
        "sendScanHypotheses", "sendScanAiMemory", "pauseAuditPipeline", "cancelAuditPipeline",
        "resumeAuditPipeline", "enqueueAuditStage", "pipelineRunForScan",
        "invalidateArmedPipelineForRetry", "requireRetryPrerequisite", "requireCompletedRole",
        "auditRunMap", "createOrReplayScan", "coverageMatrixForScan", "projectEvidenceGraphBase",
        "evidenceGraphForScan", "scanViewForPort", "attachPipelineProjection",
        "pathRunViewsForPort", "pathTracesByPathRunId", "buildScan", "policyFrom",
        "buildFindings", "buildPaths", "buildChains", "mergeProviderBundleIntoScan",
        "ensureProviderEvidence", "publishEvent", "scanMap", "entryMap", "dependencyMap",
        "sinkMap", "evidenceMap", "findingMap", "hypothesisMaps", "pathStepMap", "pathMap",
        "pathRunMap", "chainMap", "sinkCategoryLabel", "sinkBindingKey", "entryBindingKey",
        "staticSinkSeverity", "sinkDeclaringClass", "simpleName", "prefixRefs", "envelope",
        "stringEnvelope", "isAuthGapFinding", "latestScan", "dynamicPaths", "dynamicEvidence",
        "mergedPathRunsForScan", "mergedPathRunsForTask", "enrichedFindingMap",
    ],
    "DynamicTaskHttpHandlers": [
        "createDynamicTask", "listDynamicTasks", "dynamicTaskWithDiagnostic", "dynamicTaskMap",
        "replayFinding", "focusEntryProbe", "replaySqlExperimentCard", "findingReplayMap",
        "entryFocusProbeMap", "acceptExperimentPlan", "restoreExperimentPlans", "findAcceptedPlan",
        "sqlExperimentCardMap", "experimentPlanMap",
    ],
    "SandboxProbeSupport": [
        "requestSandboxProbe", "probeAttemptId", "probeExecutionFailureFact", "isActiveLifecycle",
        "probeState", "refreshTaskSnapshot", "awaitDynamicTaskTerminal", "probeFact",
        "enqueueDynamicForPipeline", "requireLocalArtifact", "resolveWorldPackDependencyMode",
        "restoreProbePlans", "restoredDynamicProbePlan", "persistedStringList", "probePlanHash",
        "buildProbePlan", "materializeAiPocAuth", "expandProbesByIdentityTracks",
        "hasExecutableMainClass", "dynamicBudgetForArtifact",
    ],
    "PathRunQueryHttpHandlers": [
        "streamEvents", "listPaths", "sendPath", "listScanEvidence", "listScanFindings",
        "sendFinding", "sendEvidence", "listEvidence", "listChains", "dashboard",
        "sendHealth", "query", "health",
    ],
}


def read_src() -> list[str]:
    return SRC.read_text(encoding="utf-8").splitlines()


def find_method_ranges(lines: list[str]) -> dict[str, tuple[int, int]]:
    """Map method name -> (start_line_1based, end_line_1based)."""
    pattern = re.compile(
        r"^    ((?:@\w+(?:\([^)]*\))? )*(?:public |private |protected |static )+)"
        r"(?:[\w<>,\s\[\]?]+\s+)?(\w+)\s*\("
    )
    indices: list[tuple[int, str, str]] = []
    for i, ln in enumerate(lines):
        if " class ApiHandler " in ln or ln.strip().startswith("private record "):
            continue
        m = pattern.match(ln)
        if m and not ln.strip().startswith("//"):
            indices.append((i, m.group(2), ln))
    ranges: dict[str, tuple[int, int]] = {}
    for idx, (start, name, _) in enumerate(indices):
        end = indices[idx + 1][0] - 1 if idx + 1 < len(indices) else len(lines) - 1
        # trim trailing blank lines before next section
        while end > start and lines[end].strip() == "":
            end -= 1
        ranges[name] = (start + 1, end + 1)
    return ranges


def transform_method_block(block: str) -> str:
    block = block.replace("ApiException", "ControlPlaneHttpSupport.ApiException")
    block = block.replace("MAX_BODY_BYTES", "ControlPlaneHttpLimits.MAX_BODY_BYTES")
    block = block.replace("MAX_LIST_ITEMS", "ControlPlaneHttpLimits.MAX_LIST_ITEMS")
    block = block.replace("MAX_IDEMPOTENCY_KEYS", "ControlPlaneHttpLimits.MAX_IDEMPOTENCY_KEYS")
    block = block.replace("MAX_AI_JOB_EVENTS", "ControlPlaneHttpLimits.MAX_AI_JOB_EVENTS")
    block = block.replace("API_PREFIX", "ControlPlaneHttpLimits.API_PREFIX")
    block = block.replace("DEFAULT_WALL_CLOCK_SECONDS", "ControlPlaneHttpLimits.DEFAULT_WALL_CLOCK_SECONDS")
    block = block.replace("DEFAULT_MEMORY_BYTES", "ControlPlaneHttpLimits.DEFAULT_MEMORY_BYTES")
    block = block.replace("DEFAULT_DISK_BYTES", "ControlPlaneHttpLimits.DEFAULT_DISK_BYTES")
    block = block.replace("DYNAMIC_QUEUE_TIMEOUT", "ControlPlaneHttpLimits.DYNAMIC_QUEUE_TIMEOUT")
    block = block.replace("ScanBuild", "ControlPlaneHandlerRecords.ScanBuild")
    block = block.replace("ScanStart", "ControlPlaneHandlerRecords.ScanStart")
    block = block.replace("AuditRunReplay", "ControlPlaneHandlerRecords.AuditRunReplay")
    block = block.replace("DynamicTaskPayload", "ControlPlaneHandlerRecords.DynamicTaskPayload")
    block = block.replace("DynamicTaskReplay", "ControlPlaneHandlerRecords.DynamicTaskReplay")
    block = block.replace("FindingReplay", "ControlPlaneHandlerRecords.FindingReplay")
    block = block.replace("EntryFocusProbe", "ControlPlaneHandlerRecords.EntryFocusProbe")
    block = re.sub(r"\breadObject\(", "ControlPlaneHttpSupport.readObject(", block)
    block = re.sub(r"\bsendJson\(", "ControlPlaneHttpSupport.sendJson(", block)
    block = re.sub(r"\bsendEmpty\(", "ControlPlaneHttpSupport.sendEmpty(", block)
    block = re.sub(r"\boptionalText\(", "ControlPlaneHttpSupport.optionalText(", block)
    block = re.sub(r"\btextValue\(", "ControlPlaneHttpSupport.textValue(", block)
    block = re.sub(r"\boptionalPrompt\(", "ControlPlaneHttpSupport.optionalPrompt(", block)
    block = re.sub(r"\brequiredBoolean\(", "ControlPlaneHttpSupport.requiredBoolean(", block)
    block = re.sub(r"\boptionalBoolean\(", "ControlPlaneHttpSupport.optionalBoolean(", block)
    block = re.sub(r"\bpositiveLong\(", "ControlPlaneHttpSupport.positiveLong(", block)
    block = re.sub(r"\bstringList\(", "ControlPlaneHttpSupport.stringList(", block)
    block = re.sub(r"\brequestIdempotencyKey\(", "ControlPlaneHttpSupport.requestIdempotencyKey(", block)
    block = re.sub(r"\brequireIdempotencyKey\(", "ControlPlaneHttpSupport.requireIdempotencyKey(", block)
    block = re.sub(r"\bensureIdempotencyCapacity\(", "ControlPlaneHttpSupport.ensureIdempotencyCapacity(", block)
    block = re.sub(r"\bidempotencyMapKey\(", "ControlPlaneHttpSupport.idempotencyMapKey(", block)
    block = re.sub(r"\bpayloadHash\(", "ControlPlaneHttpSupport.payloadHash(", block)
    block = re.sub(r"\bconstantTimeEquals\(", "ControlPlaneHttpSupport.constantTimeEquals(", block)
    block = re.sub(r"\bparseContentLength\(", "ControlPlaneHttpSupport.parseContentLength(", block)
    block = re.sub(r"\bnonNegativeLong\(", "ControlPlaneHttpSupport.nonNegativeLong(", block)
    block = re.sub(r"\bquery\(", "ControlPlaneHttpSupport.query(", block)
    block = re.sub(r"ControlPlaneHttpSupport\.query\(exchange\.getRequestURI\(\)",
                   "ControlPlaneHttpSupport.query(exchange.getRequestURI()", block)
    block = block.replace("ControlPlaneServer::", "ControlPlaneWireSupport::")
    return block


def field_access(block: str) -> str:
    """Rewrite bare field access to host.field."""
    fields = [
        "store", "clock", "sseHub", "artifactRegistry", "artifactUploadService", "analysis",
        "scanQueryPort", "evidenceGraphQueryPort", "coverageQueryPort", "hypothesisQueryPort",
        "findingQueryPort", "pathRunQueryPort", "providerQueryPort", "analyzerIrIngestPort",
        "scanQueryHttp", "idempotentProjects", "idempotentArtifacts", "idempotentScans",
        "idempotentAuditRuns", "idempotentDynamicTasks", "idempotentFindingReplays",
        "idempotentEntryFocusProbes", "durableIdempotency", "aiProbeTasks", "dynamicProbePlans",
        "unreachedDynamicPaths", "scanExperimentPlans", "scanExpandedProbes",
        "idempotentExperimentCardReplays", "mutationToken", "workerToken", "traceStore",
        "taskCoordinator", "traceProjectionService", "workerApi", "probePlanService",
        "providerInventoryService", "aiJobOrchestrator", "auditPipeline", "authorizer",
        "bindAddress", "retainedSandboxRelease", "JSON",
    ]
    for f in fields:
        block = re.sub(rf"(?<![\w\.]){f}(?=\.)", f"host.{f}", block)
        block = re.sub(rf"(?<![\w\.]){f}(?=\)", block.replace("host.host.", "host."), block)
    block = block.replace("host.host.", "host.")
    block = re.sub(r"this::(\w+)", r"host::\1", block)
    block = block.replace("actor(exchange)", "auth.actor(exchange)")
    block = re.sub(r"(?<![\w\.])existingDurableIdempotency\(", "idempotency.existingDurableIdempotency(", block)
    block = re.sub(r"(?<![\w\.])rememberDurableIdempotency\(", "idempotency.rememberDurableIdempotency(", block)
    block = re.sub(r"releaseRetainedSandboxForScan\(", "host.releaseRetainedSandboxForScan(", block)
    return block


def main() -> None:
    lines = read_src()
    ranges = find_method_ranges(lines)
    print(f"found {len(ranges)} methods")
    for group, names in GROUPS.items():
        chunks: list[str] = []
        missing = []
        for name in names:
            if name not in ranges:
                missing.append(name)
                continue
            s, e = ranges[name]
            block = "\n".join(lines[s - 1 : e])
            block = transform_method_block(block)
            block = field_access(block)
            chunks.append(block)
        if missing:
            print(f"  {group}: missing {missing}")
        body = "\n\n".join(chunks)
        content = textwrap.dedent(
            f"""
            package com.aq.jvmsentinel.control.http;

            import com.aq.jvmsentinel.control.ControlPlaneServer;

            /** 从 ControlPlaneServer 提取的 HTTP 处理器（{group}）。 */
            public final class {group} {{
                private final ControlPlaneHandlerHost host;
                private final ControlPlaneAuthSupport auth;
                private final ControlPlaneIdempotencySupport idempotency;

                public {group}(ControlPlaneHandlerHost host,
                               ControlPlaneAuthSupport auth,
                               ControlPlaneIdempotencySupport idempotency) {{
                    this.host = host;
                    this.auth = auth;
                    this.idempotency = idempotency;
                }}

            {body}
            }}
            """
        ).strip() + "\n"
        write(group + ".java", content)


def write(name: str, content: str) -> None:
    path = HTTP / name
    path.write_text(content, encoding="utf-8", newline="\n")
    print(f"wrote {name}: {len(content.splitlines())} lines")


if __name__ == "__main__":
    main()
