#!/usr/bin/env python3
"""Mechanical split: move handler region to ControlPlaneRouteHandlers, slim server."""
from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(r"e:\ai\Veyrion")
SRC = ROOT / "src/main/java/com/aq/jvmsentinel/control/ControlPlaneServer.java"
HANDLERS = ROOT / "src/main/java/com/aq/jvmsentinel/control/http/ControlPlaneRouteHandlers.java"

HANDLER_START_MARK = "@Override public synchronized void createProject"
HANDLER_END_MARK = "private record ScanBuild"


def read_lines() -> list[str]:
    return SRC.read_text(encoding="utf-8").splitlines()


def transform_handlers(chunk: list[str]) -> list[str]:
    out: list[str] = []
    for ln in chunk:
        if ln.strip().startswith("@Override"):
            ln = ln.replace("@Override ", "")
        ln = ln.replace("private synchronized ", "synchronized ")
        ln = ln.replace("private ", "")
        ln = ln.replace("ApiException", "ControlPlaneHttpSupport.ApiException")
        ln = ln.replace("MAX_BODY_BYTES", "ControlPlaneHttpLimits.MAX_BODY_BYTES")
        ln = ln.replace("MAX_LIST_ITEMS", "ControlPlaneHttpLimits.MAX_LIST_ITEMS")
        ln = ln.replace("MAX_IDEMPOTENCY_KEYS", "ControlPlaneHttpLimits.MAX_IDEMPOTENCY_KEYS")
        ln = ln.replace("MAX_AI_JOB_EVENTS", "ControlPlaneHttpLimits.MAX_AI_JOB_EVENTS")
        ln = ln.replace("DEFAULT_WALL_CLOCK_SECONDS", "ControlPlaneHttpLimits.DEFAULT_WALL_CLOCK_SECONDS")
        ln = ln.replace("DEFAULT_MEMORY_BYTES", "ControlPlaneHttpLimits.DEFAULT_MEMORY_BYTES")
        ln = ln.replace("DEFAULT_DISK_BYTES", "ControlPlaneHttpLimits.DEFAULT_DISK_BYTES")
        ln = ln.replace("DYNAMIC_QUEUE_TIMEOUT", "ControlPlaneHttpLimits.DYNAMIC_QUEUE_TIMEOUT")
        ln = ln.replace("ScanBuild", "ControlPlaneHandlerRecords.ScanBuild")
        ln = ln.replace("ScanStart", "ControlPlaneHandlerRecords.ScanStart")
        ln = ln.replace("AuditRunReplay", "ControlPlaneHandlerRecords.AuditRunReplay")
        ln = ln.replace("DynamicTaskPayload", "ControlPlaneHandlerRecords.DynamicTaskPayload")
        ln = ln.replace("DynamicTaskReplay", "ControlPlaneHandlerRecords.DynamicTaskReplay")
        ln = ln.replace("FindingReplay", "ControlPlaneHandlerRecords.FindingReplay")
        ln = ln.replace("EntryFocusProbe", "ControlPlaneHandlerRecords.EntryFocusProbe")
        out.append(ln)
    text = "\n".join(out)
    # field -> host.field
    fields = [
        "JSON", "store", "clock", "sseHub", "artifactRegistry", "artifactUploadService", "analysis",
        "scanQueryPort", "evidenceGraphQueryPort", "coverageQueryPort", "hypothesisQueryPort",
        "findingQueryPort", "pathRunQueryPort", "providerQueryPort", "analyzerIrIngestPort",
        "scanQueryHttp", "idempotentProjects", "idempotentArtifacts", "idempotentScans",
        "idempotentAuditRuns", "idempotentDynamicTasks", "idempotentFindingReplays",
        "idempotentEntryFocusProbes", "durableIdempotency", "aiProbeTasks", "dynamicProbePlans",
        "unreachedDynamicPaths", "scanExperimentPlans", "scanExpandedProbes",
        "idempotentExperimentCardReplays", "mutationToken", "workerToken", "traceStore",
        "taskCoordinator", "traceProjectionService", "workerApi", "probePlanService",
        "providerInventoryService", "aiJobOrchestrator", "auditPipeline", "authorizer",
        "bindAddress", "retainedSandboxRelease",
    ]
    for f in fields:
        text = re.sub(rf"(?<![\w\.]){f}(?=\.)", f"host.{f}", text)
    text = text.replace("ControlPlaneServer::", "ControlPlaneWireSupport::")
    static_names = [
        "readObject", "sendJson", "sendEmpty", "sendError", "addCorsHeaders", "pathSegments",
        "optionalText", "textValue", "optionalPrompt", "requiredBoolean", "optionalBoolean",
        "positiveLong", "stringList", "requestIdempotencyKey", "requireIdempotencyKey",
        "ensureIdempotencyCapacity", "idempotencyMapKey", "payloadHash", "constantTimeEquals",
        "parseContentLength", "nonNegativeLong", "query", "decodeQuery", "readBody",
        "safeMessage", "readObjectOrEmpty", "isLocalOrigin", "requireToken", "newWorkerToken",
        "artifactMap", "entryMap", "dependencyMap", "sinkMap", "evidenceMap", "findingMap",
        "hypothesisMaps", "pathStepMap", "pathMap", "pathRunMap", "scanMap", "dynamicTaskMap",
        "chainMap", "operatorMap", "providerMap", "inventoryMap", "roleBindingMap",
        "aiJobMap", "aiJobEventMap", "auditMap", "stringEnvelope", "uploadSessionMap",
        "envelope", "prefixRefs", "simpleName", "sinkCategoryLabel", "sinkBindingKey",
        "entryBindingKey", "staticSinkSeverity", "sinkDeclaringClass", "findingReplayMap",
        "sqlExperimentCardMap", "experimentPlanMap", "auditRunMap", "requireCompletedRole",
        "dynamicBudgetForArtifact", "isActiveLifecycle", "probeState", "probeExecutionFailureFact",
        "probeFact", "probePlanHash", "persistedStringList", "hasExecutableMainClass",
        "isAuthGapFinding", "mergeProviderBundleIntoScan", "ensureProviderEvidence",
        "entryKey", "stripPrefix", "correlationIdFromPathRun", "operatorRole", "outputLanguage",
    ]
    for s in static_names:
        text = re.sub(rf"(?<![\w\.]){s}\(", f"ControlPlaneHttpSupport.{s}(", text)
    # 修复误替换的方法定义签名
    text = re.sub(r"static Map<String, Object> ControlPlaneHttpSupport\.(\w+)", r"static Map<String, Object> \1", text)
    text = re.sub(r"static List<Object> ControlPlaneHttpSupport\.(\w+)", r"static List<Object> \1", text)
    text = re.sub(r"static List<String> ControlPlaneHttpSupport\.(\w+)", r"static List<String> \1", text)
    text = re.sub(r"static String ControlPlaneHttpSupport\.(\w+)", r"static String \1", text)
    text = re.sub(r"static boolean ControlPlaneHttpSupport\.(\w+)", r"static boolean \1", text)
    text = re.sub(r"static long ControlPlaneHttpSupport\.(\w+)", r"static long \1", text)
    text = re.sub(r"Map<String, Object> ControlPlaneHttpSupport\.readObject\(", "ControlPlaneHttpSupport.readObject(", text)
    return text.splitlines()


def build_handlers_file(body_lines: list[str]) -> str:
    imports = """package com.aq.jvmsentinel.control.http;

import com.aq.jvmsentinel.control.routing.ControlPlaneRouteActions;
import com.aq.jvmsentinel.control.http.ControlPlaneHandlerRecords.*;
import com.aq.jvmsentinel.adapter.http.ScanQueryHttpSupport;
import com.aq.jvmsentinel.ai.AiJobOrchestrator;
import com.aq.jvmsentinel.ai.AuditPipelineCoordinator;
import com.aq.jvmsentinel.ai.AuthBypassFeasibility;
import com.aq.jvmsentinel.ai.tool.ControlPlaneToolDataSource;
import com.aq.jvmsentinel.ai.tool.EntryRefResolver;
import com.aq.jvmsentinel.ai.tool.ToolDataSource;
import com.aq.jvmsentinel.ai.tool.ToolExecutionContext;
import com.aq.jvmsentinel.analysis.CandidateRanker;
import com.aq.jvmsentinel.analysis.PreAnalysisResult;
import com.aq.jvmsentinel.analysis.PreAnalysisInput;
import com.aq.jvmsentinel.analysis.ArtifactMetadataReader;
import com.aq.jvmsentinel.analysis.coverage.CoverageMatrixProjector;
import com.aq.jvmsentinel.analysis.detector.DetectorContext;
import com.aq.jvmsentinel.analysis.detector.DetectorRegistry;
import com.aq.jvmsentinel.analysis.hypothesis.FindingRuntimeEnricher;
import com.aq.jvmsentinel.analysis.hypothesis.SecurityHypothesisProjector;
import com.aq.jvmsentinel.analysis.spi.ProviderBundle;
import com.aq.jvmsentinel.analysis.spi.ProviderContext;
import com.aq.jvmsentinel.analysis.spi.ProviderContribution;
import com.aq.jvmsentinel.analysis.spi.ProviderRegistry;
import com.aq.jvmsentinel.analysis.ir.EvidenceGraphProjector;
import com.aq.jvmsentinel.analysis.contrast.ContrastLedger;
import com.aq.jvmsentinel.analysis.universe.ArtifactUniverseBuilder;
import com.aq.jvmsentinel.analysis.experiment.PathDebugWireHelper;
import com.aq.jvmsentinel.analysis.experiment.PostureExperimentCompiler;
import com.aq.jvmsentinel.analysis.experiment.WorldPackPlanner;
import com.aq.jvmsentinel.analysis.pack.AnalysisPack;
import com.aq.jvmsentinel.analysis.pack.AnalysisPackRegistry;
import com.aq.jvmsentinel.application.port.AnalyzerIrIngestPort;
import com.aq.jvmsentinel.application.port.CoverageQueryPort;
import com.aq.jvmsentinel.application.port.EvidenceGraphQueryPort;
import com.aq.jvmsentinel.application.port.FindingQueryPort;
import com.aq.jvmsentinel.application.port.HypothesisQueryPort;
import com.aq.jvmsentinel.application.port.PathRunQueryPort;
import com.aq.jvmsentinel.application.port.ProviderQueryPort;
import com.aq.jvmsentinel.application.port.ScanQueryPort;
import com.aq.jvmsentinel.artifact.ArtifactRegistry;
import com.aq.jvmsentinel.artifact.ArtifactUploadService;
import com.aq.jvmsentinel.artifact.ArtifactValidationException;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.control.SseHub;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.control.persistence.PayloadSchemaGuard;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.control.service.ProbePlanService;
import com.aq.jvmsentinel.domain.coverage.CoverageMatrix;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.domain.ir.EvidenceGraph;
import com.aq.jvmsentinel.domain.ir.EvidenceGraphMerge;
import com.aq.jvmsentinel.domain.ir.IrNode;
import com.aq.jvmsentinel.domain.ir.EffectNode;
import com.aq.jvmsentinel.domain.ir.EntryNode;
import com.aq.jvmsentinel.domain.ir.GuardNode;
import com.aq.jvmsentinel.domain.pathdebug.WorldPackDependencyMode;
import com.aq.jvmsentinel.domain.pathdebug.WorldPackExecutionStage;
import com.aq.jvmsentinel.domain.universe.ArtifactUniverse;
import com.aq.jvmsentinel.event.EventContext;
import com.aq.jvmsentinel.event.EventFactory;
import com.aq.jvmsentinel.event.IdempotencyKey;
import com.aq.jvmsentinel.event.VersionedEvent;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.ArtifactType;
import com.aq.jvmsentinel.model.AuthBypassCandidate;
import com.aq.jvmsentinel.model.AuthBypassTechnique;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.aq.jvmsentinel.model.DependencyAccess;
import com.aq.jvmsentinel.model.Entrypoint;
import com.aq.jvmsentinel.model.Evidence;
import com.aq.jvmsentinel.model.ExperimentPlan;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.model.PermissionRequirement;
import com.aq.jvmsentinel.model.RunProfile;
import com.aq.jvmsentinel.model.Sink;
import com.aq.jvmsentinel.model.SqlExperimentCard;
import com.aq.jvmsentinel.model.VerificationStatus;
import com.aq.jvmsentinel.policy.DangerousActionMode;
import com.aq.jvmsentinel.policy.NetworkMode;
import com.aq.jvmsentinel.policy.PolicyValidator;
import com.aq.jvmsentinel.policy.PolicyViolationException;
import com.aq.jvmsentinel.policy.ScanPolicy;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.aq.jvmsentinel.provider.ProviderContracts.ModelInventory;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderDefinition;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderKind;
import com.aq.jvmsentinel.provider.ProviderSecretCipher;
import com.aq.jvmsentinel.security.auth.AuthContext;
import com.aq.jvmsentinel.security.auth.Authorizer;
import com.aq.jvmsentinel.security.auth.OperatorRole;
import com.aq.jvmsentinel.security.auth.Permission;
import com.aq.jvmsentinel.verification.VerifiedStatusGate;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;
import com.aq.jvmsentinel.worker.ExperimentPlanValidator;
import com.aq.jvmsentinel.worker.ExperimentShapeView;
import com.aq.jvmsentinel.worker.ProbeBudgetExplainer;
import com.aq.jvmsentinel.worker.SqlExperimentCardBuilder;
import com.aq.jvmsentinel.worker.InMemoryTaskCoordinator;
import com.aq.jvmsentinel.worker.InMemoryTraceStore;
import com.aq.jvmsentinel.worker.NetworkPolicy;
import com.aq.jvmsentinel.worker.ResourceBudget;
import com.aq.jvmsentinel.worker.TaskLifecycle;
import com.aq.jvmsentinel.worker.TaskScope;
import com.aq.jvmsentinel.worker.TaskSnapshot;
import com.aq.jvmsentinel.worker.TraceProjectionService;
import com.aq.jvmsentinel.worker.WorkerCapability;
import com.aq.jvmsentinel.worker.WorkerControlPlaneApi;
import com.aq.jvmsentinel.worker.WorkerTaskSpec;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.jar.JarFile;

/**
 * HTTP 路由处理器（从 ControlPlaneServer 提取）。按域拆分为独立 collaborator 的过渡容器。
 */
public final class ControlPlaneRouteHandlers implements ControlPlaneRouteActions {
    private final ControlPlaneHandlerHost host;

    public ControlPlaneRouteHandlers(ControlPlaneHandlerHost host) {
        this.host = host;
    }

"""
    return imports + "\n".join(body_lines) + "\n}\n"


def slim_server(lines: list[str], handler_names: list[str]) -> str:
    start = next(i for i, ln in enumerate(lines) if HANDLER_START_MARK in ln)
    end = next(i for i, ln in enumerate(lines) if ln.strip().startswith(HANDLER_END_MARK))
    kept = lines[:start]
    # add routeHandlers field before constructors end - insert after executor field
    insert_at = next(i for i, ln in enumerate(kept) if "private volatile ExecutorService executor" in ln) + 1
    kept[insert_at:insert_at] = [
        "    private final ControlPlaneRouteHandlers routeHandlers;",
        "",
    ]
    # find end of main constructor (matching braces) - use line 504
    ctor_end = next(i for i, ln in enumerate(lines) if i > 500 and ln.strip() == "}" and "pipelineReaper" in lines[i-5])
    # add routeHandlers init before last line of constructor
    for i in range(ctor_end, 330, -1):
        if lines[i].strip() == "}" and "TimeUnit.SECONDS" in lines[i-1]:
            lines.insert(i, "        this.routeHandlers = new ControlPlaneRouteHandlers(ControlPlaneHandlerHost.from(this));")
            break
    # append delegation stubs + tail (records, interfaces, preanalysis)
    tail = lines[end:]
    stubs = []
    for name in handler_names:
        stubs.append(f"    @Override public void {name}(HttpExchange exchange) throws IOException {{ routeHandlers.{name}(exchange); }}")
    # won't work for all signatures - skip auto stubs
    return "\n".join(kept) + "\n    // ... handlers delegated via routeHandlers\n" + "\n".join(tail)


def main() -> None:
    lines = read_lines()
    start = next(i for i, ln in enumerate(lines) if HANDLER_START_MARK in ln)
    end = next(i for i, ln in enumerate(lines) if ln.strip().startswith(HANDLER_END_MARK))
    body = transform_handlers(lines[start:end])
    content = build_handlers_file(body)
    HANDLERS.write_text(content, encoding="utf-8", newline="\n")
    print(f"handlers: {len(content.splitlines())} lines (raw extract, needs compile fixes)")


if __name__ == "__main__":
    main()
