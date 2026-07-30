package com.aq.jvmsentinel.control.http;

import com.aq.jvmsentinel.adapter.http.ScanQueryHttpSupport;
import com.aq.jvmsentinel.ai.AiJobOrchestrator;
import com.aq.jvmsentinel.ai.AuditPipelineCoordinator;
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
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.SseHub;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.control.service.ProbePlanService;
import com.aq.jvmsentinel.model.ExperimentPlan;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;
import com.aq.jvmsentinel.worker.InMemoryTaskCoordinator;
import com.aq.jvmsentinel.worker.InMemoryTraceStore;
import com.aq.jvmsentinel.worker.TaskSnapshot;
import com.aq.jvmsentinel.worker.TraceProjectionService;
import com.aq.jvmsentinel.control.WorkerControlPlaneApi;
import com.aq.jvmsentinel.security.auth.Authorizer;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.InetSocketAddress;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** HTTP 处理器共享依赖与可变运行时状态。 */
public final class ControlPlaneHandlerHost {
    public final ObjectMapper JSON;
    public final InetSocketAddress bindAddress;
    public final ArtifactRegistry artifactRegistry;
    public final ArtifactUploadService artifactUploadService;
    public final ControlPlaneServer.PreAnalysisServiceAdapter analysis;
    public final ControlPlaneStore store;
    public final ScanQueryPort scanQueryPort;
    public final EvidenceGraphQueryPort evidenceGraphQueryPort;
    public final CoverageQueryPort coverageQueryPort;
    public final HypothesisQueryPort hypothesisQueryPort;
    public final FindingQueryPort findingQueryPort;
    public final PathRunQueryPort pathRunQueryPort;
    public final ProviderQueryPort providerQueryPort;
    public final AnalyzerIrIngestPort analyzerIrIngestPort;
    public final ScanQueryHttpSupport scanQueryHttp;
    public final SseHub sseHub;
    public final Map<String, String> idempotentProjects;
    public final Map<String, String> idempotentArtifacts;
    public final Map<String, String> idempotentScans;
    public final Map<String, ControlPlaneHandlerRecords.AuditRunReplay> idempotentAuditRuns;
    public final Map<String, ControlPlaneHandlerRecords.DynamicTaskReplay> idempotentDynamicTasks;
    public final Map<String, ControlPlaneHandlerRecords.FindingReplay> idempotentFindingReplays;
    public final Map<String, ControlPlaneHandlerRecords.EntryFocusProbe> idempotentEntryFocusProbes;
    public final Map<String, SQLiteControlPlanePersistence.IdempotencyData> durableIdempotency;
    public final Map<String, TaskSnapshot> aiProbeTasks;
    public final Map<String, ProbePlanService.ProbePlan> dynamicProbePlans;
    public final Map<String, List<ApiDtos.PathDto>> unreachedDynamicPaths;
    public final Map<String, List<ExperimentPlan>> scanExperimentPlans;
    public final Map<String, List<ExternalArtifactTaskExecutor.ProbeTarget>> scanExpandedProbes;
    public final Map<String, ControlPlaneHandlerRecords.EntryFocusProbe> idempotentExperimentCardReplays;
    public final String mutationToken;
    public final String workerToken;
    public final InMemoryTraceStore traceStore;
    public final InMemoryTaskCoordinator taskCoordinator;
    public final TraceProjectionService traceProjectionService;
    public final WorkerControlPlaneApi workerApi;
    public final ProbePlanService probePlanService;
    public final ControlPlaneServer.ProviderInventoryService providerInventoryService;
    public final AiJobOrchestrator aiJobOrchestrator;
    public final AuditPipelineCoordinator auditPipeline;
    public volatile ControlPlaneServer.RetainedSandboxRelease retainedSandboxRelease;
    public final Clock clock;
    public final Authorizer authorizer;

    public ControlPlaneHandlerHost(
            ObjectMapper json,
            InetSocketAddress bindAddress,
            ArtifactRegistry artifactRegistry,
            ArtifactUploadService artifactUploadService,
            ControlPlaneServer.PreAnalysisServiceAdapter analysis,
            ControlPlaneStore store,
            ScanQueryPort scanQueryPort,
            EvidenceGraphQueryPort evidenceGraphQueryPort,
            CoverageQueryPort coverageQueryPort,
            HypothesisQueryPort hypothesisQueryPort,
            FindingQueryPort findingQueryPort,
            PathRunQueryPort pathRunQueryPort,
            ProviderQueryPort providerQueryPort,
            AnalyzerIrIngestPort analyzerIrIngestPort,
            ScanQueryHttpSupport scanQueryHttp,
            SseHub sseHub,
            Map<String, String> idempotentProjects,
            Map<String, String> idempotentArtifacts,
            Map<String, String> idempotentScans,
            Map<String, ControlPlaneHandlerRecords.AuditRunReplay> idempotentAuditRuns,
            Map<String, ControlPlaneHandlerRecords.DynamicTaskReplay> idempotentDynamicTasks,
            Map<String, ControlPlaneHandlerRecords.FindingReplay> idempotentFindingReplays,
            Map<String, ControlPlaneHandlerRecords.EntryFocusProbe> idempotentEntryFocusProbes,
            Map<String, SQLiteControlPlanePersistence.IdempotencyData> durableIdempotency,
            Map<String, TaskSnapshot> aiProbeTasks,
            Map<String, ProbePlanService.ProbePlan> dynamicProbePlans,
            Map<String, List<ApiDtos.PathDto>> unreachedDynamicPaths,
            Map<String, List<ExperimentPlan>> scanExperimentPlans,
            Map<String, List<ExternalArtifactTaskExecutor.ProbeTarget>> scanExpandedProbes,
            Map<String, ControlPlaneHandlerRecords.EntryFocusProbe> idempotentExperimentCardReplays,
            String mutationToken,
            String workerToken,
            InMemoryTraceStore traceStore,
            InMemoryTaskCoordinator taskCoordinator,
            TraceProjectionService traceProjectionService,
            WorkerControlPlaneApi workerApi,
            ProbePlanService probePlanService,
            ControlPlaneServer.ProviderInventoryService providerInventoryService,
            AiJobOrchestrator aiJobOrchestrator,
            AuditPipelineCoordinator auditPipeline,
            ControlPlaneServer.RetainedSandboxRelease retainedSandboxRelease,
            Clock clock,
            Authorizer authorizer) {
        this.JSON = json;
        this.bindAddress = bindAddress;
        this.artifactRegistry = artifactRegistry;
        this.artifactUploadService = artifactUploadService;
        this.analysis = analysis;
        this.store = store;
        this.scanQueryPort = scanQueryPort;
        this.evidenceGraphQueryPort = evidenceGraphQueryPort;
        this.coverageQueryPort = coverageQueryPort;
        this.hypothesisQueryPort = hypothesisQueryPort;
        this.findingQueryPort = findingQueryPort;
        this.pathRunQueryPort = pathRunQueryPort;
        this.providerQueryPort = providerQueryPort;
        this.analyzerIrIngestPort = analyzerIrIngestPort;
        this.scanQueryHttp = scanQueryHttp;
        this.sseHub = sseHub;
        this.idempotentProjects = idempotentProjects;
        this.idempotentArtifacts = idempotentArtifacts;
        this.idempotentScans = idempotentScans;
        this.idempotentAuditRuns = idempotentAuditRuns;
        this.idempotentDynamicTasks = idempotentDynamicTasks;
        this.idempotentFindingReplays = idempotentFindingReplays;
        this.idempotentEntryFocusProbes = idempotentEntryFocusProbes;
        this.durableIdempotency = durableIdempotency;
        this.aiProbeTasks = aiProbeTasks;
        this.dynamicProbePlans = dynamicProbePlans;
        this.unreachedDynamicPaths = unreachedDynamicPaths;
        this.scanExperimentPlans = scanExperimentPlans;
        this.scanExpandedProbes = scanExpandedProbes;
        this.idempotentExperimentCardReplays = idempotentExperimentCardReplays;
        this.mutationToken = mutationToken;
        this.workerToken = workerToken;
        this.traceStore = traceStore;
        this.taskCoordinator = taskCoordinator;
        this.traceProjectionService = traceProjectionService;
        this.workerApi = workerApi;
        this.probePlanService = probePlanService;
        this.providerInventoryService = providerInventoryService;
        this.aiJobOrchestrator = aiJobOrchestrator;
        this.auditPipeline = auditPipeline;
        this.retainedSandboxRelease = retainedSandboxRelease;
        this.clock = clock;
        this.authorizer = authorizer;
    }
}
