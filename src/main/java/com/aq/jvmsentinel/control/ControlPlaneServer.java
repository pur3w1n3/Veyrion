package com.aq.jvmsentinel.control;

import com.aq.jvmsentinel.control.http.ControlPlaneHandlerHost;
import com.aq.jvmsentinel.control.http.ControlPlaneRouteHandlers;
import com.aq.jvmsentinel.control.http.ControlPlaneHttpSupport;
import com.aq.jvmsentinel.control.http.ControlPlaneHttpLimits;
import com.aq.jvmsentinel.control.http.ControlPlaneHandlerRecords;
import com.aq.jvmsentinel.control.routing.ControlPlaneRouteActions;
import com.aq.jvmsentinel.control.routing.RouteTable;
import com.aq.jvmsentinel.adapter.control.DelegatingCoverageQueryAdapter;
import com.aq.jvmsentinel.adapter.control.DelegatingEvidenceGraphQueryAdapter;
import com.aq.jvmsentinel.adapter.control.DelegatingPathRunQueryAdapter;
import com.aq.jvmsentinel.adapter.control.StoreAnalyzerIrIngestAdapter;
import com.aq.jvmsentinel.adapter.control.StoreFindingQueryAdapter;
import com.aq.jvmsentinel.adapter.control.StoreHypothesisQueryAdapter;
import com.aq.jvmsentinel.adapter.control.StoreProviderQueryAdapter;
import com.aq.jvmsentinel.adapter.control.StoreScanQueryAdapter;
import com.aq.jvmsentinel.adapter.http.ScanQueryHttpSupport;
import com.aq.jvmsentinel.application.port.AnalyzerIrIngestPort;
import com.aq.jvmsentinel.application.port.CoverageQueryPort;
import com.aq.jvmsentinel.application.port.EvidenceGraphQueryPort;
import com.aq.jvmsentinel.application.port.FindingQueryPort;
import com.aq.jvmsentinel.application.port.HypothesisQueryPort;
import com.aq.jvmsentinel.application.port.PathRunQueryPort;
import com.aq.jvmsentinel.application.port.ProviderQueryPort;
import com.aq.jvmsentinel.application.port.ScanQueryPort;

import com.aq.jvmsentinel.analysis.experiment.PathDebugWireHelper;
import com.aq.jvmsentinel.analysis.experiment.PostureExperimentCompiler;
import com.aq.jvmsentinel.domain.pathdebug.WorldPackDependencyMode;
import com.aq.jvmsentinel.domain.pathdebug.WorldPackExecutionStage;
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
import com.aq.jvmsentinel.domain.ir.EffectNode;
import com.aq.jvmsentinel.domain.ir.EntryNode;
import com.aq.jvmsentinel.domain.ir.GuardNode;
import com.aq.jvmsentinel.analysis.contrast.ContrastLedger;
import com.aq.jvmsentinel.analysis.universe.ArtifactUniverseBuilder;
import com.aq.jvmsentinel.domain.coverage.CoverageMatrix;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.domain.ir.EvidenceGraph;
import com.aq.jvmsentinel.domain.ir.EvidenceGraphMerge;
import com.aq.jvmsentinel.domain.ir.IrNode;
import com.aq.jvmsentinel.domain.universe.ArtifactUniverse;
import com.aq.jvmsentinel.analysis.identity.SyntheticIdentityService;
import com.aq.jvmsentinel.analysis.entry.NonHttpEntryProtocol;
import com.aq.jvmsentinel.analysis.pack.AnalysisPack;
import com.aq.jvmsentinel.analysis.pack.AnalysisPackRegistry;
import com.aq.jvmsentinel.model.ArtifactType;
import com.aq.jvmsentinel.model.AuthBypassCandidate;
import com.aq.jvmsentinel.model.AuthBypassTechnique;
import com.aq.jvmsentinel.model.ExperimentPlan;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.model.RunProfile;
import com.aq.jvmsentinel.model.SqlExperimentCard;
import com.aq.jvmsentinel.verification.VerifiedStatusGate;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;
import com.aq.jvmsentinel.worker.ExperimentPlanValidator;
import com.aq.jvmsentinel.worker.ExperimentShapeView;
import com.aq.jvmsentinel.worker.ProbeBudgetExplainer;
import com.aq.jvmsentinel.worker.SqlExperimentCardBuilder;
import com.aq.jvmsentinel.ai.AiJobOrchestrator;
import com.aq.jvmsentinel.ai.AuditPipelineCoordinator;
import com.aq.jvmsentinel.ai.AuthBypassFeasibility;
import com.aq.jvmsentinel.ai.tool.ControlPlaneToolDataSource;
import com.aq.jvmsentinel.ai.tool.EntryRefResolver;
import com.aq.jvmsentinel.ai.tool.ToolDataSource;
import com.aq.jvmsentinel.ai.tool.ToolExecutionContext;
import com.aq.jvmsentinel.artifact.ArtifactRegistry;
import com.aq.jvmsentinel.artifact.ArtifactUploadService;
import com.aq.jvmsentinel.artifact.ArtifactValidationException;
import com.aq.jvmsentinel.event.EventContext;
import com.aq.jvmsentinel.event.EventFactory;
import com.aq.jvmsentinel.event.IdempotencyKey;
import com.aq.jvmsentinel.event.VersionedEvent;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.aq.jvmsentinel.model.DependencyAccess;
import com.aq.jvmsentinel.model.Entrypoint;
import com.aq.jvmsentinel.model.Evidence;
import com.aq.jvmsentinel.model.PermissionRequirement;
import com.aq.jvmsentinel.model.Sink;
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
import com.aq.jvmsentinel.provider.ProviderModelInventoryClient;
import com.aq.jvmsentinel.provider.chat.ChatTransport;
import com.aq.jvmsentinel.provider.chat.ProviderChatTransport;
import com.aq.jvmsentinel.security.ProviderSecretCipher;
import com.aq.jvmsentinel.security.auth.AuthContext;
import com.aq.jvmsentinel.security.auth.Authorizer;
import com.aq.jvmsentinel.security.auth.OperatorRole;
import com.aq.jvmsentinel.security.auth.Permission;
import com.aq.jvmsentinel.control.persistence.PayloadSchemaGuard;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.control.service.ProbePlanService;
import com.aq.jvmsentinel.worker.InMemoryTaskCoordinator;
import com.aq.jvmsentinel.worker.InMemoryTraceStore;
import com.aq.jvmsentinel.analysis.experiment.WorldPackPlanner;
import com.aq.jvmsentinel.worker.NetworkPolicy;
import com.aq.jvmsentinel.worker.ResourceBudget;
import com.aq.jvmsentinel.worker.TaskLifecycle;
import com.aq.jvmsentinel.worker.TaskScope;
import com.aq.jvmsentinel.worker.TaskSnapshot;
import com.aq.jvmsentinel.worker.TraceProjectionService;
import com.aq.jvmsentinel.worker.WorkerCapability;
import com.aq.jvmsentinel.worker.WorkerTaskSpec;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.JarFile;

/**
 * 本地 MVP 的无额外 HTTP 框架 Java 17 Control Plane。
 *
 * <p>仅暴露元数据分析，并通过策略校验的沙箱 Worker 调度制品执行；
 * 从不在 control-plane 进程内启动被导入的 JAR/WAR/CLASS。
 * 默认绑定 loopback，所有变更类路由需要配置的本地授权 token。</p>
 */
public final class ControlPlaneServer implements AutoCloseable, ControlPlaneRouteActions {
    private static final ObjectMapper JSON = new ObjectMapper();
    public static final String API_PREFIX = ControlPlaneHttpLimits.API_PREFIX;
    public static final String DEFAULT_TOKEN = "local-demo";
    /** 无 Worker 认领且长期 QUEUED 的动态任务由 reaper 标记为 DYNAMIC_DISABLED。 */
    static final Duration DYNAMIC_QUEUE_TIMEOUT = ControlPlaneHttpLimits.DYNAMIC_QUEUE_TIMEOUT;
    
    private final InetSocketAddress bindAddress;
    private final ArtifactRegistry artifactRegistry;
    private final ArtifactUploadService artifactUploadService;
    private final PreAnalysisServiceAdapter analysis = new PreAnalysisServiceAdapter();
    private final ControlPlaneStore store;
    /** P1-08 查询端口 — 新读路径优先于继续膨胀 RouteTable 逻辑。 */
    private final ScanQueryPort scanQueryPort;
    private final EvidenceGraphQueryPort evidenceGraphQueryPort;
    private final CoverageQueryPort coverageQueryPort;
    private final HypothesisQueryPort hypothesisQueryPort;
    private final FindingQueryPort findingQueryPort;
    private final PathRunQueryPort pathRunQueryPort;
    private final ProviderQueryPort providerQueryPort;
    private final AnalyzerIrIngestPort analyzerIrIngestPort;
    private final ScanQueryHttpSupport scanQueryHttp;
    private final SseHub sseHub;
    private final Map<String, String> idempotentProjects = new ConcurrentHashMap<>();
    private final Map<String, String> idempotentArtifacts = new ConcurrentHashMap<>();
    private final Map<String, String> idempotentScans = new ConcurrentHashMap<>();
    private final Map<String, ControlPlaneHandlerRecords.AuditRunReplay> idempotentAuditRuns = new ConcurrentHashMap<>();
    private final Map<String, ControlPlaneHandlerRecords.DynamicTaskReplay> idempotentDynamicTasks = new ConcurrentHashMap<>();
    private final Map<String, ControlPlaneHandlerRecords.FindingReplay> idempotentFindingReplays = new ConcurrentHashMap<>();
    private final Map<String, ControlPlaneHandlerRecords.EntryFocusProbe> idempotentEntryFocusProbes = new ConcurrentHashMap<>();
    /** 持久化幂等索引；遗留 typed map 仍为进程内快速路径。 */
    private final Map<String, SQLiteControlPlanePersistence.IdempotencyData> durableIdempotency = new ConcurrentHashMap<>();
    /** 每个 AI job 一个服务端持有的 probe task；模型重试不得无界 fan-out task。 */
    private final Map<String, TaskSnapshot> aiProbeTasks = new ConcurrentHashMap<>();
    /** 服务端生成的 probe plan 按 task id 索引；模型输入永不变为命令。 */
    private final Map<String, ProbePlanService.ProbePlan> dynamicProbePlans = new ConcurrentHashMap<>();
    /** scan 作用域 UNREACHED 动态 path 占位，用于超出 probe 预算的 entry。 */
    private final Map<String, List<ApiDtos.PathDto>> unreachedDynamicPaths = new ConcurrentHashMap<>();
    /** 来自 plan_propose 的服务端门禁 experiment plan，按 scanId 索引（进程内 MVP）。 */
    private final Map<String, List<ExperimentPlan>> scanExperimentPlans = new ConcurrentHashMap<>();
    /** 每个 scan 最近一次展开的 probe target，用于 T2+T3 预算说明。 */
    private final Map<String, List<ExternalArtifactTaskExecutor.ProbeTarget>> scanExpandedProbes =
            new ConcurrentHashMap<>();
    /** 幂等 D3 experiment-card replay。 */
    private final Map<String, ControlPlaneHandlerRecords.EntryFocusProbe> idempotentExperimentCardReplays = new ConcurrentHashMap<>();
    private final String mutationToken;
    private final String workerToken;
    private final InMemoryTraceStore traceStore;
    private final InMemoryTaskCoordinator taskCoordinator;
    private final TraceProjectionService traceProjectionService;
    private final WorkerControlPlaneApi workerApi;
    private final ProbePlanService probePlanService;
    private final ProviderInventoryService providerInventoryService;
    private final AiJobOrchestrator aiJobOrchestrator;
    private final AuditPipelineCoordinator auditPipeline;
    private volatile RetainedSandboxRelease retainedSandboxRelease = (projectId, artifactDigest, scanId) -> { };
    private final Clock clock;
    private final Authorizer authorizer = new Authorizer();
    private final ScheduledExecutorService pipelineReaper = Executors.newSingleThreadScheduledExecutor(runnable -> {
        Thread thread = new Thread(runnable, "audit-pipeline-reaper");
        thread.setDaemon(true);
        return thread;
    });
    private volatile HttpServer server;
    private volatile ExecutorService executor;
    private final ControlPlaneHandlerHost handlerHost;
    private final ControlPlaneRouteHandlers routeHandlers;

    public ControlPlaneServer(Path allowedRoot) {
        this(new InetSocketAddress("127.0.0.1", 0), new ArtifactRegistry(allowedRoot),
                DEFAULT_TOKEN, Clock.systemUTC(), new ControlPlaneStore(), new SseHub());
    }

    /** 显式端口的 loopback 构造函数；port 0 由 OS 分配空闲端口。 */
    public ControlPlaneServer(Path allowedRoot, int port) {
        this(new InetSocketAddress("127.0.0.1", port), new ArtifactRegistry(allowedRoot),
                DEFAULT_TOKEN, Clock.systemUTC(), new ControlPlaneStore(), new SseHub());
    }

    /** 集成测试与本地桌面启动器使用的 loopback 构造函数。 */
    public ControlPlaneServer(Path allowedRoot, int port, String mutationToken) {
        this(new InetSocketAddress("127.0.0.1", port), new ArtifactRegistry(allowedRoot),
                mutationToken == null || mutationToken.isBlank() ? DEFAULT_TOKEN : mutationToken,
                Clock.systemUTC(), new ControlPlaneStore(), new SseHub());
    }

    /** 显式控制 SQLite 持久化的 loopback 构造函数。 */
    public ControlPlaneServer(Path allowedRoot, int port, String mutationToken, Path databasePath) {
        this(new InetSocketAddress("127.0.0.1", port), new ArtifactRegistry(allowedRoot),
                mutationToken == null || mutationToken.isBlank() ? DEFAULT_TOKEN : mutationToken,
                Clock.systemUTC(), ControlPlaneStore.sqlite(databasePath, allowedRoot), new SseHub());
    }

    /** 受控 inventory 注入，供 HTTP 验收测试；生产使用安全 client。 */
    public ControlPlaneServer(Path allowedRoot, int port, String mutationToken, Path databasePath,
                              ProviderInventoryService providerInventoryService) {
        this(new InetSocketAddress("127.0.0.1", port), new ArtifactRegistry(allowedRoot),
                mutationToken == null || mutationToken.isBlank() ? DEFAULT_TOKEN : mutationToken,
                Clock.systemUTC(), ControlPlaneStore.sqlite(databasePath, allowedRoot), new SseHub(),
                providerInventoryService, new ProviderChatTransport());
    }

    /** 受控 provider 注入，供验收测试；生产构造函数保留固定 transport。 */
    public ControlPlaneServer(Path allowedRoot, int port, String mutationToken, Path databasePath,
                              ProviderInventoryService providerInventoryService,
                              ChatTransport chatTransport) {
        this(new InetSocketAddress("127.0.0.1", port), new ArtifactRegistry(allowedRoot),
                mutationToken == null || mutationToken.isBlank() ? DEFAULT_TOKEN : mutationToken,
                Clock.systemUTC(), ControlPlaneStore.sqlite(databasePath, allowedRoot), new SseHub(),
                providerInventoryService, chatTransport);
    }

    public ControlPlaneServer(InetSocketAddress bindAddress, Path allowedRoot) {
        this(bindAddress, new ArtifactRegistry(allowedRoot), DEFAULT_TOKEN, Clock.systemUTC(),
                new ControlPlaneStore(), new SseHub());
    }

    public ControlPlaneServer(InetSocketAddress bindAddress, Path allowedRoot, String mutationToken) {
        this(bindAddress, new ArtifactRegistry(allowedRoot),
                mutationToken == null || mutationToken.isBlank() ? DEFAULT_TOKEN : mutationToken,
                Clock.systemUTC(), new ControlPlaneStore(), new SseHub());
    }

    public ControlPlaneServer(String host, int port, Path allowedRoot, String mutationToken) {
        this(new InetSocketAddress(Objects.requireNonNull(host, "host"), port),
                new ArtifactRegistry(allowedRoot), mutationToken == null || mutationToken.isBlank() ? DEFAULT_TOKEN : mutationToken, Clock.systemUTC(),
                new ControlPlaneStore(), new SseHub());
    }

    public ControlPlaneServer(String host, int port, Path allowedRoot, String mutationToken,
                              Path databasePath) {
        this(new InetSocketAddress(Objects.requireNonNull(host, "host"), port),
                new ArtifactRegistry(allowedRoot),
                mutationToken == null || mutationToken.isBlank() ? DEFAULT_TOKEN : mutationToken,
                Clock.systemUTC(), ControlPlaneStore.sqlite(databasePath, allowedRoot), new SseHub());
    }

    public ControlPlaneServer(InetSocketAddress bindAddress, ArtifactRegistry artifactRegistry,
                              String mutationToken, Clock clock, ControlPlaneStore store,
                              SseHub sseHub) {
        this(bindAddress, artifactRegistry, mutationToken, clock, store, sseHub,
                new ProviderModelInventoryClient()::fetch, new ProviderChatTransport());
    }

    public ControlPlaneServer(InetSocketAddress bindAddress, ArtifactRegistry artifactRegistry,
                              String mutationToken, Clock clock, ControlPlaneStore store,
                              SseHub sseHub, ProviderInventoryService providerInventoryService) {
        this(bindAddress, artifactRegistry, mutationToken, clock, store, sseHub,
                providerInventoryService, new ProviderChatTransport());
    }

    public ControlPlaneServer(InetSocketAddress bindAddress, ArtifactRegistry artifactRegistry,
                              String mutationToken, Clock clock, ControlPlaneStore store,
                              SseHub sseHub, ProviderInventoryService providerInventoryService,
                              ChatTransport chatTransport) {
        this.bindAddress = Objects.requireNonNull(bindAddress, "bindAddress");
        this.artifactRegistry = Objects.requireNonNull(artifactRegistry, "artifactRegistry");
        this.mutationToken = ControlPlaneHttpSupport.requireToken(mutationToken);
        this.clock = Objects.requireNonNull(clock, "clock");
        this.store = Objects.requireNonNull(store, "store");
        this.analyzerIrIngestPort = new StoreAnalyzerIrIngestAdapter(this.store);
        this.hypothesisQueryPort = new StoreHypothesisQueryAdapter(this.store);
        this.scanQueryPort = new StoreScanQueryAdapter(this.store, this::scanViewForPort);
        this.coverageQueryPort = new DelegatingCoverageQueryAdapter(this.store, this::coverageMatrixForScan);
        this.evidenceGraphQueryPort = new DelegatingEvidenceGraphQueryAdapter(
                this.store, this::projectEvidenceGraphBase, this.analyzerIrIngestPort);
        this.findingQueryPort = new StoreFindingQueryAdapter(this.store, this::enrichedFindingMap);
        this.pathRunQueryPort = new DelegatingPathRunQueryAdapter(this.store, this::pathRunViewsForPort);
        this.providerQueryPort = new StoreProviderQueryAdapter(this.store, ControlPlaneRouteHandlers::providerMap);
        this.scanQueryHttp = new ScanQueryHttpSupport(
                this.evidenceGraphQueryPort, this.coverageQueryPort, this.hypothesisQueryPort);
        this.sseHub = Objects.requireNonNull(sseHub, "sseHub");
        this.sseHub.attachPersistence(this.store.loadSseEvents(), this.store::persistSseEvent);
        this.artifactUploadService = new ArtifactUploadService(this.artifactRegistry, this.clock,
                256, 2L * 1024 * 1024 * 1024, java.time.Duration.ofHours(1),
                this.store.artifactUploadPersistence());
        this.workerToken = ControlPlaneHttpSupport.newWorkerToken(this.mutationToken);
        var workerState = this.store.loadWorkerState();
        this.traceStore = new InMemoryTraceStore(this.clock, workerState.traces(), this.store::persistWorkerTrace);
        this.taskCoordinator = new InMemoryTaskCoordinator(this.clock, this.traceStore, workerState.tasks(), this.store::persistWorkerTask);
        this.traceProjectionService = new TraceProjectionService(this.traceStore);
        this.traceProjectionService.bindPosturePlanResolver(store::postureExperiment);
        this.workerApi = new WorkerControlPlaneApi(this.workerToken, this.clock, this.store, this.sseHub,
                this.traceStore, this.taskCoordinator, this.traceProjectionService);
        this.probePlanService = new ProbePlanService(this.store,
                (projectId, scanId) -> this.workerApi.snapshots(projectId, scanId));
        for (var record : this.store.loadIdempotency()) {
            durableIdempotency.put(ControlPlaneHttpSupport.idempotencyMapKey(record.scope(), record.key()), record);
        }
        this.providerInventoryService = Objects.requireNonNull(
                providerInventoryService, "providerInventoryService");
        if ("SQLITE".equals(this.store.persistenceMode())) {
            this.store.bootstrapOperator(this.mutationToken, Instant.now(this.clock).toString());
        }
        ProviderRegistry.ensureDefaults();
        this.aiJobOrchestrator = new AiJobOrchestrator(this.store,
                Objects.requireNonNull(chatTransport, "chatTransport"), this.clock,
                this.traceProjectionService::evidenceForScan,
                (scanId, scope, principalId, jobId, toolCallId, entrypointRef, candidateInputs,
                 maxRequests, techniqueId, authorizationHeader, bladeAuthHeader, experimentPlanId) ->
                        requestSandboxProbe(scanId, scope, principalId, jobId, toolCallId,
                                entrypointRef, candidateInputs, maxRequests, techniqueId,
                                authorizationHeader, bladeAuthHeader, experimentPlanId),
                this::mergedPathRunsForScan,
                this::acceptExperimentPlan);
        this.auditPipeline = new AuditPipelineCoordinator(new AuditPipelineCoordinator.Actions() {
            @Override
            public String createRoleJob(String projectId, String scanId, AgentRole role,
                                        AiOutputLanguage language, String actorId) {
                var job = store.createAiJob(projectId, role, scanId, language, true, actorId,
                        Instant.now(clock).toString());
                store.auditChange(projectId, actorId, "audit-pipeline.enqueue-role", "ai-job",
                        job.aiJobId(), "{\"role\":\"" + role.name() + "\",\"scanId\":\"" + scanId + "\"}",
                        Instant.now(clock).toString());
                return job.aiJobId();
            }

            @Override
            public void submitRoleJob(String jobId, String actorId) {
                aiJobOrchestrator.submit(store.requireAiJob(jobId), actorId);
            }

            @Override
            public String enqueueDynamic(String scanId, String actorId) {
                return enqueueDynamicForPipeline(scanId, actorId).scope().taskId();
            }

            @Override
            public boolean hasRunningDynamicTask(String scanId) {
                ControlPlaneStore.ScanRecord scan = store.requireScan(scanId);
                return workerApi.hasActiveDynamicTask(scan.dto().projectId(), scanId);
            }

            @Override
            public void replaceCursor(AuditPipelineCoordinator.Cursor cursor, boolean armed, String stopReason) {
                store.persistPipelineRun(pipelineRunData(cursor, armed, stopReason));
            }

            @Override
            public boolean compareAndAdvance(AuditPipelineCoordinator.Cursor expected,
                                             AuditPipelineCoordinator.Cursor next,
                                             boolean armed, String stopReason) {
                return store.compareAndAdvancePipelineRun(
                        pipelineRunData(expected, true, null),
                        pipelineRunData(next, armed, stopReason));
            }

            @Override
            public String jobStatus(String jobId) {
                try {
                    return store.requireAiJob(jobId).status();
                } catch (ControlPlaneStore.MissingRecordException | IllegalStateException missing) {
                    return null;
                }
            }

            @Override
            public String jobStopReason(String jobId) {
                try {
                    return store.requireAiJob(jobId).stopReason();
                } catch (ControlPlaneStore.MissingRecordException | IllegalStateException missing) {
                    return null;
                }
            }

            @Override
            public String taskLifecycle(String projectId, String scanId, String taskId) {
                for (TaskSnapshot snapshot : workerApi.snapshots(projectId, scanId)) {
                    if (taskId.equals(snapshot.scope().taskId())) {
                        return snapshot.lifecycle().name();
                    }
                }
                return null;
            }

            @Override
            public void releaseRetainedSandbox(AuditPipelineCoordinator.Arm arm) {
                releaseRetainedSandboxForScan(arm.scanId());
            }

            @Override
            public boolean hasDynamicAuthEvidence(String scanId) {
                try {
                    ControlPlaneStore.ScanRecord scan = store.requireScan(scanId);
                    List<ApiDtos.PathRunDto> runs = mergedPathRunsForScan(
                            scan.dto().projectId(), scan.dto().artifactDigest(), scanId);
                    return AuthBypassFeasibility.hasConfirmableDynamicAuthEvidence(runs);
                } catch (RuntimeException missing) {
                    return false;
                }
            }

            @Override
            public void recomputeDetectorsAfterObservation(String scanId) {
                store.recomputeDetectorsAfterObservation(scanId);
            }

            @Override
            public boolean hasPendingObservationLoopWork(String scanId) {
                return store.hasPendingObservationLoopWork(scanId);
            }

            @Override
            public int observationLoopMax() {
                return AuditPipelineCoordinator.resolveObservationLoopMax();
            }
        });
        this.aiJobOrchestrator.setTerminalListener(auditPipeline::onAiJobFinished);
        this.workerApi.setTerminalListener(auditPipeline::onDynamicTaskFinished);
        reclaimStaleDynamicTasks(DYNAMIC_QUEUE_TIMEOUT);
        recoverAuditPipelines();
        this.pipelineReaper.scheduleAtFixedRate(
                () -> {
                    try {
                        reclaimStaleDynamicTasks(DYNAMIC_QUEUE_TIMEOUT);
                    } catch (RuntimeException ignored) {
                        // Reaper 故障不得停止 control plane。
                    }
                },
                DYNAMIC_QUEUE_TIMEOUT.toSeconds(),
                Math.max(30L, DYNAMIC_QUEUE_TIMEOUT.toSeconds() / 2),
                TimeUnit.SECONDS);
        this.handlerHost = new ControlPlaneHandlerHost(
                JSON, bindAddress, artifactRegistry, artifactUploadService, analysis, store,
                scanQueryPort, evidenceGraphQueryPort, coverageQueryPort, hypothesisQueryPort,
                findingQueryPort, pathRunQueryPort, providerQueryPort, analyzerIrIngestPort,
                scanQueryHttp, sseHub, idempotentProjects, idempotentArtifacts, idempotentScans,
                idempotentAuditRuns, idempotentDynamicTasks, idempotentFindingReplays,
                idempotentEntryFocusProbes, durableIdempotency, aiProbeTasks, dynamicProbePlans,
                unreachedDynamicPaths, scanExperimentPlans, scanExpandedProbes,
                idempotentExperimentCardReplays, mutationToken, workerToken, traceStore,
                taskCoordinator, traceProjectionService, workerApi, probePlanService,
                providerInventoryService, aiJobOrchestrator, auditPipeline, retainedSandboxRelease,
                clock, authorizer);
        this.routeHandlers = new ControlPlaneRouteHandlers(handlerHost);
        restoreProbePlans();
        restoreExperimentPlans();
    }

    /**
     * 对无 Worker 的 QUEUED 动态 task 做 fail-closed 回收。验收测试可见。
     */
    public int reclaimStaleDynamicTasks(Duration maxQueuedAge) {
        List<TaskSnapshot> failed = workerApi.failStaleQueuedTasks(maxQueuedAge, Instant.now(clock));
        for (TaskSnapshot snapshot : failed) {
            store.auditChange(snapshot.scope().projectId(), "local-admin",
                    "audit-pipeline.dynamic-disabled", "worker-task", snapshot.scope().taskId(),
                    "{\"reason\":\"WORKER_UNAVAILABLE\",\"failureCode\":\"WORKER_UNAVAILABLE\","
                            + "\"scanId\":\"" + snapshot.scope().scanId() + "\"}",
                    Instant.now(clock).toString());
        }
        return failed.size();
    }

    private SQLiteControlPlanePersistence.PipelineRunData pipelineRunData(
            AuditPipelineCoordinator.Cursor cursor, boolean armed, String stopReason) {
        AuditPipelineCoordinator.Arm arm = cursor.arm();
        return new SQLiteControlPlanePersistence.PipelineRunData(
                arm.scanId(), arm.projectId(), arm.actorId(), arm.outputLanguage().name(),
                armed, cursor.stage().name(), Instant.now(clock).toString(),
                arm.pipelineRunId(), cursor.stageAttemptId(),
                cursor.expectedJobId(), cursor.expectedTaskId(), stopReason);
    }

    private void recoverAuditPipelines() {
        for (SQLiteControlPlanePersistence.PipelineRunData run : store.loadPipelineRuns()) {
            if (!run.armed()) {
                continue;
            }
            ControlPlaneStore.ScanRecord scan = store.scan(run.scanId());
            if (scan == null || !scan.dto().projectId().equals(run.projectId())) {
                throw new SQLiteControlPlanePersistence.PersistenceException(
                        "pipeline run scope does not match a persistent scan");
            }
            if (!run.hasStageIdentity()) {
                SQLiteControlPlanePersistence.PipelineRunData stopped =
                        new SQLiteControlPlanePersistence.PipelineRunData(
                                run.scanId(), run.projectId(), run.actorId(), run.outputLanguage(),
                                false, run.nextStage(), Instant.now(clock).toString(),
                                run.pipelineRunId(), run.stageAttemptId(),
                                run.expectedJobId(), run.expectedTaskId(),
                                "LEGACY_ARMED_WITHOUT_STAGE_IDENTITY");
                store.persistPipelineRun(stopped);
                store.auditChange(run.projectId(), run.actorId(), "audit-pipeline.fail-closed", "scan",
                        run.scanId(), "{\"reason\":\"LEGACY_ARMED_WITHOUT_STAGE_IDENTITY\"}",
                        Instant.now(clock).toString());
                continue;
            }
            AiOutputLanguage language;
            try {
                language = AiOutputLanguage.valueOf(run.outputLanguage());
            } catch (IllegalArgumentException invalid) {
                throw new SQLiteControlPlanePersistence.PersistenceException(
                        "pipeline run output language is invalid", invalid);
            }
            AuditPipelineCoordinator.PipelineStage stage;
            try {
                stage = AuditPipelineCoordinator.PipelineStage.valueOf(run.nextStage());
            } catch (IllegalArgumentException invalid) {
                SQLiteControlPlanePersistence.PipelineRunData stopped =
                        new SQLiteControlPlanePersistence.PipelineRunData(
                                run.scanId(), run.projectId(), run.actorId(), run.outputLanguage(),
                                false, run.nextStage(), Instant.now(clock).toString(),
                                run.pipelineRunId(), run.stageAttemptId(),
                                run.expectedJobId(), run.expectedTaskId(),
                                "INVALID_PERSISTED_STAGE");
                store.persistPipelineRun(stopped);
                store.auditChange(run.projectId(), run.actorId(), "audit-pipeline.fail-closed", "scan",
                        run.scanId(), "{\"reason\":\"INVALID_PERSISTED_STAGE\"}",
                        Instant.now(clock).toString());
                continue;
            }
            AuditPipelineCoordinator.Arm arm = new AuditPipelineCoordinator.Arm(
                    run.scanId(), run.projectId(), run.actorId(), language, run.pipelineRunId());
            AuditPipelineCoordinator.Cursor cursor = new AuditPipelineCoordinator.Cursor(
                    arm, stage, run.stageAttemptId(), run.expectedJobId(), run.expectedTaskId());
            auditPipeline.resume(cursor);
            store.auditChange(run.projectId(), run.actorId(), "audit-pipeline.recover", "scan",
                    run.scanId(), "{\"stage\":\"" + stage.name()
                            + "\",\"pipelineRunId\":\"" + run.pipelineRunId()
                            + "\",\"stageAttemptId\":\"" + run.stageAttemptId() + "\"}",
                    Instant.now(clock).toString());
        }
    }

    /** 开始监听；多次调用 start 幂等。 */
    public synchronized ControlPlaneServer start() throws IOException {
        if (server != null) return this;
        HttpServer created = HttpServer.create(bindAddress, 64);
        created.createContext(API_PREFIX, new ApiHandler());
        created.createContext(WorkerControlPlaneApi.PREFIX, workerApi);
        AtomicInteger threadId = new AtomicInteger();
        ThreadFactory threads = runnable -> {
            Thread thread = new Thread(runnable, "jvm-sentinel-control-" + threadId.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
        ExecutorService pool = Executors.newFixedThreadPool(32, threads);
        created.setExecutor(pool);
        this.executor = pool;
        this.server = created;
        created.start();
        return this;
    }

    public synchronized void stop(int delaySeconds) {
        HttpServer current = server;
        server = null;
        if (current != null) current.stop(Math.max(0, delaySeconds));
        sseHub.close();
        pipelineReaper.shutdownNow();
        ExecutorService pool = executor;
        executor = null;
        if (pool != null) pool.shutdownNow();
        aiProbeTasks.clear();
        dynamicProbePlans.clear();
        idempotentFindingReplays.clear();
        idempotentEntryFocusProbes.clear();
        idempotentExperimentCardReplays.clear();
        scanExperimentPlans.clear();
        scanExpandedProbes.clear();
        aiJobOrchestrator.close();
    }

    public void stop() { stop(0); }

    @Override public void close() { stop(); }

    public InetSocketAddress address() {
        HttpServer current = server;
        return current == null ? bindAddress : current.getAddress();
    }

    public URI baseUri() {
        InetSocketAddress address = address();
        String host = address.getHostString();
        if (host.contains(":")) host = "[" + host + "]";
        return URI.create("http://" + host + ":" + address.getPort() + API_PREFIX);
    }

    public String mutationToken() { return mutationToken; }
    /** 内部 Worker 合约的进程内凭据；GUI 路由永不接受。 */
    public String workerToken() { return workerToken; }

    /**
     * 来自同机 trusted Docker worker 的可选 hook。TRIAGE 完成或 audit pipeline
     * 放弃仍可能持有 retained deny-all sandbox 的 scan 时调用。
     */
    @FunctionalInterface
    public interface RetainedSandboxRelease {
        void release(String projectId, String artifactDigest, String scanId);
    }

    public void setRetainedSandboxRelease(RetainedSandboxRelease release) {
        this.retainedSandboxRelease = release == null
                ? (projectId, artifactDigest, scanId) -> { }
                : release;
    }

    private void releaseRetainedSandboxForScan(String scanId) {
        try {
            ControlPlaneStore.ScanRecord scan = store.requireScan(scanId);
            retainedSandboxRelease.release(
                    scan.dto().projectId(), scan.dto().artifactDigest(), scanId);
        } catch (RuntimeException ignored) {
            // 尽力而为；scan 拆除或外部回调不得阻塞 pipeline CAS。
        }
    }

    public ControlPlaneStore store() { return store; }
    public SseHub sseHub() { return sseHub; }
    public ArtifactRegistry artifactRegistry() { return artifactRegistry; }

    /** P1-08：application port，供测试与渐进 RouteTable 迁移。 */
    public ScanQueryPort scanQueryPort() { return scanQueryPort; }
    public EvidenceGraphQueryPort evidenceGraphQueryPort() { return evidenceGraphQueryPort; }
    public CoverageQueryPort coverageQueryPort() { return coverageQueryPort; }
    public HypothesisQueryPort hypothesisQueryPort() { return hypothesisQueryPort; }
    public FindingQueryPort findingQueryPort() { return findingQueryPort; }
    public PathRunQueryPort pathRunQueryPort() { return pathRunQueryPort; }
    public ProviderQueryPort providerQueryPort() { return providerQueryPort; }
    public AnalyzerIrIngestPort analyzerIrIngestPort() { return analyzerIrIngestPort; }

    private final class ApiHandler implements HttpHandler {
        @Override public void handle(HttpExchange exchange) throws IOException {
            String requestId = UUID.randomUUID().toString();
            ControlPlaneHttpSupport.addCorsHeaders(exchange);
            try {
                if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                    exchange.getResponseHeaders().set("Allow", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
                    ControlPlaneHttpSupport.sendEmpty(exchange, 204);
                    return;
                }
                List<String> path = ControlPlaneHttpSupport.pathSegments(exchange.getRequestURI());
                if (path.isEmpty()) {
                    if ("GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                        ControlPlaneHttpSupport.sendJson(exchange, 200, health());
                    } else {
                        throw new ControlPlaneHttpSupport.ApiException(405, "METHOD_NOT_ALLOWED", "method is not allowed");
                    }
                    return;
                }
                route(exchange, path, requestId);
            } catch (ControlPlaneHttpSupport.ApiException failure) {
                ControlPlaneHttpSupport.sendError(exchange, failure.status, failure.code, failure.getMessage(), requestId);
            } catch (ControlPlaneStore.MissingRecordException missing) {
                ControlPlaneHttpSupport.sendError(exchange, 404, "NOT_FOUND", missing.getMessage(), requestId);
            } catch (ControlPlaneStore.DuplicateRecordException duplicate) {
                ControlPlaneHttpSupport.sendError(exchange, 409, "DUPLICATE", duplicate.getMessage(), requestId);
            } catch (ControlPlaneStore.StoreLimitException limited) {
                ControlPlaneHttpSupport.sendError(exchange, 429, "STORE_LIMIT", limited.getMessage(), requestId);
            } catch (ArtifactValidationException invalidArtifact) {
                ControlPlaneHttpSupport.sendError(exchange, 422, "INVALID_ARTIFACT", invalidArtifact.getMessage(), requestId);
            } catch (ArtifactUploadService.UploadException uploadFailure) {
                ControlPlaneHttpSupport.sendError(exchange, uploadFailure.status(), uploadFailure.code(), uploadFailure.getMessage(), requestId);
            } catch (PolicyViolationException policyViolation) {
                ControlPlaneHttpSupport.sendError(exchange, 403, "POLICY_REJECTED", policyViolation.getMessage(), requestId);
            } catch (IllegalArgumentException badRequest) {
                ControlPlaneHttpSupport.sendError(exchange, 400, "INVALID_REQUEST", ControlPlaneHttpSupport.safeMessage(badRequest), requestId);
            } catch (SQLiteControlPlanePersistence.PersistenceException persistence) {
                ControlPlaneHttpSupport.sendError(exchange, 409, "PERSISTENCE_REJECTED", ControlPlaneHttpSupport.safeMessage(persistence), requestId);
            } catch (Exception unexpected) {
                // 勿向 browser 暴露 host path、stack trace 或 parser 内部细节。
                // request ID 足以在本地日志中定位。
                ControlPlaneHttpSupport.sendError(exchange, 500, "INTERNAL_ERROR", "control plane request failed", requestId);
            } finally {
                // SSE 在 streaming 期间持有 exchange，仅在 disconnect 后返回；
                // 此处 close 无害，也会关闭 client 发送 SSE Accept header 的错误响应。
                try { exchange.close(); } catch (RuntimeException ignored) { }
            }
        }
    }

    private void route(HttpExchange exchange, List<String> path, String requestId) throws IOException {
        try {
            RouteTable.dispatch(this, exchange, path);
        } catch (ControlPlaneRouteActions.RouteException routeError) {
            throw new ControlPlaneHttpSupport.ApiException(routeError.status, routeError.code, routeError.getMessage());
        }
    }


    // ---- HTTP 路由委托 ----
    @Override public synchronized void createProject(HttpExchange exchange) throws IOException {
        routeHandlers.createProject(exchange);
    }
    @Override public void sendProject(HttpExchange exchange, String projectId) throws IOException {
        routeHandlers.sendProject(exchange, projectId);
    }
    @Override public void listProjects(HttpExchange exchange) throws IOException {
        routeHandlers.listProjects(exchange);
    }
    @Override public synchronized void updateProject(HttpExchange exchange, String projectId) throws IOException {
        routeHandlers.updateProject(exchange, projectId);
    }
    @Override public synchronized void deleteProject(HttpExchange exchange, String projectId) throws IOException {
        routeHandlers.deleteProject(exchange, projectId);
    }
    @Override public void listOperators(HttpExchange exchange) throws IOException {
        routeHandlers.listOperators(exchange);
    }
    @Override public void createOperator(HttpExchange exchange) throws IOException {
        routeHandlers.createOperator(exchange);
    }
    @Override public void updateOperator(HttpExchange exchange, String operatorId) throws IOException {
        routeHandlers.updateOperator(exchange, operatorId);
    }
    @Override public void listProviders(HttpExchange exchange) throws IOException {
        routeHandlers.listProviders(exchange);
    }
    @Override public void createProvider(HttpExchange exchange) throws IOException {
        routeHandlers.createProvider(exchange);
    }
    @Override public void updateProvider(HttpExchange exchange, String providerId) throws IOException {
        routeHandlers.updateProvider(exchange, providerId);
    }
    @Override public void deleteProvider(HttpExchange exchange, String providerId) throws IOException {
        routeHandlers.deleteProvider(exchange, providerId);
    }
    @Override public void detectProviderProtocol(HttpExchange exchange) throws IOException {
        routeHandlers.detectProviderProtocol(exchange);
    }
    @Override public void refreshProviderModels(HttpExchange exchange, String providerId) throws IOException {
        routeHandlers.refreshProviderModels(exchange, providerId);
    }
    @Override public void listRoleAssignments(HttpExchange exchange, String projectId) throws IOException {
        routeHandlers.listRoleAssignments(exchange, projectId);
    }
    @Override public void sendRoleAssignment(HttpExchange exchange, String projectId, AgentRole role) throws IOException {
        routeHandlers.sendRoleAssignment(exchange, projectId, role);
    }
    @Override public void saveRoleAssignment(HttpExchange exchange, String projectId, AgentRole role) throws IOException {
        routeHandlers.saveRoleAssignment(exchange, projectId, role);
    }
    @Override public void deleteRoleAssignment(HttpExchange exchange, String projectId, AgentRole role) throws IOException {
        routeHandlers.deleteRoleAssignment(exchange, projectId, role);
    }
    @Override public void listAiJobs(HttpExchange exchange, String projectId) throws IOException {
        routeHandlers.listAiJobs(exchange, projectId);
    }
    @Override public void createAiJob(HttpExchange exchange, String projectId) throws IOException {
        routeHandlers.createAiJob(exchange, projectId);
    }
    @Override public void sendAiJob(HttpExchange exchange, String jobId) throws IOException {
        routeHandlers.sendAiJob(exchange, jobId);
    }
    @Override public void listAiJobEvents(HttpExchange exchange, String jobId) throws IOException {
        routeHandlers.listAiJobEvents(exchange, jobId);
    }
    @Override public void updateAiJob(HttpExchange exchange, String jobId) throws IOException {
        routeHandlers.updateAiJob(exchange, jobId);
    }
    @Override public void deleteAiJob(HttpExchange exchange, String jobId) throws IOException {
        routeHandlers.deleteAiJob(exchange, jobId);
    }
    @Override public void listAudit(HttpExchange exchange, String projectId) throws IOException {
        routeHandlers.listAudit(exchange, projectId);
    }
    @Override public synchronized void registerArtifact(HttpExchange exchange, String projectId) throws IOException {
        routeHandlers.registerArtifact(exchange, projectId);
    }
    @Override public void initializeArtifactUpload(HttpExchange exchange, String projectId) throws IOException {
        routeHandlers.initializeArtifactUpload(exchange, projectId);
    }
    @Override public void appendArtifactUpload(HttpExchange exchange, String projectId,
                                      String uploadId) throws IOException {
        routeHandlers.appendArtifactUpload(exchange, projectId, uploadId);
    }
    @Override public void completeArtifactUpload(HttpExchange exchange, String projectId,
                                        String uploadId) throws IOException {
        routeHandlers.completeArtifactUpload(exchange, projectId, uploadId);
    }
    @Override public void cancelArtifactUpload(HttpExchange exchange, String projectId,
                                      String uploadId) throws IOException {
        routeHandlers.cancelArtifactUpload(exchange, projectId, uploadId);
    }
    @Override public void listArtifacts(HttpExchange exchange, String projectId) throws IOException {
        routeHandlers.listArtifacts(exchange, projectId);
    }
    @Override public void listEntries(HttpExchange exchange, String projectId) throws IOException {
        routeHandlers.listEntries(exchange, projectId);
    }
    @Override public void listScans(HttpExchange exchange, String projectId) throws IOException {
        routeHandlers.listScans(exchange, projectId);
    }
    @Override public void deleteScan(HttpExchange exchange, String projectId, String scanId) throws IOException {
        routeHandlers.deleteScan(exchange, projectId, scanId);
    }
    @Override public synchronized void startAudit(HttpExchange exchange, String projectId) throws IOException {
        routeHandlers.startAudit(exchange, projectId);
    }
    @Override public synchronized void retryAuditStage(HttpExchange exchange, String projectId) throws IOException {
        routeHandlers.retryAuditStage(exchange, projectId);
    }
    @Override public synchronized void updateScan(HttpExchange exchange, String scanId) throws IOException {
        routeHandlers.updateScan(exchange, scanId);
    }
    @Override public synchronized void createScan(HttpExchange exchange, String projectId) throws IOException {
        routeHandlers.createScan(exchange, projectId);
    }
    @Override public void sendScan(HttpExchange exchange, String scanId) throws IOException {
        routeHandlers.sendScan(exchange, scanId);
    }
    @Override public void sendScanCoverage(HttpExchange exchange, String scanId) throws IOException {
        routeHandlers.sendScanCoverage(exchange, scanId);
    }
    @Override public void sendScanEvidenceGraph(HttpExchange exchange, String scanId) throws IOException {
        routeHandlers.sendScanEvidenceGraph(exchange, scanId);
    }
    @Override public void sendScanHypotheses(HttpExchange exchange, String scanId) throws IOException {
        routeHandlers.sendScanHypotheses(exchange, scanId);
    }
    @Override public void sendScanAiMemory(HttpExchange exchange, String scanId) throws IOException {
        routeHandlers.sendScanAiMemory(exchange, scanId);
    }
    @Override public synchronized void createDynamicTask(HttpExchange exchange, String scanId) throws IOException {
        routeHandlers.createDynamicTask(exchange, scanId);
    }
    @Override public void listDynamicTasks(HttpExchange exchange, String scanId) throws IOException {
        routeHandlers.listDynamicTasks(exchange, scanId);
    }
    @Override public void streamEvents(HttpExchange exchange, String scanId) throws IOException {
        routeHandlers.streamEvents(exchange, scanId);
    }
    @Override public void listPaths(HttpExchange exchange, String scanId) throws IOException {
        routeHandlers.listPaths(exchange, scanId);
    }
    @Override public void sendPath(HttpExchange exchange, String scanId, String pathId) throws IOException {
        routeHandlers.sendPath(exchange, scanId, pathId);
    }
    @Override public void listScanEvidence(HttpExchange exchange, String scanId) throws IOException {
        routeHandlers.listScanEvidence(exchange, scanId);
    }
    @Override public void listScanFindings(HttpExchange exchange, String scanId) throws IOException {
        routeHandlers.listScanFindings(exchange, scanId);
    }
    @Override public void sendFinding(HttpExchange exchange, String findingId) throws IOException {
        routeHandlers.sendFinding(exchange, findingId);
    }
    @Override public synchronized void replayFinding(HttpExchange exchange, String findingId) throws IOException {
        routeHandlers.replayFinding(exchange, findingId);
    }
    @Override public synchronized void focusEntryProbe(HttpExchange exchange, String scanId, String entryId) throws IOException {
        routeHandlers.focusEntryProbe(exchange, scanId, entryId);
    }
    @Override public synchronized void replaySqlExperimentCard(HttpExchange exchange, String scanId, String cardId) throws IOException {
        routeHandlers.replaySqlExperimentCard(exchange, scanId, cardId);
    }
    @Override public void sendEvidence(HttpExchange exchange, String evidenceId) throws IOException {
        routeHandlers.sendEvidence(exchange, evidenceId);
    }
    @Override public void listEvidence(HttpExchange exchange, String projectId) throws IOException {
        routeHandlers.listEvidence(exchange, projectId);
    }
    @Override public void listChains(HttpExchange exchange) throws IOException {
        routeHandlers.listChains(exchange);
    }
    @Override public void dashboard(HttpExchange exchange, String projectId) throws IOException {
        routeHandlers.dashboard(exchange, projectId);
    }
    @Override public void sendHealth(HttpExchange exchange) throws IOException {
        routeHandlers.sendHealth(exchange);
    }
    @Override public String query(java.net.URI uri, String name) { return routeHandlers.query(uri, name); }
    @Override public AgentRole role(String value) { return routeHandlers.role(value); }
    @Override public void requirePermission(HttpExchange exchange, Permission permission) {
        routeHandlers.requirePermission(exchange, permission);
    }
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

    public synchronized void acceptExperimentPlan(String scanId, ExperimentPlan plan) {
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

    private void restoreProbePlans() {
        routeHandlers.restoreProbePlans();
    }

    private void restoreExperimentPlans() {
        routeHandlers.restoreExperimentPlans();
    }

    public static String probeAttemptId(String jobId, String toolCallId) {
        return ControlPlaneRouteHandlers.probeAttemptId(jobId, toolCallId);
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

    @FunctionalInterface
    public interface ProviderInventoryService {
        ModelInventory fetch(ProviderDefinition provider, byte[] credential);
    }

    /** CLI 元数据提取适配器；保持对现有安全 reader 的封装。 */
    public static final class PreAnalysisServiceAdapter {
        private final com.aq.jvmsentinel.analysis.PreAnalysisService delegate =
                new com.aq.jvmsentinel.analysis.PreAnalysisService();

        public PreAnalysisResult analyze(PreAnalysisInput input) {
            return delegate.analyze(input);
        }
    }
}