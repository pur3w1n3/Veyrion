package com.aq.jvmsentinel.control;

import com.aq.jvmsentinel.analysis.PreAnalysisResult;
import com.aq.jvmsentinel.analysis.PreAnalysisInput;
import com.aq.jvmsentinel.analysis.ArtifactMetadataReader;
import com.aq.jvmsentinel.analysis.identity.SyntheticIdentityService;
import com.aq.jvmsentinel.analysis.pack.AnalysisPackRegistry;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.ai.AiJobOrchestrator;
import com.aq.jvmsentinel.ai.AuditPipelineCoordinator;
import com.aq.jvmsentinel.ai.tool.ControlPlaneToolDataSource;
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
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.worker.InMemoryTaskCoordinator;
import com.aq.jvmsentinel.worker.InMemoryTraceStore;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;
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
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.JarFile;

/**
 * Dependency-free Java 17 Control Plane for the local MVP.
 *
 * <p>The server exposes metadata analysis and schedules artifact execution only
 * through the policy-checked sandbox worker. It never starts an imported
 * JAR/WAR/CLASS in the control-plane process; artifact requests stay inside the
 * authorized sandbox loopback. The default bind address is loopback and all
 * mutating routes require the configured local authorization token.</p>
 */
public final class ControlPlaneServer implements AutoCloseable {
    private static final ObjectMapper JSON = new ObjectMapper();
    public static final String API_PREFIX = "/api/v1";
    public static final String DEFAULT_TOKEN = "local-demo";
    private static final int MAX_BODY_BYTES = 1 * 1024 * 1024;
    private static final int MAX_LIST_ITEMS = 10_000;
    private static final long DEFAULT_WALL_CLOCK_SECONDS = 900;
    private static final long DEFAULT_MEMORY_BYTES = 4L * 1024 * 1024 * 1024;
    private static final long DEFAULT_DISK_BYTES = 2L * 1024 * 1024 * 1024;
    private static final int MAX_IDEMPOTENCY_KEYS = 50_000;
    private static final int MAX_AI_JOB_EVENTS = 128;

    private final InetSocketAddress bindAddress;
    private final ArtifactRegistry artifactRegistry;
    private final ArtifactUploadService artifactUploadService;
    private final PreAnalysisServiceAdapter analysis = new PreAnalysisServiceAdapter();
    private final ControlPlaneStore store;
    private final SseHub sseHub;
    private final Map<String, String> idempotentProjects = new ConcurrentHashMap<>();
    private final Map<String, String> idempotentArtifacts = new ConcurrentHashMap<>();
    private final Map<String, String> idempotentScans = new ConcurrentHashMap<>();
    private final Map<String, AuditRunReplay> idempotentAuditRuns = new ConcurrentHashMap<>();
    private final Map<String, DynamicTaskReplay> idempotentDynamicTasks = new ConcurrentHashMap<>();
    private final Map<String, FindingReplay> idempotentFindingReplays = new ConcurrentHashMap<>();
    /** Durable idempotency index; the legacy typed maps remain an in-process fast path. */
    private final Map<String, SQLiteControlPlanePersistence.IdempotencyData> durableIdempotency = new ConcurrentHashMap<>();
    /** One server-owned probe task per AI job; model retries cannot fan out unbounded tasks. */
    private final Map<String, TaskSnapshot> aiProbeTasks = new ConcurrentHashMap<>();
    /** Server-generated probe plans keyed by task id; model input never becomes a command. */
    private final Map<String, ProbePlan> dynamicProbePlans = new ConcurrentHashMap<>();
    /** Scan-scoped UNREACHED dynamic path placeholders for entries beyond the probe budget. */
    private final Map<String, List<ApiDtos.PathDto>> unreachedDynamicPaths = new ConcurrentHashMap<>();
    private final String mutationToken;
    private final String workerToken;
    private final InMemoryTraceStore traceStore;
    private final InMemoryTaskCoordinator taskCoordinator;
    private final TraceProjectionService traceProjectionService;
    private final WorkerControlPlaneApi workerApi;
    private final ProviderInventoryService providerInventoryService;
    private final AiJobOrchestrator aiJobOrchestrator;
    private final AuditPipelineCoordinator auditPipeline;
    private final Clock clock;
    private final Authorizer authorizer = new Authorizer();
    private volatile HttpServer server;
    private volatile ExecutorService executor;

    public ControlPlaneServer(Path allowedRoot) {
        this(new InetSocketAddress("127.0.0.1", 0), new ArtifactRegistry(allowedRoot),
                DEFAULT_TOKEN, Clock.systemUTC(), new ControlPlaneStore(), new SseHub());
    }

    /** Loopback constructor with an explicit port; port 0 asks the OS for a free port. */
    public ControlPlaneServer(Path allowedRoot, int port) {
        this(new InetSocketAddress("127.0.0.1", port), new ArtifactRegistry(allowedRoot),
                DEFAULT_TOKEN, Clock.systemUTC(), new ControlPlaneStore(), new SseHub());
    }

    /** Loopback constructor used by integration tests and local desktop launchers. */
    public ControlPlaneServer(Path allowedRoot, int port, String mutationToken) {
        this(new InetSocketAddress("127.0.0.1", port), new ArtifactRegistry(allowedRoot),
                mutationToken == null || mutationToken.isBlank() ? DEFAULT_TOKEN : mutationToken,
                Clock.systemUTC(), new ControlPlaneStore(), new SseHub());
    }

    /** Loopback constructor with explicitly controlled SQLite persistence. */
    public ControlPlaneServer(Path allowedRoot, int port, String mutationToken, Path databasePath) {
        this(new InetSocketAddress("127.0.0.1", port), new ArtifactRegistry(allowedRoot),
                mutationToken == null || mutationToken.isBlank() ? DEFAULT_TOKEN : mutationToken,
                Clock.systemUTC(), ControlPlaneStore.sqlite(databasePath, allowedRoot), new SseHub());
    }

    /** Controlled inventory injection for HTTP acceptance tests; production uses the secure client. */
    public ControlPlaneServer(Path allowedRoot, int port, String mutationToken, Path databasePath,
                              ProviderInventoryService providerInventoryService) {
        this(new InetSocketAddress("127.0.0.1", port), new ArtifactRegistry(allowedRoot),
                mutationToken == null || mutationToken.isBlank() ? DEFAULT_TOKEN : mutationToken,
                Clock.systemUTC(), ControlPlaneStore.sqlite(databasePath, allowedRoot), new SseHub(),
                providerInventoryService, new ProviderChatTransport());
    }

    /** Controlled provider injections for acceptance tests; production constructors keep the fixed transport. */
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
        this.mutationToken = requireToken(mutationToken);
        this.clock = Objects.requireNonNull(clock, "clock");
        this.store = Objects.requireNonNull(store, "store");
        this.sseHub = Objects.requireNonNull(sseHub, "sseHub");
        this.sseHub.attachPersistence(this.store.loadSseEvents(), this.store::persistSseEvent);
        this.artifactUploadService = new ArtifactUploadService(this.artifactRegistry, this.clock,
                256, 2L * 1024 * 1024 * 1024, java.time.Duration.ofHours(1),
                this.store.artifactUploadPersistence());
        this.workerToken = newWorkerToken(this.mutationToken);
        var workerState = this.store.loadWorkerState();
        this.traceStore = new InMemoryTraceStore(this.clock, workerState.traces(), this.store::persistWorkerTrace);
        this.taskCoordinator = new InMemoryTaskCoordinator(this.clock, this.traceStore, workerState.tasks(), this.store::persistWorkerTask);
        this.traceProjectionService = new TraceProjectionService(this.traceStore);
        this.workerApi = new WorkerControlPlaneApi(this.workerToken, this.clock, this.store, this.sseHub,
                this.traceStore, this.taskCoordinator, this.traceProjectionService);
        for (var record : this.store.loadIdempotency()) {
            durableIdempotency.put(idempotencyMapKey(record.scope(), record.key()), record);
        }
        restoreProbePlans();
        this.providerInventoryService = Objects.requireNonNull(
                providerInventoryService, "providerInventoryService");
        if ("SQLITE".equals(this.store.persistenceMode())) {
            this.store.bootstrapOperator(this.mutationToken, Instant.now(this.clock).toString());
        }
        this.aiJobOrchestrator = new AiJobOrchestrator(this.store,
                Objects.requireNonNull(chatTransport, "chatTransport"), this.clock,
                this.traceProjectionService::evidenceForScan,
                this::requestSandboxProbe);
        this.auditPipeline = new AuditPipelineCoordinator(new AuditPipelineCoordinator.Actions() {
            @Override
            public boolean hasRoleJob(String projectId, String scanId, AgentRole role) {
                return store.aiJobs(projectId).stream()
                        .anyMatch(AuditPipelineCoordinator.busyOrDoneFor(scanId, role));
            }

            @Override
            public int countRoleJobs(String projectId, String scanId, AgentRole role) {
                return (int) store.aiJobs(projectId).stream()
                        .filter(AuditPipelineCoordinator.busyOrDoneFor(scanId, role))
                        .count();
            }

            @Override
            public boolean hasBusyDynamicTask(String scanId) {
                return hasRunningDynamicTask(scanId);
            }

            @Override
            public boolean hasRunningDynamicTask(String scanId) {
                return workerApi.snapshots(store.requireScan(scanId).dto().projectId(), scanId).stream()
                        .anyMatch(snapshot -> snapshot.lifecycle() == TaskLifecycle.QUEUED
                                || snapshot.lifecycle() == TaskLifecycle.LEASED
                                || snapshot.lifecycle() == TaskLifecycle.RUNNING
                                || snapshot.lifecycle() == TaskLifecycle.PAUSED);
            }

            @Override
            public boolean hasCompletedDynamicTask(String scanId) {
                return workerApi.snapshots(store.requireScan(scanId).dto().projectId(), scanId).stream()
                        .anyMatch(snapshot -> snapshot.lifecycle() == TaskLifecycle.COMPLETED);
            }

            @Override
            public void enqueueRole(String projectId, String scanId, AgentRole role,
                                    AiOutputLanguage language, String actorId) {
                var job = store.createAiJob(projectId, role, scanId, language, true, actorId,
                        Instant.now(clock).toString());
                aiJobOrchestrator.submit(job, actorId);
                store.auditChange(projectId, actorId, "audit-pipeline.enqueue-role", "ai-job",
                        job.aiJobId(), "{\"role\":\"" + role.name() + "\",\"scanId\":\"" + scanId + "\"}",
                        Instant.now(clock).toString());
            }

            @Override
            public void enqueueDynamic(String scanId, String actorId) {
                enqueueDynamicForPipeline(scanId, actorId);
            }

            @Override
            public void persistState(AuditPipelineCoordinator.Arm arm, String nextStage, boolean armed) {
                store.persistPipelineRun(new SQLiteControlPlanePersistence.PipelineRunData(
                        arm.scanId(), arm.projectId(), arm.actorId(), arm.outputLanguage().name(),
                        armed, nextStage, Instant.now(clock).toString()));
            }
        });
        this.aiJobOrchestrator.setTerminalListener(auditPipeline::onAiJobFinished);
        this.workerApi.setTerminalListener(auditPipeline::onDynamicTaskFinished);
        recoverAuditPipelines();
    }

    private void recoverAuditPipelines() {
        for (SQLiteControlPlanePersistence.PipelineRunData run : store.loadPipelineRuns()) {
            if (!run.armed()) continue;
            ControlPlaneStore.ScanRecord scan = store.scan(run.scanId());
            if (scan == null || !scan.dto().projectId().equals(run.projectId())) {
                throw new SQLiteControlPlanePersistence.PersistenceException(
                        "pipeline run scope does not match a persistent scan");
            }
            AiOutputLanguage language;
            try {
                language = AiOutputLanguage.valueOf(run.outputLanguage());
            } catch (IllegalArgumentException invalid) {
                throw new SQLiteControlPlanePersistence.PersistenceException(
                        "pipeline run output language is invalid", invalid);
            }
            List<SQLiteControlPlanePersistence.AiJobData> jobs = store.aiJobs(run.projectId()).stream()
                    .filter(job -> run.scanId().equals(job.scanId())).toList();
            boolean pre = completed(jobs, AgentRole.PRE_ANALYSIS);
            long authCount = jobs.stream()
                    .filter(job -> job.role() == AgentRole.AUTH_ANALYSIS && "COMPLETED".equals(job.status()))
                    .count();
            boolean dynamicVerification = completed(jobs, AgentRole.DYNAMIC_VERIFICATION);
            boolean path = completed(jobs, AgentRole.PATH_EXPLORATION);
            boolean triage = completed(jobs, AgentRole.VULNERABILITY_TRIAGE);
            boolean report = completed(jobs, AgentRole.REPORT_GENERATION);
            List<TaskSnapshot> tasks = workerApi.snapshots(run.projectId(), run.scanId());
            boolean dynamicCompleted = tasks.stream()
                    .anyMatch(task -> task.lifecycle() == TaskLifecycle.COMPLETED);
            AuditPipelineCoordinator.PipelineStage stage;
            if (report) stage = AuditPipelineCoordinator.PipelineStage.COMPLETE;
            else if (triage) stage = AuditPipelineCoordinator.PipelineStage.REPORT_GENERATION;
            else if (path) stage = AuditPipelineCoordinator.PipelineStage.VULNERABILITY_TRIAGE;
            else if (dynamicVerification) stage = AuditPipelineCoordinator.PipelineStage.PATH_EXPLORATION;
            else if (dynamicCompleted && authCount >= 2) {
                stage = AuditPipelineCoordinator.PipelineStage.DYNAMIC_VERIFICATION;
            } else if (dynamicCompleted) {
                stage = AuditPipelineCoordinator.PipelineStage.AUTH_BYPASS_CONFIRM;
            } else if (authCount >= 1) {
                stage = AuditPipelineCoordinator.PipelineStage.DYNAMIC_OBSERVATION;
            } else if (pre) stage = AuditPipelineCoordinator.PipelineStage.AUTH_ANALYSIS;
            else stage = AuditPipelineCoordinator.PipelineStage.PRE_ANALYSIS;
            AuditPipelineCoordinator.Arm arm = new AuditPipelineCoordinator.Arm(
                    run.scanId(), run.projectId(), run.actorId(), language);
            auditPipeline.resumeAt(arm, stage);
            store.auditChange(run.projectId(), run.actorId(), "audit-pipeline.recover", "scan",
                    run.scanId(), "{\"stage\":\"" + stage.name() + "\"}",
                    Instant.now(clock).toString());
        }
    }

    private static boolean completed(List<SQLiteControlPlanePersistence.AiJobData> jobs, AgentRole role) {
        return jobs.stream().anyMatch(job -> job.role() == role && "COMPLETED".equals(job.status()));
    }

    /** Starts listening; calling start more than once is idempotent. */
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
        ExecutorService pool = executor;
        executor = null;
        if (pool != null) pool.shutdownNow();
        aiProbeTasks.clear();
        dynamicProbePlans.clear();
        idempotentFindingReplays.clear();
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
    /** Process-local credential for the internal Worker contract; never accepted by GUI routes. */
    public String workerToken() { return workerToken; }
    public ControlPlaneStore store() { return store; }
    public SseHub sseHub() { return sseHub; }
    public ArtifactRegistry artifactRegistry() { return artifactRegistry; }

    private final class ApiHandler implements HttpHandler {
        @Override public void handle(HttpExchange exchange) throws IOException {
            String requestId = UUID.randomUUID().toString();
            addCorsHeaders(exchange);
            try {
                if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                    exchange.getResponseHeaders().set("Allow", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
                    sendEmpty(exchange, 204);
                    return;
                }
                List<String> path = pathSegments(exchange.getRequestURI());
                if (path.isEmpty()) {
                    if ("GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                        sendJson(exchange, 200, health());
                    } else {
                        throw new ApiException(405, "METHOD_NOT_ALLOWED", "method is not allowed");
                    }
                    return;
                }
                route(exchange, path, requestId);
            } catch (ApiException failure) {
                sendError(exchange, failure.status, failure.code, failure.getMessage(), requestId);
            } catch (ControlPlaneStore.MissingRecordException missing) {
                sendError(exchange, 404, "NOT_FOUND", missing.getMessage(), requestId);
            } catch (ControlPlaneStore.DuplicateRecordException duplicate) {
                sendError(exchange, 409, "DUPLICATE", duplicate.getMessage(), requestId);
            } catch (ControlPlaneStore.StoreLimitException limited) {
                sendError(exchange, 429, "STORE_LIMIT", limited.getMessage(), requestId);
            } catch (ArtifactValidationException invalidArtifact) {
                sendError(exchange, 422, "INVALID_ARTIFACT", invalidArtifact.getMessage(), requestId);
            } catch (ArtifactUploadService.UploadException uploadFailure) {
                sendError(exchange, uploadFailure.status(), uploadFailure.code(), uploadFailure.getMessage(), requestId);
            } catch (PolicyViolationException policyViolation) {
                sendError(exchange, 403, "POLICY_REJECTED", policyViolation.getMessage(), requestId);
            } catch (IllegalArgumentException badRequest) {
                sendError(exchange, 400, "INVALID_REQUEST", safeMessage(badRequest), requestId);
            } catch (SQLiteControlPlanePersistence.PersistenceException persistence) {
                sendError(exchange, 409, "PERSISTENCE_REJECTED", safeMessage(persistence), requestId);
            } catch (Exception unexpected) {
                // Do not expose host paths, stack traces or parser internals to
                // the browser.  The request ID is enough for local logs.
                sendError(exchange, 500, "INTERNAL_ERROR", "control plane request failed", requestId);
            } finally {
                // SSE owns the exchange while streaming and returns only after
                // disconnect; closing here is harmless and also closes error
                // responses where the client sent an SSE Accept header.
                try { exchange.close(); } catch (RuntimeException ignored) { }
            }
        }
    }

    private void route(HttpExchange exchange, List<String> path, String requestId) throws IOException {
        String method = exchange.getRequestMethod().toUpperCase(Locale.ROOT);
        if (path.size() == 1 && "health".equals(path.get(0)) && "GET".equals(method)) {
            sendJson(exchange, 200, health());
            return;
        }
        if (path.size() == 1 && "projects".equals(path.get(0))) {
            if ("POST".equals(method)) { requirePermission(exchange, Permission.MANAGE_PROJECTS); createProject(exchange); return; }
            if ("GET".equals(method)) { listProjects(exchange); return; }
        }
        if (path.size() == 2 && "projects".equals(path.get(0))) {
            if ("GET".equals(method)) { sendProject(exchange, path.get(1)); return; }
            if ("PATCH".equals(method)) {
                requirePermission(exchange, Permission.MANAGE_PROJECTS);
                updateProject(exchange, path.get(1));
                return;
            }
            if ("DELETE".equals(method)) {
                requirePermission(exchange, Permission.MANAGE_PROJECTS);
                deleteProject(exchange, path.get(1));
                return;
            }
        }
        if (path.size() == 3 && "projects".equals(path.get(0)) && "artifacts".equals(path.get(2))) {
            if ("POST".equals(method)) { requirePermission(exchange, Permission.MANAGE_PROJECTS); registerArtifact(exchange, path.get(1)); return; }
            if ("GET".equals(method)) { listArtifacts(exchange, path.get(1)); return; }
        }
        if (path.size() == 3 && "projects".equals(path.get(0)) && "artifact-uploads".equals(path.get(2))
                && "POST".equals(method)) {
            requirePermission(exchange, Permission.MANAGE_PROJECTS);
            initializeArtifactUpload(exchange, path.get(1));
            return;
        }
        if (path.size() == 4 && "projects".equals(path.get(0)) && "artifact-uploads".equals(path.get(2))) {
            requirePermission(exchange, Permission.MANAGE_PROJECTS);
            if ("PUT".equals(method)) {
                appendArtifactUpload(exchange, path.get(1), path.get(3));
                return;
            }
            if ("DELETE".equals(method)) {
                cancelArtifactUpload(exchange, path.get(1), path.get(3));
                return;
            }
        }
        if (path.size() == 5 && "projects".equals(path.get(0)) && "artifact-uploads".equals(path.get(2))
                && "complete".equals(path.get(4)) && "POST".equals(method)) {
            requirePermission(exchange, Permission.MANAGE_PROJECTS);
            completeArtifactUpload(exchange, path.get(1), path.get(3));
            return;
        }
        if (path.size() == 3 && "projects".equals(path.get(0)) && "entries".equals(path.get(2))
                && "GET".equals(method)) {
            listEntries(exchange, path.get(1));
            return;
        }
        if (path.size() == 3 && "projects".equals(path.get(0)) && "audit-runs".equals(path.get(2))
                && "POST".equals(method)) {
            requirePermission(exchange, Permission.RUN_SCANS);
            requirePermission(exchange, Permission.RUN_AI_JOBS);
            startAudit(exchange, path.get(1));
            return;
        }
        if (path.size() == 3 && "projects".equals(path.get(0)) && "audit-stage-retries".equals(path.get(2))
                && "POST".equals(method)) {
            requirePermission(exchange, Permission.RUN_SCANS);
            requirePermission(exchange, Permission.RUN_AI_JOBS);
            retryAuditStage(exchange, path.get(1));
            return;
        }
        if (path.size() == 3 && "projects".equals(path.get(0)) && "scans".equals(path.get(2))) {
            if ("POST".equals(method)) { requirePermission(exchange, Permission.RUN_SCANS); createScan(exchange, path.get(1)); return; }
            if ("GET".equals(method)) { listScans(exchange, path.get(1)); return; }
        }
        if (path.size() == 3 && "projects".equals(path.get(0)) && "dashboard".equals(path.get(2))
                && "GET".equals(method)) {
            dashboard(exchange, path.get(1));
            return;
        }
        if (path.size() == 3 && "projects".equals(path.get(0)) && "evidence".equals(path.get(2))
                && "GET".equals(method)) {
            listEvidence(exchange, path.get(1));
            return;
        }
        if (path.size() == 2 && "scans".equals(path.get(0))) {
            if ("GET".equals(method)) { sendScan(exchange, path.get(1)); return; }
        }
        if (path.size() == 3 && "scans".equals(path.get(0)) && "events".equals(path.get(2))
                && "GET".equals(method)) {
            streamEvents(exchange, path.get(1));
            return;
        }
        if (path.size() == 3 && "scans".equals(path.get(0)) && "dynamic-tasks".equals(path.get(2))) {
            requirePermission(exchange, "GET".equals(method) ? Permission.READ_AUDIT : Permission.RUN_SCANS);
            if ("GET".equals(method)) { listDynamicTasks(exchange, path.get(1)); return; }
            if ("POST".equals(method)) { createDynamicTask(exchange, path.get(1)); return; }
        }
        if (path.size() == 3 && "scans".equals(path.get(0)) && "paths".equals(path.get(2))
                && "GET".equals(method)) {
            listPaths(exchange, path.get(1));
            return;
        }
        if (path.size() == 3 && "scans".equals(path.get(0)) && "evidence".equals(path.get(2))
                && "GET".equals(method)) {
            listScanEvidence(exchange, path.get(1));
            return;
        }
        if (path.size() == 3 && "scans".equals(path.get(0)) && "findings".equals(path.get(2))
                && "GET".equals(method)) {
            listScanFindings(exchange, path.get(1));
            return;
        }
        if (path.size() == 4 && "scans".equals(path.get(0)) && "paths".equals(path.get(2))
                && "GET".equals(method)) {
            sendPath(exchange, path.get(1), path.get(3));
            return;
        }
        if (path.size() == 2 && "findings".equals(path.get(0)) && "GET".equals(method)) {
            sendFinding(exchange, path.get(1));
            return;
        }
        if (path.size() == 3 && "findings".equals(path.get(0)) && "replay".equals(path.get(2))) {
            if ("POST".equals(method)) { requirePermission(exchange, Permission.RUN_SCANS); replayFinding(exchange, path.get(1)); return; }
        }
        if (path.size() == 1 && "operators".equals(path.get(0))) {
            requirePermission(exchange, Permission.MANAGE_OPERATOR_ACCESS);
            if ("GET".equals(method)) { listOperators(exchange); return; }
            if ("POST".equals(method)) { createOperator(exchange); return; }
        }
        if (path.size() == 2 && "operators".equals(path.get(0)) && "PATCH".equals(method)) {
            requirePermission(exchange, Permission.MANAGE_OPERATOR_ACCESS);
            updateOperator(exchange, path.get(1));
            return;
        }
        if (path.size() == 1 && "providers".equals(path.get(0))) {
            requirePermission(exchange, "GET".equals(method)
                    ? Permission.READ_SECURITY_CONFIGURATION : Permission.MANAGE_PROVIDERS);
            if ("GET".equals(method)) { listProviders(exchange); return; }
            if ("POST".equals(method)) { createProvider(exchange); return; }
        }
        if (path.size() == 2 && "providers".equals(path.get(0))) {
            requirePermission(exchange, Permission.MANAGE_PROVIDERS);
            if ("PATCH".equals(method)) { updateProvider(exchange, path.get(1)); return; }
            if ("DELETE".equals(method)) { deleteProvider(exchange, path.get(1)); return; }
        }
        if (path.size() == 4 && "providers".equals(path.get(0))
                && "models".equals(path.get(2)) && "refresh".equals(path.get(3))
                && "POST".equals(method)) {
            requirePermission(exchange, Permission.MANAGE_PROVIDERS);
            refreshProviderModels(exchange, path.get(1));
            return;
        }
        if (path.size() == 3 && "projects".equals(path.get(0))
                && "role-assignments".equals(path.get(2)) && "GET".equals(method)) {
            requirePermission(exchange, Permission.READ_SECURITY_CONFIGURATION);
            listRoleAssignments(exchange, path.get(1));
            return;
        }
        if (path.size() == 4 && "projects".equals(path.get(0))
                && "role-assignments".equals(path.get(2))) {
            if ("GET".equals(method)) {
                requirePermission(exchange, Permission.READ_SECURITY_CONFIGURATION);
                sendRoleAssignment(exchange, path.get(1), role(path.get(3)));
                return;
            }
            requirePermission(exchange, Permission.ASSIGN_AGENT_ROLES);
            if ("PATCH".equals(method)) { saveRoleAssignment(exchange, path.get(1), role(path.get(3))); return; }
            if ("DELETE".equals(method)) { deleteRoleAssignment(exchange, path.get(1), role(path.get(3))); return; }
        }
        if (path.size() == 3 && "projects".equals(path.get(0))
                && "ai-jobs".equals(path.get(2))) {
            requirePermission(exchange, "GET".equals(method) ? Permission.READ_SECURITY_CONFIGURATION : Permission.RUN_AI_JOBS);
            if ("GET".equals(method)) { listAiJobs(exchange, path.get(1)); return; }
            if ("POST".equals(method)) { createAiJob(exchange, path.get(1)); return; }
        }
        if (path.size() == 3 && "ai-jobs".equals(path.get(0))
                && "events".equals(path.get(2)) && "GET".equals(method)) {
            requirePermission(exchange, Permission.READ_SECURITY_CONFIGURATION);
            listAiJobEvents(exchange, path.get(1));
            return;
        }
        if (path.size() == 2 && "ai-jobs".equals(path.get(0))) {
            requirePermission(exchange, "GET".equals(method) ? Permission.READ_SECURITY_CONFIGURATION : Permission.RUN_AI_JOBS);
            if ("GET".equals(method)) { sendAiJob(exchange, path.get(1)); return; }
            if ("PATCH".equals(method)) { updateAiJob(exchange, path.get(1)); return; }
            if ("DELETE".equals(method)) { deleteAiJob(exchange, path.get(1)); return; }
        }
        if (path.size() == 1 && "audit-events".equals(path.get(0)) && "GET".equals(method)) {
            requirePermission(exchange, Permission.READ_AUDIT);
            listAudit(exchange, query(exchange.getRequestURI(), "projectId"));
            return;
        }
        if (path.size() == 3 && "projects".equals(path.get(0))
                && "audit-events".equals(path.get(2)) && "GET".equals(method)) {
            requirePermission(exchange, Permission.READ_AUDIT);
            listAudit(exchange, path.get(1));
            return;
        }
        if (path.size() == 2 && "evidence".equals(path.get(0)) && "GET".equals(method)) {
            sendEvidence(exchange, path.get(1));
            return;
        }
        if (path.size() == 1 && "attack-chains".equals(path.get(0)) && "GET".equals(method)) {
            listChains(exchange);
            return;
        }
        throw new ApiException(405, "METHOD_NOT_ALLOWED", "route or method is not allowed");
    }

    private synchronized void createProject(HttpExchange exchange) throws IOException {
        String idempotencyHeader = requestIdempotencyKey(exchange);
        Map<String, Object> body = readObject(exchange);
        String payload = JsonCodec.stringify(body);
        String durableScope = "project:create";
        ensureIdempotencyCapacity(durableIdempotency,
                idempotencyHeader == null ? null : idempotencyMapKey(durableScope, idempotencyHeader));
        SQLiteControlPlanePersistence.IdempotencyData durable = existingDurableIdempotency(
                durableScope, idempotencyHeader, payload);
        if (idempotencyHeader != null) {
            String existingId = idempotentProjects.get(idempotencyHeader);
            if (existingId == null && durable != null) existingId = durable.resultRef();
            if (existingId != null) {
                sendProject(exchange, existingId);
                return;
            }
        }
        String id = optionalText(body, "projectId", optionalText(body, "id", null));
        String name = optionalText(body, "name", optionalText(body, "displayName", null));
        ControlPlaneStore.ProjectRecord project = store.createProject(id, name, Instant.now(clock).toString(),
                actor(exchange).operatorId());
        if (idempotencyHeader != null) {
            idempotentProjects.put(idempotencyHeader, project.projectId());
            rememberDurableIdempotency(durableScope, idempotencyHeader, payload, project.projectId(), null);
        }
        sendJson(exchange, 201, projectMap(project));
    }

    private void sendProject(HttpExchange exchange, String projectId) throws IOException {
        sendJson(exchange, 200, projectMap(store.requireProject(projectId)));
    }

    private void listProjects(HttpExchange exchange) throws IOException {
        List<Object> projects = new ArrayList<>();
        for (ControlPlaneStore.ProjectRecord project : store.projects()) projects.add(projectMap(project));
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", ApiDtos.SCHEMA_VERSION);
        result.put("projects", projects);
        result.put("items", projects);
        sendJson(exchange, 200, result);
    }

    private synchronized void updateProject(HttpExchange exchange, String projectId) throws IOException {
        Map<String, Object> body = readObject(exchange);
        for (String field : body.keySet()) {
            if (!Set.of("name", "status").contains(field)) {
                throw new ApiException(400, "INVALID_FIELD", "project patch only accepts name and status");
            }
        }
        if (body.isEmpty()) throw new ApiException(400, "INVALID_FIELD", "project patch cannot be empty");
        String name = body.containsKey("name") ? optionalText(body, "name", null) : null;
        String status = body.containsKey("status") ? optionalText(body, "status", null) : null;
        sendJson(exchange, 200, projectMap(store.updateProject(projectId, name, status,
                Instant.now(clock).toString(), actor(exchange).operatorId())));
    }

    private synchronized void deleteProject(HttpExchange exchange, String projectId) throws IOException {
        store.softDeleteProject(projectId, Instant.now(clock).toString(), actor(exchange).operatorId());
        sendEmpty(exchange, 204);
    }

    private void listOperators(HttpExchange exchange) throws IOException {
        List<Object> items = new ArrayList<>();
        for (var operator : store.operators()) items.add(operatorMap(operator, null));
        sendJson(exchange, 200, stringEnvelope("operators", items));
    }

    private void createOperator(HttpExchange exchange) throws IOException {
        Map<String, Object> body = readObject(exchange);
        String username = optionalText(body, "username", null);
        OperatorRole role = operatorRole(optionalText(body, "role", null));
        String now = Instant.now(clock).toString();
        ControlPlaneStore.CreatedOperator created =
                store.createOperator(username, role, actor(exchange).operatorId(), now);
        sendJson(exchange, 201, operatorMap(created.operator(), created.personalAccessToken()));
    }

    private void updateOperator(HttpExchange exchange, String operatorId) throws IOException {
        Map<String, Object> body = readObject(exchange);
        OperatorRole role = operatorRole(optionalText(body, "role", null));
        boolean revoke = optionalBoolean(body, "revokeTokens", false);
        AuthContext actor = actor(exchange);
        if (actor.operatorId().equals(operatorId)
                && (revoke || role != OperatorRole.ADMINISTRATOR)) {
            throw new ApiException(409, "SELF_LOCKOUT_REJECTED",
                    "administrator cannot revoke or demote the active account");
        }
        store.updateOperator(operatorId, role, revoke, actor.operatorId(), Instant.now(clock).toString());
        var updated = store.operators().stream().filter(value -> value.operatorId().equals(operatorId))
                .findFirst().orElseThrow(() -> new ControlPlaneStore.MissingRecordException("operator not found"));
        sendJson(exchange, 200, operatorMap(updated, null));
    }

    private void listProviders(HttpExchange exchange) throws IOException {
        List<Object> items = new ArrayList<>();
        for (var provider : store.providers()) items.add(providerMap(provider));
        sendJson(exchange, 200, stringEnvelope("providers", items));
    }

    private void createProvider(HttpExchange exchange) throws IOException {
        Map<String, Object> body = readObject(exchange);
        String id = optionalText(body, "providerId",
                "provider-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16));
        var saved = saveProviderBody(exchange, id, body, null);
        sendJson(exchange, 201, providerMap(saved));
    }

    private void updateProvider(HttpExchange exchange, String providerId) throws IOException {
        var existing = store.requireProvider(providerId);
        Map<String, Object> body = readObject(exchange);
        sendJson(exchange, 200, providerMap(saveProviderBody(exchange, providerId, body, existing)));
    }

    private com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.ProviderData saveProviderBody(
            HttpExchange exchange, String providerId, Map<String, Object> body,
            com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.ProviderData existing) {
        String name = optionalText(body, "name", existing == null ? null : existing.name());
        String kindText = optionalText(body, "kind", existing == null ? null : existing.kind().name());
        String baseUrl = optionalText(body, "baseUrl", existing == null ? null : existing.baseUrl());
        if (name == null || kindText == null || baseUrl == null) {
            throw new ApiException(400, "INVALID_PROVIDER", "name, kind, and baseUrl are required");
        }
        ProviderKind kind;
        try { kind = ProviderKind.valueOf(kindText); }
        catch (IllegalArgumentException invalid) {
            throw new ApiException(400, "INVALID_PROVIDER_KIND", "unsupported provider kind");
        }
        String model = optionalText(body, "model", existing == null ? null : existing.model());
        boolean enabled = optionalBoolean(body, "enabled", existing == null || existing.enabled());
        String apiKey = body.containsKey("apiKey") ? optionalText(body, "apiKey", null) : null;
        return store.saveProvider(providerId, name, kind, baseUrl, model, enabled, apiKey,
                actor(exchange).operatorId(), Instant.now(clock).toString());
    }

    private void deleteProvider(HttpExchange exchange, String providerId) throws IOException {
        store.deleteProvider(providerId, actor(exchange).operatorId(), Instant.now(clock).toString());
        sendEmpty(exchange, 204);
    }

    private void refreshProviderModels(HttpExchange exchange, String providerId) throws IOException {
        var provider = store.requireProvider(providerId);
        if (!provider.enabled()) {
            throw new ApiException(409, "PROVIDER_DISABLED",
                    "provider must be enabled before inventory refresh");
        }
        if (!provider.hasCredential()) {
            throw new ApiException(409, "PROVIDER_CREDENTIAL_REQUIRED",
                    "provider credential is required for inventory refresh");
        }
        if (provider.kind() == ProviderKind.AZURE_OPENAI) {
            throw new ApiException(422, "PROVIDER_INVENTORY_UNSUPPORTED",
                    "provider kind does not support model inventory");
        }
        ProviderDefinition definition;
        try {
            definition = new ProviderDefinition(1,
                    com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.LOCAL_WORKSPACE,
                    provider.providerId(), provider.name(), provider.kind(), URI.create(provider.baseUrl()),
                    provider.enabled(), provider.hasCredential(), Instant.parse(provider.createdAt()),
                    Instant.parse(provider.updatedAt()));
        } catch (RuntimeException invalidConfiguration) {
            throw new ApiException(409, "PROVIDER_CONFIGURATION_INVALID",
                    "provider configuration is invalid");
        }
        ModelInventory inventory;
        try {
            inventory = store.withProviderCredential(providerId,
                    credential -> providerInventoryService.fetch(definition, credential));
        } catch (ProviderSecretCipher.SecretCipherException invalidCredential) {
            throw new ApiException(409, "PROVIDER_CREDENTIAL_INVALID",
                    "provider credential could not be used");
        } catch (ControlPlaneStore.MissingRecordException missingCredential) {
            throw new ApiException(409, "PROVIDER_CREDENTIAL_REQUIRED",
                    "provider credential is required for inventory refresh");
        } catch (RuntimeException providerFailure) {
            throw new ApiException(502, "PROVIDER_INVENTORY_FAILED",
                    "provider inventory request failed");
        }
        if (inventory == null
                || !definition.workspaceId().equals(inventory.workspaceId())
                || !providerId.equals(inventory.providerId())) {
            throw new ApiException(502, "PROVIDER_INVENTORY_INVALID",
                    "provider inventory response was invalid");
        }
        sendJson(exchange, 200, inventoryMap(inventory));
    }

    private void listRoleAssignments(HttpExchange exchange, String projectId) throws IOException {
        List<Object> items = new ArrayList<>();
        for (var binding : store.roleBindings(projectId)) items.add(roleBindingMap(binding));
        sendJson(exchange, 200, stringEnvelope("roleAssignments", items));
    }

    private void sendRoleAssignment(HttpExchange exchange, String projectId, AgentRole role) throws IOException {
        var binding = store.roleBindings(projectId).stream().filter(value -> value.role() == role)
                .findFirst().orElseThrow(() -> new ControlPlaneStore.MissingRecordException(
                        "role assignment not found"));
        sendJson(exchange, 200, roleBindingMap(binding));
    }

    private void saveRoleAssignment(HttpExchange exchange, String projectId, AgentRole role) throws IOException {
        Map<String, Object> body = readObject(exchange);
        String providerId = optionalText(body, "providerId", null);
        if (providerId == null) throw new ApiException(400, "PROVIDER_REQUIRED", "providerId is required");
        var provider = store.requireProvider(providerId);
        String model = optionalText(body, "model", provider.model());
        if (model == null) throw new ApiException(400, "MODEL_REQUIRED", "model is required");
        String promptZh = optionalPrompt(body, "promptZh");
        String promptEn = optionalPrompt(body, "promptEn");
        sendJson(exchange, 200, roleBindingMap(store.saveRoleBinding(projectId, role, providerId, model,
                promptZh, promptEn, actor(exchange).operatorId(), Instant.now(clock).toString())));
    }

    private void deleteRoleAssignment(HttpExchange exchange, String projectId, AgentRole role) throws IOException {
        store.deleteRoleBinding(projectId, role, actor(exchange).operatorId(), Instant.now(clock).toString());
        sendEmpty(exchange, 204);
    }

    private void listAiJobs(HttpExchange exchange, String projectId) throws IOException {
        List<Object> items = new ArrayList<>();
        for (var job : store.aiJobs(projectId)) items.add(aiJobMap(job));
        sendJson(exchange, 200, stringEnvelope("aiJobs", items));
    }

    private void createAiJob(HttpExchange exchange, String projectId) throws IOException {
        Map<String, Object> body = readObject(exchange);
        for (String field : body.keySet()) {
            if (!Set.of("role", "scanId", "authorized", "outputLanguage").contains(field)) {
                throw new ApiException(400, "AI_JOB_FIELD_REJECTED",
                        "AI job body only accepts role, scanId, authorized and outputLanguage");
            }
        }
        AgentRole role = role(optionalText(body, "role", null));
        String scanId = optionalText(body, "scanId", null);
        AiOutputLanguage outputLanguage = outputLanguage(optionalText(
                body, "outputLanguage", AiOutputLanguage.ZH_CN.name()));
        if (!requiredBoolean(body, "authorized")) {
            throw new ApiException(403, "AUTHORIZATION_REQUIRED",
                    "explicit AI job authorization is required");
        }
        String operatorId = actor(exchange).operatorId();
        var job = store.createAiJob(projectId, role, scanId, outputLanguage, true, operatorId,
                Instant.now(clock).toString());
        aiJobOrchestrator.submit(job, operatorId);
        sendJson(exchange, 202, aiJobMap(job));
    }

    private void sendAiJob(HttpExchange exchange, String jobId) throws IOException {
        sendJson(exchange, 200, aiJobMap(store.requireAiJob(jobId)));
    }

    private void listAiJobEvents(HttpExchange exchange, String jobId) throws IOException {
        var job = store.requireAiJob(jobId);
        var events = store.aiJobEvents(jobId);
        if (events.size() > MAX_AI_JOB_EVENTS) {
            throw new ApiException(500, "AI_JOB_EVENT_BOUND_INVALID",
                    "stored AI job event history exceeds its fixed bound");
        }
        List<Object> items = new ArrayList<>();
        long expectedSequence = 1;
        for (var event : events) {
            if (!job.aiJobId().equals(event.aiJobId())
                    || !job.workspaceId().equals(event.workspaceId())
                    || !job.projectId().equals(event.projectId())) {
                throw new ApiException(500, "AI_JOB_EVENT_SCOPE_INVALID",
                        "stored AI job event scope does not match its job");
            }
            if (event.sequence() != expectedSequence++) {
                throw new ApiException(500, "AI_JOB_EVENT_ORDER_INVALID",
                        "stored AI job events are not contiguous and ordered");
            }
            items.add(aiJobEventMap(event, job.stopReason()));
        }
        Map<String, Object> response = stringEnvelope("aiJobEvents", items);
        response.put("aiJobId", job.aiJobId());
        response.put("projectId", job.projectId());
        sendJson(exchange, 200, response);
    }

    private void updateAiJob(HttpExchange exchange, String jobId) throws IOException {
        String action = optionalText(readObject(exchange), "action", null);
        if ("retry".equals(action)) {
            throw new ApiException(409, "RETRY_REQUIRES_NEW_AUTHORIZATION",
                    "create a new explicitly authorized AI job");
        }
        if (!"cancel".equals(action)) throw new ApiException(400, "INVALID_ACTION", "action must be cancel or retry");
        var cancelled = store.cancelAiJob(jobId, actor(exchange).operatorId(), Instant.now(clock).toString());
        aiJobOrchestrator.cancel(jobId);
        sendJson(exchange, 200, aiJobMap(cancelled));
    }

    private void deleteAiJob(HttpExchange exchange, String jobId) throws IOException {
        var existing = store.requireAiJob(jobId);
        if ("QUEUED".equals(existing.status()) || "RUNNING".equals(existing.status())) {
            throw new ApiException(409, "AI_JOB_ACTIVE",
                    "cancel the AI job before deletion");
        }
        store.deleteAiJob(jobId, actor(exchange).operatorId(), Instant.now(clock).toString());
        sendEmpty(exchange, 204);
    }

    private void listAudit(HttpExchange exchange, String projectId) throws IOException {
        List<Object> items = new ArrayList<>();
        for (var event : store.auditEvents(projectId)) items.add(auditMap(event));
        sendJson(exchange, 200, stringEnvelope("auditEvents", items));
    }

    private synchronized void registerArtifact(HttpExchange exchange, String projectId) throws IOException {
        ControlPlaneStore.ProjectRecord project = store.requireProject(projectId);
        String idempotencyHeader = requestIdempotencyKey(exchange);
        ensureIdempotencyCapacity(idempotentArtifacts,
                idempotencyHeader == null ? null : projectId + ":" + idempotencyHeader);
        Map<String, Object> body = readObject(exchange);
        String payload = JsonCodec.stringify(body);
        String durableScope = "artifact:create:" + projectId;
        ensureIdempotencyCapacity(durableIdempotency,
                idempotencyHeader == null ? null : idempotencyMapKey(durableScope, idempotencyHeader));
        if (body.containsKey("authorized") && !requiredBoolean(body, "authorized")) {
            throw new ApiException(403, "AUTHORIZATION_REQUIRED", "artifact authorization was denied");
        }
        SQLiteControlPlanePersistence.IdempotencyData durable = existingDurableIdempotency(
                durableScope, idempotencyHeader, payload);
        if (idempotencyHeader != null) {
            String existingDigest = idempotentArtifacts.get(projectId + ":" + idempotencyHeader);
            if (existingDigest == null && durable != null) existingDigest = durable.resultRef();
            if (existingDigest != null) {
                ArtifactDescriptor existing = store.artifact(project, existingDigest);
                if (existing != null) {
                    sendJson(exchange, 200, artifactMap(artifactDto(projectId, existing)));
                    return;
                }
            }
        }
        String rawPath = optionalText(body, "path", optionalText(body, "artifactPath", null));
        if (rawPath == null) throw new ApiException(400, "PATH_REQUIRED", "artifact path is required");
        ArtifactDescriptor descriptor = artifactRegistry.register(Path.of(rawPath));
        artifactRegistry.verifyUnchanged(descriptor);
        store.registerArtifact(project, descriptor, actor(exchange).operatorId());
        if (idempotencyHeader != null) {
            idempotentArtifacts.putIfAbsent(projectId + ":" + idempotencyHeader, descriptor.sha256());
            rememberDurableIdempotency(durableScope, idempotencyHeader, payload, descriptor.sha256(), null);
        }
        sendJson(exchange, 201, artifactMap(artifactDto(projectId, descriptor)));
    }

    private void initializeArtifactUpload(HttpExchange exchange, String projectId) throws IOException {
        store.requireProject(projectId);
        Map<String, Object> body = readObject(exchange);
        String fileName = optionalText(body, "fileName", null);
        String sha256 = optionalText(body, "sha256", null);
        if (fileName == null || sha256 == null || !body.containsKey("sizeBytes")) {
            throw new ApiException(400, "UPLOAD_METADATA_REQUIRED",
                    "fileName, sizeBytes and sha256 are required");
        }
        long sizeBytes = positiveLong(body, "sizeBytes", -1);
        ArtifactUploadService.UploadSession session =
                artifactUploadService.initialize(projectId, fileName, sizeBytes, sha256);
        sendJson(exchange, 201, uploadSessionMap(session));
    }

    private void appendArtifactUpload(HttpExchange exchange, String projectId,
                                      String uploadId) throws IOException {
        store.requireProject(projectId);
        String rawOffset = query(exchange.getRequestURI(), "offset");
        if (rawOffset == null) {
            throw new ApiException(400, "OFFSET_REQUIRED", "offset query parameter is required");
        }
        long offset = nonNegativeLong(rawOffset, "offset");
        String rawLength = exchange.getRequestHeaders().getFirst("Content-Length");
        if (rawLength == null) {
            throw new ApiException(411, "CONTENT_LENGTH_REQUIRED", "Content-Length is required");
        }
        long contentLength = parseContentLength(rawLength);
        String chunkSha256 = exchange.getRequestHeaders().getFirst("X-Chunk-SHA256");
        if (chunkSha256 == null) {
            throw new ApiException(400, "CHUNK_DIGEST_REQUIRED", "X-Chunk-SHA256 is required");
        }
        ArtifactUploadService.UploadSession session = artifactUploadService.append(
                projectId, uploadId, offset, contentLength, chunkSha256, exchange.getRequestBody());
        sendJson(exchange, 200, uploadSessionMap(session));
    }

    private void completeArtifactUpload(HttpExchange exchange, String projectId,
                                        String uploadId) throws IOException {
        ControlPlaneStore.ProjectRecord project = store.requireProject(projectId);
        Map<String, Object> body = readObject(exchange);
        if (!requiredBoolean(body, "authorized")) {
            throw new ApiException(403, "AUTHORIZATION_REQUIRED",
                    "artifact upload completion requires explicit authorization");
        }
        ArtifactDescriptor descriptor = artifactUploadService.complete(projectId, uploadId);
        store.registerArtifact(project, descriptor, actor(exchange).operatorId());
        artifactUploadService.finish(projectId, uploadId);
        sendJson(exchange, 201, artifactMap(artifactDto(projectId, descriptor)));
    }

    private void cancelArtifactUpload(HttpExchange exchange, String projectId,
                                      String uploadId) throws IOException {
        store.requireProject(projectId);
        artifactUploadService.cancel(projectId, uploadId);
        sendEmpty(exchange, 204);
    }

    private void listArtifacts(HttpExchange exchange, String projectId) throws IOException {
        ControlPlaneStore.ProjectRecord project = store.requireProject(projectId);
        List<Object> artifacts = new ArrayList<>();
        for (ArtifactDescriptor descriptor : store.artifacts(project)) artifacts.add(artifactMap(artifactDto(projectId, descriptor)));
        Map<String, Object> result = envelope(projectId, artifacts);
        result.put("artifacts", artifacts);
        result.put("artifactDigest", artifacts.isEmpty() ? "unscanned" : ((Map<?, ?>) artifacts.get(0)).get("artifactDigest"));
        result.put("scanId", project.latestScanId() == null ? "unscanned" : project.latestScanId());
        sendJson(exchange, 200, result);
    }

    private void listEntries(HttpExchange exchange, String projectId) throws IOException {
        ControlPlaneStore.ProjectRecord project = store.requireProject(projectId);
        String scanId = query(exchange.getRequestURI(), "scanId");
        ControlPlaneStore.ScanRecord scan = scanId == null ? latestScan(project) : store.scan(scanId);
        if (scan == null || !projectId.equals(scan.dto().projectId())) {
            Map<String, Object> result = envelope(projectId, List.of());
            result.put("entries", List.of());
            result.put("verificationStatus", "UNREACHED");
            result.put("artifactDigest", "unscanned");
            result.put("scanId", "unscanned");
            sendJson(exchange, 200, result);
            return;
        }
        List<Object> entries = new ArrayList<>();
        for (ApiDtos.EntryDto entry : scan.dto().entries()) entries.add(entryMap(entry));
        sendJson(exchange, 200, envelope(scan, "entries", entries));
    }

    private void listScans(HttpExchange exchange, String projectId) throws IOException {
        ControlPlaneStore.ProjectRecord project = store.requireProject(projectId);
        List<ControlPlaneStore.ScanRecord> records = store.scansForProject(projectId);
        List<Object> scans = new ArrayList<>(records.size());
        for (ControlPlaneStore.ScanRecord record : records) {
            scans.add(scanMap(record.dto()));
        }
        Map<String, Object> result = envelope(projectId, scans);
        result.put("scans", scans);
        String latest = project.latestScanId();
        ControlPlaneStore.ScanRecord latestRecord = latest == null ? null : store.scan(latest);
        result.put("artifactDigest", latestRecord == null ? "unscanned" : latestRecord.dto().artifactDigest());
        result.put("scanId", latestRecord == null ? "unscanned" : latestRecord.dto().scanId());
        result.put("latestScanId", latestRecord == null ? "unscanned" : latestRecord.dto().scanId());
        sendJson(exchange, 200, result);
    }

    private synchronized void startAudit(HttpExchange exchange, String projectId) throws IOException {
        String key = requireIdempotencyKey(exchange);
        String replayKey = projectId + ":" + key;
        ensureIdempotencyCapacity(idempotentAuditRuns, replayKey);
        Map<String, Object> body = readObject(exchange);
        Set<String> allowed = Set.of(
                "artifactDigest", "artifactId", "artifact", "authorized", "aiAuthorized", "dependencyMode",
                "outputLanguage",
                "networkMode", "dangerousActionMode", "networkAllowlist",
                "maxWallClockSeconds", "maxMemoryBytes", "maxDiskBytes");
        for (String field : body.keySet()) {
            if (!allowed.contains(field)) {
                throw new ApiException(400, "AUDIT_RUN_FIELD_REJECTED",
                        "audit run body contains an unsupported field");
            }
        }
        if (!requiredBoolean(body, "authorized")) {
            throw new ApiException(403, "AUTHORIZATION_REQUIRED",
                    "explicit scan authorization is required");
        }
        if (!requiredBoolean(body, "aiAuthorized")) {
            throw new ApiException(403, "AI_AUTHORIZATION_REQUIRED",
                    "explicit PRE_ANALYSIS authorization is required");
        }
        String payload = JsonCodec.stringify(body);
        String durableScope = "audit-run:create:" + projectId;
        ensureIdempotencyCapacity(durableIdempotency, idempotencyMapKey(durableScope, key));
        SQLiteControlPlanePersistence.IdempotencyData durable = existingDurableIdempotency(
                durableScope, key, payload);
        AuditRunReplay replay = idempotentAuditRuns.get(replayKey);
        if (replay == null && durable != null && durable.resultJson() != null) {
            Map<String, Object> stored = JsonCodec.parseObject(durable.resultJson());
            replay = new AuditRunReplay(payload, textValue(stored, "scanId"),
                    textValue(stored, "preAnalysisJobId"));
            idempotentAuditRuns.putIfAbsent(replayKey, replay);
        }
        if (replay != null) {
            if (!replay.payload().equals(payload)) {
                throw new ApiException(409, "IDEMPOTENCY_CONFLICT",
                        "Idempotency-Key was already used with a different audit request");
            }
            ControlPlaneStore.ScanRecord scan = store.requireScan(replay.scanId());
            var job = store.requireAiJob(replay.preAnalysisJobId());
            sendJson(exchange, 200, auditRunMap(scan.dto(), job));
            return;
        }

        String operatorId = actor(exchange).operatorId();
        AiOutputLanguage outputLanguage = outputLanguage(optionalText(
                body, "outputLanguage", AiOutputLanguage.ZH_CN.name()));
        Map<String, Object> scanBody = new LinkedHashMap<>(body);
        scanBody.remove("aiAuthorized");
        scanBody.remove("outputLanguage");
        ScanStart started = createOrReplayScan(projectId, scanBody, "audit-run-" + key, operatorId);
        var job = store.createAiJob(projectId, AgentRole.PRE_ANALYSIS,
                started.scan().dto().scanId(), outputLanguage, true, operatorId,
                Instant.now(clock).toString());
        auditPipeline.arm(new AuditPipelineCoordinator.Arm(
                started.scan().dto().scanId(), projectId, operatorId, outputLanguage));
        aiJobOrchestrator.submit(job, operatorId);
        idempotentAuditRuns.put(replayKey,
                new AuditRunReplay(payload, started.scan().dto().scanId(), job.aiJobId()));
        rememberDurableIdempotency(durableScope, key, payload, started.scan().dto().scanId(),
                JsonCodec.stringify(Map.of("scanId", started.scan().dto().scanId(),
                        "preAnalysisJobId", job.aiJobId())));
        sendJson(exchange, 202, auditRunMap(started.scan().dto(), job));
    }

    /**
     * Re-arms the scan pipeline and re-enqueues one failed stage. Creates a new authorized
     * AI job / dynamic task; never mutates the failed record into success.
     */
    private synchronized void retryAuditStage(HttpExchange exchange, String projectId) throws IOException {
        Map<String, Object> body = readObject(exchange);
        for (String field : body.keySet()) {
            if (!Set.of("scanId", "stage", "authorized", "aiAuthorized", "outputLanguage").contains(field)) {
                throw new ApiException(400, "RETRY_FIELD_REJECTED",
                        "audit stage retry body contains an unsupported field");
            }
        }
        if (!requiredBoolean(body, "authorized")) {
            throw new ApiException(403, "AUTHORIZATION_REQUIRED",
                    "explicit authorization is required to retry an audit stage");
        }
        String scanId = optionalText(body, "scanId", null);
        String stageRaw = optionalText(body, "stage", null);
        if (scanId == null || scanId.isBlank() || stageRaw == null || stageRaw.isBlank()) {
            throw new ApiException(400, "RETRY_FIELD_REQUIRED", "scanId and stage are required");
        }
        String stage = stageRaw.toUpperCase(Locale.ROOT);
        ControlPlaneStore.ScanRecord scan = store.requireScan(scanId);
        if (!scan.dto().projectId().equals(projectId)) {
            throw new ApiException(404, "SCAN_NOT_FOUND", "scan not found for project");
        }
        String operatorId = actor(exchange).operatorId();
        AiOutputLanguage language = outputLanguage(optionalText(
                body, "outputLanguage", AiOutputLanguage.ZH_CN.name()));
        auditPipeline.arm(new AuditPipelineCoordinator.Arm(scanId, projectId, operatorId, language));
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", 1);
        result.put("projectId", projectId);
        result.put("scanId", scanId);
        result.put("stage", stage);
        result.put("pipelineArmed", true);
        switch (stage) {
            case "PRE_ANALYSIS", "AUTH_ANALYSIS", "AUTH_BYPASS_CONFIRM", "PATH_EXPLORATION",
                    "DYNAMIC_VERIFICATION", "VULNERABILITY_TRIAGE", "REPORT_GENERATION" -> {
                if ("AUTH_BYPASS_CONFIRM".equals(stage)) {
                    stage = "AUTH_ANALYSIS";
                }
                if (!requiredBoolean(body, "aiAuthorized")) {
                    throw new ApiException(403, "AI_AUTHORIZATION_REQUIRED",
                            "explicit AI authorization is required to retry a model stage");
                }
                AgentRole role = AgentRole.valueOf(stage);
                var job = store.createAiJob(projectId, role, scanId, language, true, operatorId,
                        Instant.now(clock).toString());
                aiJobOrchestrator.submit(job, operatorId);
                store.auditChange(projectId, operatorId, "audit-stage.retry", "ai-job", job.aiJobId(),
                        "{\"stage\":\"" + stage + "\",\"scanId\":\"" + scanId + "\"}",
                        Instant.now(clock).toString());
                result.put("aiJob", aiJobMap(job));
            }
            case "DYNAMIC_OBSERVATION", "TRUSTED_DOCKER", "DYNAMIC" -> {
                if (workerApi.snapshots(projectId, scanId).stream().anyMatch(snapshot ->
                        snapshot.lifecycle() == TaskLifecycle.QUEUED
                                || snapshot.lifecycle() == TaskLifecycle.LEASED
                                || snapshot.lifecycle() == TaskLifecycle.RUNNING
                                || snapshot.lifecycle() == TaskLifecycle.PAUSED)) {
                    throw new ApiException(409, "DYNAMIC_TASK_BUSY",
                            "a dynamic task is already active for this scan");
                }
                TaskSnapshot snapshot = enqueueDynamicForPipeline(scanId, operatorId);
                store.auditChange(projectId, operatorId, "audit-stage.retry", "worker-task",
                        snapshot.scope().taskId(),
                        "{\"stage\":\"DYNAMIC_OBSERVATION\",\"scanId\":\"" + scanId + "\"}",
                        Instant.now(clock).toString());
                result.put("dynamicTask", dynamicTaskMap(snapshot));
            }
            default -> throw new ApiException(400, "RETRY_STAGE_UNKNOWN",
                    "unsupported retry stage");
        }
        sendJson(exchange, 202, result);
    }

    private static ResourceBudget dynamicBudgetForArtifact(ArtifactDescriptor artifact, int probeCount) {
        long size = Math.max(0L, artifact.sizeBytes());
        int probes = Math.max(1, Math.min(512, probeCount));
        // Cold start (~90s) + batched loopback probes (~0.2s each) + teardown margin.
        long baseWall = size >= 80L * 1024 * 1024 ? 420 : size >= 20L * 1024 * 1024 ? 300 : 180;
        long wallSeconds = Math.min(3_600L, Math.max(baseWall, 150L + probes));
        long memoryBytes = size >= 80L * 1024 * 1024 ? 3L * 1024 * 1024 * 1024 : 2L * 1024 * 1024 * 1024;
        // Keep room for agent events plus one APPLICATION_REPORTED HTTP line per probe.
        long traceBytes = Math.min(16L * 1024 * 1024,
                Math.max(size >= 20L * 1024 * 1024 ? 4L * 1024 * 1024 : 512L * 1024,
                        512L * 1024 + probes * 2_048L));
        return new ResourceBudget(wallSeconds, wallSeconds * 1_000L, memoryBytes,
                64L * 1024 * 1024, traceBytes);
    }

    private static Map<String, Object> auditRunMap(
            ApiDtos.ScanDto scan,
            com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.AiJobData job) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", 1);
        result.put("auditRunId", "audit-" + scan.scanId().substring("scan-".length()));
        result.put("projectId", scan.projectId());
        result.put("artifactDigest", scan.artifactDigest());
        result.put("scanId", scan.scanId());
        result.put("status", "COMPLETED".equals(job.status())
                ? "PRE_ANALYSIS_COMPLETED"
                : "BLOCKED".equals(job.status()) ? "PRE_ANALYSIS_BLOCKED" : "PRE_ANALYSIS_QUEUED");
        result.put("scan", scanMap(scan));
        result.put("preAnalysisJob", aiJobMap(job));
        return result;
    }

    private synchronized void createScan(HttpExchange exchange, String projectId) throws IOException {
        Map<String, Object> body = readObject(exchange);
        ScanStart started = createOrReplayScan(projectId, body, requestIdempotencyKey(exchange),
                actor(exchange).operatorId());
        sendJson(exchange, started.replayed() ? 200 : 202, scanMap(started.scan().dto()));
    }

    private ScanStart createOrReplayScan(String projectId, Map<String, Object> body,
                                         String idempotencyHeader, String operatorId) throws IOException {
        ControlPlaneStore.ProjectRecord project = store.requireProject(projectId);
        ensureIdempotencyCapacity(idempotentScans,
                idempotencyHeader == null ? null : projectId + ":" + idempotencyHeader);
        String payload = JsonCodec.stringify(body);
        String durableScope = "scan:create:" + projectId;
        ensureIdempotencyCapacity(durableIdempotency,
                idempotencyHeader == null ? null : idempotencyMapKey(durableScope, idempotencyHeader));
        // Parse and validate the consent flag before serving an idempotent
        // replay.  Reusing a key must not turn an omitted authorization field
        // into an implicit permission to analyze an artifact.
        if (!optionalBoolean(body, "authorized", false)) {
            throw new ApiException(403, "AUTHORIZATION_REQUIRED", "scan authorization is required");
        }
        SQLiteControlPlanePersistence.IdempotencyData durable = existingDurableIdempotency(
                durableScope, idempotencyHeader, payload);
        if (idempotencyHeader != null) {
            String existingId = idempotentScans.get(projectId + ":" + idempotencyHeader);
            if (existingId == null && durable != null) existingId = durable.resultRef();
            if (existingId != null) {
                ControlPlaneStore.ScanRecord existing = store.scan(existingId);
                if (existing != null) {
                    return new ScanStart(existing, true);
                }
            }
        }
        String digestOrId = optionalText(body, "artifactDigest",
                optionalText(body, "artifactId", optionalText(body, "artifact", null)));
        if (digestOrId == null) throw new ApiException(400, "ARTIFACT_REQUIRED", "artifactDigest is required");
        ArtifactDescriptor descriptor = store.artifact(project, digestOrId);
        if (descriptor == null) throw new ApiException(404, "ARTIFACT_NOT_FOUND", "artifact is not registered for this project");
        ScanPolicy policy = policyFrom(body);
        PolicyValidator.requireStartAllowed(policy);
        artifactRegistry.verifyUnchanged(descriptor);

        String scanId = "scan-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        EventContext context = new EventContext(projectId, descriptor.sha256(), scanId, "task-preanalysis");
        publishEvent(scanId, context, "ScanCreated", "created", Map.of(
                "status", "QUEUED", "verificationStatus", ApiDtos.STATIC_INFERRED,
                "dependencyMode", ApiDtos.MOCK));
        publishEvent(scanId, context, "TaskLeased", "preanalysis", Map.of("status", "RUNNING"));

        ScanBuild build;
        try {
            // Re-check after metadata extraction as well as before it.  This
            // closes the TOCTOU window where a file can be replaced while a
            // ZIP/class listing is being read.
            PreAnalysisResult result = analysis.analyze(ArtifactMetadataReader.read(descriptor));
            artifactRegistry.verifyUnchanged(descriptor);
            build = buildScan(projectId, descriptor, scanId, result);
        } catch (ArtifactValidationException invalidArtifact) {
            publishEvent(scanId, context, "TaskStopped", "preanalysis", Map.of(
                    "status", "STOPPED", "reason", "INVALID_ARTIFACT"));
            throw invalidArtifact;
        } catch (IOException analysisFailure) {
            publishEvent(scanId, context, "TaskStopped", "preanalysis", Map.of(
                    "status", "STOPPED", "reason", "STATIC_ANALYSIS_FAILED"));
            throw new ApiException(422, "ANALYSIS_FAILED", "static metadata analysis could not complete");
        } catch (RuntimeException analysisFailure) {
            publishEvent(scanId, context, "TaskStopped", "preanalysis", Map.of(
                    "status", "STOPPED", "reason", "STATIC_ANALYSIS_FAILED"));
            throw new ApiException(422, "ANALYSIS_FAILED", "static metadata analysis could not complete");
        }
        ControlPlaneStore.ScanRecord scanRecord =
                new ControlPlaneStore.ScanRecord(build.scan(), build.evidence(), build.findings(), build.chains());
        store.saveScan(scanRecord, operatorId);
        if (idempotencyHeader != null) {
            idempotentScans.putIfAbsent(projectId + ":" + idempotencyHeader, scanId);
            rememberDurableIdempotency(durableScope, idempotencyHeader, payload, scanId, null);
        }
        for (ApiDtos.FindingDto finding : build.findings()) {
            publishEvent(scanId, context, "FindingUpdated", finding.findingId(), Map.of(
                    "findingId", finding.findingId(), "verificationStatus", finding.verificationStatus(),
                    "evidenceRefs", finding.evidenceRefs()));
        }
        publishEvent(scanId, context, "ScanCompleted", "completed", Map.of(
                "status", "COMPLETED", "verificationStatus", ApiDtos.STATIC_INFERRED,
                "dependencyMode", ApiDtos.MOCK, "evidenceRefs", build.scan().evidenceRefs()));
        return new ScanStart(scanRecord, false);
    }

    private void sendScan(HttpExchange exchange, String scanId) throws IOException {
        sendJson(exchange, 200, scanMap(store.requireScan(scanId).dto()));
    }

    private synchronized void createDynamicTask(HttpExchange exchange, String scanId) throws IOException {
        String key = requireIdempotencyKey(exchange);
        String replayKey = scanId + ":" + key;
        if (!idempotentDynamicTasks.containsKey(replayKey)
                && idempotentDynamicTasks.size() >= MAX_IDEMPOTENCY_KEYS) {
            throw new ApiException(429, "IDEMPOTENCY_LIMIT", "idempotency key store is full");
        }

        Map<String, Object> body = readObject(exchange);
        String requestPayload = JsonCodec.stringify(body);
        String durableScope = "dynamic-task:create:" + scanId;
        ensureIdempotencyCapacity(durableIdempotency, idempotencyMapKey(durableScope, key));
        for (String field : body.keySet()) {
            if (!Set.of("authorized").contains(field)) {
                throw new ApiException(400, "RUNTIME_FIELD_REJECTED",
                        "dynamic task body only accepts authorized");
            }
        }
        if (!body.containsKey("authorized") || !requiredBoolean(body, "authorized")) {
            throw new ApiException(403, "AUTHORIZATION_REQUIRED", "dynamic task authorization is required");
        }
        String operatorId = actor(exchange).operatorId();
        DynamicTaskReplay existing = idempotentDynamicTasks.get(replayKey);
        SQLiteControlPlanePersistence.IdempotencyData durable = existingDurableIdempotency(
                durableScope, key, requestPayload);
        if (existing == null && durable != null) {
            TaskSnapshot restored = workerApi.snapshots(store.requireScan(scanId).dto().projectId(), scanId).stream()
                    .filter(value -> value.scope().taskId().equals(durable.resultRef())).findFirst().orElse(null);
            if (restored != null) {
                existing = new DynamicTaskReplay(new DynamicTaskPayload(
                        scanId, restored.spec().artifactDigest(), restored.spec().targetEntryId()), restored);
                idempotentDynamicTasks.putIfAbsent(replayKey, existing);
            }
        }
        TaskSnapshot snapshot;
        if (existing != null) {
            snapshot = existing.snapshot();
            sendJson(exchange, 200, dynamicTaskMap(snapshot));
            return;
        }
        snapshot = enqueueDynamicForPipeline(scanId, operatorId);
        DynamicTaskPayload payload = new DynamicTaskPayload(
                scanId, snapshot.spec().artifactDigest(), snapshot.spec().targetEntryId());
        DynamicTaskReplay conflict = idempotentDynamicTasks.putIfAbsent(
                replayKey, new DynamicTaskReplay(payload, snapshot));
        if (conflict != null) {
            sendJson(exchange, 200, dynamicTaskMap(conflict.snapshot()));
            return;
        }
        rememberDurableIdempotency(durableScope, key, requestPayload, snapshot.scope().taskId(), null);
        sendJson(exchange, 202, dynamicTaskMap(snapshot));
    }

    private Optional<ToolDataSource.FactRecord> requestSandboxProbe(
            String scanId, ToolExecutionContext.Scope scope, String principalId, String jobId,
            String entrypointRef, List<String> candidateInputs, int maxRequests) {
        if (!"local".equals(scope.workspaceId()) || principalId == null || principalId.isBlank()) {
            throw new SecurityException("sandbox probe scope is invalid");
        }
        ControlPlaneStore.ScanRecord scan = store.requireScan(scanId);
        if (!scope.projectId().equals(scan.dto().projectId())) {
            throw new SecurityException("sandbox probe project scope mismatch");
        }
        if (entrypointRef == null || !entrypointRef.startsWith("entry:")) {
            throw new IllegalArgumentException("sandbox probe requires an entry evidence reference");
        }
        String entryId = entrypointRef.substring("entry:".length());
        ApiDtos.EntryDto entry = scan.dto().entries().stream()
                .filter(value -> value.id().equals(entryId)).findFirst()
                .orElseThrow(() -> new IllegalArgumentException("sandbox probe entry is not in scan"));
        if (!"HTTP".equalsIgnoreCase(entry.protocol()) || entry.route() == null
                || entry.method() == null || maxRequests < 1 || maxRequests > 8) {
            throw new IllegalArgumentException("sandbox probe entry is not an eligible HTTP endpoint");
        }
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("entrypointRef", entrypointRef);
        request.put("candidateInputs", candidateInputs == null ? List.of() : candidateInputs);
        request.put("maxRequests", maxRequests);
        String requestPayload = JsonCodec.stringify(request);
        String durableScope = "sandbox-probe:job";
        ensureIdempotencyCapacity(durableIdempotency, idempotencyMapKey(durableScope, jobId));
        SQLiteControlPlanePersistence.IdempotencyData durable = existingDurableIdempotency(
                durableScope, jobId, requestPayload);
        TaskSnapshot existing = aiProbeTasks.get(jobId);
        if (existing == null && durable != null) {
            existing = workerApi.snapshots(scan.dto().projectId(), scanId).stream()
                    .filter(value -> value.scope().taskId().equals(durable.resultRef())).findFirst()
                    .orElseThrow(() -> new SQLiteControlPlanePersistence.PersistenceException(
                            "sandbox probe replay has no persistent worker task"));
            aiProbeTasks.putIfAbsent(jobId, existing);
        }
        if (existing != null) {
            TaskSnapshot refreshed = refreshTaskSnapshot(scan.dto().projectId(), scanId, existing.scope().taskId())
                    .orElse(existing);
            aiProbeTasks.put(jobId, refreshed);
            if (isActiveLifecycle(refreshed.lifecycle())) {
                refreshed = awaitDynamicTaskTerminal(scan.dto().projectId(), scanId, refreshed.scope().taskId(),
                        Duration.ofMinutes(8)).orElse(refreshed);
                aiProbeTasks.put(jobId, refreshed);
            }
            return Optional.of(probeFact(scope, refreshed, entry, probeState(refreshed), candidateInputs, maxRequests));
        }
        boolean scanBusy = workerApi.snapshots(scan.dto().projectId(), scanId).stream()
                .anyMatch(value -> isActiveLifecycle(value.lifecycle()));
        if (scanBusy) {
            // Do not bind a foreign in-flight task to the requested entry.
            Map<String, Object> busy = new LinkedHashMap<>();
            busy.put("schemaVersion", 1);
            busy.put("state", "BUSY");
            busy.put("scanId", scanId);
            busy.put("entrypointRef", entrypointRef);
            busy.put("method", entry.method());
            busy.put("route", entry.route());
            busy.put("networkMode", "DENY");
            busy.put("executor", "SERVER_OWNED_TRUSTED_DOCKER");
            busy.put("candidateCount", candidateInputs == null ? 0 : Math.min(16, candidateInputs.size()));
            busy.put("requestLimit", Math.min(8, Math.max(1, maxRequests)));
            busy.put("retryable", true);
            return Optional.of(new ToolDataSource.FactRecord(scope, "sandbox-probe:busy:" + jobId,
                    JSON.valueToTree(busy)));
        }
        TaskSnapshot snapshot = enqueueDynamicForPipeline(scanId, principalId, entryId, candidateInputs, maxRequests);
        if (aiProbeTasks.size() >= MAX_IDEMPOTENCY_KEYS && !aiProbeTasks.containsKey(jobId)) {
            throw new IllegalStateException("sandbox probe job limit reached");
        }
        aiProbeTasks.putIfAbsent(jobId, snapshot);
        rememberDurableIdempotency(durableScope, jobId, requestPayload, snapshot.scope().taskId(), null);
        TaskSnapshot finished = awaitDynamicTaskTerminal(scan.dto().projectId(), scanId, snapshot.scope().taskId(),
                Duration.ofMinutes(8)).orElse(snapshot);
        aiProbeTasks.put(jobId, finished);
        return Optional.of(probeFact(scope, finished, entry, probeState(finished), candidateInputs, maxRequests));
    }

    private static boolean isActiveLifecycle(TaskLifecycle lifecycle) {
        return lifecycle == TaskLifecycle.QUEUED
                || lifecycle == TaskLifecycle.LEASED
                || lifecycle == TaskLifecycle.RUNNING
                || lifecycle == TaskLifecycle.PAUSED;
    }

    private static String probeState(TaskSnapshot snapshot) {
        return switch (snapshot.lifecycle()) {
            case COMPLETED -> "COMPLETED";
            case FAILED -> "FAILED";
            case CANCELLED -> "CANCELLED";
            default -> "QUEUED";
        };
    }

    private Optional<TaskSnapshot> refreshTaskSnapshot(String projectId, String scanId, String taskId) {
        return workerApi.snapshots(projectId, scanId).stream()
                .filter(value -> value.scope().taskId().equals(taskId))
                .findFirst();
    }

    private Optional<TaskSnapshot> awaitDynamicTaskTerminal(String projectId, String scanId, String taskId,
                                                            Duration timeout) {
        long deadline = System.nanoTime() + timeout.toNanos();
        Optional<TaskSnapshot> latest = refreshTaskSnapshot(projectId, scanId, taskId);
        while (System.nanoTime() < deadline) {
            if (latest.isPresent() && !isActiveLifecycle(latest.get().lifecycle())) {
                return latest;
            }
            try {
                Thread.sleep(250L);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return latest;
            }
            latest = refreshTaskSnapshot(projectId, scanId, taskId);
        }
        return latest;
    }

    private static ToolDataSource.FactRecord probeFact(ToolExecutionContext.Scope scope,
                                                       TaskSnapshot snapshot,
                                                       ApiDtos.EntryDto entry,
                                                       String state,
                                                       List<String> candidateInputs,
                                                       int maxRequests) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("schemaVersion", 1);
        value.put("state", state);
        value.put("taskId", snapshot.scope().taskId());
        value.put("scanId", snapshot.scope().scanId());
        value.put("lifecycle", snapshot.lifecycle().name());
        value.put("entrypointRef", "entry:" + entry.id());
        value.put("method", entry.method());
        value.put("route", entry.route());
        value.put("networkMode", "DENY");
        value.put("executor", "SERVER_OWNED_TRUSTED_DOCKER");
        value.put("candidateCount", candidateInputs == null ? 0 : Math.min(16, candidateInputs.size()));
        value.put("requestLimit", Math.min(8, Math.max(1, maxRequests)));
        value.put("probePlanId", "probe-plan:" + snapshot.scope().taskId());
        if (snapshot.stopReason() != null) value.put("stopReason", snapshot.stopReason().name());
        if (snapshot.failureCode() != null) value.put("failureCode", snapshot.failureCode());
        return new ToolDataSource.FactRecord(scope, "sandbox-probe:" + snapshot.scope().taskId(),
                JSON.valueToTree(value));
    }

    private synchronized TaskSnapshot enqueueDynamicForPipeline(String scanId, String actorId) {
        return enqueueDynamicForPipeline(scanId, actorId, null, List.of(), 512);
    }

    private synchronized TaskSnapshot enqueueDynamicForPipeline(String scanId, String actorId,
                                                                 String preferredEntryId) {
        return enqueueDynamicForPipeline(scanId, actorId, preferredEntryId, List.of(), 512);
    }

    private synchronized TaskSnapshot enqueueDynamicForPipeline(String scanId, String actorId,
                                                                 String preferredEntryId,
                                                                 List<String> candidateInputs,
                                                                 int maxRequests) {
        ControlPlaneStore.ScanRecord scan = store.requireScan(scanId);
        ControlPlaneStore.ProjectRecord project = store.requireProject(scan.dto().projectId());
        ArtifactDescriptor artifact = store.artifact(project, scan.dto().artifactDigest());
        if (artifact == null) {
            throw new ApiException(409, "SCAN_SCOPE_INVALID", "scan artifact is not registered for project");
        }
        if (artifact.type() != com.aq.jvmsentinel.model.ArtifactType.JAR) {
            throw new ApiException(409, "JAR_REQUIRED", "Docker dynamic execution currently requires a JAR");
        }
        ProbePlan plan = buildProbePlan(scan, null, preferredEntryId, candidateInputs, maxRequests);
        if (plan.primary() == null) {
            throw new ApiException(409, "TARGET_ENTRY_NOT_IN_SCAN",
                    "the scan has no entrypoint to observe");
        }
        unreachedDynamicPaths.put(scanId, plan.unreachedPaths());
        String taskId = "task-dynamic-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        ResourceBudget budget = dynamicBudgetForArtifact(artifact, plan.probes().size());
        WorkerTaskSpec spec = new WorkerTaskSpec(
                WorkerControlPlaneApi.CONTRACT_VERSION,
                scan.dto().projectId(),
                scan.dto().artifactDigest(),
                scanId,
                taskId,
                plan.primary().id(),
                true,
                budget,
                NetworkPolicy.denyAll(),
                WorkerCapability.TRUSTED_DOCKER);
        dynamicProbePlans.put(taskId, plan);
        TaskSnapshot snapshot;
        try {
            snapshot = workerApi.enqueueFromControlPlane(spec,
                    "pipeline-dynamic-" + UUID.randomUUID().toString().replace("-", ""));
        } catch (RuntimeException failure) {
            dynamicProbePlans.remove(taskId, plan);
            throw failure;
        }
        List<String> boundedInputs = candidateInputs == null ? List.of()
                : candidateInputs.stream().filter(Objects::nonNull).limit(16).toList();
        String inputsJson = JsonCodec.stringify(boundedInputs);
        // V011 stores only bounded probe-input metadata (CHECK max_requests 1..8), not the
        // full flood size; actual probe count remains in the in-memory / recovered plan.
        int storedMaxRequests = Math.max(1, Math.min(8, maxRequests));
        store.persistProbePlan(new SQLiteControlPlanePersistence.ProbePlanData(
                taskId, scan.dto().projectId(), scan.dto().artifactDigest(), scanId,
                plan.primary().id(), inputsJson, storedMaxRequests,
                probePlanHash(scanId, plan.primary().id(), inputsJson, storedMaxRequests),
                Instant.now(clock).toString()));
        store.auditChange(scan.dto().projectId(), actorId, "dynamic-task.enqueue",
                "worker-task", taskId,
                "{\"capability\":\"TRUSTED_DOCKER\",\"networkMode\":\"DENY\",\"source\":\"PIPELINE\","
                        + "\"probeCount\":" + plan.probes().size()
                        + ",\"unreachedCount\":" + plan.unreachedPaths().size() + "}",
                Instant.now(clock).toString());
        return snapshot;
    }

    private void listDynamicTasks(HttpExchange exchange, String scanId) throws IOException {
        ControlPlaneStore.ScanRecord scan = store.requireScan(scanId);
        List<Object> tasks = workerApi.snapshots(scan.dto().projectId(), scanId).stream()
                .map(this::dynamicTaskWithDiagnostic).map(value -> (Object) value).toList();
        sendJson(exchange, 200, stringEnvelope("dynamicTasks", tasks));
    }

    private Map<String, Object> dynamicTaskWithDiagnostic(TaskSnapshot snapshot) {
        Map<String, Object> result = dynamicTaskMap(snapshot);
        String diagnostic = workerApi.failureDiagnostic(snapshot.scope());
        if (diagnostic != null) result.put("failureDiagnostic", diagnostic);
        String progress = workerApi.progressDetail(snapshot.scope());
        if (progress != null) result.put("progressDetail", progress);
        return result;
    }

    /**
     * Resolves only the immutable backend-managed copy for the process-local Docker worker.
     * This method does not expose the path through HTTP.
     */
    public ExternalArtifactTaskExecutor.ArtifactRegistration requireLocalArtifact(TaskScope scope) {
        Objects.requireNonNull(scope, "scope");
        ControlPlaneStore.ScanRecord scan = store.requireScan(scope.scanId());
        if (!scan.dto().projectId().equals(scope.projectId())
                || !scan.dto().artifactDigest().equals(scope.artifactDigest())) {
            throw new SecurityException("worker task scope does not match the persisted scan");
        }
        ControlPlaneStore.ProjectRecord project = store.requireProject(scope.projectId());
        ArtifactDescriptor artifact = store.artifact(project, scope.artifactDigest());
        if (artifact == null) throw new SecurityException("worker artifact is not registered");
        artifactRegistry.verifyUnchanged(artifact);
        Path path = artifact.normalizedPath().toAbsolutePath().normalize();
        Path managedRoot = artifactRegistry.allowedRoot().resolve(".veyrion")
                .resolve("artifacts").resolve("sha256").toAbsolutePath().normalize();
        if (!path.startsWith(managedRoot)
                || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(path)
                || !path.getFileName().toString().matches(scope.artifactDigest() + "\\.jar")) {
            throw new SecurityException("dynamic execution requires the managed content-addressed JAR copy");
        }
        if (!hasExecutableMainClass(path)) {
            throw new SecurityException("registered JAR has no executable Main-Class");
        }
        ProbePlan plan = dynamicProbePlans.getOrDefault(scope.taskId(), buildProbePlan(scan, scope.taskId()));
        if (plan.primary() == null) {
            throw new SecurityException("scan has no bounded HTTP probe target");
        }
        unreachedDynamicPaths.put(scope.scanId(), plan.unreachedPaths());
        ApiDtos.EntryDto entry = plan.primary();
        int packageSeparator = entry.declaringClass().lastIndexOf('.');
        String classPrefix = packageSeparator > 0
                ? entry.declaringClass().substring(0, packageSeparator) : entry.declaringClass();
        ExternalArtifactTaskExecutor.ProbeTarget primaryProbe = probeTargetFor(entry);
        return new ExternalArtifactTaskExecutor.ArtifactRegistration(
                scope.projectId(), scope.artifactDigest(), path, artifact.sizeBytes(), true,
                primaryProbe.method(), primaryProbe.route(), classPrefix, plan.probes());
    }

    /**
     * Builds a budgeted multi-entry probe plan for one TRUSTED_DOCKER task.
     * Entries beyond the budget become UNREACHED path placeholders (not silently dropped).
     */
    private void restoreProbePlans() {
        for (SQLiteControlPlanePersistence.ProbePlanData stored : store.loadProbePlans()) {
            ControlPlaneStore.ScanRecord scan = store.scan(stored.scanId());
            if (scan == null || !scan.dto().projectId().equals(stored.projectId())
                    || !scan.dto().artifactDigest().equals(stored.artifactDigest())) {
                throw new SQLiteControlPlanePersistence.PersistenceException("probe plan scope does not match scan");
            }
            TaskSnapshot task = workerApi.snapshots(stored.projectId(), stored.scanId()).stream()
                    .filter(value -> value.scope().taskId().equals(stored.taskId())).findFirst()
                    .orElseThrow(() -> new SQLiteControlPlanePersistence.PersistenceException(
                            "probe plan has no persistent worker task"));
            if (!task.spec().targetEntryId().equals(stored.targetEntryId())) {
                throw new SQLiteControlPlanePersistence.PersistenceException("probe plan target does not match task");
            }
            List<String> inputs = persistedStringList(stored.candidateInputsJson());
            String expectedHash = probePlanHash(stored.scanId(), stored.targetEntryId(),
                    stored.candidateInputsJson(), stored.maxRequests());
            if (!expectedHash.equals(stored.planHash())) {
                throw new SQLiteControlPlanePersistence.PersistenceException("probe plan checksum mismatch");
            }
            ProbePlan plan = buildProbePlan(scan, stored.taskId(), stored.targetEntryId(),
                    inputs, stored.maxRequests());
            dynamicProbePlans.put(stored.taskId(), plan);
        }
    }

    private static List<String> persistedStringList(String json) {
        Object value;
        try {
            value = JsonCodec.parse(json);
        } catch (IllegalArgumentException malformed) {
            throw new SQLiteControlPlanePersistence.PersistenceException("probe plan inputs are malformed", malformed);
        }
        if (!(value instanceof List<?> list) || list.size() > 16) {
            throw new SQLiteControlPlanePersistence.PersistenceException("probe plan input limit exceeded");
        }
        List<String> result = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof String text) || text.length() > 1024) {
                throw new SQLiteControlPlanePersistence.PersistenceException("probe plan input is invalid");
            }
            result.add(text);
        }
        return List.copyOf(result);
    }

    private static String probePlanHash(String scanId, String targetEntryId,
                                        String inputsJson, int maxRequests) {
        return payloadHash(scanId + "\n" + targetEntryId + "\n" + inputsJson + "\n"
                + Math.max(1, Math.min(8, maxRequests)));
    }

    private ProbePlan buildProbePlan(ControlPlaneStore.ScanRecord scan, String taskIdHint) {
        return buildProbePlan(scan, taskIdHint, null, List.of(), 512);
    }

    private ProbePlan buildProbePlan(ControlPlaneStore.ScanRecord scan, String taskIdHint,
                                     String preferredEntryId) {
        return buildProbePlan(scan, taskIdHint, preferredEntryId, List.of(), 512);
    }

    private ProbePlan buildProbePlan(ControlPlaneStore.ScanRecord scan, String taskIdHint,
                                     String preferredEntryId, List<String> candidateInputs,
                                     int requestedMaxRequests) {
        List<ApiDtos.EntryDto> httpEntries = scan.dto().entries().stream()
                .filter(entry -> "HTTP".equalsIgnoreCase(entry.protocol()))
                .filter(entry -> entry.route() != null
                        && entry.route().matches("/[A-Za-z0-9_./{}:-]{0,1023}"))
                .filter(entry -> entry.method() != null
                        && (Set.of("GET", "POST", "PUT", "PATCH", "DELETE")
                        .contains(entry.method().toUpperCase(Locale.ROOT))
                        || "UNKNOWN".equalsIgnoreCase(entry.method())))
                .toList();
        if (httpEntries.isEmpty()) {
            return new ProbePlan(null, List.of(), List.of());
        }
        // Cover every discovered HTTP entry in one batched probe JVM (hard cap matches worker).
        int maxProbes = Math.min(512, httpEntries.size());
        LinkedHashSet<String> selectedIds = new LinkedHashSet<>();
        List<ExternalArtifactTaskExecutor.ProbeTarget> probes = new ArrayList<>();
        if (preferredEntryId != null) {
            httpEntries.stream().filter(entry -> entry.id().equals(preferredEntryId)).findFirst()
                    .ifPresent(entry -> {
                        selectedIds.add(entry.id());
                        probes.add(probeTargetFor(entry));
                    });
        }
        // Prefer the worker task's target entry when present in the scan.
        if (taskIdHint != null) {
            workerApi.snapshots(scan.dto().projectId(), scan.dto().scanId()).stream()
                    .filter(snapshot -> snapshot.scope().taskId().equals(taskIdHint))
                    .map(snapshot -> snapshot.spec().targetEntryId())
                    .findFirst()
                    .flatMap(targetId -> httpEntries.stream().filter(entry -> entry.id().equals(targetId)).findFirst())
                    .ifPresent(entry -> {
                        if (selectedIds.add(entry.id())) probes.add(probeTargetFor(entry));
                    });
        }
        // Prefer entries named by PATH_EXPLORATION / plan_propose inferences (untrusted hints only).
        String explorationHint = pathExplorationHintText(scan);
        if (!explorationHint.isBlank()) {
            for (ApiDtos.EntryDto entry : httpEntries) {
                if (probes.size() >= maxProbes) break;
                if (!(explorationHint.contains(entry.id()) || explorationHint.contains(entry.route()))) {
                    continue;
                }
                if (!selectedIds.add(entry.id())) continue;
                probes.add(probeTargetFor(entry));
            }
        }
        for (ApiDtos.EntryDto entry : httpEntries) {
            if (probes.size() >= maxProbes) break;
            if (!selectedIds.add(entry.id())) continue;
            probes.add(probeTargetFor(entry));
        }
        ApiDtos.EntryDto primary = httpEntries.stream()
                .filter(entry -> selectedIds.contains(entry.id()))
                .findFirst()
                .orElse(httpEntries.get(0));
        List<ExternalArtifactTaskExecutor.ProbeTarget> candidateProbes = candidateProbeTargets(
                primary, candidateInputs, requestedMaxRequests);
        List<ExternalArtifactTaskExecutor.ProbeTarget> effectiveProbes = probes;
        if (!candidateProbes.isEmpty()) {
            effectiveProbes = candidateProbes;
            selectedIds.clear();
            selectedIds.add(primary.id());
        }
        effectiveProbes = expandProbesByIdentityTracks(scan, httpEntries, effectiveProbes, maxProbes);
        List<ApiDtos.PathDto> unreached = new ArrayList<>();
        for (ApiDtos.EntryDto entry : httpEntries) {
            if (selectedIds.contains(entry.id())) continue;
            unreached.add(new ApiDtos.PathDto(
                    ApiDtos.SCHEMA_VERSION, scan.dto().projectId(), scan.dto().artifactDigest(),
                    scan.dto().scanId(),
                    "path-unreached-" + scan.dto().scanId() + "-" + entry.id(),
                    entry.id(), ApiDtos.UNREACHED, ApiDtos.MOCK,
                    entry.preconditions(), "PROBE_BUDGET_EXHAUSTED", List.of(),
                    List.of(new ApiDtos.PathStepDto(entry.method() + " " + entry.route(),
                            "超出本次断网探针预算，未动态刺激", "entry", "blocked", entry.evidenceRefs()))));
        }
        return new ProbePlan(primary, List.copyOf(effectiveProbes), List.copyOf(unreached));
    }

    /** Converts only bounded name=value hints into URL query data for the selected entry. */
    private static List<ExternalArtifactTaskExecutor.ProbeTarget> candidateProbeTargets(
            ApiDtos.EntryDto entry, List<String> candidateInputs, int requestedMaxRequests) {
        if (candidateInputs == null || candidateInputs.isEmpty()) return List.of();
        int limit = Math.max(1, Math.min(8, requestedMaxRequests));
        List<String> parameterNames = entry.parameters() == null ? List.of() : entry.parameters().stream()
                .map(ControlPlaneServer::parameterName).filter(Objects::nonNull).limit(12).toList();
        List<ExternalArtifactTaskExecutor.ProbeTarget> result = new ArrayList<>();
        for (String candidate : candidateInputs) {
            if (result.size() >= limit || candidate == null || candidate.length() > 1024) break;
            String name;
            String value;
            int separator = candidate.indexOf('=');
            if (separator > 0) {
                name = candidate.substring(0, separator);
                value = candidate.substring(separator + 1);
            } else if (!parameterNames.isEmpty()) {
                name = parameterNames.get(Math.min(result.size(), parameterNames.size() - 1));
                value = candidate;
            } else {
                continue;
            }
            if (!name.matches("[A-Za-z][A-Za-z0-9_]{0,63}") || value.length() > 512
                    || value.chars().anyMatch(character -> character < 0x20 || character == 0x7f)
                    || parameterNames.isEmpty() || !parameterNames.contains(name)) continue;
            String encoded = java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
            result.add(new ExternalArtifactTaskExecutor.ProbeTarget(
                    entry.method() == null || "UNKNOWN".equalsIgnoreCase(entry.method())
                            ? "GET" : entry.method().toUpperCase(Locale.ROOT),
                    materializeRoute(entry.route()), name + "=" + encoded));
        }
        return List.copyOf(result);
    }

    private static String parameterName(String parameter) {
        if (parameter == null) return null;
        int nameAt = parameter.indexOf("name=");
        if (nameAt < 0) return null;
        String name = parameter.substring(nameAt + 5).split("[,\\s]", 2)[0].trim();
        return name.matches("[A-Za-z][A-Za-z0-9_]{0,63}") ? name : null;
    }

    private record ProbePlan(ApiDtos.EntryDto primary,
                             List<ExternalArtifactTaskExecutor.ProbeTarget> probes,
                             List<ApiDtos.PathDto> unreachedPaths) {
    }

    private static ExternalArtifactTaskExecutor.ProbeTarget probeTargetFor(ApiDtos.EntryDto entry) {
        String method = entry.method() == null ? "GET" : entry.method().toUpperCase(Locale.ROOT);
        if ("UNKNOWN".equals(method)) method = "GET";
        return new ExternalArtifactTaskExecutor.ProbeTarget(
                method, materializeRoute(entry.route()), syntheticQuery(entry), "UNAUTH", "");
    }

    /**
     * T2+T3: high-value entries probe all synthesizable tracks; others UNAUTH + ADMIN when available.
     * Total probes remain capped by {@code maxProbes}.
     */
    private List<ExternalArtifactTaskExecutor.ProbeTarget> expandProbesByIdentityTracks(
            ControlPlaneStore.ScanRecord scan,
            List<ApiDtos.EntryDto> httpEntries,
            List<ExternalArtifactTaskExecutor.ProbeTarget> base,
            int maxProbes) {
        if (base == null || base.isEmpty()) return List.of();
        Path artifactPath = null;
        try {
            ControlPlaneStore.ProjectRecord project = store.requireProject(scan.dto().projectId());
            ArtifactDescriptor artifact = store.artifact(project, scan.dto().artifactDigest());
            if (artifact != null) artifactPath = artifact.normalizedPath();
        } catch (RuntimeException ignored) {
            artifactPath = null;
        }
        SyntheticIdentityService identity = new SyntheticIdentityService();
        List<String> routes = httpEntries.stream().map(ApiDtos.EntryDto::route).toList();
        boolean packMatch = !AnalysisPackRegistry.matching(artifactPath, routes).isEmpty();
        Map<String, ApiDtos.EntryDto> byRoute = new LinkedHashMap<>();
        for (ApiDtos.EntryDto entry : httpEntries) {
            byRoute.putIfAbsent(materializeRoute(entry.route()), entry);
        }
        List<ExternalArtifactTaskExecutor.ProbeTarget> expanded = new ArrayList<>();
        for (ExternalArtifactTaskExecutor.ProbeTarget probe : base) {
            if (expanded.size() >= maxProbes) break;
            ApiDtos.EntryDto entry = byRoute.get(probe.route());
            boolean highValue = packMatch || isHighValueRoute(probe.route());
            Map<IdentityTrack, SyntheticIdentityService.SyntheticIdentity> tracks =
                    identity.defaultTracks(artifactPath, highValue);
            for (Map.Entry<IdentityTrack, SyntheticIdentityService.SyntheticIdentity> item : tracks.entrySet()) {
                if (expanded.size() >= maxProbes) break;
                SyntheticIdentityService.SyntheticIdentity synth = item.getValue();
                if (!synth.available() && item.getKey() != IdentityTrack.UNAUTH) continue;
                expanded.add(new ExternalArtifactTaskExecutor.ProbeTarget(
                        probe.method(), probe.route(), probe.query(),
                        item.getKey().name(),
                        synth.available() ? synth.authorizationHeader() : ""));
            }
        }
        return List.copyOf(expanded.isEmpty() ? base : expanded);
    }

    private static boolean isHighValueRoute(String route) {
        String value = route == null ? "" : route.toLowerCase(Locale.ROOT);
        return value.contains("admin") || value.contains("upload") || value.contains("deploy")
                || value.contains("token") || value.contains("exec") || value.contains("flowable")
                || value.contains("bpmn") || value.contains("oauth") || value.contains("blade-");
    }

    /** Replace `{pathVar}` templates with a bounded synthetic token for loopback probes. */
    private static String materializeRoute(String route) {
        if (route == null || route.isBlank()) return "/";
        String materialized = route.replaceAll("\\{[A-Za-z_][A-Za-z0-9_]{0,63}}", "1");
        if (!materialized.matches("/[A-Za-z0-9_./:-]{0,1023}")) {
            throw new IllegalArgumentException("materialized probe route is invalid");
        }
        return materialized;
    }

    /** Bounded synthetic query for discovered params (INFERENCE stimulus only). */
    private static String syntheticQuery(ApiDtos.EntryDto entry) {
        if (entry.parameters() == null || entry.parameters().isEmpty()) return "";
        List<String> parts = new ArrayList<>();
        for (String parameter : entry.parameters()) {
            if (parameter == null || parts.size() >= 12) continue;
            int nameAt = parameter.indexOf("name=");
            if (nameAt < 0) continue;
            String name = parameter.substring(nameAt + 5).split("[,\\s]", 2)[0].trim();
            if (!name.matches("[A-Za-z][A-Za-z0-9_]{0,63}")) continue;
            String lower = name.toLowerCase(Locale.ROOT);
            if ("businessId".equals(name) || lower.endsWith("id") || lower.endsWith("ids")) {
                parts.add(name + "=1");
            } else {
                parts.add(name + "=synthetic");
            }
        }
        String joined = String.join("&", parts);
        return joined.length() <= 256 ? joined : joined.substring(0, 256);
    }

    /** Untrusted PATH_EXPLORATION conclusion text used only to prioritize probe order. */
    private String pathExplorationHintText(ControlPlaneStore.ScanRecord scan) {
        try {
            return store.aiJobs(scan.dto().projectId()).stream()
                    .filter(job -> scan.dto().scanId().equals(job.scanId()))
                    .filter(job -> job.role() == com.aq.jvmsentinel.provider.AgentRole.PATH_EXPLORATION)
                    .filter(job -> "COMPLETED".equals(job.status()) && job.conclusionJson() != null)
                    .map(job -> job.conclusionJson())
                    .findFirst()
                    .orElse("");
        } catch (RuntimeException ignored) {
            return "";
        }
    }

    private static boolean hasExecutableMainClass(Path path) {
        try (JarFile jar = new JarFile(path.toFile(), false)) {
            return jar.getManifest() != null
                    && jar.getManifest().getMainAttributes().getValue("Main-Class") != null;
        } catch (IOException invalidJar) {
            throw new SecurityException("registered JAR manifest could not be read", invalidJar);
        }
    }

    private void streamEvents(HttpExchange exchange, String scanId) throws IOException {
        store.requireScan(scanId);
        sseHub.open(exchange, scanId, exchange.getRequestHeaders().getFirst("Last-Event-ID"));
    }

    private void listPaths(HttpExchange exchange, String scanId) throws IOException {
        ControlPlaneStore.ScanRecord scan = store.requireScan(scanId);
        List<Object> paths = new ArrayList<>();
        for (ApiDtos.PathDto path : scan.dto().paths()) paths.add(pathMap(path));
        for (ApiDtos.PathDto path : dynamicPaths(scan)) paths.add(pathMap(path));
        sendJson(exchange, 200, envelope(scan, "paths", paths));
    }

    private void sendPath(HttpExchange exchange, String scanId, String pathId) throws IOException {
        ControlPlaneStore.ScanRecord scan = store.requireScan(scanId);
        for (ApiDtos.PathDto path : scan.dto().paths()) {
            if (path.pathId().equals(pathId)) { sendJson(exchange, 200, pathMap(path)); return; }
        }
        for (ApiDtos.PathDto path : dynamicPaths(scan)) {
            if (path.pathId().equals(pathId)) { sendJson(exchange, 200, pathMap(path)); return; }
        }
        throw new ApiException(404, "PATH_NOT_FOUND", "path not found");
    }

    private void listScanEvidence(HttpExchange exchange, String scanId) throws IOException {
        ControlPlaneStore.ScanRecord scan = store.requireScan(scanId);
        List<Object> items = new ArrayList<>();
        for (ApiDtos.EvidenceDto item : scan.evidence().values()) items.add(evidenceMap(item));
        for (ApiDtos.EvidenceDto item : dynamicEvidence(scan)) items.add(evidenceMap(item));
        sendJson(exchange, 200, envelope(scan, "evidence", items));
    }

    private void listScanFindings(HttpExchange exchange, String scanId) throws IOException {
        ControlPlaneStore.ScanRecord scan = store.requireScan(scanId);
        List<Object> items = new ArrayList<>();
        for (ApiDtos.FindingDto item : scan.findings()) items.add(findingMap(item));
        sendJson(exchange, 200, envelope(scan, "findings", items));
    }

    private void sendFinding(HttpExchange exchange, String findingId) throws IOException {
        ApiDtos.FindingDto finding = store.finding(findingId);
        if (finding == null) throw new ApiException(404, "FINDING_NOT_FOUND", "finding not found");
        sendJson(exchange, 200, findingMap(finding));
    }

    private synchronized void replayFinding(HttpExchange exchange, String findingId) throws IOException {
        ApiDtos.FindingDto finding = store.finding(findingId);
        if (finding == null) throw new ApiException(404, "FINDING_NOT_FOUND", "finding not found");
        Map<String, Object> body = readObject(exchange);
        String requestPayload = JsonCodec.stringify(body);
        String durableScope = "finding:replay:" + findingId;
        for (String field : body.keySet()) {
            if (!Set.of("authorized").contains(field)) {
                throw new ApiException(400, "REPLAY_FIELD_REJECTED", "finding replay body contains an unsupported field");
            }
        }
        if (!requiredBoolean(body, "authorized")) {
            throw new ApiException(403, "AUTHORIZATION_REQUIRED", "explicit authorization is required to replay a finding");
        }
        String key = requireIdempotencyKey(exchange);
        String replayKey = finding.projectId() + ":" + findingId + ":" + key;
        ensureIdempotencyCapacity(idempotentFindingReplays, replayKey);
        ensureIdempotencyCapacity(durableIdempotency, idempotencyMapKey(durableScope, key));
        FindingReplay existing = idempotentFindingReplays.get(replayKey);
        SQLiteControlPlanePersistence.IdempotencyData durable = existingDurableIdempotency(
                durableScope, key, requestPayload);
        if (existing == null && durable != null) {
            TaskSnapshot restored = workerApi.snapshots(finding.projectId(), finding.scanId()).stream()
                    .filter(value -> value.scope().taskId().equals(durable.resultRef())).findFirst().orElse(null);
            if (restored != null) {
                existing = new FindingReplay(finding.scanId(), restored);
                idempotentFindingReplays.putIfAbsent(replayKey, existing);
            }
        }
        if (existing != null) {
            ControlPlaneStore.ScanRecord scan = store.requireScan(existing.scanId());
            sendJson(exchange, 200, findingReplayMap(finding, scan, existing.snapshot(), true));
            return;
        }
        ControlPlaneStore.ScanRecord scan = store.requireScan(finding.scanId());
        if (!finding.projectId().equals(scan.dto().projectId())
                || !finding.artifactDigest().equals(scan.dto().artifactDigest())) {
            throw new ApiException(409, "FINDING_SCOPE_INVALID", "finding is not bound to its scan");
        }
        if (scan.dto().entries().stream().noneMatch(entry -> entry.id().equals(finding.entrypointId()))) {
            throw new ApiException(409, "ENTRY_NOT_FOUND", "finding entrypoint is not present in the scan");
        }
        String operatorId = actor(exchange).operatorId();
        if (workerApi.snapshots(finding.projectId(), finding.scanId()).stream().anyMatch(snapshot ->
                snapshot.lifecycle() == TaskLifecycle.QUEUED
                        || snapshot.lifecycle() == TaskLifecycle.LEASED
                        || snapshot.lifecycle() == TaskLifecycle.RUNNING
                        || snapshot.lifecycle() == TaskLifecycle.PAUSED)) {
            throw new ApiException(409, "DYNAMIC_TASK_BUSY", "a dynamic task is already active for this scan");
        }
        TaskSnapshot snapshot = enqueueDynamicForPipeline(finding.scanId(), operatorId, finding.entrypointId());
        idempotentFindingReplays.put(replayKey, new FindingReplay(finding.scanId(), snapshot));
        rememberDurableIdempotency(durableScope, key, requestPayload, snapshot.scope().taskId(), null);
        store.auditChange(finding.projectId(), operatorId, "finding.replay", "finding", findingId,
                "{\"scanId\":\"" + finding.scanId() + "\",\"entrypointId\":\""
                        + finding.entrypointId() + "\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\"}",
                Instant.now(clock).toString());
        sendJson(exchange, 202, findingReplayMap(finding, scan, snapshot, false));
    }

    private static Map<String, Object> findingReplayMap(ApiDtos.FindingDto finding,
                                                        ControlPlaneStore.ScanRecord scan,
                                                        TaskSnapshot snapshot,
                                                        boolean replayed) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", ApiDtos.SCHEMA_VERSION);
        result.put("projectId", finding.projectId());
        result.put("scanId", scan.dto().scanId());
        result.put("findingId", finding.findingId());
        result.put("entrypointId", finding.entrypointId());
        result.put("taskId", snapshot.scope().taskId());
        result.put("lifecycle", snapshot.lifecycle().name());
        result.put("verificationStatus", "DYNAMIC_SUSPECTED");
        result.put("dependencyMode", "MOCK");
        result.put("replayed", replayed);
        result.put("requiredCapability", snapshot.spec().requiredCapability().name());
        result.put("dynamicExecutionMode", snapshot.spec().requiredCapability().name());
        return result;
    }

    private void sendEvidence(HttpExchange exchange, String evidenceId) throws IOException {
        ApiDtos.EvidenceDto item = store.evidence(evidenceId);
        if (item == null) item = traceProjectionService.evidence(evidenceId);
        if (item == null) throw new ApiException(404, "EVIDENCE_NOT_FOUND", "evidence not found");
        sendJson(exchange, 200, evidenceMap(item));
    }

    private void listEvidence(HttpExchange exchange, String projectId) throws IOException {
        ControlPlaneStore.ProjectRecord project = store.requireProject(projectId);
        String scanId = query(exchange.getRequestURI(), "scanId");
        ControlPlaneStore.ScanRecord scan = scanId == null ? latestScan(project) : store.scan(scanId);
        if (scan == null || !projectId.equals(scan.dto().projectId())) {
            Map<String, Object> result = envelope(projectId, List.of());
            result.put("evidence", List.of());
            result.put("verificationStatus", "UNREACHED");
            result.put("artifactDigest", "unscanned");
            result.put("scanId", "unscanned");
            sendJson(exchange, 200, result);
            return;
        }
        List<Object> items = new ArrayList<>();
        for (ApiDtos.EvidenceDto item : scan.evidence().values()) items.add(evidenceMap(item));
        for (ApiDtos.EvidenceDto item : dynamicEvidence(scan)) items.add(evidenceMap(item));
        sendJson(exchange, 200, envelope(scan, "evidence", items));
    }

    private void listChains(HttpExchange exchange) throws IOException {
        String projectId = query(exchange.getRequestURI(), "projectId");
        List<Object> items = new ArrayList<>();
        for (ApiDtos.AttackChainDto chain : store.attackChains(projectId)) items.add(chainMap(chain));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("schemaVersion", ApiDtos.SCHEMA_VERSION);
        body.put("projectId", projectId == null ? "all" : projectId);
        body.put("attackChains", items);
        body.put("dependencyMode", ApiDtos.MOCK);
        body.put("verificationStatus", ApiDtos.STATIC_INFERRED);
        body.put("evidenceRefs", List.of());
        if (!items.isEmpty() && items.get(0) instanceof Map<?, ?> first) {
            body.put("artifactDigest", first.get("artifactDigest"));
            body.put("scanId", first.get("scanId"));
        } else {
            body.put("artifactDigest", "unscoped");
            body.put("scanId", "unscoped");
        }
        sendJson(exchange, 200, body);
    }

    private void dashboard(HttpExchange exchange, String projectId) throws IOException {
        ControlPlaneStore.ProjectRecord project = store.requireProject(projectId);
        String requestedScanId = query(exchange.getRequestURI(), "scanId");
        ControlPlaneStore.ScanRecord scan = requestedScanId == null || requestedScanId.isBlank()
                ? latestScan(project)
                : store.scan(requestedScanId);
        if (scan != null && !scan.dto().projectId().equals(projectId)) {
            throw new ApiException(404, "SCAN_NOT_FOUND", "scan not found for project");
        }
        if (scan == null && requestedScanId != null && !requestedScanId.isBlank()) {
            throw new ApiException(404, "SCAN_NOT_FOUND", "scan not found for project");
        }
        if (scan == null) {
            Map<String, Object> empty = new LinkedHashMap<>();
            empty.put("schemaVersion", ApiDtos.SCHEMA_VERSION);
            empty.put("projectId", projectId);
            empty.put("artifactDigest", "unscanned");
            empty.put("scanId", "unscanned");
            empty.put("verificationStatus", "UNREACHED");
            empty.put("dependencyMode", ApiDtos.MOCK);
            empty.put("evidenceRefs", List.of());
            empty.put("entries", List.of());
            empty.put("findings", List.of());
            empty.put("paths", List.of());
            empty.put("pathRuns", List.of());
            empty.put("path", List.of());
            sendJson(exchange, 200, empty);
            return;
        }
        ApiDtos.ScanDto dto = scan.dto();
        List<ApiDtos.PathDto> dynamicPaths = dynamicPaths(scan);
        List<ApiDtos.PathRunDto> pathRuns = traceProjectionService.pathRunsForScan(
                dto.projectId(), dto.artifactDigest(), dto.scanId());
        List<ApiDtos.PathStepDto> flattened = !dynamicPaths.isEmpty()
                ? dynamicPaths.get(dynamicPaths.size() - 1).steps()
                : dto.paths().isEmpty() ? List.of() : dto.paths().get(0).steps();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("schemaVersion", ApiDtos.SCHEMA_VERSION);
        body.put("projectId", dto.projectId());
        body.put("artifactDigest", dto.artifactDigest());
        body.put("scanId", dto.scanId());
        boolean confirmed = pathRuns.stream()
                .anyMatch(run -> ApiDtos.DYNAMIC_CONFIRMED.equals(run.verificationStatus()));
        body.put("verificationStatus", confirmed ? ApiDtos.DYNAMIC_CONFIRMED
                : dynamicPaths.isEmpty() ? dto.verificationStatus() : "DYNAMIC_SUSPECTED");
        body.put("dependencyMode", dto.dependencyMode());
        List<String> dashboardEvidence = new ArrayList<>(dto.evidenceRefs());
        for (ApiDtos.PathDto pathDto : dynamicPaths) dashboardEvidence.addAll(pathDto.evidenceRefs());
        body.put("evidenceRefs", List.copyOf(dashboardEvidence));
        List<Object> entries = new ArrayList<>();
        for (ApiDtos.EntryDto entry : dto.entries()) entries.add(entryMap(entry));
        List<Object> findings = new ArrayList<>();
        for (ApiDtos.FindingDto finding : dto.findings()) findings.add(findingMap(finding));
        List<Object> paths = new ArrayList<>();
        for (ApiDtos.PathDto path : dto.paths()) paths.add(pathMap(path));
        for (ApiDtos.PathDto dynamic : dynamicPaths) paths.add(pathMap(dynamic));
        List<Object> pathRunMaps = new ArrayList<>();
        for (ApiDtos.PathRunDto run : pathRuns) pathRunMaps.add(pathRunMap(run));
        List<Object> path = new ArrayList<>();
        for (ApiDtos.PathStepDto step : flattened) path.add(pathStepMap(step));
        body.put("entries", entries);
        body.put("findings", findings);
        body.put("paths", paths);
        body.put("pathRuns", pathRunMaps);
        body.put("path", path);
        sendJson(exchange, 200, body);
    }

    private List<ApiDtos.PathDto> dynamicPaths(ControlPlaneStore.ScanRecord scan) {
        ApiDtos.ScanDto dto = scan.dto();
        List<ApiDtos.PathDto> projected = new ArrayList<>(traceProjectionService.pathsForScan(
                dto.projectId(), dto.artifactDigest(), dto.scanId()));
        List<ApiDtos.PathDto> unreached = unreachedDynamicPaths.getOrDefault(dto.scanId(), List.of());
        if (!unreached.isEmpty()) projected.addAll(unreached);
        return List.copyOf(projected);
    }

    private List<ApiDtos.EvidenceDto> dynamicEvidence(ControlPlaneStore.ScanRecord scan) {
        ApiDtos.ScanDto dto = scan.dto();
        return traceProjectionService.evidenceForScan(dto.projectId(), dto.artifactDigest(), dto.scanId());
    }

    private ControlPlaneStore.ScanRecord latestScan(ControlPlaneStore.ProjectRecord project) {
        String id = project.latestScanId();
        return id == null ? null : store.scan(id);
    }

    private Map<String, Object> health() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("schemaVersion", ApiDtos.SCHEMA_VERSION);
        body.put("status", "UP");
        body.put("service", "jvm-sentinel-control-plane");
        body.put("persistenceMode", store.persistenceMode());
        body.put("analysisMode", "STATIC_METADATA_ONLY");
        body.put("dynamicExecutionMode", "DYNAMIC_DISABLED");
        body.put("workerContractVersion", WorkerControlPlaneApi.CONTRACT_VERSION);
        body.put("dependencyMode", ApiDtos.MOCK);
        body.put("bindAddress", address().getHostString());
        body.put("port", address().getPort());
        return body;
    }

    private void requirePermission(HttpExchange exchange, Permission permission) {
        AuthContext context = actor(exchange);
        Authorizer.Decision decision = authorizer.authorize(
                context, com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.LOCAL_WORKSPACE,
                permission);
        if (!decision.allowed()) {
            throw new ApiException(403, "PERMISSION_DENIED", "operator permission is required");
        }
    }

    private AuthContext actor(HttpExchange exchange) {
        String supplied = exchange.getRequestHeaders().getFirst("X-Sentinel-Authorization");
        if (supplied == null || supplied.isBlank()) {
            String authorization = exchange.getRequestHeaders().getFirst("Authorization");
            if (authorization != null && authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
                supplied = authorization.substring(7).trim();
            }
        }
        if (supplied == null || supplied.isBlank() || constantTimeEquals(workerToken, supplied)) {
            throw new ApiException(401, "AUTHORIZATION_REQUIRED", "a local authorization token is required");
        }
        if ("SQLITE".equals(store.persistenceMode())) {
            var operator = store.authenticateOperator(supplied);
            if (operator == null) {
                throw new ApiException(401, "AUTHORIZATION_REQUIRED", "a local authorization token is required");
            }
            return AuthContext.authenticated(operator.operatorId(),
                    com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.LOCAL_WORKSPACE,
                    Set.of(operator.role()));
        }
        if (!constantTimeEquals(mutationToken, supplied)) {
            throw new ApiException(401, "AUTHORIZATION_REQUIRED", "a local authorization token is required");
        }
        return AuthContext.authenticated("local-admin",
                com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.LOCAL_WORKSPACE,
                Set.of(OperatorRole.ADMINISTRATOR));
    }

    private static AgentRole role(String value) {
        if (value == null) throw new ApiException(400, "INVALID_ROLE", "AI role is required");
        try { return AgentRole.valueOf(value); }
        catch (IllegalArgumentException invalid) {
            throw new ApiException(400, "INVALID_ROLE", "unsupported AI role");
        }
    }

    private static AiOutputLanguage outputLanguage(String value) {
        try {
            return AiOutputLanguage.parse(value);
        } catch (IllegalArgumentException invalid) {
            throw new ApiException(400, "INVALID_OUTPUT_LANGUAGE",
                    "outputLanguage must be ZH_CN or EN");
        }
    }

    private static OperatorRole operatorRole(String value) {
        if (value == null) throw new ApiException(400, "INVALID_ROLE", "operator role is required");
        try { return OperatorRole.valueOf(value); }
        catch (IllegalArgumentException invalid) {
            throw new ApiException(400, "INVALID_ROLE", "unsupported operator role");
        }
    }

    private ScanPolicy policyFrom(Map<String, Object> body) {
        // A mutation token authenticates the caller; it is not equivalent to
        // authorization to analyze a supplied artifact.  Require an explicit
        // per-scan consent flag so an accidentally omitted field fails closed.
        boolean authorized = optionalBoolean(body, "authorized", false);
        String network = optionalText(body, "networkMode", "DENY").toUpperCase(Locale.ROOT);
        String dangerous = optionalText(body, "dangerousActionMode", "DRY_RUN").toUpperCase(Locale.ROOT);
        NetworkMode networkMode;
        DangerousActionMode dangerousMode;
        try {
            networkMode = NetworkMode.valueOf(network);
            dangerousMode = DangerousActionMode.valueOf(dangerous);
        } catch (IllegalArgumentException invalid) {
            throw new ApiException(400, "INVALID_POLICY", "unsupported scan policy value");
        }
        List<String> allowlist = stringList(body.get("networkAllowlist"), "networkAllowlist");
        long wall = positiveLong(body, "maxWallClockSeconds", DEFAULT_WALL_CLOCK_SECONDS);
        long memory = positiveLong(body, "maxMemoryBytes", DEFAULT_MEMORY_BYTES);
        long disk = positiveLong(body, "maxDiskBytes", DEFAULT_DISK_BYTES);
        return new ScanPolicy(authorized, networkMode, dangerousMode, allowlist, wall, memory, disk);
    }

    private ScanBuild buildScan(String projectId, ArtifactDescriptor descriptor, String scanId,
                                PreAnalysisResult result) {
        String now = Instant.now(clock).toString();
        Map<String, String> evidenceIds = new LinkedHashMap<>();
        Map<String, ApiDtos.EvidenceDto> evidence = new LinkedHashMap<>();
        for (Evidence source : result.entryCatalog().evidence()) {
            String id = "evidence-" + scanId + "-" + source.evidenceId();
            evidenceIds.put(source.evidenceId(), id);
            evidence.put(id, new ApiDtos.EvidenceDto(ApiDtos.SCHEMA_VERSION, projectId,
                    descriptor.sha256(), scanId, id, source.kind().name(), source.source(),
                    source.confidence(), source.summary(), now, "jvm-sentinel-preanalysis/0.1",
                    "none", "artifact:" + descriptor.sha256(), ApiDtos.MOCK));
        }
        List<ApiDtos.EntryDto> entries = new ArrayList<>();
        Map<String, List<String>> entryRefs = new LinkedHashMap<>();
        Map<String, List<String>> permissionPreconditions = new LinkedHashMap<>();
        for (PermissionRequirement permission : result.permissionMatrix().requirements()) {
            List<String> conditions = new ArrayList<>();
            for (String role : permission.roles()) conditions.add("ROLE=" + role);
            for (String tenant : permission.tenants()) conditions.add("TENANT=" + tenant);
            for (String state : permission.states()) conditions.add("STATE=" + state);
            permissionPreconditions.put(permission.entrypointId(), List.copyOf(conditions));
        }
        for (Entrypoint source : result.entryCatalog().entries()) {
            List<String> refs = prefixRefs(source.evidenceRefs(), evidenceIds);
            String module = simpleName(source.declaringClass());
            int coverage = source.status() == VerificationStatus.STATIC_INFERRED ? 0 : 0;
            List<String> preconditions = new ArrayList<>(source.preconditions());
            preconditions.addAll(permissionPreconditions.getOrDefault(source.id(), List.of()));
            entries.add(new ApiDtos.EntryDto(ApiDtos.SCHEMA_VERSION, projectId, descriptor.sha256(), scanId,
                    source.id(), source.protocol(), source.method(), source.route(), source.declaringClass(), module,
                    source.parameters(), preconditions, source.status().name(), source.confidence(), coverage, refs));
            entryRefs.put(source.id(), refs);
        }
        List<ApiDtos.DependencyDto> dependencies = new ArrayList<>();
        for (DependencyAccess source : result.dependencyMap().accesses()) {
            dependencies.add(new ApiDtos.DependencyDto(ApiDtos.SCHEMA_VERSION, projectId, descriptor.sha256(), scanId,
                    source.id(), source.kind(), source.target(), source.accessType(), source.mode(), source.fields(),
                    source.status().name(), source.confidence(), prefixRefs(source.evidenceRefs(), evidenceIds)));
        }
        List<ApiDtos.SinkDto> sinks = new ArrayList<>();
        for (Sink source : result.sinkCatalog().sinks()) {
            sinks.add(new ApiDtos.SinkDto(ApiDtos.SCHEMA_VERSION, projectId, descriptor.sha256(), scanId,
                    source.id(), source.category(), source.symbol(), source.source(), source.status().name(),
                    source.confidence(), prefixRefs(source.evidenceRefs(), evidenceIds)));
        }
        List<ApiDtos.FindingDto> findings = buildFindings(
                projectId, descriptor, scanId, entries, dependencies, sinks, evidence);
        List<ApiDtos.PathDto> paths = buildPaths(
                projectId, descriptor, scanId, entries, sinks, evidence);
        List<String> allEvidence = new ArrayList<>(evidence.keySet());
        List<ApiDtos.AttackChainDto> chains = buildChains(
                projectId, descriptor.sha256(), scanId, findings);
        ApiDtos.ScanDto scan = new ApiDtos.ScanDto(ApiDtos.SCHEMA_VERSION, projectId, descriptor.sha256(), scanId,
                "COMPLETED", ApiDtos.STATIC_INFERRED, ApiDtos.MOCK, now, now, allEvidence,
                entries, dependencies, sinks, findings, paths);
        return new ScanBuild(scan, evidence, findings, chains);
    }

    private List<ApiDtos.FindingDto> buildFindings(String projectId, ArtifactDescriptor descriptor, String scanId,
                                                   List<ApiDtos.EntryDto> entries, List<ApiDtos.DependencyDto> dependencies,
                                                   List<ApiDtos.SinkDto> sinks,
                                                   Map<String, ApiDtos.EvidenceDto> evidence) {
        List<ApiDtos.FindingDto> findings = new ArrayList<>();
        String dependencyId = dependencies.isEmpty() ? "none" : dependencies.get(0).id();
        String dependency = dependencies.isEmpty() ? "none" : dependencies.get(0).target();
        int index = 0;
        for (ApiDtos.SinkDto sink : sinks) {
            String sinkBindingKey = sinkBindingKey(sink, evidence);
            ApiDtos.EntryDto linkedEntry = entries.stream()
                    .filter(entry -> entryBindingKey(entry, evidence).equals(sinkBindingKey))
                    .findFirst().orElse(null);
            String entryId = linkedEntry == null ? "entry-unbound" : linkedEntry.id();
            String route = linkedEntry == null ? "UNBOUND" : linkedEntry.route();
            // A class-name/static signal is not an exploitability verdict. In
            // particular, an unbound sink has no demonstrated path from an entrypoint.
            String severity = linkedEntry == null ? "info"
                    : staticSinkSeverity(sink.category(), sink.confidence());
            String title = "静态推断的" + sinkCategoryLabel(sink.category()) + "信号";
            List<String> refs = sink.evidenceRefs();
            findings.add(new ApiDtos.FindingDto(ApiDtos.SCHEMA_VERSION, projectId, descriptor.sha256(), scanId,
                    "finding-" + scanId + "-" + (++index), title, severity, ApiDtos.STATIC_INFERRED,
                    entryId, route, sink.id(), sink.symbol(), dependency, List.of(dependencyId), refs,
                    refs.size(), sink.confidence(), ApiDtos.MOCK));
        }
        return findings;
    }

    private static String sinkCategoryLabel(String category) {
        if (category == null || category.isBlank()) return "敏感调用";
        return switch (category.toUpperCase(Locale.ROOT)) {
            case "SSRF" -> "服务端请求伪造";
            case "DESERIALIZATION" -> "反序列化";
            case "COMMAND_EXECUTION", "RCE", "COMMAND" -> "命令执行";
            case "SQL_INJECTION", "SQLi", "SQL" -> "SQL 注入";
            case "JNDI" -> "JNDI 注入";
            case "XXE" -> "XML 外部实体";
            case "PATH_TRAVERSAL", "FILE" -> "文件路径穿越";
            case "EXPRESSION", "SSTI", "TEMPLATE" -> "表达式/模板注入";
            case "REFLECTION", "CLASSLOADER" -> "反射/类加载";
            case "JWT" -> "JWT/令牌处理";
            case "AUTH", "AUTH_GAP" -> "鉴权缺口";
            default -> category;
        };
    }

    private List<ApiDtos.PathDto> buildPaths(String projectId, ArtifactDescriptor descriptor, String scanId,
                                              List<ApiDtos.EntryDto> entries,
                                              List<ApiDtos.SinkDto> sinks,
                                              Map<String, ApiDtos.EvidenceDto> evidence) {
        List<ApiDtos.PathDto> paths = new ArrayList<>();
        for (ApiDtos.EntryDto entry : entries) {
            List<ApiDtos.PathStepDto> steps = new ArrayList<>();
            LinkedHashSet<String> pathEvidence = new LinkedHashSet<>(entry.evidenceRefs());
            steps.add(new ApiDtos.PathStepDto(entry.method() + " " + entry.route(),
                    "入口类=" + entry.declaringClass() + " · 静态元数据", "entry", "done", entry.evidenceRefs()));
            for (ApiDtos.SinkDto sink : sinks) {
                if (!entryBindingKey(entry, evidence).equals(sinkBindingKey(sink, evidence))) continue;
                steps.add(new ApiDtos.PathStepDto(sink.symbol(), "类别=" + sinkCategoryLabel(sink.category())
                        + " · 同一处理函数内的字节码调用候选；污点与运行时执行尚未证明",
                        "sink", "blocked", sink.evidenceRefs()));
                pathEvidence.addAll(sink.evidenceRefs());
            }
            paths.add(new ApiDtos.PathDto(ApiDtos.SCHEMA_VERSION, projectId, descriptor.sha256(), scanId,
                    "path-" + scanId + "-" + entry.id(), entry.id(), ApiDtos.STATIC_INFERRED, ApiDtos.MOCK,
                    entry.preconditions(), "STATIC_ONLY_NOT_EXECUTED", List.copyOf(pathEvidence), steps));
        }
        return paths;
    }

    private List<ApiDtos.AttackChainDto> buildChains(String projectId, String artifactDigest, String scanId,
                                                      List<ApiDtos.FindingDto> findings) {
        Map<String, List<ApiDtos.FindingDto>> byEntry = new LinkedHashMap<>();
        for (ApiDtos.FindingDto finding : findings) {
            if (!"entry-unbound".equals(finding.entrypointId())) {
                byEntry.computeIfAbsent(finding.entrypointId(), ignored -> new ArrayList<>()).add(finding);
            }
        }
        List<ApiDtos.AttackChainDto> result = new ArrayList<>();
        int index = 0;
        for (Map.Entry<String, List<ApiDtos.FindingDto>> group : byEntry.entrySet()) {
            if (group.getValue().size() < 2) continue;
            List<String> findingRefs = group.getValue().stream().map(ApiDtos.FindingDto::findingId).toList();
            LinkedHashSet<String> groupEvidence = new LinkedHashSet<>();
            for (ApiDtos.FindingDto finding : group.getValue()) groupEvidence.addAll(finding.evidenceRefs());
            double confidence = group.getValue().stream()
                    .mapToDouble(ApiDtos.FindingDto::confidence).min().orElse(0);
            result.add(new ApiDtos.AttackChainDto(ApiDtos.SCHEMA_VERSION, projectId, artifactDigest, scanId,
                    "chain-" + scanId + "-" + (++index),
                    "同一静态入口处理类上的多个敏感调用候选（数据流尚未验证）",
                    confidence, ApiDtos.STATIC_INFERRED, findingRefs, List.copyOf(groupEvidence)));
        }
        return List.copyOf(result);
    }

    private static String sinkDeclaringClass(ApiDtos.SinkDto sink) {
        int methodSeparator = sink.symbol().indexOf('#');
        return methodSeparator > 0 ? sink.symbol().substring(0, methodSeparator) : sink.symbol();
    }

    private static String entryBindingKey(ApiDtos.EntryDto entry,
                                          Map<String, ApiDtos.EvidenceDto> evidence) {
        for (String ref : entry.evidenceRefs()) {
            ApiDtos.EvidenceDto item = evidence.get(ref);
            if (item != null && item.source().startsWith("classfile-annotation:")) {
                return item.source().substring("classfile-annotation:".length());
            }
        }
        return entry.declaringClass();
    }

    private static String sinkBindingKey(ApiDtos.SinkDto sink,
                                         Map<String, ApiDtos.EvidenceDto> evidence) {
        for (String ref : sink.evidenceRefs()) {
            ApiDtos.EvidenceDto item = evidence.get(ref);
            if (item != null && item.source().startsWith("classfile-call:")) {
                String location = item.source().substring("classfile-call:".length());
                int descriptor = location.indexOf('(');
                return descriptor > 0 ? location.substring(0, descriptor) : location;
            }
        }
        return sinkDeclaringClass(sink);
    }

    private static String staticSinkSeverity(String category, double confidence) {
        if (confidence < 0.80) return "low";
        return switch (category.toUpperCase(Locale.ROOT)) {
            case "COMMAND", "NATIVE_CODE", "CLASS_LOADING", "DESERIALIZATION",
                    "EXPRESSION", "TEMPLATE", "JNDI" -> "medium";
            case "SQL", "NOSQL", "LDAP", "XPATH", "XML", "XSLT", "SSRF",
                    "FILE_READ", "FILE_WRITE", "FILE_DELETE", "ARCHIVE", "REDIRECT",
                    "REFLECTION", "FILE", "JWT", "AUTH" -> "low";
            case "AUTH_GAP" -> "info";
            default -> "info";
        };
    }

    private void publishEvent(String scanId, EventContext context, String type, String key,
                              Map<String, Object> payload) {
        // Context is included even in v1 so consumers receive the required
        // project, artifact, scan and task scope identifiers.
        VersionedEvent event = EventFactory.create(type, ApiDtos.EVENT_SCHEMA_VERSION, context,
                new IdempotencyKey("scan", scanId + ":" + type + ":" + key), JsonCodec.stringify(payload), clock);
        sseHub.publish(scanId, event);
    }

    private ApiDtos.ProjectDto projectDto(ControlPlaneStore.ProjectRecord project) {
        List<ApiDtos.ArtifactDto> artifacts = new ArrayList<>();
        for (ArtifactDescriptor descriptor : store.artifacts(project)) artifacts.add(artifactDto(project.projectId(), descriptor));
        ControlPlaneStore.ScanRecord latest = latestScan(project);
        String status = latest == null ? "UNREACHED" : latest.dto().verificationStatus();
        List<String> refs = latest == null ? List.of() : latest.dto().evidenceRefs();
        return new ApiDtos.ProjectDto(ApiDtos.SCHEMA_VERSION, project.projectId(), project.name(), project.createdAt(),
                status, ApiDtos.MOCK, refs, artifacts);
    }

    private ApiDtos.ArtifactDto artifactDto(String projectId, ArtifactDescriptor descriptor) {
        return new ApiDtos.ArtifactDto(ApiDtos.SCHEMA_VERSION, projectId, descriptor.artifactId(),
                descriptor.type().name(), descriptor.sha256(), descriptor.sizeBytes(), descriptor.staticOnly(),
                descriptor.registeredAt().toString(), ApiDtos.STATIC_INFERRED, ApiDtos.MOCK, List.of());
    }

    private static List<String> prefixRefs(List<String> refs, Map<String, String> mapping) {
        List<String> result = new ArrayList<>();
        for (String ref : refs == null ? List.<String>of() : refs) result.add(mapping.getOrDefault(ref, ref));
        return List.copyOf(result);
    }

    private static String simpleName(String className) {
        int index = Math.max(className.lastIndexOf('.'), className.lastIndexOf('/'));
        return index < 0 ? className : className.substring(index + 1);
    }

    private static Map<String, Object> envelope(String projectId, List<Object> items) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", ApiDtos.SCHEMA_VERSION);
        result.put("projectId", projectId);
        result.put("verificationStatus", ApiDtos.STATIC_INFERRED);
        result.put("dependencyMode", ApiDtos.MOCK);
        result.put("evidenceRefs", List.of());
        result.put("items", items);
        return result;
    }

    private static Map<String, Object> envelope(ControlPlaneStore.ScanRecord scan, String key, List<Object> items) {
        Map<String, Object> result = new LinkedHashMap<>();
        ApiDtos.ScanDto dto = scan.dto();
        result.put("schemaVersion", ApiDtos.SCHEMA_VERSION);
        result.put("projectId", dto.projectId());
        result.put("artifactDigest", dto.artifactDigest());
        result.put("scanId", dto.scanId());
        result.put("verificationStatus", dto.verificationStatus());
        result.put("dependencyMode", dto.dependencyMode());
        result.put("evidenceRefs", dto.evidenceRefs());
        result.put(key, items);
        result.put("items", items);
        return result;
    }

    private static Map<String, Object> artifactMap(ApiDtos.ArtifactDto dto) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", dto.schemaVersion()); result.put("projectId", dto.projectId());
        result.put("artifactId", dto.artifactId()); result.put("artifactType", dto.artifactType());
        result.put("artifactDigest", dto.artifactDigest()); result.put("sha256", dto.artifactDigest());
        result.put("sizeBytes", dto.sizeBytes()); result.put("staticOnly", dto.staticOnly());
        result.put("registeredAt", dto.registeredAt()); result.put("verificationStatus", dto.verificationStatus());
        result.put("dependencyMode", dto.dependencyMode()); result.put("evidenceRefs", dto.evidenceRefs());
        return result;
    }

    private Map<String, Object> projectMap(ControlPlaneStore.ProjectRecord project) {
        ApiDtos.ProjectDto dto = projectDto(project);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", dto.schemaVersion());
        result.put("projectId", dto.projectId());
        result.put("name", dto.name());
        result.put("status", project.status());
        result.put("createdAt", dto.createdAt());
        result.put("updatedAt", project.updatedAt());
        result.put("verificationStatus", dto.verificationStatus());
        result.put("dependencyMode", dto.dependencyMode());
        result.put("evidenceRefs", dto.evidenceRefs());
        List<Object> artifacts = new ArrayList<>();
        for (ApiDtos.ArtifactDto artifact : dto.artifacts()) artifacts.add(artifactMap(artifact));
        result.put("artifacts", artifacts);
        ControlPlaneStore.ScanRecord latest = latestScan(project);
        result.put("artifactDigest", latest == null
                ? (artifacts.isEmpty() ? "unscanned" : ((Map<?, ?>) artifacts.get(0)).get("artifactDigest"))
                : latest.dto().artifactDigest());
        result.put("scanId", latest == null ? "unscanned" : latest.dto().scanId());
        return result;
    }

    private static Map<String, Object> entryMap(ApiDtos.EntryDto dto) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", dto.schemaVersion()); result.put("projectId", dto.projectId());
        result.put("artifactDigest", dto.artifactDigest()); result.put("scanId", dto.scanId());
        result.put("id", dto.id()); result.put("protocol", dto.protocol()); result.put("method", dto.method());
        result.put("route", dto.route()); result.put("declaringClass", dto.declaringClass());
        result.put("module", dto.module()); result.put("parameters", dto.parameters());
        result.put("preconditions", dto.preconditions());
        result.put("precondition", dto.preconditions().isEmpty() ? "UNSPECIFIED" : dto.preconditions().get(0));
        result.put("verificationStatus", dto.verificationStatus()); result.put("status", dto.verificationStatus());
        result.put("dependencyMode", ApiDtos.MOCK);
        result.put("confidence", dto.confidence()); result.put("coverage", dto.coverage());
        result.put("evidenceRefs", dto.evidenceRefs());
        return result;
    }

    private static Map<String, Object> dependencyMap(ApiDtos.DependencyDto dto) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", dto.schemaVersion()); result.put("projectId", dto.projectId());
        result.put("artifactDigest", dto.artifactDigest()); result.put("scanId", dto.scanId());
        result.put("id", dto.id()); result.put("kind", dto.kind()); result.put("target", dto.target());
        result.put("accessType", dto.accessType()); result.put("mode", dto.mode()); result.put("fields", dto.fields());
        result.put("verificationStatus", dto.verificationStatus()); result.put("status", dto.verificationStatus());
        result.put("confidence", dto.confidence()); result.put("evidenceRefs", dto.evidenceRefs());
        return result;
    }

    private static Map<String, Object> sinkMap(ApiDtos.SinkDto dto) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", dto.schemaVersion()); result.put("projectId", dto.projectId());
        result.put("artifactDigest", dto.artifactDigest()); result.put("scanId", dto.scanId());
        result.put("id", dto.id()); result.put("category", dto.category()); result.put("symbol", dto.symbol());
        result.put("source", dto.source()); result.put("verificationStatus", dto.verificationStatus());
        result.put("status", dto.verificationStatus()); result.put("confidence", dto.confidence());
        result.put("evidenceRefs", dto.evidenceRefs());
        return result;
    }

    private static Map<String, Object> evidenceMap(ApiDtos.EvidenceDto dto) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", dto.schemaVersion()); result.put("projectId", dto.projectId());
        result.put("artifactDigest", dto.artifactDigest()); result.put("scanId", dto.scanId());
        result.put("evidenceId", dto.evidenceId()); result.put("provenanceKind", dto.provenanceKind());
        result.put("kind", dto.provenanceKind()); result.put("source", dto.source());
        result.put("confidence", dto.confidence()); result.put("summary", dto.summary());
        result.put("verificationStatus", dto.verificationStatus());
        result.put("evidenceRefs", List.of(dto.evidenceId()));
        result.put("observedAt", dto.observedAt()); result.put("toolVersion", dto.toolVersion());
        result.put("modelVersion", dto.modelVersion()); result.put("snapshotRef", dto.snapshotRef());
        result.put("dependencyMode", dto.dependencyMode());
        return result;
    }

    private static Map<String, Object> findingMap(ApiDtos.FindingDto dto) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", dto.schemaVersion()); result.put("projectId", dto.projectId());
        result.put("artifactDigest", dto.artifactDigest()); result.put("scanId", dto.scanId());
        result.put("findingId", dto.findingId()); result.put("id", dto.findingId()); result.put("title", dto.title());
        result.put("severity", dto.severity()); result.put("verificationStatus", dto.verificationStatus());
        result.put("status", dto.verificationStatus()); result.put("entrypointId", dto.entrypointId());
        result.put("entry", dto.entry()); result.put("sinkId", dto.sinkId()); result.put("sink", dto.sink());
        result.put("dependency", dto.dependency()); result.put("dependencyRefs", dto.dependencyRefs());
        result.put("evidenceRefs", dto.evidenceRefs()); result.put("evidenceCount", dto.evidenceCount());
        result.put("evidence", dto.evidenceCount()); result.put("confidence", dto.confidence());
        result.put("dependencyMode", dto.dependencyMode());
        return result;
    }

    private static Map<String, Object> pathStepMap(ApiDtos.PathStepDto dto) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("label", dto.label()); result.put("detail", dto.detail()); result.put("kind", dto.kind());
        result.put("state", dto.state()); result.put("evidenceRefs", dto.evidenceRefs());
        result.put("verificationStatus", dto.verificationStatus());
        result.put("provenanceKind", dto.provenanceKind());
        result.put("eventType", dto.eventType());
        if (dto.sequence() != null) result.put("sequence", dto.sequence());
        return result;
    }

    private static Map<String, Object> pathMap(ApiDtos.PathDto dto) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", dto.schemaVersion()); result.put("projectId", dto.projectId());
        result.put("artifactDigest", dto.artifactDigest()); result.put("scanId", dto.scanId());
        result.put("pathId", dto.pathId()); result.put("entrypointId", dto.entrypointId());
        result.put("verificationStatus", dto.verificationStatus()); result.put("status", dto.verificationStatus());
        result.put("dependencyMode", dto.dependencyMode()); result.put("preconditions", dto.preconditions());
        result.put("stopReason", dto.stopReason()); result.put("evidenceRefs", dto.evidenceRefs());
        if (dto.taskId() != null) {
            result.put("taskId", dto.taskId());
            result.put("fixtureOnly", dto.fixtureOnly());
            result.put("requiredCapability", dto.requiredCapability());
            result.put("dynamicExecutionMode", dto.dynamicExecutionMode());
        }
        List<Object> steps = new ArrayList<>(); for (ApiDtos.PathStepDto step : dto.steps()) steps.add(pathStepMap(step));
        result.put("steps", steps); result.put("path", steps);
        return result;
    }

    private static Map<String, Object> pathRunMap(ApiDtos.PathRunDto dto) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", dto.schemaVersion());
        result.put("pathRunId", dto.pathRunId());
        result.put("scanId", dto.scanId());
        result.put("entrypointRef", dto.entrypointRef());
        result.put("track", dto.track());
        result.put("attemptId", dto.attemptId());
        if (dto.experimentPlanId() != null && !dto.experimentPlanId().isBlank()) {
            result.put("experimentPlanId", dto.experimentPlanId());
        }
        result.put("method", dto.method());
        result.put("contentType", dto.contentType());
        result.put("requestSummary", dto.requestSummary());
        result.put("outcomeClass", dto.outcomeClass());
        result.put("httpStatus", dto.httpStatus());
        result.put("entryHit", dto.entryHit());
        result.put("parameterBound", dto.parameterBound());
        List<Object> sqlEvents = new ArrayList<>();
        for (ApiDtos.SqlEventDto sql : dto.sqlEvents()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("sqlText", sql.sqlText());
            row.put("parameterSummary", sql.parameterSummary());
            row.put("readWrite", sql.readWrite());
            row.put("parameterized", sql.parameterized());
            row.put("maliciousFragmentPresent", sql.maliciousFragmentPresent());
            row.put("captureMode", sql.captureMode());
            sqlEvents.add(row);
        }
        result.put("sqlEvents", sqlEvents);
        result.put("stopReason", dto.stopReason());
        result.put("verificationStatus", dto.verificationStatus());
        result.put("evidenceRefs", dto.evidenceRefs());
        result.put("identityProvenance", dto.identityProvenance());
        result.put("identityPrecondition", dto.identityPrecondition());
        return result;
    }

    private static Map<String, Object> scanMap(ApiDtos.ScanDto dto) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", dto.schemaVersion()); result.put("projectId", dto.projectId());
        result.put("artifactDigest", dto.artifactDigest()); result.put("scanId", dto.scanId());
        result.put("status", dto.status()); result.put("verificationStatus", dto.verificationStatus());
        result.put("dependencyMode", dto.dependencyMode()); result.put("createdAt", dto.createdAt());
        result.put("completedAt", dto.completedAt()); result.put("evidenceRefs", dto.evidenceRefs());
        List<Object> entries = new ArrayList<>(); for (ApiDtos.EntryDto x : dto.entries()) entries.add(entryMap(x));
        List<Object> deps = new ArrayList<>(); for (ApiDtos.DependencyDto x : dto.dependencies()) deps.add(dependencyMap(x));
        List<Object> sinks = new ArrayList<>(); for (ApiDtos.SinkDto x : dto.sinks()) sinks.add(sinkMap(x));
        List<Object> findings = new ArrayList<>(); for (ApiDtos.FindingDto x : dto.findings()) findings.add(findingMap(x));
        List<Object> paths = new ArrayList<>(); for (ApiDtos.PathDto x : dto.paths()) paths.add(pathMap(x));
        result.put("entries", entries); result.put("entryCatalog", entries); result.put("dependencies", deps);
        result.put("dependencyMap", deps); result.put("sinks", sinks); result.put("sinkCatalog", sinks);
        result.put("findings", findings); result.put("paths", paths);
        return result;
    }

    private static Map<String, Object> dynamicTaskMap(TaskSnapshot snapshot) {
        WorkerTaskSpec spec = snapshot.spec();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", ApiDtos.SCHEMA_VERSION);
        result.put("projectId", spec.projectId());
        result.put("artifactDigest", spec.artifactDigest());
        result.put("scanId", spec.scanId());
        result.put("taskId", spec.taskId());
        result.put("targetEntryId", spec.targetEntryId());
        result.put("status", snapshot.lifecycle().name());
        result.put("verificationStatus", "DYNAMIC_SUSPECTED");
        result.put("requiredCapability", spec.requiredCapability().name());
        result.put("fixtureOnly", false);
        result.put("networkMode", "DENY");
        result.put("networkAllowlist", List.of());
        result.put("dynamicExecutionMode", "TRUSTED_DOCKER_NETWORK_NONE");
        result.put("maxWallClockSeconds", spec.resourceBudget().maxWallClockSeconds());
        result.put("maxCpuMillis", spec.resourceBudget().maxCpuMillis());
        result.put("maxMemoryBytes", spec.resourceBudget().maxMemoryBytes());
        result.put("maxDiskBytes", spec.resourceBudget().maxDiskBytes());
        result.put("maxTraceBytes", spec.resourceBudget().maxTraceBytes());
        result.put("stopReason", snapshot.stopReason() == null ? null : snapshot.stopReason().name());
        result.put("failureCode", snapshot.failureCode());
        result.put("updatedAt", snapshot.updatedAt().toString());
        return result;
    }

    private static Map<String, Object> chainMap(ApiDtos.AttackChainDto dto) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", dto.schemaVersion()); result.put("projectId", dto.projectId());
        result.put("artifactDigest", dto.artifactDigest()); result.put("scanId", dto.scanId());
        result.put("chainId", dto.chainId()); result.put("id", dto.chainId()); result.put("title", dto.title());
        result.put("confidence", dto.confidence()); result.put("verificationStatus", dto.verificationStatus());
        result.put("status", dto.verificationStatus()); result.put("findingRefs", dto.findingRefs());
        result.put("evidenceRefs", dto.evidenceRefs());
        return result;
    }

    private static Map<String, Object> operatorMap(
            com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.OperatorData operator,
            String personalAccessToken) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", 1);
        result.put("operatorId", operator.operatorId());
        result.put("username", operator.username());
        result.put("role", operator.role().name());
        result.put("createdAt", operator.createdAt());
        result.put("updatedAt", operator.updatedAt());
        if (personalAccessToken != null) result.put("personalAccessToken", personalAccessToken);
        return result;
    }

    private static Map<String, Object> providerMap(
            com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.ProviderData provider) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", 1);
        result.put("providerId", provider.providerId());
        result.put("name", provider.name());
        result.put("kind", provider.kind().name());
        result.put("baseUrl", provider.baseUrl());
        if (provider.model() != null) result.put("model", provider.model());
        result.put("enabled", provider.enabled());
        result.put("hasCredential", provider.hasCredential());
        result.put("updatedAt", provider.updatedAt());
        return result;
    }

    private static Map<String, Object> inventoryMap(ModelInventory inventory) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", inventory.schemaVersion());
        result.put("workspaceId", inventory.workspaceId());
        result.put("providerId", inventory.providerId());
        result.put("protocol", inventory.protocol().name());
        result.put("semantics", inventory.semantics().name());
        result.put("fetchedAt", inventory.fetchedAt().toString());
        List<Object> models = new ArrayList<>();
        for (var model : inventory.models()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("schemaVersion", model.schemaVersion());
            item.put("workspaceId", model.workspaceId());
            item.put("modelId", model.modelId());
            item.put("providerId", model.providerId());
            item.put("providerModelName", model.providerModelName());
            item.put("contextWindowTokens", model.contextWindowTokens());
            item.put("enabled", model.enabled());
            item.put("createdAt", model.createdAt().toString());
            item.put("updatedAt", model.updatedAt().toString());
            models.add(item);
        }
        result.put("models", models);
        return result;
    }

    private static Map<String, Object> roleBindingMap(
            com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.RoleBindingData binding) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", 2);
        result.put("projectId", binding.projectId());
        result.put("role", binding.role().name());
        result.put("providerId", binding.providerId());
        result.put("model", binding.model());
        result.put("promptZh", binding.promptZh());
        result.put("promptEn", binding.promptEn());
        result.put("updatedAt", binding.updatedAt());
        return result;
    }

    private static Map<String, Object> aiJobMap(
            com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.AiJobData job) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", 1);
        result.put("aiJobId", job.aiJobId());
        result.put("workspaceId", job.workspaceId());
        result.put("projectId", job.projectId());
        if (job.scanId() != null) result.put("scanId", job.scanId());
        if (job.artifactDigest() != null) result.put("artifactDigest", job.artifactDigest());
        result.put("role", job.role().name());
        if (job.providerId() != null) result.put("providerId", job.providerId());
        if (job.model() != null) result.put("model", job.model());
        result.put("authorized", job.authorized());
        result.put("status", job.status());
        result.put("stopReason", job.stopReason());
        if (!"COMPLETED".equals(job.status())) result.put("errorCode", job.stopReason());
        result.put("stages", JsonCodec.parse(job.stagesJson()));
        Object policySnapshot = JsonCodec.parse(job.policySnapshotJson());
        result.put("policySnapshot", policySnapshot);
        if (policySnapshot instanceof Map<?, ?> policy
                && policy.get("outputLanguage") instanceof String language
                && ("ZH_CN".equals(language) || "EN".equals(language))) {
            result.put("outputLanguage", language);
        }
        if (job.providerRequestId() != null) result.put("providerRequestId", job.providerRequestId());
        result.put("elapsedMillis", job.elapsedMillis());
        result.put("rounds", job.rounds());
        result.put("toolSummary", JsonCodec.parse(job.toolSummaryJson()));
        if (job.conclusionJson() != null) result.put("conclusion", JsonCodec.parse(job.conclusionJson()));
        result.put("createdAt", job.createdAt());
        result.put("updatedAt", job.updatedAt());
        result.put("verificationStatus", job.conclusionJson() == null ? "UNREACHED" : "INFERENCE");
        return result;
    }

    private static Map<String, Object> aiJobEventMap(
            com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.AiJobEventData event,
            String jobStopReason) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", 1);
        result.put("aiJobId", event.aiJobId());
        result.put("sequence", event.sequence());
        result.put("workspaceId", event.workspaceId());
        result.put("projectId", event.projectId());
        result.put("stage", event.stage());
        result.put("status", event.status());
        if (event.providerRequestSummary() != null) {
            result.put("providerRequestSummary", event.providerRequestSummary());
        }
        if (event.providerResultSummary() != null) {
            result.put("providerResultSummary", event.providerResultSummary());
        }
        if (event.toolCallName() != null) result.put("toolCallName", event.toolCallName());
        if (event.toolArgumentsSummary() != null) {
            result.put("toolArgumentsSummary", event.toolArgumentsSummary());
        }
        if (event.toolResultStatus() != null) {
            result.put("toolResultStatus", event.toolResultStatus());
        }
        if (event.modelInferenceSummary() != null) {
            result.put("modelInferenceSummary", event.modelInferenceSummary());
        }
        if (event.failureDiagnostic() != null) {
            result.put("failureDiagnostic", event.failureDiagnostic());
        } else if ("FAILED".equals(event.status())) {
            String failureCode = jobStopReason != null
                    && jobStopReason.matches("[A-Z0-9_]{1,64}")
                    ? jobStopReason : "AI_JOB_FAILED";
            result.put("failureDiagnostic",
                    "Failure code: " + failureCode + "; detailed provider output was not retained");
        }
        result.put("createdAt", event.createdAt());
        return result;
    }

    private static Map<String, Object> auditMap(
            com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.AuditData event) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", 1);
        result.put("auditEventId", event.auditEventId());
        if (event.projectId() != null) result.put("projectId", event.projectId());
        result.put("operatorId", event.operatorId());
        result.put("action", event.action());
        result.put("targetType", event.targetType());
        result.put("targetId", event.targetId());
        result.put("outcome", event.outcome());
        result.put("details", JsonCodec.parse(event.detailsJson()));
        result.put("createdAt", event.createdAt());
        return result;
    }

    private static Map<String, Object> stringEnvelope(String key, Object value) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", ApiDtos.SCHEMA_VERSION); result.put(key, value); return result;
    }

    private static Map<String, Object> uploadSessionMap(ArtifactUploadService.UploadSession session) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", ApiDtos.SCHEMA_VERSION);
        result.put("uploadId", session.uploadId());
        result.put("projectId", session.projectId());
        result.put("fileName", session.fileName());
        result.put("sizeBytes", session.sizeBytes());
        result.put("sha256", session.sha256());
        result.put("nextOffset", session.nextOffset());
        result.put("expiresAt", session.expiresAt().toString());
        result.put("recommendedChunkBytes", session.recommendedChunkBytes());
        result.put("maxChunkBytes", session.maxChunkBytes());
        return result;
    }

    private static Map<String, Object> readObjectOrEmpty(String body) {
        if (body == null || body.isBlank()) return new LinkedHashMap<>();
        return JsonCodec.parseObject(body);
    }

    private static String safeMessage(IllegalArgumentException exception) {
        String message = exception.getMessage();
        return message == null || message.isBlank() ? "invalid request" : message;
    }

    private Map<String, Object> readObject(HttpExchange exchange) throws IOException {
        String body = readBody(exchange);
        if (body.isBlank()) return new LinkedHashMap<>();
        try { return JsonCodec.parseObject(body); }
        catch (IllegalArgumentException invalid) { throw new ApiException(400, "INVALID_JSON", "request body must be a JSON object"); }
    }

    private static String readBody(HttpExchange exchange) throws IOException {
        long declared = exchange.getRequestHeaders().getFirst("Content-Length") == null ? -1
                : parseContentLength(exchange.getRequestHeaders().getFirst("Content-Length"));
        if (declared > MAX_BODY_BYTES) throw new ApiException(413, "BODY_TOO_LARGE", "request body exceeds the limit");
        try (var input = exchange.getRequestBody()) {
            byte[] bytes = input.readNBytes(MAX_BODY_BYTES + 1);
            if (bytes.length > MAX_BODY_BYTES) throw new ApiException(413, "BODY_TOO_LARGE", "request body exceeds the limit");
            try {
                var decoder = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT);
                return decoder.decode(java.nio.ByteBuffer.wrap(bytes)).toString();
            } catch (CharacterCodingException invalidEncoding) {
                throw new ApiException(400, "INVALID_ENCODING", "request body must be UTF-8");
            }
        }
    }

    private static long parseContentLength(String value) {
        try { long result = Long.parseLong(value); if (result < 0) throw new NumberFormatException(); return result; }
        catch (NumberFormatException invalid) { throw new ApiException(400, "INVALID_LENGTH", "invalid Content-Length"); }
    }

    private static long nonNegativeLong(String value, String name) {
        try {
            long result = Long.parseLong(value);
            if (result < 0) throw new NumberFormatException();
            return result;
        } catch (NumberFormatException invalid) {
            throw new ApiException(400, "INVALID_FIELD", name + " must be a non-negative integer");
        }
    }

    private static List<String> pathSegments(URI uri) {
        String raw = uri.getRawPath();
        if (raw == null || !raw.startsWith(API_PREFIX)) throw new ApiException(404, "NOT_FOUND", "route not found");
        if (raw.length() > 4096) throw new ApiException(414, "URI_TOO_LONG", "request path exceeds the limit");
        String remainder = raw.substring(API_PREFIX.length());
        if (remainder.isEmpty() || "/".equals(remainder)) return List.of();
        if (!remainder.startsWith("/")) throw new ApiException(404, "NOT_FOUND", "route not found");
        String[] rawSegments = remainder.substring(1).split("/", -1);
        if (rawSegments.length > 8) throw new ApiException(414, "URI_TOO_LONG", "too many path segments");
        List<String> result = new ArrayList<>();
        for (String rawSegment : rawSegments) {
            if (rawSegment.isEmpty()) throw new ApiException(400, "INVALID_PATH", "empty path segment");
            if (rawSegment.length() > 512) throw new ApiException(414, "URI_TOO_LONG", "path segment exceeds the limit");
            try {
                String decoded = URLDecoder.decode(rawSegment.replace("+", "%2B"), StandardCharsets.UTF_8);
                if (decoded.isBlank() || decoded.contains("/") || decoded.contains("\\") || decoded.equals(".") || decoded.equals("..")) {
                    throw new ApiException(400, "INVALID_PATH", "invalid path segment");
                }
                result.add(decoded);
            } catch (ApiException api) {
                throw api;
            } catch (IllegalArgumentException invalid) {
                throw new ApiException(400, "INVALID_PATH", "invalid path encoding");
            }
        }
        return List.copyOf(result);
    }

    private static String query(URI uri, String key) {
        String raw = uri.getRawQuery(); if (raw == null || raw.isBlank()) return null;
        for (String part : raw.split("&")) {
            int equals = part.indexOf('='); String name = equals < 0 ? part : part.substring(0, equals);
            if (!key.equals(decodeQuery(name))) continue;
            return equals < 0 ? "" : decodeQuery(part.substring(equals + 1));
        }
        return null;
    }

    private static String decodeQuery(String value) {
        try { return URLDecoder.decode(value, StandardCharsets.UTF_8); }
        catch (IllegalArgumentException invalid) { throw new ApiException(400, "INVALID_QUERY", "invalid query encoding"); }
    }

    private static String optionalText(Map<String, Object> body, String key, String fallback) {
        Object value = body.get(key); if (value == null) return fallback;
        if (!(value instanceof String text) || text.isBlank() || text.length() > 4096) {
            throw new ApiException(400, "INVALID_FIELD", key + " must be a non-empty string");
        }
        return text;
    }

    private static String textValue(Map<String, Object> body, String key) {
        Object value = body.get(key);
        if (!(value instanceof String text) || text.isBlank()) {
            throw new IllegalStateException("persistent value is missing " + key);
        }
        return text;
    }

    private static String optionalPrompt(Map<String, Object> body, String key) {
        Object value = body.get(key);
        if (value == null) return null;
        if (!(value instanceof String text) || text.length() > 16_384 || text.indexOf('\0') >= 0
                || text.chars().anyMatch(ch -> Character.isISOControl(ch)
                && ch != '\n' && ch != '\r' && ch != '\t')) {
            throw new ApiException(400, "INVALID_FIELD", key + " is invalid");
        }
        return text.isBlank() ? null : text;
    }

    private static String requestIdempotencyKey(HttpExchange exchange) {
        String value = exchange.getRequestHeaders().getFirst("Idempotency-Key");
        if (value == null) return null;
        if (value.isBlank() || value.length() > 256 || value.chars().anyMatch(Character::isWhitespace)) {
            throw new ApiException(400, "INVALID_IDEMPOTENCY_KEY", "Idempotency-Key is invalid");
        }
        return value;
    }

    private static String requireIdempotencyKey(HttpExchange exchange) {
        String value = requestIdempotencyKey(exchange);
        if (value == null) {
            throw new ApiException(400, "IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key is required");
        }
        return value;
    }

    private static void ensureIdempotencyCapacity(Map<String, ?> keys, String key) {
        if (key != null && !keys.containsKey(key) && keys.size() >= MAX_IDEMPOTENCY_KEYS) {
            throw new ApiException(429, "IDEMPOTENCY_LIMIT", "idempotency key store is full");
        }
    }

    private static String idempotencyMapKey(String scope, String key) {
        return scope + "\u0000" + key;
    }

    private SQLiteControlPlanePersistence.IdempotencyData existingDurableIdempotency(
            String scope, String key, String payload) {
        if (key == null) return null;
        SQLiteControlPlanePersistence.IdempotencyData record = durableIdempotency.get(idempotencyMapKey(scope, key));
        if (record == null) return null;
        if (!record.payloadHash().equals(payloadHash(payload))) {
            throw new ApiException(409, "IDEMPOTENCY_CONFLICT",
                    "Idempotency-Key was already used with a different request");
        }
        return record;
    }

    private SQLiteControlPlanePersistence.IdempotencyData rememberDurableIdempotency(
            String scope, String key, String payload, String resultRef, String resultJson) {
        if (key == null) return null;
        String mapKey = idempotencyMapKey(scope, key);
        ensureIdempotencyCapacity(durableIdempotency, mapKey);
        SQLiteControlPlanePersistence.IdempotencyData candidate =
                new SQLiteControlPlanePersistence.IdempotencyData(scope, key, payloadHash(payload),
                        resultRef, resultJson, Instant.now(clock).toString());
        SQLiteControlPlanePersistence.IdempotencyData stored = store.persistIdempotency(candidate);
        if (!stored.payloadHash().equals(candidate.payloadHash())) {
            throw new ApiException(409, "IDEMPOTENCY_CONFLICT",
                    "Idempotency-Key was already used with a different request");
        }
        durableIdempotency.putIfAbsent(mapKey, stored);
        return stored;
    }

    private static String payloadHash(String payload) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(payload.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static boolean optionalBoolean(Map<String, Object> body, String key, boolean fallback) {
        Object value = body.get(key); if (value == null) return fallback;
        if (!(value instanceof Boolean bool)) throw new ApiException(400, "INVALID_FIELD", key + " must be boolean");
        return bool;
    }

    private static boolean requiredBoolean(Map<String, Object> body, String key) { return optionalBoolean(body, key, false); }

    private static long positiveLong(Map<String, Object> body, String key, long fallback) {
        Object value = body.get(key); if (value == null) return fallback;
        if (!(value instanceof Number number) || number.doubleValue() < 1 || number.doubleValue() > Long.MAX_VALUE
                || number.doubleValue() != Math.rint(number.doubleValue())) {
            throw new ApiException(400, "INVALID_FIELD", key + " must be a positive integer");
        }
        return number.longValue();
    }

    private static List<String> stringList(Object value, String key) {
        if (value == null) return List.of();
        if (!(value instanceof List<?> list) || list.size() > MAX_LIST_ITEMS) {
            throw new ApiException(400, "INVALID_FIELD", key + " must be an array");
        }
        List<String> result = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof String text) || text.isBlank() || text.length() > 512) {
                throw new ApiException(400, "INVALID_FIELD", key + " contains an invalid value");
            }
            result.add(text);
        }
        return List.copyOf(result);
    }

    private static boolean constantTimeEquals(String expected, String actual) {
        if (expected == null || actual == null) return false;
        return java.security.MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), actual.getBytes(StandardCharsets.UTF_8));
    }

    private static String requireToken(String token) {
        if (token == null || token.isBlank() || token.length() > 512) throw new IllegalArgumentException("mutationToken is required");
        return token;
    }

    private static String newWorkerToken(String mutationToken) {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        String token;
        do {
            random.nextBytes(bytes);
            token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        } while (constantTimeEquals(mutationToken, token));
        return token;
    }

    private static void addCorsHeaders(HttpExchange exchange) {
        String origin = exchange.getRequestHeaders().getFirst("Origin");
        if (isLocalOrigin(origin)) {
            // The server is intended for local GUI use.  Echoing the origin
            // (rather than '*') keeps EventSource credentials compatible;
            // deployment-facing origin allowlisting belongs in the next slice.
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", origin);
            exchange.getResponseHeaders().set("Vary", "Origin");
            exchange.getResponseHeaders().set("Access-Control-Allow-Credentials", "true");
        }
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Authorization, X-Sentinel-Authorization, X-Chunk-SHA256, Last-Event-ID, Idempotency-Key");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
    }

    private static boolean isLocalOrigin(String origin) {
        if (origin == null || origin.isBlank()) return false;
        try {
            URI parsed = URI.create(origin);
            String scheme = parsed.getScheme();
            String host = parsed.getHost();
            return ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))
                    && ("localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host)
                    || "[::1]".equalsIgnoreCase(host) || "::1".equals(host));
        } catch (IllegalArgumentException invalid) {
            return false;
        }
    }

    private static void sendJson(HttpExchange exchange, int status, Object value) throws IOException {
        byte[] bytes = JsonCodec.stringify(value).getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "application/json; charset=utf-8");
        headers.set("Cache-Control", "no-store");
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-Sentinel-Schema-Version", Integer.toString(ApiDtos.SCHEMA_VERSION));
        exchange.sendResponseHeaders(status, bytes.length);
        try (var output = exchange.getResponseBody()) { output.write(bytes); }
    }

    private static void sendEmpty(HttpExchange exchange, int status) throws IOException {
        exchange.sendResponseHeaders(status, -1);
    }

    private static void sendError(HttpExchange exchange, int status, String code, String message, String requestId) throws IOException {
        try {
            sendJson(exchange, status, Map.of("schemaVersion", ApiDtos.SCHEMA_VERSION, "code", code,
                    "message", message == null ? "request failed" : message, "requestId", requestId));
        } catch (IOException ignored) { }
    }

    private static boolean isSseRequest(HttpExchange exchange) {
        String accept = exchange.getRequestHeaders().getFirst("Accept");
        return accept != null && accept.toLowerCase(Locale.ROOT).contains("text/event-stream");
    }

    private record ScanBuild(ApiDtos.ScanDto scan, Map<String, ApiDtos.EvidenceDto> evidence,
                             List<ApiDtos.FindingDto> findings, List<ApiDtos.AttackChainDto> chains) { }
    private record ScanStart(ControlPlaneStore.ScanRecord scan, boolean replayed) { }
    private record AuditRunReplay(String payload, String scanId, String preAnalysisJobId) { }
    private record DynamicTaskPayload(String scanId, String artifactDigest, String targetEntryId) { }
    private record DynamicTaskReplay(DynamicTaskPayload payload, TaskSnapshot snapshot) { }
    private record FindingReplay(String scanId, TaskSnapshot snapshot) { }

    @FunctionalInterface
    public interface ProviderInventoryService {
        ModelInventory fetch(ProviderDefinition provider, byte[] credential);
    }

    private static final class ApiException extends RuntimeException {
        private final int status;
        private final String code;
        private ApiException(int status, String code, String message) { super(message); this.status = status; this.code = code; }
    }

    /** Adapter keeps CLI metadata extraction private to the existing safe reader. */
    private static final class PreAnalysisServiceAdapter {
        private final com.aq.jvmsentinel.analysis.PreAnalysisService delegate = new com.aq.jvmsentinel.analysis.PreAnalysisService();
        private PreAnalysisResult analyze(PreAnalysisInput input) { return delegate.analyze(input); }
    }
}
