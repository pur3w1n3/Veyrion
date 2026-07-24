package com.aq.jvmsentinel.control;

import com.aq.jvmsentinel.analysis.PreAnalysisResult;
import com.aq.jvmsentinel.analysis.PreAnalysisInput;
import com.aq.jvmsentinel.analysis.ArtifactMetadataReader;
import com.aq.jvmsentinel.ai.AiJobOrchestrator;
import com.aq.jvmsentinel.artifact.ArtifactRegistry;
import com.aq.jvmsentinel.artifact.ArtifactUploadService;
import com.aq.jvmsentinel.artifact.ArtifactValidationException;
import com.aq.jvmsentinel.event.EventContext;
import com.aq.jvmsentinel.event.EventFactory;
import com.aq.jvmsentinel.event.IdempotencyKey;
import com.aq.jvmsentinel.event.VersionedEvent;
import com.aq.jvmsentinel.fixture.TrustedFixtureCatalog;
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
import com.aq.jvmsentinel.worker.InMemoryTaskCoordinator;
import com.aq.jvmsentinel.worker.InMemoryTraceStore;
import com.aq.jvmsentinel.worker.NetworkPolicy;
import com.aq.jvmsentinel.worker.ResourceBudget;
import com.aq.jvmsentinel.worker.TaskSnapshot;
import com.aq.jvmsentinel.worker.TraceProjectionService;
import com.aq.jvmsentinel.worker.WorkerCapability;
import com.aq.jvmsentinel.worker.WorkerTaskSpec;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Dependency-free Java 17 Control Plane for the local MVP.
 *
 * <p>The server exposes only metadata analysis.  It never starts an imported
 * JAR/WAR/CLASS and never opens a network connection on behalf of an artifact.
 * The default bind address is loopback and all mutating routes require the
 * configured local authorization token.</p>
 */
public final class ControlPlaneServer implements AutoCloseable {
    public static final String API_PREFIX = "/api/v1";
    public static final String DEFAULT_TOKEN = "local-demo";
    private static final int MAX_BODY_BYTES = 1 * 1024 * 1024;
    private static final int MAX_LIST_ITEMS = 10_000;
    private static final long DEFAULT_WALL_CLOCK_SECONDS = 900;
    private static final long DEFAULT_MEMORY_BYTES = 4L * 1024 * 1024 * 1024;
    private static final long DEFAULT_DISK_BYTES = 2L * 1024 * 1024 * 1024;
    private static final int MAX_IDEMPOTENCY_KEYS = 50_000;

    private final InetSocketAddress bindAddress;
    private final ArtifactRegistry artifactRegistry;
    private final ArtifactUploadService artifactUploadService;
    private final PreAnalysisServiceAdapter analysis = new PreAnalysisServiceAdapter();
    private final ControlPlaneStore store;
    private final SseHub sseHub;
    private final Map<String, String> idempotentProjects = new ConcurrentHashMap<>();
    private final Map<String, String> idempotentArtifacts = new ConcurrentHashMap<>();
    private final Map<String, String> idempotentScans = new ConcurrentHashMap<>();
    private final Map<String, DynamicTaskReplay> idempotentDynamicTasks = new ConcurrentHashMap<>();
    private final String mutationToken;
    private final String workerToken;
    private final TrustedFixtureCatalog fixtureCatalog;
    private final InMemoryTraceStore traceStore;
    private final InMemoryTaskCoordinator taskCoordinator;
    private final TraceProjectionService traceProjectionService;
    private final WorkerControlPlaneApi workerApi;
    private final ProviderInventoryService providerInventoryService;
    private final AiJobOrchestrator aiJobOrchestrator;
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
                new TrustedFixtureCatalog(), providerInventoryService, new ProviderChatTransport());
    }

    /** Controlled provider injections for acceptance tests; production constructors keep HTTPS-only chat. */
    public ControlPlaneServer(Path allowedRoot, int port, String mutationToken, Path databasePath,
                              ProviderInventoryService providerInventoryService,
                              ChatTransport chatTransport) {
        this(new InetSocketAddress("127.0.0.1", port), new ArtifactRegistry(allowedRoot),
                mutationToken == null || mutationToken.isBlank() ? DEFAULT_TOKEN : mutationToken,
                Clock.systemUTC(), ControlPlaneStore.sqlite(databasePath, allowedRoot), new SseHub(),
                new TrustedFixtureCatalog(), providerInventoryService, chatTransport);
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
                              TrustedFixtureCatalog fixtureCatalog) {
        this(new InetSocketAddress(Objects.requireNonNull(host, "host"), port),
                new ArtifactRegistry(allowedRoot),
                mutationToken == null || mutationToken.isBlank() ? DEFAULT_TOKEN : mutationToken,
                Clock.systemUTC(), new ControlPlaneStore(), new SseHub(), fixtureCatalog);
    }

    public ControlPlaneServer(String host, int port, Path allowedRoot, String mutationToken,
                              TrustedFixtureCatalog fixtureCatalog, Path databasePath) {
        this(new InetSocketAddress(Objects.requireNonNull(host, "host"), port),
                new ArtifactRegistry(allowedRoot),
                mutationToken == null || mutationToken.isBlank() ? DEFAULT_TOKEN : mutationToken,
                Clock.systemUTC(), ControlPlaneStore.sqlite(databasePath, allowedRoot), new SseHub(), fixtureCatalog);
    }

    public ControlPlaneServer(InetSocketAddress bindAddress, ArtifactRegistry artifactRegistry,
                              String mutationToken, Clock clock, ControlPlaneStore store,
                              SseHub sseHub) {
        this(bindAddress, artifactRegistry, mutationToken, clock, store, sseHub,
                new TrustedFixtureCatalog());
    }

    public ControlPlaneServer(InetSocketAddress bindAddress, ArtifactRegistry artifactRegistry,
                              String mutationToken, Clock clock, ControlPlaneStore store,
                              SseHub sseHub, TrustedFixtureCatalog fixtureCatalog) {
        this(bindAddress, artifactRegistry, mutationToken, clock, store, sseHub, fixtureCatalog,
                new ProviderModelInventoryClient()::fetch, new ProviderChatTransport());
    }

    public ControlPlaneServer(InetSocketAddress bindAddress, ArtifactRegistry artifactRegistry,
                              String mutationToken, Clock clock, ControlPlaneStore store,
                              SseHub sseHub, TrustedFixtureCatalog fixtureCatalog,
                              ProviderInventoryService providerInventoryService) {
        this(bindAddress, artifactRegistry, mutationToken, clock, store, sseHub, fixtureCatalog,
                providerInventoryService, new ProviderChatTransport());
    }

    public ControlPlaneServer(InetSocketAddress bindAddress, ArtifactRegistry artifactRegistry,
                              String mutationToken, Clock clock, ControlPlaneStore store,
                              SseHub sseHub, TrustedFixtureCatalog fixtureCatalog,
                              ProviderInventoryService providerInventoryService,
                              ChatTransport chatTransport) {
        this.bindAddress = Objects.requireNonNull(bindAddress, "bindAddress");
        this.artifactRegistry = Objects.requireNonNull(artifactRegistry, "artifactRegistry");
        this.artifactUploadService = new ArtifactUploadService(this.artifactRegistry);
        this.mutationToken = requireToken(mutationToken);
        this.clock = Objects.requireNonNull(clock, "clock");
        this.store = Objects.requireNonNull(store, "store");
        this.sseHub = Objects.requireNonNull(sseHub, "sseHub");
        this.workerToken = newWorkerToken(this.mutationToken);
        this.fixtureCatalog = Objects.requireNonNull(fixtureCatalog, "fixtureCatalog");
        this.traceStore = new InMemoryTraceStore(this.clock);
        this.taskCoordinator = new InMemoryTaskCoordinator(this.clock, this.traceStore);
        this.traceProjectionService = new TraceProjectionService(this.traceStore);
        this.workerApi = new WorkerControlPlaneApi(this.workerToken, this.clock, this.store, this.sseHub,
                this.traceStore, this.taskCoordinator, this.traceProjectionService);
        this.providerInventoryService = Objects.requireNonNull(
                providerInventoryService, "providerInventoryService");
        if ("SQLITE".equals(this.store.persistenceMode())) {
            this.store.bootstrapOperator(this.mutationToken, Instant.now(this.clock).toString());
        }
        this.aiJobOrchestrator = new AiJobOrchestrator(this.store,
                Objects.requireNonNull(chatTransport, "chatTransport"), this.clock);
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
            } catch (TrustedFixtureCatalog.UnknownFixtureException unknownFixture) {
                sendError(exchange, 404, "FIXTURE_NOT_FOUND", unknownFixture.getMessage(), requestId);
            } catch (IllegalArgumentException badRequest) {
                sendError(exchange, 400, "INVALID_REQUEST", safeMessage(badRequest), requestId);
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
        if (path.size() == 3 && "scans".equals(path.get(0)) && "dynamic-tasks".equals(path.get(2))
                && "POST".equals(method)) {
            requirePermission(exchange, Permission.RUN_SCANS);
            createDynamicTask(exchange, path.get(1));
            return;
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
        ensureIdempotencyCapacity(idempotentProjects, idempotencyHeader);
        if (idempotencyHeader != null) {
            String existingId = idempotentProjects.get(idempotencyHeader);
            if (existingId != null) {
                sendProject(exchange, existingId);
                return;
            }
        }
        Map<String, Object> body = readObject(exchange);
        String id = optionalText(body, "projectId", optionalText(body, "id", null));
        String name = optionalText(body, "name", optionalText(body, "displayName", null));
        ControlPlaneStore.ProjectRecord project = store.createProject(id, name, Instant.now(clock).toString(),
                actor(exchange).operatorId());
        if (idempotencyHeader != null) idempotentProjects.put(idempotencyHeader, project.projectId());
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
        sendJson(exchange, 200, roleBindingMap(store.saveRoleBinding(projectId, role, providerId, model,
                actor(exchange).operatorId(), Instant.now(clock).toString())));
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
            if (!Set.of("role", "authorized").contains(field)) {
                throw new ApiException(400, "AI_JOB_FIELD_REJECTED",
                        "AI job body only accepts role and authorized");
            }
        }
        AgentRole role = role(optionalText(body, "role", null));
        if (!requiredBoolean(body, "authorized")) {
            throw new ApiException(403, "AUTHORIZATION_REQUIRED",
                    "explicit AI job authorization is required");
        }
        String operatorId = actor(exchange).operatorId();
        var job = store.createAiJob(projectId, role, true, operatorId,
                Instant.now(clock).toString());
        aiJobOrchestrator.submit(job, operatorId);
        sendJson(exchange, 202, aiJobMap(job));
    }

    private void sendAiJob(HttpExchange exchange, String jobId) throws IOException {
        sendJson(exchange, 200, aiJobMap(store.requireAiJob(jobId)));
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
        if (body.containsKey("authorized") && !requiredBoolean(body, "authorized")) {
            throw new ApiException(403, "AUTHORIZATION_REQUIRED", "artifact authorization was denied");
        }
        if (idempotencyHeader != null) {
            String existingDigest = idempotentArtifacts.get(projectId + ":" + idempotencyHeader);
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
        if (idempotencyHeader != null) idempotentArtifacts.putIfAbsent(projectId + ":" + idempotencyHeader, descriptor.sha256());
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
        List<Object> scans = new ArrayList<>();
        String latest = project.latestScanId();
        if (latest != null) {
            ControlPlaneStore.ScanRecord scan = store.scan(latest);
            if (scan != null) scans.add(scanMap(scan.dto()));
        }
        Map<String, Object> result = envelope(projectId, scans);
        result.put("scans", scans);
        result.put("artifactDigest", scans.isEmpty() ? "unscanned" : ((Map<?, ?>) scans.get(0)).get("artifactDigest"));
        result.put("scanId", scans.isEmpty() ? "unscanned" : ((Map<?, ?>) scans.get(0)).get("scanId"));
        sendJson(exchange, 200, result);
    }

    private synchronized void createScan(HttpExchange exchange, String projectId) throws IOException {
        ControlPlaneStore.ProjectRecord project = store.requireProject(projectId);
        String idempotencyHeader = requestIdempotencyKey(exchange);
        ensureIdempotencyCapacity(idempotentScans,
                idempotencyHeader == null ? null : projectId + ":" + idempotencyHeader);
        // Parse and validate the consent flag before serving an idempotent
        // replay.  Reusing a key must not turn an omitted authorization field
        // into an implicit permission to analyze an artifact.
        Map<String, Object> body = readObject(exchange);
        if (body.containsKey("authorized") && !requiredBoolean(body, "authorized")) {
            throw new ApiException(403, "AUTHORIZATION_REQUIRED", "scan authorization was denied");
        }
        if (idempotencyHeader != null) {
            String existingId = idempotentScans.get(projectId + ":" + idempotencyHeader);
            if (existingId != null) {
                if (!optionalBoolean(body, "authorized", false)) {
                    throw new PolicyViolationException("scan authorization is required");
                }
                ControlPlaneStore.ScanRecord existing = store.scan(existingId);
                if (existing != null) {
                    sendJson(exchange, 200, scanMap(existing.dto()));
                    return;
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
        store.saveScan(new ControlPlaneStore.ScanRecord(build.scan(), build.evidence(), build.findings(), build.chains()),
                actor(exchange).operatorId());
        if (idempotencyHeader != null) {
            idempotentScans.putIfAbsent(projectId + ":" + idempotencyHeader, scanId);
        }
        for (ApiDtos.FindingDto finding : build.findings()) {
            publishEvent(scanId, context, "FindingUpdated", finding.findingId(), Map.of(
                    "findingId", finding.findingId(), "verificationStatus", finding.verificationStatus(),
                    "evidenceRefs", finding.evidenceRefs()));
        }
        publishEvent(scanId, context, "ScanCompleted", "completed", Map.of(
                "status", "COMPLETED", "verificationStatus", ApiDtos.STATIC_INFERRED,
                "dependencyMode", ApiDtos.MOCK, "evidenceRefs", build.scan().evidenceRefs()));
        sendJson(exchange, 202, scanMap(build.scan()));
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
        for (String field : body.keySet()) {
            if (!Set.of("authorized", "fixtureId").contains(field)) {
                throw new ApiException(400, "RUNTIME_FIELD_REJECTED",
                        "dynamic task body only accepts authorized and fixtureId");
            }
        }
        if (!body.containsKey("authorized") || !requiredBoolean(body, "authorized")) {
            throw new ApiException(403, "AUTHORIZATION_REQUIRED", "dynamic task authorization is required");
        }
        String fixtureId = optionalText(body, "fixtureId", null);
        if (fixtureId == null) throw new ApiException(400, "FIXTURE_REQUIRED", "fixtureId is required");
        TrustedFixtureCatalog.TrustedFixture fixture = fixtureCatalog.require(fixtureId);

        ControlPlaneStore.ScanRecord scan = store.requireScan(scanId);
        ControlPlaneStore.ProjectRecord project = store.requireProject(scan.dto().projectId());
        if (store.artifact(project, scan.dto().artifactDigest()) == null) {
            throw new ApiException(409, "SCAN_SCOPE_INVALID", "scan artifact is not registered for project");
        }
        boolean targetExists = scan.dto().entries().stream()
                .anyMatch(entry -> fixture.targetEntryId().equals(entry.id()));
        if (!targetExists) {
            throw new ApiException(409, "TARGET_ENTRY_NOT_IN_SCAN",
                    "trusted fixture target entry is not present in scan");
        }

        DynamicTaskPayload payload = new DynamicTaskPayload(scanId, fixture.fixtureId(), fixture.targetEntryId());
        DynamicTaskReplay replay = idempotentDynamicTasks.get(replayKey);
        if (replay != null) {
            if (!replay.payload().equals(payload)) {
                throw new ApiException(409, "IDEMPOTENCY_CONFLICT",
                        "Idempotency-Key was already used with a different payload");
            }
            sendJson(exchange, 200, dynamicTaskMap(replay.snapshot()));
            return;
        }

        String taskId = "task-dynamic-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        WorkerTaskSpec spec = new WorkerTaskSpec(
                WorkerControlPlaneApi.CONTRACT_VERSION,
                scan.dto().projectId(),
                scan.dto().artifactDigest(),
                scanId,
                taskId,
                fixture.targetEntryId(),
                true,
                true,
                new ResourceBudget(60, 30_000, 128L * 1024 * 1024,
                        64L * 1024 * 1024, 2L * 1024 * 1024),
                NetworkPolicy.denyAll(),
                WorkerCapability.FIXTURE_RUNC,
                fixture.fixtureId(),
                fixture.imageUri(),
                fixture.mainClass(),
                fixture.fixtureDigest());
        TaskSnapshot snapshot = workerApi.enqueueFromControlPlane(spec,
                "public-dynamic-" + UUID.randomUUID().toString().replace("-", ""));
        store.auditChange(scan.dto().projectId(), actor(exchange).operatorId(), "dynamic-task.enqueue",
                "worker-task", taskId, "{\"fixtureOnly\":true}", Instant.now(clock).toString());
        idempotentDynamicTasks.put(replayKey, new DynamicTaskReplay(payload, snapshot));
        sendJson(exchange, 202, dynamicTaskMap(snapshot));
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

    private void replayFinding(HttpExchange exchange, String findingId) throws IOException {
        ApiDtos.FindingDto finding = store.finding(findingId);
        if (finding == null) throw new ApiException(404, "FINDING_NOT_FOUND", "finding not found");
        // Dynamic replay is intentionally not implemented in this slice.  A
        // 409 makes the distinction from a successful verification explicit.
        throw new ApiException(409, "STATIC_ONLY", "replay requires an approved sandbox worker");
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
        ControlPlaneStore.ScanRecord scan = latestScan(project);
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
            empty.put("path", List.of());
            sendJson(exchange, 200, empty);
            return;
        }
        ApiDtos.ScanDto dto = scan.dto();
        List<ApiDtos.PathDto> dynamicPaths = dynamicPaths(scan);
        List<ApiDtos.PathStepDto> flattened = !dynamicPaths.isEmpty()
                ? dynamicPaths.get(dynamicPaths.size() - 1).steps()
                : dto.paths().isEmpty() ? List.of() : dto.paths().get(0).steps();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("schemaVersion", ApiDtos.SCHEMA_VERSION);
        body.put("projectId", dto.projectId());
        body.put("artifactDigest", dto.artifactDigest());
        body.put("scanId", dto.scanId());
        body.put("verificationStatus", dynamicPaths.isEmpty()
                ? dto.verificationStatus() : "DYNAMIC_SUSPECTED");
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
        List<Object> path = new ArrayList<>();
        for (ApiDtos.PathStepDto step : flattened) path.add(pathStepMap(step));
        body.put("entries", entries);
        body.put("findings", findings);
        body.put("paths", paths);
        body.put("path", path);
        sendJson(exchange, 200, body);
    }

    private List<ApiDtos.PathDto> dynamicPaths(ControlPlaneStore.ScanRecord scan) {
        ApiDtos.ScanDto dto = scan.dto();
        return traceProjectionService.pathsForScan(dto.projectId(), dto.artifactDigest(), dto.scanId());
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
        List<ApiDtos.FindingDto> findings = buildFindings(projectId, descriptor, scanId, entries, dependencies, sinks);
        List<ApiDtos.PathDto> paths = buildPaths(projectId, descriptor, scanId, entries, dependencies, sinks, evidenceIds);
        List<String> allEvidence = new ArrayList<>(evidence.keySet());
        List<ApiDtos.AttackChainDto> chains = buildChains(projectId, descriptor.sha256(), scanId, findings, sinks, allEvidence);
        ApiDtos.ScanDto scan = new ApiDtos.ScanDto(ApiDtos.SCHEMA_VERSION, projectId, descriptor.sha256(), scanId,
                "COMPLETED", ApiDtos.STATIC_INFERRED, ApiDtos.MOCK, now, now, allEvidence,
                entries, dependencies, sinks, findings, paths);
        return new ScanBuild(scan, evidence, findings, chains);
    }

    private List<ApiDtos.FindingDto> buildFindings(String projectId, ArtifactDescriptor descriptor, String scanId,
                                                   List<ApiDtos.EntryDto> entries, List<ApiDtos.DependencyDto> dependencies,
                                                   List<ApiDtos.SinkDto> sinks) {
        List<ApiDtos.FindingDto> findings = new ArrayList<>();
        String dependencyId = dependencies.isEmpty() ? "none" : dependencies.get(0).id();
        String dependency = dependencies.isEmpty() ? "none" : dependencies.get(0).target();
        int index = 0;
        for (ApiDtos.SinkDto sink : sinks) {
            ApiDtos.EntryDto linkedEntry = entries.stream()
                    .filter(entry -> entry.declaringClass().equals(sink.symbol()))
                    .findFirst().orElse(null);
            String entryId = linkedEntry == null ? "entry-unbound" : linkedEntry.id();
            String route = linkedEntry == null ? "UNBOUND" : linkedEntry.route();
            String severity = "COMMAND".equalsIgnoreCase(sink.category()) ? "critical"
                    : "FILE".equalsIgnoreCase(sink.category()) ? "high" : "medium";
            String title = "Potential " + sink.category().toLowerCase(Locale.ROOT)
                    + " sink (static inference)";
            List<String> refs = sink.evidenceRefs();
            findings.add(new ApiDtos.FindingDto(ApiDtos.SCHEMA_VERSION, projectId, descriptor.sha256(), scanId,
                    "finding-" + scanId + "-" + (++index), title, severity, ApiDtos.STATIC_INFERRED,
                    entryId, route, sink.id(), sink.symbol(), dependency, List.of(dependencyId), refs,
                    refs.size(), sink.confidence(), ApiDtos.MOCK));
        }
        return findings;
    }

    private List<ApiDtos.PathDto> buildPaths(String projectId, ArtifactDescriptor descriptor, String scanId,
                                              List<ApiDtos.EntryDto> entries, List<ApiDtos.DependencyDto> dependencies,
                                              List<ApiDtos.SinkDto> sinks, Map<String, String> evidenceIds) {
        List<ApiDtos.PathDto> paths = new ArrayList<>();
        for (ApiDtos.EntryDto entry : entries) {
            List<ApiDtos.PathStepDto> steps = new ArrayList<>();
            steps.add(new ApiDtos.PathStepDto(entry.method() + " " + entry.route(),
                    "entrypoint=" + entry.declaringClass() + " · static metadata", "entry", "done", entry.evidenceRefs()));
            for (ApiDtos.DependencyDto dependency : dependencies) {
                steps.add(new ApiDtos.PathStepDto(dependency.target(), "mode=" + dependency.mode() + " · fields="
                        + String.join(",", dependency.fields()), "dependency", "done", dependency.evidenceRefs()));
            }
            for (ApiDtos.SinkDto sink : sinks) {
                steps.add(new ApiDtos.PathStepDto(sink.symbol(), "category=" + sink.category()
                        + " · runtime execution not performed", "sink", "blocked", sink.evidenceRefs()));
            }
            paths.add(new ApiDtos.PathDto(ApiDtos.SCHEMA_VERSION, projectId, descriptor.sha256(), scanId,
                    "path-" + scanId + "-" + entry.id(), entry.id(), ApiDtos.STATIC_INFERRED, ApiDtos.MOCK,
                    entry.preconditions(), "STATIC_ONLY_NOT_EXECUTED", entry.evidenceRefs(), steps));
        }
        return paths;
    }

    private List<ApiDtos.AttackChainDto> buildChains(String projectId, String artifactDigest, String scanId,
                                                      List<ApiDtos.FindingDto> findings,
                                                      List<ApiDtos.SinkDto> sinks, List<String> evidenceRefs) {
        if (findings.isEmpty()) return List.of();
        List<String> refs = findings.stream().map(ApiDtos.FindingDto::findingId).toList();
        double confidence = findings.stream().mapToDouble(ApiDtos.FindingDto::confidence).min().orElse(0);
        String title = sinks.size() > 1 ? "Potential cross-sink flow (static inference)" : "Potential sink reachability (static inference)";
        return List.of(new ApiDtos.AttackChainDto(ApiDtos.SCHEMA_VERSION, projectId, artifactDigest, scanId,
                "chain-" + scanId + "-1", title, confidence, ApiDtos.STATIC_INFERRED, refs, evidenceRefs));
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
        result.put("fixtureId", spec.fixtureId());
        result.put("fixtureDigest", spec.fixtureDigest());
        result.put("status", snapshot.lifecycle().name());
        result.put("verificationStatus", "DYNAMIC_SUSPECTED");
        result.put("requiredCapability", WorkerCapability.FIXTURE_RUNC.name());
        result.put("fixtureOnly", true);
        result.put("networkMode", "DENY");
        result.put("networkAllowlist", List.of());
        result.put("dynamicExecutionMode", "FIXTURE_RUNC_QUEUED");
        result.put("maxWallClockSeconds", spec.resourceBudget().maxWallClockSeconds());
        result.put("maxCpuMillis", spec.resourceBudget().maxCpuMillis());
        result.put("maxMemoryBytes", spec.resourceBudget().maxMemoryBytes());
        result.put("maxDiskBytes", spec.resourceBudget().maxDiskBytes());
        result.put("maxTraceBytes", spec.resourceBudget().maxTraceBytes());
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
        result.put("schemaVersion", 1);
        result.put("projectId", binding.projectId());
        result.put("role", binding.role().name());
        result.put("providerId", binding.providerId());
        result.put("model", binding.model());
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
        result.put("policySnapshot", JsonCodec.parse(job.policySnapshotJson()));
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

    private static void ensureIdempotencyCapacity(Map<String, String> keys, String key) {
        if (key != null && !keys.containsKey(key) && keys.size() >= MAX_IDEMPOTENCY_KEYS) {
            throw new ApiException(429, "IDEMPOTENCY_LIMIT", "idempotency key store is full");
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
    private record DynamicTaskPayload(String scanId, String fixtureId, String targetEntryId) { }
    private record DynamicTaskReplay(DynamicTaskPayload payload, TaskSnapshot snapshot) { }

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
