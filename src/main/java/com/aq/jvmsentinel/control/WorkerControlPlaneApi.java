package com.aq.jvmsentinel.control;

import com.aq.jvmsentinel.event.EventContext;
import com.aq.jvmsentinel.event.EventFactory;
import com.aq.jvmsentinel.event.IdempotencyKey;
import com.aq.jvmsentinel.event.VersionedEvent;
import com.aq.jvmsentinel.policy.NetworkMode;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.worker.InMemoryTaskCoordinator;
import com.aq.jvmsentinel.worker.InMemoryTraceStore;
import com.aq.jvmsentinel.worker.NetworkPolicy;
import com.aq.jvmsentinel.worker.ResourceBudget;
import com.aq.jvmsentinel.worker.StopReason;
import com.aq.jvmsentinel.worker.TaskCheckpoint;
import com.aq.jvmsentinel.worker.TaskLifecycle;
import com.aq.jvmsentinel.worker.TaskScope;
import com.aq.jvmsentinel.worker.TaskSnapshot;
import com.aq.jvmsentinel.worker.TraceChunk;
import com.aq.jvmsentinel.worker.TraceManifest;
import com.aq.jvmsentinel.worker.TraceProjectionService;
import com.aq.jvmsentinel.worker.WorkerCapability;
import com.aq.jvmsentinel.worker.WorkerLease;
import com.aq.jvmsentinel.worker.WorkerTaskSpec;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * Versioned, in-memory Worker contract endpoint. This component coordinates task state and
 * immutable traces only; it does not provide or invoke a sandbox runtime.
 */
final class WorkerControlPlaneApi implements HttpHandler {
    static final String PREFIX = "/internal/worker/v1";
    static final int CONTRACT_VERSION = 1;
    private static final int MAX_BODY_BYTES = 1_500_000;
    private static final long DEFAULT_WALL_SECONDS = 900;
    private static final long DEFAULT_CPU_MILLIS = 300_000;
    private static final long DEFAULT_MEMORY_BYTES = 2L * 1024 * 1024 * 1024;
    private static final long DEFAULT_DISK_BYTES = 512L * 1024 * 1024;
    private static final long DEFAULT_TRACE_BYTES = 16L * 1024 * 1024;

    private final String token;
    private final Clock clock;
    private final ControlPlaneStore store;
    private final SseHub sseHub;
    private final InMemoryTraceStore traceStore;
    private final InMemoryTaskCoordinator coordinator;
    private final TraceProjectionService projectionService;
    private final Map<TaskScope, Boolean> scopes = new ConcurrentHashMap<>();
    private final Map<TaskScope, String> failureDiagnostics = new ConcurrentHashMap<>();
    private final Map<TaskScope, String> progressDetails = new ConcurrentHashMap<>();
    private final Map<String, Boolean> publishedEvents = new ConcurrentHashMap<>();
    private volatile Consumer<TaskSnapshot> terminalListener = snapshot -> { };

    WorkerControlPlaneApi(String token, Clock clock, ControlPlaneStore store, SseHub sseHub) {
        this(token, clock, store, sseHub, new InMemoryTraceStore(clock));
    }

    private WorkerControlPlaneApi(String token, Clock clock, ControlPlaneStore store, SseHub sseHub,
                                  InMemoryTraceStore traceStore) {
        this(token, clock, store, sseHub, traceStore, new InMemoryTaskCoordinator(clock, traceStore),
                new TraceProjectionService(traceStore));
    }

    WorkerControlPlaneApi(String token, Clock clock, ControlPlaneStore store, SseHub sseHub,
                          InMemoryTraceStore traceStore, InMemoryTaskCoordinator coordinator) {
        this(token, clock, store, sseHub, traceStore, coordinator, new TraceProjectionService(traceStore));
    }

    WorkerControlPlaneApi(String token, Clock clock, ControlPlaneStore store, SseHub sseHub,
                          InMemoryTraceStore traceStore, InMemoryTaskCoordinator coordinator,
                          TraceProjectionService projectionService) {
        this.token = Objects.requireNonNull(token, "token");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.store = Objects.requireNonNull(store, "store");
        this.sseHub = Objects.requireNonNull(sseHub, "sseHub");
        this.traceStore = Objects.requireNonNull(traceStore, "traceStore");
        this.coordinator = Objects.requireNonNull(coordinator, "coordinator");
        this.projectionService = Objects.requireNonNull(projectionService, "projectionService");
        for (TaskSnapshot snapshot : coordinator.snapshots()) {
            scopes.put(snapshot.scope(), Boolean.TRUE);
            if (snapshot.lifecycle() == TaskLifecycle.COMPLETED) {
                try {
                    persistProjectedPathRuns(snapshot, projectionService.publishCompleted(snapshot));
                } catch (RuntimeException ignored) {
                    /* invalid persisted evidence stays fail-closed; durable PathRuns remain readable */
                }
            }
        }
    }

    void setTerminalListener(Consumer<TaskSnapshot> listener) {
        this.terminalListener = listener == null ? snapshot -> { } : listener;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String requestId = java.util.UUID.randomUUID().toString();
        try {
            requireWorker(exchange);
            List<String> path = pathSegments(exchange.getRequestURI());
            route(exchange, path);
        } catch (WorkerApiException failure) {
            sendError(exchange, failure.status, failure.code, failure.getMessage(), requestId);
        } catch (SecurityException failure) {
            sendError(exchange, 403, "WORKER_SCOPE_REJECTED", safeMessage(failure), requestId);
        } catch (ControlPlaneStore.MissingRecordException failure) {
            sendError(exchange, 404, "NOT_FOUND", safeMessage(failure), requestId);
        } catch (IllegalStateException failure) {
            String message = safeMessage(failure);
            String code = message.contains("idempotency") ? "IDEMPOTENCY_CONFLICT" : "TASK_STATE_CONFLICT";
            sendError(exchange, 409, code, message, requestId);
        } catch (IllegalArgumentException failure) {
            sendError(exchange, 400, "INVALID_WORKER_REQUEST", safeMessage(failure), requestId);
        } catch (Exception failure) {
            sendError(exchange, 500, "INTERNAL_ERROR", "worker control request failed", requestId);
        } finally {
            try { exchange.close(); } catch (RuntimeException ignored) { }
        }
    }

    private void route(HttpExchange exchange, List<String> path) throws IOException {
        String method = exchange.getRequestMethod().toUpperCase(Locale.ROOT);
        if (path.size() == 1 && "tasks".equals(path.get(0))) {
            if ("POST".equals(method)) { enqueue(exchange); return; }
            if ("GET".equals(method)) { list(exchange); return; }
        }
        if (path.size() == 2 && "tasks".equals(path.get(0)) && "GET".equals(method)) {
            sendJson(exchange, 200, snapshotMap(coordinator.get(scopeFromQuery(exchange, path.get(1)))));
            return;
        }
        if (path.size() == 3 && "tasks".equals(path.get(0)) && "POST".equals(method)) {
            mutate(exchange, path.get(1), path.get(2));
            return;
        }
        throw new WorkerApiException(405, "METHOD_NOT_ALLOWED", "worker route or method is not allowed");
    }

    private synchronized void enqueue(HttpExchange exchange) throws IOException {
        String key = requireIdempotencyKey(exchange);
        Map<String, Object> body = readObject(exchange);
        WorkerTaskSpec spec = taskSpec(body);
        TaskSnapshot result = enqueueFromControlPlane(spec, key);
        publish(result.scope(), "ScanCreated", key, Map.of(
                "status", result.lifecycle().name(),
                "verificationStatus", "UNREACHED",
                "dependencyMode", ApiDtos.MOCK,
                "dynamicExecutionMode", "DYNAMIC_DISABLED"));
        sendJson(exchange, 202, snapshotMap(result));
    }

    synchronized TaskSnapshot enqueueFromControlPlane(WorkerTaskSpec spec, String key) {
        validateExternalScope(spec.scope());
        TaskSnapshot result = coordinator.enqueue(spec, key);
        scopes.putIfAbsent(result.scope(), Boolean.TRUE);
        if (spec.requiredCapability() != WorkerCapability.STATIC_ONLY) {
            publish(result.scope(), "DynamicTaskQueued", key, Map.of(
                    "status", result.lifecycle().name(),
                    "verificationStatus", "DYNAMIC_SUSPECTED",
                    "requiredCapability", spec.requiredCapability().name(),
                    "fixtureOnly", false,
                    "dynamicExecutionMode", dynamicExecutionMode(result)));
        }
        return result;
    }

    synchronized List<TaskSnapshot> snapshots(String projectId, String scanId) {
        List<TaskSnapshot> snapshots = new ArrayList<>();
        for (TaskScope scope : scopes.keySet()) {
            if (projectId != null && !projectId.equals(scope.projectId())) continue;
            if (scanId != null && !scanId.equals(scope.scanId())) continue;
            snapshots.add(coordinator.get(scope));
        }
        // Newest-first stable order so operator UIs that take the last element see the
        // chronologically latest task (not lexicographic taskId order).
        snapshots.sort(Comparator
                .comparing(TaskSnapshot::updatedAt)
                .thenComparing(value -> value.scope().taskId()));
        return List.copyOf(snapshots);
    }

    /**
     * Operator stage-retry supersede: cancel every in-flight dynamic task for the scan.
     * Terminal FAILED/COMPLETED/CANCELLED tasks are left as history. Fail-closed callers
     * must re-check {@link #hasActiveDynamicTask} before enqueueing a replacement.
     */
    synchronized List<TaskSnapshot> cancelActiveDynamicTasks(String projectId, String scanId) {
        List<TaskSnapshot> cancelled = new ArrayList<>();
        for (TaskSnapshot snapshot : snapshots(projectId, scanId)) {
            if (!isActiveLifecycle(snapshot.lifecycle())) continue;
            String key = "control-plane-cancel:" + snapshot.scope().taskId();
            TaskSnapshot result = coordinator.controlPlaneCancel(
                    snapshot.scope(), StopReason.USER_CANCELLED, key);
            if (isTerminal(result.lifecycle())) {
                publishTerminal(result, key);
                try {
                    terminalListener.accept(result);
                } catch (RuntimeException ignored) {
                    // Pipeline faults must not rewrite worker terminal state.
                }
            }
            cancelled.add(result);
        }
        return List.copyOf(cancelled);
    }

    synchronized boolean hasActiveDynamicTask(String projectId, String scanId) {
        return snapshots(projectId, scanId).stream()
                .anyMatch(snapshot -> isActiveLifecycle(snapshot.lifecycle()));
    }

    /**
     * Removes terminal worker/task history for a scan after durable delete.
     * Active leases must already be absent (fail-closed).
     */
    synchronized void forgetScanHistory(String projectId, String scanId) {
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(scanId, "scanId");
        if (hasActiveDynamicTask(projectId, scanId)) {
            throw new IllegalStateException("active worker task must be cancelled before deletion");
        }
        for (TaskSnapshot snapshot : snapshots(projectId, scanId)) {
            TaskScope scope = snapshot.scope();
            coordinator.forget(scope);
            traceStore.forget(scope);
            projectionService.forget(scope);
            scopes.remove(scope);
            failureDiagnostics.remove(scope);
            progressDetails.remove(scope);
        }
    }

    /**
     * Fail-closed reclaim for dynamic tasks that remain {@code QUEUED} without a Worker.
     * Emits terminal callbacks so the audit pipeline can disarm instead of waiting forever.
     */
    synchronized List<TaskSnapshot> failStaleQueuedTasks(Duration maxQueuedAge, Instant now) {
        Objects.requireNonNull(maxQueuedAge, "maxQueuedAge");
        Objects.requireNonNull(now, "now");
        if (maxQueuedAge.isNegative()) {
            throw new IllegalArgumentException("maxQueuedAge");
        }
        List<TaskSnapshot> failed = new ArrayList<>();
        for (TaskSnapshot snapshot : snapshots(null, null)) {
            if (snapshot.lifecycle() != TaskLifecycle.QUEUED) {
                continue;
            }
            if (snapshot.spec().requiredCapability() == WorkerCapability.STATIC_ONLY) {
                continue;
            }
            Duration age = Duration.between(snapshot.updatedAt(), now);
            if (age.compareTo(maxQueuedAge) < 0) {
                continue;
            }
            String key = "stale-queue:" + snapshot.scope().taskId() + ":" + now;
            TaskSnapshot result = coordinator.failQueued(
                    snapshot.scope(), StopReason.WALL_CLOCK_TIMEOUT, "WORKER_UNAVAILABLE", key);
            failureDiagnostics.putIfAbsent(result.scope(),
                    "dynamic task remained QUEUED without a Worker beyond "
                            + maxQueuedAge.toSeconds() + "s");
            if (isTerminal(result.lifecycle())) {
                publishTerminal(result, key);
                try {
                    terminalListener.accept(result);
                } catch (RuntimeException ignored) {
                    // Pipeline faults must not rewrite worker terminal state.
                }
            }
            failed.add(result);
        }
        return List.copyOf(failed);
    }

    private static boolean isActiveLifecycle(TaskLifecycle lifecycle) {
        return lifecycle == TaskLifecycle.QUEUED
                || lifecycle == TaskLifecycle.LEASED
                || lifecycle == TaskLifecycle.RUNNING
                || lifecycle == TaskLifecycle.PAUSED;
    }

    String failureDiagnostic(TaskScope scope) {
        return failureDiagnostics.get(scope);
    }

    String progressDetail(TaskScope scope) {
        return progressDetails.get(scope);
    }

    private void list(HttpExchange exchange) throws IOException {
        String projectId = query(exchange.getRequestURI(), "projectId");
        String scanId = query(exchange.getRequestURI(), "scanId");
        List<TaskSnapshot> snapshots = snapshots(projectId, scanId);
        List<Object> tasks = snapshots.stream().map(WorkerControlPlaneApi::snapshotMap).map(x -> (Object) x).toList();
        sendJson(exchange, 200, Map.of(
                "schemaVersion", CONTRACT_VERSION,
                "workerContractVersion", CONTRACT_VERSION,
                "dynamicExecutionMode", "DYNAMIC_DISABLED",
                "tasks", tasks));
    }

    private void mutate(HttpExchange exchange, String taskId, String action) throws IOException {
        String key = requireIdempotencyKey(exchange);
        Map<String, Object> body = readObject(exchange);
        TaskScope scope = scope(body, taskId);
        validateExternalScope(scope);
        TaskSnapshot snapshot;
        switch (action) {
            case "lease" -> {
                String workerId = requiredText(body, "workerId");
                Set<WorkerCapability> capabilities = capabilities(body.get("capabilities"));
                WorkerLease lease = coordinator.lease(scope, workerId, capabilities,
                        Duration.ofSeconds(positiveLong(body, "durationSeconds", 60)), key);
                publish(scope, "TaskLeased", key, Map.of(
                        "status", "LEASED", "leaseId", lease.leaseId(), "workerId", lease.workerId()));
                sendJson(exchange, 200, leaseMap(lease));
                return;
            }
            case "heartbeat" -> {
                WorkerLease lease = coordinator.heartbeat(scope, requiredText(body, "leaseId"),
                        requiredText(body, "workerId"),
                        Duration.ofSeconds(positiveLong(body, "extensionSeconds", 60)), key);
                String progress = sanitizeProgress(optionalText(body, "progressDetail", null));
                if (progress != null) progressDetails.put(scope, progress);
                sendJson(exchange, 200, leaseMap(lease));
                return;
            }
            case "start" -> {
                snapshot = coordinator.start(scope, requiredText(body, "leaseId"),
                        requiredText(body, "workerId"), key);
                progressDetails.putIfAbsent(scope, "任务已开始，准备断网沙箱");
            }
            case "trace" -> {
                commitTrace(exchange, scope, body, key);
                return;
            }
            case "pause" -> snapshot = coordinator.pause(scope, requiredText(body, "leaseId"),
                    requiredText(body, "workerId"), checkpoint(scope, body), key);
            case "resume" -> snapshot = coordinator.resume(scope, requiredText(body, "leaseId"),
                    requiredText(body, "workerId"), key);
            case "cancel" -> snapshot = coordinator.cancel(scope, optionalText(body, "leaseId", null),
                    optionalText(body, "workerId", null), stopReason(body, "reason", StopReason.USER_CANCELLED), key);
            case "complete" -> {
                String leaseId = requiredText(body, "leaseId");
                String workerId = requiredText(body, "workerId");
                TaskSnapshot running = coordinator.get(scope);
                try {
                    // Fail closed before COMPLETED so bad traces cannot advance the pipeline (P0-06).
                    projectionService.validateProjectable(running);
                } catch (IllegalArgumentException | IllegalStateException | SecurityException rejected) {
                    snapshot = coordinator.fail(scope, leaseId, workerId, StopReason.WORKER_FAILURE,
                            "PROJECTION_FAILED", key);
                    failureDiagnostics.putIfAbsent(scope,
                            rejected.getMessage() == null ? "PROJECTION_FAILED" : rejected.getMessage());
                    break;
                }
                snapshot = coordinator.complete(scope, leaseId, workerId, key);
            }
            case "fail" -> {
                snapshot = coordinator.fail(scope, requiredText(body, "leaseId"),
                        requiredText(body, "workerId"), stopReason(body, "reason", StopReason.WORKER_FAILURE),
                        requiredText(body, "failureCode"), key);
                String diagnostic = optionalText(body, "failureDiagnostic", null);
                if (diagnostic != null) failureDiagnostics.putIfAbsent(scope, diagnostic);
            }
            case "fail-queued" -> {
                snapshot = coordinator.failQueued(scope,
                        stopReason(body, "reason", StopReason.WORKER_FAILURE),
                        requiredText(body, "failureCode"), key);
                String diagnostic = optionalText(body, "failureDiagnostic", null);
                if (diagnostic != null) failureDiagnostics.putIfAbsent(scope, diagnostic);
            }
            default -> throw new WorkerApiException(405, "METHOD_NOT_ALLOWED", "worker action is not allowed");
        }
        if (snapshot.lifecycle() == TaskLifecycle.COMPLETED) {
            try {
                persistProjectedPathRuns(snapshot, projectionService.publishCompleted(snapshot));
            } catch (IllegalArgumentException | IllegalStateException | SecurityException rejected) {
                // Should be rare after validateProjectable; keep COMPLETED but do not advance on empty PathRuns.
                failureDiagnostics.putIfAbsent(scope,
                        "PROJECTION_PERSIST_FAILED:" + (rejected.getMessage() == null
                                ? "unknown" : rejected.getMessage()));
            }
        }
        if (isTerminal(snapshot.lifecycle())) {
            publishTerminal(snapshot, key);
            try {
                terminalListener.accept(snapshot);
            } catch (RuntimeException ignored) {
                // Pipeline faults must not rewrite worker terminal state.
            }
        }
        sendJson(exchange, 200, snapshotMap(snapshot));
    }

    private void commitTrace(HttpExchange exchange, TaskScope scope, Map<String, Object> body, String key)
            throws IOException {
        TaskSnapshot task = coordinator.get(scope);
        WorkerLease lease = task.lease();
        String leaseId = requiredText(body, "leaseId");
        String workerId = requiredText(body, "workerId");
        if (lease == null || !lease.leaseId().equals(leaseId) || !lease.workerId().equals(workerId)
                || lease.expiredAt(clock.instant())) {
            throw new SecurityException("lease or worker scope mismatch");
        }
        if (!Set.of(TaskLifecycle.LEASED, TaskLifecycle.RUNNING, TaskLifecycle.PAUSED).contains(task.lifecycle())) {
            throw new IllegalStateException("task cannot accept trace in " + task.lifecycle());
        }
        byte[] payload;
        try {
            payload = Base64.getDecoder().decode(requiredPayloadBase64(body));
        } catch (IllegalArgumentException invalid) {
            throw new WorkerApiException(400, "INVALID_TRACE_PAYLOAD", "payloadBase64 is invalid");
        }
        TraceManifest before = traceStore.manifest(scope);
        long nextTraceBytes;
        try {
            nextTraceBytes = Math.addExact(before.totalPayloadBytes(), payload.length);
        } catch (ArithmeticException overflow) {
            throw new WorkerApiException(413, "TRACE_BUDGET_EXCEEDED", "trace byte budget exceeded");
        }
        if (nextTraceBytes > task.spec().resourceBudget().maxTraceBytes()) {
            throw new WorkerApiException(413, "TRACE_BUDGET_EXCEEDED", "trace byte budget exceeded");
        }
        TraceChunk chunk = new TraceChunk(CONTRACT_VERSION, scope, nonNegativeLong(body, "sequence"),
                optionalText(body, "previousDigest", null), optionalInstant(body, "emittedAt", clock.instant()),
                payload, optionalText(body, "digest", null));
        TraceChunk committed = traceStore.append(scope, key, chunk);
        TraceManifest manifest = traceStore.manifest(scope);
        publish(scope, "TraceCommitted", key, Map.of(
                "status", task.lifecycle().name(),
                "sequence", committed.sequence(),
                "digest", committed.digest(),
                "payloadBytes", committed.payload().length,
                "traceHeadDigest", manifest.headDigest()));
        sendJson(exchange, 201, traceMap(committed, manifest));
    }

    private void persistProjectedPathRuns(TaskSnapshot snapshot, TraceProjectionService.Projection projection) {
        TaskScope scope = snapshot.scope();
        String createdAt = Instant.now(clock).toString();
        List<SQLiteControlPlanePersistence.PathTraceData> traces = new ArrayList<>();
        int index = 0;
        for (com.aq.jvmsentinel.domain.pathdebug.PathTrace trace : projection.pathTraces()) {
            if (trace == null) continue;
            Map<String, Object> payload = new LinkedHashMap<>(trace.toMap());
            payload.put("schemaVersion", com.aq.jvmsentinel.domain.pathdebug.PathTrace.SCHEMA_VERSION);
            traces.add(new SQLiteControlPlanePersistence.PathTraceData(
                    trace.pathTraceId(),
                    trace.pathRunId().isBlank() && index < projection.pathRuns().size()
                            ? projection.pathRuns().get(index).pathRunId() : trace.pathRunId(),
                    scope.scanId(),
                    scope.projectId(),
                    scope.artifactDigest(),
                    scope.taskId(),
                    trace.experimentPlanId(),
                    trace.tracePlanId(),
                    trace.worldPackId(),
                    trace.posture().postureKind().name(),
                    trace.exitReason().name(),
                    trace.legacyIncomplete(),
                    com.aq.jvmsentinel.control.JsonCodec.stringify(payload),
                    createdAt));
            index++;
        }
        store.replacePathRunsAndTracesForTask(
                scope.projectId(),
                scope.artifactDigest(),
                scope.scanId(),
                scope.taskId(),
                projection.pathRuns(),
                traces,
                createdAt);
    }

    private void publishTerminal(TaskSnapshot snapshot, String key) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("status", snapshot.lifecycle().name());
        payload.put("reason", snapshot.stopReason() == null ? snapshot.lifecycle().name() : snapshot.stopReason().name());
        // P0-20: task lifecycle events never promote DYNAMIC_SUSPECTED; PathRun projection owns suspicion.
        payload.put("verificationStatus", ApiDtos.UNREACHED);
        payload.put("dependencyMode", ApiDtos.MOCK);
        payload.put("fixtureOnly", false);
        payload.put("requiredCapability", snapshot.spec().requiredCapability().name());
        payload.put("dynamicExecutionMode", dynamicExecutionMode(snapshot));
        payload.put("evidenceRefs", List.of());
        publish(snapshot.scope(), "TaskStopped", key, payload);
        publish(snapshot.scope(), "ScanCompleted", key, payload);
    }

    private void publish(TaskScope scope, String type, String key, Map<String, Object> payload) {
        String eventKey = scope.projectId() + ":" + scope.artifactDigest() + ":" + scope.scanId()
                + ":" + scope.taskId() + ":" + type + ":" + key;
        if (publishedEvents.putIfAbsent(eventKey, Boolean.TRUE) != null) return;
        EventContext context = new EventContext(scope.projectId(), scope.artifactDigest(), scope.scanId(), scope.taskId());
        VersionedEvent event = EventFactory.create(type, ApiDtos.EVENT_SCHEMA_VERSION, context,
                new IdempotencyKey("worker", scope.taskId() + ":" + type + ":" + key),
                JsonCodec.stringify(payload), clock);
        sseHub.publish(scope.scanId(), event);
    }

    private void validateExternalScope(TaskScope scope) {
        ControlPlaneStore.ProjectRecord project = store.requireProject(scope.projectId());
        if (store.artifact(project, scope.artifactDigest()) == null) {
            throw new SecurityException("artifact is not registered for project");
        }
        ControlPlaneStore.ScanRecord scan = store.requireScan(scope.scanId());
        if (!scope.projectId().equals(scan.dto().projectId())
                || !scope.artifactDigest().equals(scan.dto().artifactDigest())) {
            throw new SecurityException("project, artifact, and scan scope mismatch");
        }
    }

    private static WorkerTaskSpec taskSpec(Map<String, Object> body) {
        TaskScope scope = scope(body, requiredText(body, "taskId"));
        boolean authorized = requiredBoolean(body, "authorized");
        boolean fixtureOnly = optionalBoolean(body, "fixtureOnly", false);
        if (fixtureOnly || body.containsKey("fixtureId") || body.containsKey("imageUri")
                || body.containsKey("mainClass") || body.containsKey("fixtureDigest")) {
            throw new SecurityException("controlled fixture task fields are no longer supported");
        }
        WorkerCapability capability = enumValue(WorkerCapability.class,
                optionalText(body, "requiredCapability", "STATIC_ONLY"), "requiredCapability");
        ResourceBudget budget = new ResourceBudget(
                positiveLong(body, "maxWallClockSeconds", DEFAULT_WALL_SECONDS),
                positiveLong(body, "maxCpuMillis", DEFAULT_CPU_MILLIS),
                positiveLong(body, "maxMemoryBytes", DEFAULT_MEMORY_BYTES),
                positiveLong(body, "maxDiskBytes", DEFAULT_DISK_BYTES),
                positiveLong(body, "maxTraceBytes", DEFAULT_TRACE_BYTES));
        NetworkMode mode = enumValue(NetworkMode.class, optionalText(body, "networkMode", "DENY"), "networkMode");
        NetworkPolicy network = new NetworkPolicy(mode, stringList(body.get("networkAllowlist"), "networkAllowlist"));
        return new WorkerTaskSpec(CONTRACT_VERSION, scope.projectId(), scope.artifactDigest(), scope.scanId(),
                scope.taskId(), requiredText(body, "targetEntryId"), authorized, budget, network, capability);
    }

    private TaskCheckpoint checkpoint(TaskScope scope, Map<String, Object> body) {
        return new TaskCheckpoint(CONTRACT_VERSION, scope, requiredText(body, "checkpointId"),
                longValue(body, "traceSequence"), optionalText(body, "traceHeadDigest", null),
                optionalInstant(body, "checkpointCreatedAt", clock.instant()));
    }

    private static TaskScope scope(Map<String, Object> body, String taskId) {
        String bodyTask = optionalText(body, "taskId", taskId);
        if (!taskId.equals(bodyTask)) throw new SecurityException("task scope mismatch");
        return new TaskScope(requiredText(body, "projectId"), requiredText(body, "artifactDigest"),
                requiredText(body, "scanId"), taskId);
    }

    private static TaskScope scopeFromQuery(HttpExchange exchange, String taskId) {
        return new TaskScope(requiredQuery(exchange, "projectId"), requiredQuery(exchange, "artifactDigest"),
                requiredQuery(exchange, "scanId"), taskId);
    }

    private void requireWorker(HttpExchange exchange) {
        String supplied = exchange.getRequestHeaders().getFirst("X-Sentinel-Worker-Authorization");
        if (supplied == null || supplied.isBlank()) {
            String authorization = exchange.getRequestHeaders().getFirst("Authorization");
            if (authorization != null && authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
                supplied = authorization.substring(7).trim();
            }
        }
        if (!constantTimeEquals(token, supplied)) {
            throw new WorkerApiException(401, "WORKER_AUTHORIZATION_REQUIRED", "a worker authorization token is required");
        }
    }

    private static String requireIdempotencyKey(HttpExchange exchange) {
        String key = exchange.getRequestHeaders().getFirst("Idempotency-Key");
        if (key == null || key.isBlank()) {
            throw new WorkerApiException(400, "IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key is required");
        }
        if (key.length() > 128 || key.chars().anyMatch(Character::isWhitespace)) {
            throw new WorkerApiException(400, "INVALID_IDEMPOTENCY_KEY", "Idempotency-Key is invalid");
        }
        return key;
    }

    private static List<String> pathSegments(URI uri) {
        String raw = uri.getRawPath();
        if (raw == null || !raw.startsWith(PREFIX)) throw new WorkerApiException(404, "NOT_FOUND", "route not found");
        String remainder = raw.substring(PREFIX.length());
        if (remainder.isEmpty() || "/".equals(remainder)) return List.of();
        if (!remainder.startsWith("/")) throw new WorkerApiException(404, "NOT_FOUND", "route not found");
        String[] parts = remainder.substring(1).split("/", -1);
        if (parts.length > 4) throw new WorkerApiException(414, "URI_TOO_LONG", "too many path segments");
        List<String> result = new ArrayList<>();
        for (String part : parts) {
            String decoded;
            try { decoded = URLDecoder.decode(part.replace("+", "%2B"), StandardCharsets.UTF_8); }
            catch (IllegalArgumentException invalid) { throw new WorkerApiException(400, "INVALID_PATH", "invalid path"); }
            if (decoded.isBlank() || decoded.contains("/") || decoded.contains("\\") || ".".equals(decoded) || "..".equals(decoded)) {
                throw new WorkerApiException(400, "INVALID_PATH", "invalid path");
            }
            result.add(decoded);
        }
        return List.copyOf(result);
    }

    private static Map<String, Object> readObject(HttpExchange exchange) throws IOException {
        long declared = exchange.getRequestHeaders().getFirst("Content-Length") == null ? -1
                : Long.parseLong(exchange.getRequestHeaders().getFirst("Content-Length"));
        if (declared > MAX_BODY_BYTES) throw new WorkerApiException(413, "BODY_TOO_LARGE", "request body exceeds limit");
        byte[] bytes = exchange.getRequestBody().readNBytes(MAX_BODY_BYTES + 1);
        if (bytes.length > MAX_BODY_BYTES) throw new WorkerApiException(413, "BODY_TOO_LARGE", "request body exceeds limit");
        try {
            String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(bytes)).toString();
            return text.isBlank() ? new LinkedHashMap<>() : JsonCodec.parseObject(text);
        } catch (CharacterCodingException invalid) {
            throw new WorkerApiException(400, "INVALID_ENCODING", "request body must be UTF-8");
        }
    }

    private static Map<String, Object> snapshotMap(TaskSnapshot value) {
        Map<String, Object> result = scopeMap(value.scope());
        result.put("lifecycle", value.lifecycle().name());
        result.put("status", value.lifecycle().name());
        result.put("updatedAt", value.updatedAt().toString());
        result.put("targetEntryId", value.spec().targetEntryId());
        result.put("authorized", value.spec().authorized());
        // v1 wire compatibility: old clients require this field. It is now invariantly false.
        result.put("fixtureOnly", false);
        result.put("requiredCapability", value.spec().requiredCapability().name());
        ResourceBudget budget = value.spec().resourceBudget();
        result.put("resourceBudget", Map.of(
                "maxWallClockSeconds", budget.maxWallClockSeconds(),
                "maxCpuMillis", budget.maxCpuMillis(),
                "maxMemoryBytes", budget.maxMemoryBytes(),
                "maxDiskBytes", budget.maxDiskBytes(),
                "maxTraceBytes", budget.maxTraceBytes()));
        result.put("networkPolicy", Map.of(
                "mode", value.spec().networkPolicy().mode().name(),
                "allowlist", value.spec().networkPolicy().allowlist()));
        result.put("dynamicExecutionMode", dynamicExecutionMode(value));
        result.put("lease", value.lease() == null ? null : leaseMap(value.lease()));
        result.put("checkpoint", value.checkpoint() == null ? null : checkpointMap(value.checkpoint()));
        result.put("stopReason", value.stopReason() == null ? null : value.stopReason().name());
        result.put("failureCode", value.failureCode());
        return result;
    }

    private static String dynamicExecutionMode(TaskSnapshot snapshot) {
        if (snapshot.spec().requiredCapability() == WorkerCapability.STATIC_ONLY) return "DYNAMIC_DISABLED";
        return snapshot.spec().requiredCapability().name()
                + (snapshot.lifecycle() == TaskLifecycle.QUEUED ? "_QUEUED" : "_WORKER_MANAGED");
    }

    private static Map<String, Object> leaseMap(WorkerLease value) {
        Map<String, Object> result = scopeMap(value.scope());
        result.put("leaseId", value.leaseId());
        result.put("workerId", value.workerId());
        result.put("capability", value.capability().name());
        result.put("issuedAt", value.issuedAt().toString());
        result.put("heartbeatAt", value.heartbeatAt().toString());
        result.put("expiresAt", value.expiresAt().toString());
        return result;
    }

    private static Map<String, Object> checkpointMap(TaskCheckpoint value) {
        Map<String, Object> result = scopeMap(value.scope());
        result.put("checkpointId", value.checkpointId());
        result.put("traceSequence", value.traceSequence());
        result.put("traceHeadDigest", value.traceHeadDigest());
        result.put("createdAt", value.createdAt().toString());
        return result;
    }

    private static Map<String, Object> traceMap(TraceChunk value, TraceManifest manifest) {
        Map<String, Object> result = scopeMap(value.scope());
        result.put("sequence", value.sequence());
        result.put("previousDigest", value.previousDigest());
        result.put("digest", value.digest());
        result.put("emittedAt", value.emittedAt().toString());
        result.put("payloadBytes", value.payload().length);
        result.put("traceHeadDigest", manifest.headDigest());
        result.put("totalPayloadBytes", manifest.totalPayloadBytes());
        return result;
    }

    private static Map<String, Object> scopeMap(TaskScope scope) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", CONTRACT_VERSION);
        result.put("workerContractVersion", CONTRACT_VERSION);
        result.put("projectId", scope.projectId());
        result.put("artifactDigest", scope.artifactDigest());
        result.put("scanId", scope.scanId());
        result.put("taskId", scope.taskId());
        return result;
    }

    private static Set<WorkerCapability> capabilities(Object value) {
        List<String> values = stringList(value, "capabilities");
        if (values.isEmpty()) throw new IllegalArgumentException("capabilities is required");
        java.util.EnumSet<WorkerCapability> result = java.util.EnumSet.noneOf(WorkerCapability.class);
        for (String item : values) result.add(enumValue(WorkerCapability.class, item, "capabilities"));
        return Set.copyOf(result);
    }

    private static List<String> stringList(Object value, String name) {
        if (value == null) return List.of();
        if (!(value instanceof List<?> list) || list.size() > 128) {
            throw new IllegalArgumentException(name + " must be an array");
        }
        List<String> result = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof String text) || text.isBlank() || text.length() > 253) {
                throw new IllegalArgumentException(name + " contains an invalid value");
            }
            result.add(text);
        }
        return List.copyOf(result);
    }

    private static String requiredText(Map<String, Object> body, String name) {
        String result = optionalText(body, name, null);
        if (result == null) throw new IllegalArgumentException(name + " is required");
        return result;
    }

    private static String requiredPayloadBase64(Map<String, Object> body) {
        Object value = body.get("payloadBase64");
        if (!(value instanceof String text) || text.isBlank() || text.length() > MAX_BODY_BYTES) {
            throw new IllegalArgumentException("payloadBase64 is invalid");
        }
        return text;
    }

    private static String optionalText(Map<String, Object> body, String name, String fallback) {
        Object value = body.get(name);
        if (value == null) return fallback;
        if (!(value instanceof String text) || text.isBlank() || text.length() > 4096) {
            throw new IllegalArgumentException(name + " must be a non-empty string");
        }
        return text;
    }

    private static boolean requiredBoolean(Map<String, Object> body, String name) {
        if (!body.containsKey(name)) throw new SecurityException(name + " must be explicitly supplied");
        return optionalBoolean(body, name, false);
    }

    private static boolean optionalBoolean(Map<String, Object> body, String name, boolean fallback) {
        Object value = body.get(name);
        if (value == null) return fallback;
        if (!(value instanceof Boolean result)) throw new IllegalArgumentException(name + " must be boolean");
        return result;
    }

    private static long positiveLong(Map<String, Object> body, String name, long fallback) {
        if (!body.containsKey(name)) return fallback;
        long result = longValue(body, name);
        if (result <= 0) throw new IllegalArgumentException(name + " must be positive");
        return result;
    }

    private static long nonNegativeLong(Map<String, Object> body, String name) {
        long result = longValue(body, name);
        if (result < 0) throw new IllegalArgumentException(name + " cannot be negative");
        return result;
    }

    private static long longValue(Map<String, Object> body, String name) {
        Object value = body.get(name);
        if (!(value instanceof Number number) || number.doubleValue() != Math.rint(number.doubleValue())
                || number.doubleValue() < Long.MIN_VALUE || number.doubleValue() > Long.MAX_VALUE) {
            throw new IllegalArgumentException(name + " must be an integer");
        }
        return number.longValue();
    }

    private static Instant optionalInstant(Map<String, Object> body, String name, Instant fallback) {
        String value = optionalText(body, name, null);
        if (value == null) return fallback;
        try { return Instant.parse(value); }
        catch (DateTimeParseException invalid) { throw new IllegalArgumentException(name + " must be an ISO-8601 instant"); }
    }

    private static StopReason stopReason(Map<String, Object> body, String name, StopReason fallback) {
        String value = optionalText(body, name, null);
        return value == null ? fallback : enumValue(StopReason.class, value, name);
    }

    private static <E extends Enum<E>> E enumValue(Class<E> type, String value, String name) {
        try { return Enum.valueOf(type, value.toUpperCase(Locale.ROOT)); }
        catch (IllegalArgumentException invalid) { throw new IllegalArgumentException(name + " is unsupported"); }
    }

    private static boolean isTerminal(TaskLifecycle lifecycle) {
        return lifecycle == TaskLifecycle.CANCELLED || lifecycle == TaskLifecycle.COMPLETED
                || lifecycle == TaskLifecycle.FAILED;
    }

    private static String sanitizeProgress(String value) {
        if (value == null || value.isBlank()) return null;
        String cleaned = value.replaceAll("[\\p{Cntrl}&&[^\\t]]", " ").strip();
        if (cleaned.isEmpty() || cleaned.length() > 240) {
            return cleaned.isEmpty() ? null : cleaned.substring(0, 240);
        }
        return cleaned;
    }

    private static String query(URI uri, String name) {
        String raw = uri.getRawQuery();
        if (raw == null) return null;
        for (String part : raw.split("&")) {
            int separator = part.indexOf('=');
            String key = separator < 0 ? part : part.substring(0, separator);
            if (name.equals(URLDecoder.decode(key, StandardCharsets.UTF_8))) {
                return separator < 0 ? "" : URLDecoder.decode(part.substring(separator + 1), StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    private static String requiredQuery(HttpExchange exchange, String name) {
        String value = query(exchange.getRequestURI(), name);
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " query parameter is required");
        return value;
    }

    private static boolean constantTimeEquals(String expected, String actual) {
        if (actual == null) return false;
        return java.security.MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }

    private static String safeMessage(Exception failure) {
        return failure.getMessage() == null || failure.getMessage().isBlank() ? "request failed" : failure.getMessage();
    }

    private static void sendJson(HttpExchange exchange, int status, Object value) throws IOException {
        byte[] bytes = JsonCodec.stringify(value).getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "application/json; charset=utf-8");
        headers.set("Cache-Control", "no-store");
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-Sentinel-Worker-Contract-Version", Integer.toString(CONTRACT_VERSION));
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
    }

    private static void sendError(HttpExchange exchange, int status, String code, String message, String requestId)
            throws IOException {
        try {
            sendJson(exchange, status, Map.of(
                    "schemaVersion", CONTRACT_VERSION,
                    "workerContractVersion", CONTRACT_VERSION,
                    "code", code,
                    "message", message,
                    "requestId", requestId));
        } catch (IOException ignored) { }
    }

    private static final class WorkerApiException extends RuntimeException {
        private final int status;
        private final String code;

        private WorkerApiException(int status, String code, String message) {
            super(message);
            this.status = status;
            this.code = code;
        }
    }
}
