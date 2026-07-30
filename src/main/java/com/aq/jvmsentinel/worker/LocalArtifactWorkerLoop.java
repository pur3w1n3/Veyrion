package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.sandbox.SandboxRuntimeClient;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** 在 deny-all Docker 后端上、针对显式授权内部 JAR 的进程内 worker。 */
public final class LocalArtifactWorkerLoop implements AutoCloseable {
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);
    private static final Duration IDLE_DELAY = Duration.ofMillis(500);
    private static final Duration FAILURE_DELAY = Duration.ofSeconds(2);

    private final AtomicBoolean running = new AtomicBoolean();
    private final AtomicBoolean closed = new AtomicBoolean();
    private final LocalWorkerQuota quota;
    private final WorkerControlPlaneClient control;
    private final SandboxRuntimeClient sandbox;
    private final ExternalArtifactTaskExecutor executor;
    private final ExecutorService workers;
    private final Thread dispatcher;
    private final Set<TaskScope> inFlight = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<String, AtomicInteger> perProjectInFlight = new ConcurrentHashMap<>();
    private final AtomicReference<String> rotateAfterProjectId = new AtomicReference<>();

    public LocalArtifactWorkerLoop(URI controlBaseUri, String workerToken,
                                   SandboxRuntimeClient sandbox,
                                   ExternalArtifactTaskExecutor.ArtifactCatalog catalog,
                                   String runtimeImageUri) {
        this(controlBaseUri, workerToken, sandbox, catalog, runtimeImageUri,
                LocalWorkerQuota.fromEnvironment());
    }

    public LocalArtifactWorkerLoop(URI controlBaseUri, String workerToken,
                                   SandboxRuntimeClient sandbox,
                                   ExternalArtifactTaskExecutor.ArtifactCatalog catalog,
                                   String runtimeImageUri,
                                   LocalWorkerQuota quota) {
        this.quota = Objects.requireNonNull(quota, "quota");
        this.control = new WorkerControlPlaneClient(
                Objects.requireNonNull(controlBaseUri, "controlBaseUri"),
                Objects.requireNonNull(workerToken, "workerToken"), REQUEST_TIMEOUT);
        AgentJsonlTraceConverter converter = new AgentJsonlTraceConverter(
                Clock.systemUTC(), 64L * 1024 * 1024, 64 * 1024,
                500_000, WorkerContracts.MAX_TRACE_PAYLOAD_BYTES);
        this.sandbox = Objects.requireNonNull(sandbox, "sandbox");
        this.executor = new ExternalArtifactTaskExecutor(
                control, sandbox, Objects.requireNonNull(catalog, "catalog"),
                ExternalArtifactTaskExecutor.RuntimePolicy.trustedLocalDocker(runtimeImageUri),
                converter, "local-docker-artifact-worker", quota);
        this.workers = Executors.newFixedThreadPool(quota.maxGlobalConcurrency(), runnable -> {
            Thread thread = new Thread(runnable, "veyrion-artifact-worker");
            thread.setDaemon(true);
            return thread;
        });
        this.dispatcher = new Thread(this::run, "veyrion-local-artifact-dispatcher");
        this.dispatcher.setDaemon(true);
    }

    public LocalWorkerQuota quota() {
        return quota;
    }

    public LocalArtifactWorkerLoop start() {
        if (!running.compareAndSet(false, true)) {
            throw new IllegalStateException("local artifact worker is already running");
        }
        dispatcher.start();
        return this;
    }

    private void run() {
        while (running.get()) {
            try {
                boolean dispatched = dispatchAvailable();
                pause(dispatched ? Duration.ZERO : IDLE_DELAY);
            } catch (RuntimeException failure) {
                if (running.get()) {
                    System.err.println("{\"status\":\"WORKER_RETRY\",\"detail\":\""
                            + safe(failure.getMessage()) + "\"}");
                    pause(FAILURE_DELAY);
                }
            }
        }
    }

    /**
     * 按 per-project / 全局配额派发可执行任务；不等待完成。
     *
     * @return 本轮是否派发了至少一条任务
     */
    public boolean dispatchAvailable() {
        Map<String, Integer> projectCounts = snapshotProjectInFlight();
        java.util.List<TaskScope> selected = ProjectFairTaskDispatcher.select(
                control.list(), inFlight, projectCounts, quota, rotateAfterProjectId.get());
        if (selected.isEmpty()) {
            return false;
        }
        boolean dispatched = false;
        for (TaskScope scope : selected) {
            if (!inFlight.add(scope)) {
                continue;
            }
            perProjectInFlight.computeIfAbsent(scope.projectId(), ignored -> new AtomicInteger())
                    .incrementAndGet();
            rotateAfterProjectId.set(scope.projectId());
            workers.execute(() -> runTask(scope));
            dispatched = true;
        }
        return dispatched;
    }

    /**
     * 兼容旧验收：派发一轮并等待 in-flight 排空（或超时）。
     */
    public boolean executeQueuedOnce() {
        boolean dispatched = dispatchAvailable();
        awaitIdle(Duration.ofMinutes(30));
        return dispatched;
    }

    /** TRIAGE 或流水线放弃后释放某 scan 的保留沙箱。 */
    public void releaseRetainedForScan(String projectId, String artifactDigest, String scanId) {
        executor.releaseRetainedForScan(projectId, artifactDigest, scanId);
    }

    int inFlightCount() {
        return inFlight.size();
    }

    private void runTask(TaskScope scope) {
        try {
            executor.execute(new ExternalArtifactTaskExecutor.ExecutionRequest(scope));
        } catch (RuntimeException failure) {
            if (running.get()) {
                System.err.println("{\"status\":\"WORKER_TASK_FAILED\",\"projectId\":\""
                        + safe(scope.projectId()) + "\",\"taskId\":\""
                        + safe(scope.taskId()) + "\",\"detail\":\""
                        + safe(failure.getMessage()) + "\"}");
            }
        } finally {
            inFlight.remove(scope);
            AtomicInteger counter = perProjectInFlight.get(scope.projectId());
            if (counter != null) {
                counter.decrementAndGet();
            }
        }
    }

    private Map<String, Integer> snapshotProjectInFlight() {
        Map<String, Integer> snapshot = new java.util.LinkedHashMap<>();
        for (Map.Entry<String, AtomicInteger> entry : perProjectInFlight.entrySet()) {
            int value = entry.getValue().get();
            if (value > 0) {
                snapshot.put(entry.getKey(), value);
            }
        }
        return snapshot;
    }

    private void awaitIdle(Duration timeout) {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (!inFlight.isEmpty()) {
            if (System.nanoTime() >= deadline) {
                throw new IllegalStateException("timed out waiting for in-flight worker tasks");
            }
            pause(Duration.ofMillis(50));
        }
    }

    private static String safe(String value) {
        if (value == null) return "TRUSTED_DOCKER_EXECUTION_FAILED";
        String normalized = value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace('\r', ' ').replace('\n', ' ');
        return normalized.length() <= 2048 ? normalized : normalized.substring(0, 2048);
    }

    private void pause(Duration delay) {
        if (delay.isZero()) return;
        try {
            Thread.sleep(delay.toMillis());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            running.set(false);
        }
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        boolean wasRunning = running.getAndSet(false);
        if (wasRunning) {
            dispatcher.interrupt();
            try {
                dispatcher.join(15_000);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
        }
        workers.shutdown();
        try {
            if (!workers.awaitTermination(30, TimeUnit.SECONDS)) {
                workers.shutdownNow();
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            workers.shutdownNow();
        }
        executor.closeRetainedSessions();
        sandbox.close();
    }
}
