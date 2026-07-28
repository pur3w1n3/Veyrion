package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.sandbox.SandboxRuntimeClient;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/** Process-local worker for explicitly authorized internal JARs on the deny-all Docker backend. */
public final class LocalArtifactWorkerLoop implements AutoCloseable {
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);
    private static final Duration IDLE_DELAY = Duration.ofMillis(500);
    private static final Duration FAILURE_DELAY = Duration.ofSeconds(2);

    private final AtomicBoolean running = new AtomicBoolean();
    private final WorkerControlPlaneClient control;
    private final SandboxRuntimeClient sandbox;
    private final ExternalArtifactTaskExecutor executor;
    private final Thread thread;

    public LocalArtifactWorkerLoop(URI controlBaseUri, String workerToken,
                                   SandboxRuntimeClient sandbox,
                                   ExternalArtifactTaskExecutor.ArtifactCatalog catalog,
                                   String runtimeImageUri) {
        this.control = new WorkerControlPlaneClient(
                Objects.requireNonNull(controlBaseUri, "controlBaseUri"),
                Objects.requireNonNull(workerToken, "workerToken"), REQUEST_TIMEOUT);
        AgentJsonlTraceConverter converter = new AgentJsonlTraceConverter(
                Clock.systemUTC(), 64L * 1024 * 1024, 64 * 1024,
                100_000, WorkerContracts.MAX_TRACE_PAYLOAD_BYTES);
        this.sandbox = Objects.requireNonNull(sandbox, "sandbox");
        this.executor = new ExternalArtifactTaskExecutor(
                control, sandbox, Objects.requireNonNull(catalog, "catalog"),
                ExternalArtifactTaskExecutor.RuntimePolicy.trustedLocalDocker(runtimeImageUri),
                converter, "local-docker-artifact-worker");
        this.thread = new Thread(this::run, "veyrion-local-artifact-worker");
        this.thread.setDaemon(true);
    }

    public LocalArtifactWorkerLoop start() {
        if (!running.compareAndSet(false, true)) {
            throw new IllegalStateException("local artifact worker is already running");
        }
        thread.start();
        return this;
    }

    private void run() {
        while (running.get()) {
            try {
                boolean executed = executeQueuedOnce();
                pause(executed ? Duration.ZERO : IDLE_DELAY);
            } catch (RuntimeException failure) {
                if (running.get()) {
                    System.err.println("{\"status\":\"WORKER_RETRY\",\"detail\":\""
                            + safe(failure.getMessage()) + "\"}");
                    pause(FAILURE_DELAY);
                }
            }
        }
    }

    public boolean executeQueuedOnce() {
        boolean executed = false;
        for (WorkerControlPlaneClient.TaskDescriptor task : control.list()) {
            if (task.lifecycle() != TaskLifecycle.QUEUED
                    || task.fixtureOnly()
                    || !task.authorized()
                    || task.requiredCapability() != WorkerCapability.TRUSTED_DOCKER) {
                continue;
            }
            executed = true;
            executor.execute(new ExternalArtifactTaskExecutor.ExecutionRequest(task.scope()));
        }
        return executed;
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
        if (running.compareAndSet(true, false)) {
            thread.interrupt();
            try {
                thread.join(15_000);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
        }
        executor.closeRetainedSessions();
        sandbox.close();
    }
}
