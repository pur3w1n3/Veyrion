package com.aq.jvmsentinel;

import com.aq.jvmsentinel.worker.AgentJsonlTraceConverter;
import com.aq.jvmsentinel.worker.InMemoryTaskCoordinator;
import com.aq.jvmsentinel.worker.InMemoryTraceStore;
import com.aq.jvmsentinel.worker.NetworkPolicy;
import com.aq.jvmsentinel.worker.ResourceBudget;
import com.aq.jvmsentinel.worker.StopReason;
import com.aq.jvmsentinel.worker.TaskSnapshot;
import com.aq.jvmsentinel.worker.TraceChunk;
import com.aq.jvmsentinel.worker.TraceManifest;
import com.aq.jvmsentinel.worker.TraceProjectionService;
import com.aq.jvmsentinel.worker.WorkerCapability;
import com.aq.jvmsentinel.worker.WorkerLease;
import com.aq.jvmsentinel.worker.WorkerTaskSpec;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;

/** Public projection and fail-closed trace validation checks. */
public final class DynamicTraceProjectionAcceptanceTest {
    private static final String DIGEST = "a".repeat(64);
    private static final String VALID_JSONL =
            "{\"schemaVersion\":1,\"sequence\":0,\"eventType\":\"AGENT_STARTED\","
                    + "\"provenanceKind\":\"RUNTIME_OBSERVED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"\",\"method\":\"premain\",\"timestamp\":\"2026-07-24T00:00:00Z\","
                    + "\"thread\":\"main\",\"detail\":{\"mode\":\"fixture\"}}\n"
                    + "{\"schemaVersion\":1,\"sequence\":1,\"eventType\":\"JDBC\","
                    + "\"provenanceKind\":\"APPLICATION_REPORTED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"fixture.Repository\",\"method\":\"query\",\"timestamp\":\"2026-07-24T00:00:01Z\","
                    + "\"thread\":\"main\",\"detail\":{\"operation\":\"select\"}}\n";
    private static final String EXTERNAL_JSONL =
            "{\"schemaVersion\":1,\"sequence\":0,\"eventType\":\"AGENT_STARTED\","
                    + "\"provenanceKind\":\"RUNTIME_OBSERVED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"agent.VeyrionAgent\",\"method\":\"premain\","
                    + "\"timestamp\":\"2026-07-24T00:00:00Z\",\"thread\":\"main\","
                    + "\"detail\":{\"captureMode\":\"automatic\"}}\n"
                    + "{\"schemaVersion\":1,\"sequence\":1,\"eventType\":\"HTTP_CLIENT\","
                    + "\"provenanceKind\":\"AGENT_INSTRUMENTED\","
                    + "\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"example.Client\",\"method\":\"call()V\","
                    + "\"timestamp\":\"2026-07-24T00:00:01Z\",\"thread\":\"main\","
                    + "\"detail\":{\"targetClass\":\"java.net.http.HttpClient\","
                    + "\"targetMethod\":\"send\",\"instructionOrdinal\":\"0\"}}\n";

    public static void main(String[] args) throws Exception {
        // Runs the real public dashboard/path/evidence HTTP loop with its mock OpenSandbox backend.
        FixtureDynamicLoopAcceptanceTest.main(args);

        Clock clock = Clock.fixed(Instant.parse("2026-07-24T00:00:10Z"), ZoneOffset.UTC);
        InMemoryTraceStore traces = new InMemoryTraceStore(clock);
        InMemoryTaskCoordinator tasks = new InMemoryTaskCoordinator(clock, traces);
        TraceProjectionService service = new TraceProjectionService(traces);
        AgentJsonlTraceConverter converter =
                new AgentJsonlTraceConverter(clock, 64 * 1024, 16 * 1024, 100, 16 * 1024);

        WorkerTaskSpec runningSpec = spec("scan-running", "task-running");
        TaskSnapshot running = start(tasks, runningSpec, "running");
        expect(IllegalArgumentException.class, () -> service.project(running),
                "RUNNING/TraceCommitted state must not project");
        TaskSnapshot failed = tasks.fail(running.scope(), running.lease().leaseId(), "worker-1",
                StopReason.WORKER_FAILURE, "FIXTURE_FAILED", "failed");
        expect(IllegalArgumentException.class, () -> service.project(failed),
                "FAILED task must not project");

        WorkerTaskSpec completedSpec = spec("scan-completed", "task-completed");
        TaskSnapshot active = start(tasks, completedSpec, "completed");
        List<TraceChunk> chunks = converter.convert(
                VALID_JSONL.getBytes(StandardCharsets.UTF_8), active.scope(), completedSpec.resourceBudget());
        for (TraceChunk chunk : chunks) traces.append(active.scope(), "chunk-" + chunk.sequence(), chunk);
        List<TraceChunk> readCopy = traces.readChunks(active.scope(), 10, completedSpec.resourceBudget().maxTraceBytes());
        byte original = readCopy.get(0).payload()[0];
        byte[] exposed = readCopy.get(0).payload();
        exposed[0] ^= 0x01;
        check(traces.readChunks(active.scope(), 10, completedSpec.resourceBudget().maxTraceBytes())
                        .get(0).payload()[0] == original,
                "trace read snapshot does not expose mutable payload");
        expect(UnsupportedOperationException.class, () -> readCopy.add(readCopy.get(0)),
                "trace read snapshot list is immutable");
        TaskSnapshot completed = tasks.complete(active.scope(), active.lease().leaseId(), "worker-1", "complete");
        TraceProjectionService.Projection projection = service.publishCompleted(completed);
        check("DYNAMIC_SUSPECTED".equals(projection.path().verificationStatus())
                        && projection.path().steps().stream()
                        .noneMatch(step -> "VERIFIED".equals(step.verificationStatus())),
                "completed fixture remains DYNAMIC_SUSPECTED");

        WorkerTaskSpec externalSpec = new WorkerTaskSpec(
                1, "project-1", DIGEST, "scan-external", "task-external", "entry-1",
                true, false, new ResourceBudget(60, 30_000, 128 * 1024 * 1024L,
                64 * 1024 * 1024L, 64 * 1024), NetworkPolicy.denyAll(),
                WorkerCapability.HARDENED_GVISOR);
        TaskSnapshot externalActive = start(tasks, externalSpec, "external");
        List<TraceChunk> externalChunks = converter.convert(
                EXTERNAL_JSONL.getBytes(StandardCharsets.UTF_8), externalActive.scope(),
                externalSpec.resourceBudget());
        for (TraceChunk chunk : externalChunks) {
            traces.append(externalActive.scope(), "external-" + chunk.sequence(), chunk);
        }
        TaskSnapshot externalCompleted = tasks.complete(
                externalActive.scope(), externalActive.lease().leaseId(), "worker-1", "external-complete");
        TraceProjectionService.Projection externalProjection = service.publishCompleted(externalCompleted);
        check(!externalProjection.path().fixtureOnly()
                        && "HARDENED_GVISOR".equals(externalProjection.path().requiredCapability())
                        && externalProjection.path().steps().stream()
                        .anyMatch(step -> "AGENT_INSTRUMENTED".equals(step.provenanceKind())),
                "hardened original-artifact trace was not projected with its provenance");

        byte[] changedPayload = VALID_JSONL.replace("Repository", "TamperedRepo")
                .getBytes(StandardCharsets.UTF_8);
        TraceChunk changed = TraceChunk.create(completed.scope(), 0, null, clock.instant(), changedPayload);
        expect(SecurityException.class,
                () -> service.project(completed, traces.manifest(completed.scope()), List.of(changed)),
                "tampered content must fail manifest/digest binding");

        WorkerTaskSpec otherSpec = spec("scan-other", "task-other");
        TaskSnapshot otherActive = start(tasks, otherSpec, "other");
        List<TraceChunk> otherChunks = converter.convert(
                VALID_JSONL.getBytes(StandardCharsets.UTF_8), otherActive.scope(), otherSpec.resourceBudget());
        for (TraceChunk chunk : otherChunks) traces.append(otherActive.scope(), "other-" + chunk.sequence(), chunk);
        TaskSnapshot otherCompleted = tasks.complete(otherActive.scope(), otherActive.lease().leaseId(),
                "worker-1", "other-complete");
        expect(SecurityException.class,
                () -> service.project(completed, traces.manifest(otherCompleted.scope()), otherChunks),
                "cross-scan scope must fail closed");

        String verifiedJsonl = VALID_JSONL.replace("DYNAMIC_SUSPECTED", "VERIFIED");
        TraceChunk verifiedChunk = TraceChunk.create(completed.scope(), 0, null, clock.instant(),
                verifiedJsonl.getBytes(StandardCharsets.UTF_8));
        TraceManifest verifiedManifest = new TraceManifest(1, completed.scope(),
                List.of(new TraceManifest.ChunkRef(0, verifiedChunk.digest(),
                        verifiedChunk.payload().length, verifiedChunk.emittedAt())),
                verifiedChunk.payload().length, verifiedChunk.digest(), clock.instant());
        expect(IllegalArgumentException.class,
                () -> service.project(completed, verifiedManifest, List.of(verifiedChunk)),
                "VERIFIED Agent event must never be projected");
        check(service.evidenceForScan(completed.scope().projectId(), completed.scope().artifactDigest(),
                        completed.scope().scanId()).stream()
                        .noneMatch(item -> "VERIFIED".equals(item.verificationStatus())),
                "published evidence contains no VERIFIED status");
        System.out.println("DynamicTraceProjectionAcceptanceTest: PASS");
    }

    private static WorkerTaskSpec spec(String scanId, String taskId) {
        return new WorkerTaskSpec(1, "project-1", DIGEST, scanId, taskId, "entry-1",
                true, true, new ResourceBudget(60, 30_000, 128 * 1024 * 1024L,
                64 * 1024 * 1024L, 64 * 1024), NetworkPolicy.denyAll(),
                WorkerCapability.FIXTURE_RUNC);
    }

    private static TaskSnapshot start(InMemoryTaskCoordinator tasks, WorkerTaskSpec spec, String key) {
        tasks.enqueue(spec, "enqueue-" + key);
        WorkerLease lease = tasks.lease(spec.scope(), "worker-1", Set.of(spec.requiredCapability()),
                Duration.ofMinutes(1), "lease-" + key);
        return tasks.start(spec.scope(), lease.leaseId(), "worker-1", "start-" + key);
    }

    private static <T extends Throwable> void expect(Class<T> type, ThrowingRunnable action, String message)
            throws Exception {
        try {
            action.run();
        } catch (Throwable actual) {
            if (type.isInstance(actual)) return;
            throw actual;
        }
        throw new AssertionError("expected " + type.getSimpleName() + ": " + message);
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
