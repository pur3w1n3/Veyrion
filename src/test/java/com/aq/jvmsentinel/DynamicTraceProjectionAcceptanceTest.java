package com.aq.jvmsentinel;

import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.domain.pathdebug.TraceEventKind;
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
                    + "\"thread\":\"main\",\"detail\":{\"mode\":\"test\"}}\n"
                    + "{\"schemaVersion\":1,\"sequence\":1,\"eventType\":\"JDBC\","
                    + "\"provenanceKind\":\"APPLICATION_REPORTED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"sample.Repository\",\"method\":\"query\",\"timestamp\":\"2026-07-24T00:00:01Z\"," 
                    + "\"thread\":\"main\",\"detail\":{\"operation\":\"select\"}}\n"
                    + "{\"schemaVersion\":1,\"sequence\":2,\"eventType\":\"HTTP\","
                    + "\"provenanceKind\":\"APPLICATION_REPORTED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"com.aq.jvmsentinel.agent.LoopbackHttpProbe\",\"method\":\"main\","
                    + "\"timestamp\":\"2026-07-24T00:00:02Z\",\"thread\":\"main\","
                    + "\"detail\":{\"httpMethod\":\"GET\",\"route\":\"/api/read\","
                    + "\"requestTarget\":\"/api/read?path=super-secret\",\"status\":\"200\","
                    + "\"port\":\"8080\",\"error\":\"\"}}\n";
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
    /** Sensor hops/effects before probe HTTP must land in PathTrace via correlation window. */
    private static final String PATH_DEBUG_JSONL =
            "{\"schemaVersion\":1,\"sequence\":0,\"eventType\":\"AGENT_STARTED\","
                    + "\"provenanceKind\":\"RUNTIME_OBSERVED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"\",\"method\":\"premain\",\"timestamp\":\"2026-07-24T00:00:00Z\","
                    + "\"thread\":\"main\",\"detail\":{\"mode\":\"test\"}}\n"
                    + "{\"schemaVersion\":1,\"sequence\":1,\"eventType\":\"HTTP\","
                    + "\"provenanceKind\":\"AGENT_INSTRUMENTED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"com.example.CodeService\",\"method\":\"handle\","
                    + "\"timestamp\":\"2026-07-24T00:00:01Z\",\"thread\":\"http-1\","
                    + "\"detail\":{\"pathDebugKind\":\"METHOD_HOP\",\"captureMode\":\"APPLICATION_METHOD\","
                    + "\"correlationId\":\"req-1\",\"route\":\"/code\",\"httpMethod\":\"GET\"}}\n"
                    + "{\"schemaVersion\":1,\"sequence\":2,\"eventType\":\"PROCESS\","
                    + "\"provenanceKind\":\"AGENT_INSTRUMENTED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"com.example.Util\",\"method\":\"eval\","
                    + "\"timestamp\":\"2026-07-24T00:00:02Z\",\"thread\":\"http-1\","
                    + "\"detail\":{\"pathDebugKind\":\"EFFECT_TRIGGERED\",\"effectKind\":\"EXPRESSION\","
                    + "\"correlationId\":\"req-1\"}}\n"
                    + "{\"schemaVersion\":1,\"sequence\":3,\"eventType\":\"JDBC\","
                    + "\"provenanceKind\":\"AGENT_INSTRUMENTED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"com.example.Repo\",\"method\":\"execute\","
                    + "\"timestamp\":\"2026-07-24T00:00:03Z\",\"thread\":\"http-1\","
                    + "\"detail\":{\"pathDebugKind\":\"DEPENDENCY_FAILURE\","
                    + "\"failureClass\":\"DEPENDENCY_UNAVAILABLE\",\"summary\":\"Connection refused\","
                    + "\"correlationId\":\"req-1\",\"sql\":\"SELECT 1\",\"readWrite\":\"READ\","
                    + "\"captureMode\":\"STATEMENT\"}}\n"
                    + "{\"schemaVersion\":1,\"sequence\":4,\"eventType\":\"HTTP\","
                    + "\"provenanceKind\":\"APPLICATION_REPORTED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"com.aq.jvmsentinel.agent.LoopbackHttpProbe\",\"method\":\"main\","
                    + "\"timestamp\":\"2026-07-24T00:00:04Z\",\"thread\":\"main\","
                    + "\"detail\":{\"httpMethod\":\"GET\",\"route\":\"/code\","
                    + "\"requestTarget\":\"/code?code=x\",\"status\":\"500\","
                    + "\"port\":\"8080\",\"error\":\"\",\"correlationId\":\"req-1\","
                    + "\"captureMode\":\"LOOPBACK_HTTP_PROBE\",\"entryHit\":\"true\","
                    + "\"parameterBound\":\"true\"}}\n";

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
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
                "completed dynamic task remains DYNAMIC_SUSPECTED");
        String projectedHttp = projection.evidence().values().stream()
                .filter(item -> item.summary().contains("HTTP probe observed"))
                .findFirst().orElseThrow(() -> new AssertionError("HTTP probe evidence missing"))
                .summary();
        check(projectedHttp.contains("GET /api/read") && projectedHttp.contains("HTTP 200")
                        && projectedHttp.contains("path=<redacted:length=12>")
                        && !projectedHttp.contains("super-secret"),
                "HTTP request/response evidence is bounded and redacted");
        check(projection.path().steps().stream()
                        .anyMatch(step -> step.detail().contains("HTTP 200")
                                && step.detail().contains("path=<redacted:length=12>")),
                "path step exposes the bounded HTTP result");

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

        WorkerTaskSpec pathDebugSpec = spec("scan-path-debug", "task-path-debug");
        TaskSnapshot pathDebugActive = start(tasks, pathDebugSpec, "path-debug");
        List<TraceChunk> pathDebugChunks = converter.convert(
                PATH_DEBUG_JSONL.getBytes(StandardCharsets.UTF_8), pathDebugActive.scope(),
                pathDebugSpec.resourceBudget());
        for (TraceChunk chunk : pathDebugChunks) {
            traces.append(pathDebugActive.scope(), "pd-" + chunk.sequence(), chunk);
        }
        TaskSnapshot pathDebugCompleted = tasks.complete(
                pathDebugActive.scope(), pathDebugActive.lease().leaseId(), "worker-1", "pd-complete");
        TraceProjectionService.Projection pathDebugProjection =
                service.publishCompleted(pathDebugCompleted);
        check(!pathDebugProjection.pathTraces().isEmpty(), "path-debug projection emits PathTrace");
        PathTrace pathTrace = pathDebugProjection.pathTraces().get(0);
        check(pathTrace.events().stream().anyMatch(e -> e.kind() == TraceEventKind.METHOD_HOP),
                "PathTrace includes correlated METHOD_HOP from sensor window");
        check(pathTrace.events().stream().anyMatch(e -> e.kind() == TraceEventKind.EFFECT_TRIGGERED),
                "PathTrace includes correlated EFFECT_TRIGGERED from sensor window");
        check(pathTrace.events().stream().anyMatch(e -> e.kind() == TraceEventKind.DEPENDENCY_FAILURE),
                "PathTrace includes correlated DEPENDENCY_FAILURE from sensor window");
        check(!"VERIFIED".equals(pathTrace.posture().postureProvenance()),
                "path-debug PathTrace does not elevate verification provenance");

        System.out.println("DynamicTraceProjectionAcceptanceTest: PASS ("
                + AcceptanceAssertions.get() + " assertions)");
    }

    private static WorkerTaskSpec spec(String scanId, String taskId) {
        return new WorkerTaskSpec(1, "project-1", DIGEST, scanId, taskId, "entry-1",
                true, false, new ResourceBudget(60, 30_000, 128 * 1024 * 1024L,
                64 * 1024 * 1024L, 64 * 1024), NetworkPolicy.denyAll(),
                WorkerCapability.TRUSTED_DOCKER);
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
        AcceptanceAssertions.record();
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
