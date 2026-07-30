package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.control.ApiDtos;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * P0-06：PathRun 仅消费 request-window SQL；SQL 不在 HTTP 探针间复制。
 */
public final class RequestWindowSqlProjectionAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();
    private static final String DIGEST = "c".repeat(64);

    private static final String TWO_HTTP_JSONL =
            "{\"schemaVersion\":1,\"sequence\":0,\"eventType\":\"AGENT_STARTED\","
                    + "\"provenanceKind\":\"RUNTIME_OBSERVED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"\",\"method\":\"premain\",\"timestamp\":\"2026-07-26T00:00:00Z\","
                    + "\"thread\":\"main\",\"detail\":{\"mode\":\"test\"}}\n"
                    + "{\"schemaVersion\":1,\"sequence\":1,\"eventType\":\"JDBC\","
                    + "\"provenanceKind\":\"APPLICATION_REPORTED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"sample.Repo\",\"method\":\"q1\",\"timestamp\":\"2026-07-26T00:00:01Z\","
                    + "\"thread\":\"main\",\"detail\":{\"captureMode\":\"AGENT_INSTRUMENTED\","
                    + "\"sql\":\"SELECT 1 FROM a WHERE id=1\",\"readWrite\":\"READ\","
                    + "\"parameterized\":\"false\",\"maliciousFragmentPresent\":\"false\"}}\n"
                    + "{\"schemaVersion\":1,\"sequence\":2,\"eventType\":\"HTTP\","
                    + "\"provenanceKind\":\"APPLICATION_REPORTED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"com.aq.jvmsentinel.agent.LoopbackHttpProbe\",\"method\":\"main\","
                    + "\"timestamp\":\"2026-07-26T00:00:02Z\",\"thread\":\"main\","
                    + "\"detail\":{\"httpMethod\":\"GET\",\"route\":\"/api/a\",\"requestTarget\":\"/api/a\","
                    + "\"status\":\"200\",\"port\":\"8080\",\"error\":\"\",\"track\":\"UNAUTH\"}}\n"
                    + "{\"schemaVersion\":1,\"sequence\":3,\"eventType\":\"JDBC\","
                    + "\"provenanceKind\":\"APPLICATION_REPORTED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"sample.Repo\",\"method\":\"q2\",\"timestamp\":\"2026-07-26T00:00:03Z\","
                    + "\"thread\":\"main\",\"detail\":{\"captureMode\":\"AGENT_INSTRUMENTED\","
                    + "\"sql\":\"SELECT 2 FROM b WHERE id=2\",\"readWrite\":\"READ\","
                    + "\"parameterized\":\"false\",\"maliciousFragmentPresent\":\"false\"}}\n"
                    + "{\"schemaVersion\":1,\"sequence\":4,\"eventType\":\"HTTP\","
                    + "\"provenanceKind\":\"APPLICATION_REPORTED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"com.aq.jvmsentinel.agent.LoopbackHttpProbe\",\"method\":\"main\","
                    + "\"timestamp\":\"2026-07-26T00:00:04Z\",\"thread\":\"main\","
                    + "\"detail\":{\"httpMethod\":\"GET\",\"route\":\"/api/b\",\"requestTarget\":\"/api/b\","
                    + "\"status\":\"200\",\"port\":\"8080\",\"error\":\"\",\"track\":\"UNAUTH\"}}\n";

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        sqlBelongsOnlyToFollowingHttp();
        experimentPlanIdStampedOnPathRun();
        correlationIdJoinsHttpAndSql();
        System.out.println("RequestWindowSqlProjectionAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void sqlBelongsOnlyToFollowingHttp() throws Exception {
        TraceProjectionService.Projection projection = project("task-window", TWO_HTTP_JSONL, null);
        check(projection.pathRuns().size() == 2, "two HTTP PathRuns");
        ApiDtos.PathRunDto first = projection.pathRuns().get(0);
        ApiDtos.PathRunDto second = projection.pathRuns().get(1);
        check(first.sqlEvents().size() == 1, "first PathRun has one SQL");
        check(second.sqlEvents().size() == 1, "second PathRun has one SQL");
        check(first.sqlEvents().get(0).sqlText().contains("FROM a"), "first owns SQL-a");
        check(second.sqlEvents().get(0).sqlText().contains("FROM b"), "second owns SQL-b");
        check(!first.sqlEvents().get(0).sqlText().contains("FROM b"),
                "first does not inherit later SQL");
        check(!second.sqlEvents().get(0).sqlText().contains("FROM a"),
                "second does not inherit prior-window SQL after clear");
        check(first.evidenceRefs() != null && !first.evidenceRefs().isEmpty(),
                "PathRun carries evidence refs");
    }

    private static void experimentPlanIdStampedOnPathRun() throws Exception {
        TraceProjectionService.Projection projection = project("task-plan", TWO_HTTP_JSONL, "plan-abc");
        check(!projection.pathRuns().isEmpty(), "PathRuns present");
        for (ApiDtos.PathRunDto run : projection.pathRuns()) {
            check("plan-abc".equals(run.experimentPlanId()),
                    "experimentPlanId stamped on PathRun");
        }
    }

    private static void correlationIdJoinsHttpAndSql() throws Exception {
        String jsonl =
                "{\"schemaVersion\":1,\"sequence\":0,\"eventType\":\"AGENT_STARTED\","
                        + "\"provenanceKind\":\"RUNTIME_OBSERVED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                        + "\"class\":\"\",\"method\":\"premain\",\"timestamp\":\"2026-07-26T00:00:00Z\","
                        + "\"thread\":\"main\",\"detail\":{\"mode\":\"test\"}}\n"
                        + "{\"schemaVersion\":1,\"sequence\":1,\"eventType\":\"JDBC\","
                        + "\"provenanceKind\":\"APPLICATION_REPORTED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                        + "\"class\":\"sample.Repo\",\"method\":\"q1\",\"timestamp\":\"2026-07-26T00:00:01Z\","
                        + "\"thread\":\"main\",\"detail\":{\"captureMode\":\"AGENT_INSTRUMENTED\","
                        + "\"correlationId\":\"req-1-aaaa\",\"sql\":\"SELECT 1 FROM a\","
                        + "\"readWrite\":\"READ\",\"parameterized\":\"false\","
                        + "\"maliciousFragmentPresent\":\"false\"}}\n"
                        + "{\"schemaVersion\":1,\"sequence\":2,\"eventType\":\"JDBC\","
                        + "\"provenanceKind\":\"APPLICATION_REPORTED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                        + "\"class\":\"sample.Repo\",\"method\":\"q2\",\"timestamp\":\"2026-07-26T00:00:02Z\","
                        + "\"thread\":\"main\",\"detail\":{\"captureMode\":\"AGENT_INSTRUMENTED\","
                        + "\"correlationId\":\"req-2-bbbb\",\"sql\":\"SELECT 2 FROM b\","
                        + "\"readWrite\":\"READ\",\"parameterized\":\"false\","
                        + "\"maliciousFragmentPresent\":\"false\"}}\n"
                        + "{\"schemaVersion\":1,\"sequence\":3,\"eventType\":\"HTTP\","
                        + "\"provenanceKind\":\"APPLICATION_REPORTED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                        + "\"class\":\"com.aq.jvmsentinel.agent.LoopbackHttpProbe\",\"method\":\"main\","
                        + "\"timestamp\":\"2026-07-26T00:00:03Z\",\"thread\":\"main\","
                        + "\"detail\":{\"httpMethod\":\"GET\",\"route\":\"/api/a\",\"requestTarget\":\"/api/a\","
                        + "\"status\":\"200\",\"port\":\"8080\",\"error\":\"\",\"track\":\"UNAUTH\","
                        + "\"correlationId\":\"req-1-aaaa\"}}\n";
        TraceProjectionService.Projection projection = project("task-corr", jsonl, null);
        check(projection.pathRuns().size() == 1, "one HTTP PathRun");
        ApiDtos.PathRunDto run = projection.pathRuns().get(0);
        check("req-1-aaaa".equals(run.attemptId()), "attemptId uses correlationId");
        check(run.requestSummary().contains("correlationId=req-1-aaaa"),
                "requestSummary carries correlationId");
        check(run.sqlEvents().size() == 1, "only matching-correlation SQL attached");
        check(run.sqlEvents().get(0).sqlText().contains("FROM a"), "matched SQL-a");
        check(!run.sqlEvents().get(0).sqlText().contains("FROM b"),
                "mismatched correlation SQL not attached");
    }

    private static TraceProjectionService.Projection project(
            String taskId, String jsonl, String experimentPlanId) throws Exception {
        Clock clock = Clock.fixed(Instant.parse("2026-07-26T00:00:10Z"), ZoneOffset.UTC);
        InMemoryTraceStore traces = new InMemoryTraceStore(clock);
        InMemoryTaskCoordinator tasks = new InMemoryTaskCoordinator(clock, traces);
        TraceProjectionService service = new TraceProjectionService(traces);
        AgentJsonlTraceConverter converter =
                new AgentJsonlTraceConverter(clock, 64 * 1024, 16 * 1024, 100, 16 * 1024);
        WorkerTaskSpec spec = new WorkerTaskSpec(
                1, "project-window", DIGEST, "scan-window", taskId, "entry-1",
                true, false, new ResourceBudget(60, 30_000, 128 * 1024 * 1024L,
                64 * 1024 * 1024L, 64 * 1024), NetworkPolicy.denyAll(),
                WorkerCapability.TRUSTED_DOCKER);
        tasks.enqueue(spec, "enqueue-" + taskId);
        WorkerLease lease = tasks.lease(spec.scope(), "worker-1", Set.of(WorkerCapability.TRUSTED_DOCKER),
                Duration.ofMinutes(1), "lease-" + taskId);
        TaskSnapshot active = tasks.start(spec.scope(), lease.leaseId(), "worker-1", "start-" + taskId);
        if (experimentPlanId != null) {
            service.bindExperimentPlan(active.scope().taskId(), experimentPlanId);
        }
        List<TraceChunk> chunks = converter.convert(
                jsonl.getBytes(StandardCharsets.UTF_8), active.scope(), spec.resourceBudget());
        for (TraceChunk chunk : chunks) traces.append(active.scope(), "chunk-" + chunk.sequence(), chunk);
        TaskSnapshot completed = tasks.complete(active.scope(), lease.leaseId(), "worker-1",
                "complete-" + taskId);
        return service.publishCompleted(completed);
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}
