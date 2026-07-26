package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.model.VerificationStatus;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;

/**
 * PathRun SQL must carry statement-level D1 fields and must not promote Redis/MySQL
 * handshake/listen meta ({@code port=6379}, {@code sqlClass=…,bytes=N}) as SQL evidence.
 */
public final class SqlPathRunProjectionAcceptanceTest {
    private static final String DIGEST = "b".repeat(64);

    private static final String MIXED_JSONL =
            "{\"schemaVersion\":1,\"sequence\":0,\"eventType\":\"AGENT_STARTED\","
                    + "\"provenanceKind\":\"RUNTIME_OBSERVED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"\",\"method\":\"premain\",\"timestamp\":\"2026-07-26T00:00:00Z\","
                    + "\"thread\":\"main\",\"detail\":{\"mode\":\"test\"}}\n"
                    + "{\"schemaVersion\":1,\"sequence\":1,\"eventType\":\"JDBC\","
                    + "\"provenanceKind\":\"APPLICATION_REPORTED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"com.aq.jvmsentinel.instrumentation.mock.LoopbackRedisStub\","
                    + "\"method\":\"resp\",\"timestamp\":\"2026-07-26T00:00:01Z\",\"thread\":\"main\","
                    + "\"detail\":{\"captureMode\":\"DEPENDENCY_PROTOCOL_MOCK\",\"dependencyMode\":\"MOCK\","
                    + "\"protocol\":\"REDIS_RESP\",\"operation\":\"START\",\"outcome\":\"RULE_GENERATED\","
                    + "\"summary\":\"port=6379\"}}\n"
                    + "{\"schemaVersion\":1,\"sequence\":2,\"eventType\":\"JDBC\","
                    + "\"provenanceKind\":\"APPLICATION_REPORTED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"com.aq.jvmsentinel.instrumentation.mock.LoopbackMysqlStub\","
                    + "\"method\":\"mysqlClassic\",\"timestamp\":\"2026-07-26T00:00:02Z\",\"thread\":\"main\","
                    + "\"detail\":{\"captureMode\":\"DEPENDENCY_PROTOCOL_MOCK\",\"dependencyMode\":\"MOCK\","
                    + "\"protocol\":\"MYSQL_CLASSIC\",\"operation\":\"AUTH\",\"outcome\":\"RULE_GENERATED\","
                    + "\"summary\":\"accepted-without-credential-capture\"}}\n"
                    + "{\"schemaVersion\":1,\"sequence\":3,\"eventType\":\"JDBC\","
                    + "\"provenanceKind\":\"APPLICATION_REPORTED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"com.aq.jvmsentinel.instrumentation.mock.LoopbackMysqlStub\","
                    + "\"method\":\"mysqlClassic\",\"timestamp\":\"2026-07-26T00:00:03Z\",\"thread\":\"main\","
                    + "\"detail\":{\"captureMode\":\"DEPENDENCY_PROTOCOL_MOCK\",\"dependencyMode\":\"MOCK\","
                    + "\"protocol\":\"MYSQL_CLASSIC\",\"operation\":\"COM_QUERY\",\"outcome\":\"RULE_GENERATED\","
                    + "\"sqlClass\":\"SELECT\",\"sql\":\"SELECT id FROM users WHERE name=?\","
                    + "\"readWrite\":\"READ\",\"parameterized\":\"true\",\"maliciousFragmentPresent\":\"false\","
                    + "\"parameterSummary\":\"jdbc-placeholders\","
                    + "\"summary\":\"sqlClass=SELECT,bytes=34\"}}\n"
                    + "{\"schemaVersion\":1,\"sequence\":4,\"eventType\":\"HTTP\","
                    + "\"provenanceKind\":\"APPLICATION_REPORTED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"com.aq.jvmsentinel.agent.LoopbackHttpProbe\",\"method\":\"main\","
                    + "\"timestamp\":\"2026-07-26T00:00:04Z\",\"thread\":\"main\","
                    + "\"detail\":{\"httpMethod\":\"GET\",\"route\":\"/api/users\",\"requestTarget\":\"/api/users\","
                    + "\"status\":\"200\",\"port\":\"8080\",\"error\":\"\",\"track\":\"UNAUTH\"}}\n";

    /** Benign + META_MARKER statement pair for D2 structure influence (protocol meta still excluded). */
    private static final String D2_JSONL =
            "{\"schemaVersion\":1,\"sequence\":0,\"eventType\":\"AGENT_STARTED\","
                    + "\"provenanceKind\":\"RUNTIME_OBSERVED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"\",\"method\":\"premain\",\"timestamp\":\"2026-07-26T00:00:00Z\","
                    + "\"thread\":\"main\",\"detail\":{\"mode\":\"test\"}}\n"
                    + "{\"schemaVersion\":1,\"sequence\":1,\"eventType\":\"JDBC\","
                    + "\"provenanceKind\":\"APPLICATION_REPORTED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"com.aq.jvmsentinel.instrumentation.mock.LoopbackRedisStub\","
                    + "\"method\":\"resp\",\"timestamp\":\"2026-07-26T00:00:01Z\",\"thread\":\"main\","
                    + "\"detail\":{\"captureMode\":\"DEPENDENCY_PROTOCOL_MOCK\",\"dependencyMode\":\"MOCK\","
                    + "\"protocol\":\"REDIS_RESP\",\"operation\":\"START\",\"outcome\":\"RULE_GENERATED\","
                    + "\"summary\":\"port=6379\",\"sql\":\"port=6379\"}}\n"
                    + "{\"schemaVersion\":1,\"sequence\":2,\"eventType\":\"JDBC\","
                    + "\"provenanceKind\":\"APPLICATION_REPORTED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"com.aq.jvmsentinel.instrumentation.mock.LoopbackMysqlStub\","
                    + "\"method\":\"mysqlClassic\",\"timestamp\":\"2026-07-26T00:00:02Z\",\"thread\":\"main\","
                    + "\"detail\":{\"captureMode\":\"DEPENDENCY_PROTOCOL_MOCK\",\"dependencyMode\":\"MOCK\","
                    + "\"protocol\":\"MYSQL_CLASSIC\",\"operation\":\"COM_QUERY\",\"outcome\":\"RULE_GENERATED\","
                    + "\"sqlClass\":\"SELECT\",\"sql\":\"SELECT id FROM users WHERE name='alice'\","
                    + "\"readWrite\":\"READ\",\"parameterized\":\"false\",\"maliciousFragmentPresent\":\"false\","
                    + "\"parameterSummary\":\"benign-literal\","
                    + "\"summary\":\"sqlClass=SELECT,bytes=40\"}}\n"
                    + "{\"schemaVersion\":1,\"sequence\":3,\"eventType\":\"JDBC\","
                    + "\"provenanceKind\":\"APPLICATION_REPORTED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"com.aq.jvmsentinel.instrumentation.mock.LoopbackMysqlStub\","
                    + "\"method\":\"mysqlClassic\",\"timestamp\":\"2026-07-26T00:00:03Z\",\"thread\":\"main\","
                    + "\"detail\":{\"captureMode\":\"DEPENDENCY_PROTOCOL_MOCK\",\"dependencyMode\":\"MOCK\","
                    + "\"protocol\":\"MYSQL_CLASSIC\",\"operation\":\"COM_QUERY\",\"outcome\":\"RULE_GENERATED\","
                    + "\"sqlClass\":\"SELECT\",\"sql\":\"SELECT id FROM users WHERE name=''\\\"veyrion-sqli-meta\","
                    + "\"readWrite\":\"READ\",\"parameterized\":\"true\",\"maliciousFragmentPresent\":\"true\","
                    + "\"parameterSummary\":\"metachar-probe\","
                    + "\"summary\":\"sqlClass=SELECT,bytes=52\"}}\n"
                    + "{\"schemaVersion\":1,\"sequence\":4,\"eventType\":\"HTTP\","
                    + "\"provenanceKind\":\"APPLICATION_REPORTED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                    + "\"class\":\"com.aq.jvmsentinel.agent.LoopbackHttpProbe\",\"method\":\"main\","
                    + "\"timestamp\":\"2026-07-26T00:00:04Z\",\"thread\":\"main\","
                    + "\"detail\":{\"httpMethod\":\"GET\",\"route\":\"/api/users\",\"requestTarget\":"
                    + "\"/api/users?name=%27%22veyrion-sqli-meta\",\"status\":\"200\",\"port\":\"8080\","
                    + "\"error\":\"\",\"track\":\"UNAUTH\"}}\n";

    public static void main(String[] args) throws Exception {
        statementLevelExcludesProtocolMeta();
        d2DifferentialAppendsStructureInfluencedSummary();
        System.out.println("SqlPathRunProjectionAcceptanceTest: PASS");
    }

    private static void statementLevelExcludesProtocolMeta() throws Exception {
        TraceProjectionService.Projection projection = projectFixture(
                "project-sql", "scan-sql", "task-sql", MIXED_JSONL);

        check(!projection.pathRuns().isEmpty(), "PathRun projected");
        ApiDtos.PathRunDto run = projection.pathRuns().get(0);
        check(run.sqlEvents().size() == 1, "only statement-level SQL attached to PathRun");
        ApiDtos.SqlEventDto sql = run.sqlEvents().get(0);
        check(sql.sqlText().startsWith("SELECT id FROM users"), "truncated SQL text present");
        check(sql.parameterized(), "parameterized flag from JDBC observation");
        check("READ".equals(sql.readWrite()), "readWrite classified");
        check("DEPENDENCY_PROTOCOL_MOCK".equals(sql.captureMode()), "captureMode preserved from agent");
        check(!sql.sqlText().contains("port=6379"), "Redis listen meta not promoted as SQL");
        check(!sql.sqlText().startsWith("sqlClass="), "sqlClass meta not used as sqlText");
        check("DYNAMIC_SUSPECTED".equals(run.verificationStatus()),
                "MOCK parameterized observation stays DYNAMIC_SUSPECTED");

        check(projection.evidence().values().stream()
                        .anyMatch(item -> item.summary().contains("dependency meta")
                                && item.summary().contains("port=6379")),
                "protocol meta remains visible on dependency evidence steps");

        check(DynamicConfirmedGate.evaluate(
                        new com.aq.jvmsentinel.model.PathRun(
                                run.pathRunId(), run.scanId(), run.entrypointRef(),
                                com.aq.jvmsentinel.model.IdentityTrack.UNAUTH, run.attemptId(), null,
                                run.method(), run.contentType(), run.requestSummary(),
                                com.aq.jvmsentinel.model.PathOutcomeClass.HTTP_OBSERVED,
                                run.httpStatus(), run.entryHit(), run.parameterBound(),
                                List.of(new com.aq.jvmsentinel.model.SqlEvent(
                                        "port=6379", "", "UNKNOWN", false, true, "MOCK")),
                                run.stopReason(), "DYNAMIC_SUSPECTED", run.evidenceRefs(),
                                run.identityProvenance(), run.identityPrecondition()),
                        SqlDiffProbe.META_MARKER) == VerificationStatus.DYNAMIC_SUSPECTED,
                "protocol meta alone cannot satisfy DYNAMIC_CONFIRMED gate");
    }

    private static void d2DifferentialAppendsStructureInfluencedSummary() throws Exception {
        TraceProjectionService.Projection projection = projectFixture(
                "project-d2", "scan-d2", "task-d2", D2_JSONL);
        check(!projection.pathRuns().isEmpty(), "D2 PathRun projected");
        ApiDtos.PathRunDto run = projection.pathRuns().get(0);
        check(run.sqlEvents().size() == 2, "benign + meta statements only (protocol excluded)");
        check(run.sqlEvents().stream().noneMatch(sql -> sql.sqlText().contains("port=6379")),
                "META_MARKER / D2 pair never treats protocol handshake as SQL");
        check(run.sqlEvents().stream().anyMatch(sql ->
                        sql.sqlText().contains(SqlDiffProbe.META_MARKER)),
                "meta statement retained with META_MARKER");
        check(run.requestSummary().contains("D2: structureInfluenced=true (MOCK)"),
                "D2 compare summary attached to meta PathRun requestSummary");
        check(!"VERIFIED".equals(run.verificationStatus()),
                "D2 never upgrades to VERIFIED");
        check("DYNAMIC_SUSPECTED".equals(run.verificationStatus())
                        || "DYNAMIC_CONFIRMED".equals(run.verificationStatus()),
                "D2 capped at DYNAMIC_SUSPECTED; only H3 may DYNAMIC_CONFIRMED");
        // Parameterized meta keeps H3 from confirming in this fixture.
        check("DYNAMIC_SUSPECTED".equals(run.verificationStatus()),
                "parameterized meta probe remains DYNAMIC_SUSPECTED under D2");
    }

    private static TraceProjectionService.Projection projectFixture(
            String projectId, String scanId, String taskId, String jsonl) throws Exception {
        Clock clock = Clock.fixed(Instant.parse("2026-07-26T00:00:10Z"), ZoneOffset.UTC);
        InMemoryTraceStore traces = new InMemoryTraceStore(clock);
        InMemoryTaskCoordinator tasks = new InMemoryTaskCoordinator(clock, traces);
        TraceProjectionService service = new TraceProjectionService(traces);
        AgentJsonlTraceConverter converter =
                new AgentJsonlTraceConverter(clock, 64 * 1024, 16 * 1024, 100, 16 * 1024);

        WorkerTaskSpec spec = new WorkerTaskSpec(
                1, projectId, DIGEST, scanId, taskId, "entry-1",
                true, false, new ResourceBudget(60, 30_000, 128 * 1024 * 1024L,
                64 * 1024 * 1024L, 64 * 1024), NetworkPolicy.denyAll(),
                WorkerCapability.TRUSTED_DOCKER);
        tasks.enqueue(spec, "enqueue-" + taskId);
        WorkerLease lease = tasks.lease(spec.scope(), "worker-1", Set.of(WorkerCapability.TRUSTED_DOCKER),
                Duration.ofMinutes(1), "lease-" + taskId);
        TaskSnapshot active = tasks.start(spec.scope(), lease.leaseId(), "worker-1", "start-" + taskId);
        List<TraceChunk> chunks = converter.convert(
                jsonl.getBytes(StandardCharsets.UTF_8), active.scope(), spec.resourceBudget());
        for (TraceChunk chunk : chunks) traces.append(active.scope(), "chunk-" + chunk.sequence(), chunk);
        TaskSnapshot completed = tasks.complete(active.scope(), lease.leaseId(), "worker-1",
                "complete-" + taskId);
        return service.publishCompleted(completed);
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
