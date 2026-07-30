package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.model.PathOutcomeClass;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * P0-02：PathRun entryHit / parameterBound 须诚实 — 优先 event detail，
 * 永不捏造 parameterBound=true，区分 REACHED_NO_BIND（404）与业务 2xx。
 */
public final class EntryHitParameterBoundAcceptanceTest {
    private static final String DIGEST = "c".repeat(64);
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        unitHeuristics();
        projectionPositive200();
        projectionNegative404();
        projectionTimeoutUnknown();
        projectionInternalHttpDoesNotCreatePathRuns();
        projectionSpringBoundEvidence();
        System.out.println("EntryHitParameterBoundAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void unitHeuristics() {
        check(Boolean.TRUE.equals(TraceProjectionService.resolveEntryHit(Map.of(), 200)),
                "200 → entryHit true");
        check(Boolean.TRUE.equals(TraceProjectionService.resolveEntryHit(Map.of(), 401)),
                "401 → entryHit true");
        check(Boolean.FALSE.equals(TraceProjectionService.resolveEntryHit(Map.of(), 404)),
                "404 → entryHit false");
        check(TraceProjectionService.resolveEntryHit(Map.of(), -1) == null,
                "timeout status → entryHit unknown");
        check(TraceProjectionService.resolveParameterBound(Map.of(), 200, "GET /x", Set.of()) == null,
                "2xx without bind evidence → parameterBound unknown (not true)");
        check(Boolean.FALSE.equals(
                        TraceProjectionService.resolveParameterBound(Map.of(), 404, "GET /x", Set.of())),
                "404 → parameterBound false");
        check(Boolean.TRUE.equals(TraceProjectionService.resolveParameterBound(
                        Map.of(), 200, "GET /api/read", Set.of("GET /api/read"))),
                "Spring bind evidence may set parameterBound true");
        check(Boolean.TRUE.equals(TraceProjectionService.resolveEntryHit(
                        Map.of("entryHit", "true"), -1)),
                "explicit detail entryHit wins over status");
        check(Boolean.FALSE.equals(TraceProjectionService.resolveParameterBound(
                        Map.of("parameterBound", "false"), 200, "GET /x", Set.of("GET /x"))),
                "explicit parameterBound=false wins over Spring set");
        check(ApiDtos.UNREACHED.equals(TraceProjectionService.verificationStatusFor(
                        PathOutcomeClass.UNKNOWN, -1)),
                "unknown transport result is UNREACHED");
        check(ApiDtos.UNREACHED.equals(TraceProjectionService.verificationStatusFor(
                        PathOutcomeClass.BUSINESS_TIMEOUT, -1)),
                "business timeout is UNREACHED");
        check(ApiDtos.DYNAMIC_SUSPECTED.equals(TraceProjectionService.verificationStatusFor(
                        PathOutcomeClass.HTTP_OBSERVED, 302)),
                "HTTP observation may be dynamic suspected");
    }

    private static void projectionPositive200() throws Exception {
        String jsonl = agentStarted()
                + httpProbe(1, "GET", "/api/ok", "/api/ok", "200", "", "HTTP_OBSERVED", null, null);
        ApiDtos.PathRunDto run = projectOne("scan-hit-200", "task-hit-200", jsonl);
        check(run.httpStatus() == 200, "positive fixture status 200");
        check(Boolean.TRUE.equals(run.entryHit()), "200 → entryHit true");
        check(run.parameterBound() == null, "200 without bind detail → parameterBound null");
        check(run.requestSummary() != null && run.requestSummary().contains("parameterBound=unknown"),
                "unknown bind noted in requestSummary");
        check(!PathOutcomeClass.REACHED_NO_BIND.name().equals(run.outcomeClass()),
                "business 2xx is not REACHED_NO_BIND");
    }

    private static void projectionNegative404() throws Exception {
        String jsonl = agentStarted()
                + httpProbe(1, "GET", "/missing", "/missing", "404", "", "REACHED_NO_BIND",
                "false", "false");
        ApiDtos.PathRunDto run = projectOne("scan-hit-404", "task-hit-404", jsonl);
        check(run.httpStatus() == 404, "negative fixture status 404");
        check(Boolean.FALSE.equals(run.entryHit()), "404 → entryHit false");
        check(Boolean.FALSE.equals(run.parameterBound()), "404 → parameterBound false");
        check(PathOutcomeClass.REACHED_NO_BIND.name().equals(run.outcomeClass()),
                "404 → REACHED_NO_BIND");
    }

    private static void projectionTimeoutUnknown() throws Exception {
        String jsonl = agentStarted()
                + httpProbe(1, "GET", "/slow", "/slow", "UNKNOWN", "SocketTimeoutException",
                "BUSINESS_TIMEOUT", null, null);
        ApiDtos.PathRunDto run = projectOne("scan-hit-timeout", "task-hit-timeout", jsonl);
        check(run.httpStatus() == -1, "timeout fixture status -1");
        check(run.entryHit() == null, "timeout → entryHit unknown/null");
        check(run.parameterBound() == null, "timeout → parameterBound unknown/null");
        check(PathOutcomeClass.BUSINESS_TIMEOUT.name().equals(run.outcomeClass()),
                "timeout outcome preserved");
        check(ApiDtos.UNREACHED.equals(run.verificationStatus()),
                "timeout PathRun remains UNREACHED");
    }

    private static void projectionInternalHttpDoesNotCreatePathRuns() throws Exception {
        String jsonl = agentStarted()
                + internalHttp(1, "org.springframework.web.filter.OncePerRequestFilter",
                "doFilter", "SERVLET_FILTER", "GET", "/")
                + internalHttp(2, "sample.ApiController", "index",
                "SPRING_MAPPING_ANNOTATION", "GET", "/")
                + httpProbe(3, "GET", "/", "/", "302", "", "HTTP_OBSERVED", "true", null);
        List<ApiDtos.PathRunDto> runs = projectAll("scan-internal-http", "task-internal-http", jsonl);
        check(runs.size() == 1, "internal HTTP instrumentation does not create PathRun flood");
        ApiDtos.PathRunDto run = runs.get(0);
        check(run.httpStatus() == 302, "only loopback probe response becomes PathRun");
        check(ApiDtos.DYNAMIC_SUSPECTED.equals(run.verificationStatus()),
                "observed HTTP response may be dynamic suspected");
    }

    private static void projectionSpringBoundEvidence() throws Exception {
        String jsonl = agentStarted()
                + "{\"schemaVersion\":1,\"sequence\":1,\"eventType\":\"HTTP\","
                + "\"provenanceKind\":\"AGENT_INSTRUMENTED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                + "\"class\":\"sample.ApiController\",\"method\":\"read\","
                + "\"timestamp\":\"2026-07-27T00:00:01Z\",\"thread\":\"http-1\","
                + "\"detail\":{\"captureMode\":\"SPRING_MAPPING_ANNOTATION\","
                + "\"httpMethod\":\"GET\",\"route\":\"/api/bound\","
                + "\"entryHit\":\"true\",\"parameterBound\":\"true\"}}\n"
                + httpProbe(2, "GET", "/api/bound", "/api/bound?q=1", "200", "", "HTTP_OBSERVED",
                "true", null);
        ApiDtos.PathRunDto probeRun = projectAll("scan-hit-bound", "task-hit-bound", jsonl).stream()
                .filter(r -> r.evidenceRefs() != null && !r.evidenceRefs().isEmpty())
                .filter(r -> r.requestSummary() != null && r.requestSummary().contains("track="))
                .filter(r -> r.httpStatus() == 200)
                .findFirst()
                .orElseThrow(() -> new AssertionError("probe PathRun missing"));
        check(Boolean.TRUE.equals(probeRun.entryHit()), "bound probe entryHit true");
        check(Boolean.TRUE.equals(probeRun.parameterBound()),
                "Spring handler bind evidence promotes parameterBound on matching probe");
    }

    private static String agentStarted() {
        return "{\"schemaVersion\":1,\"sequence\":0,\"eventType\":\"AGENT_STARTED\","
                + "\"provenanceKind\":\"RUNTIME_OBSERVED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                + "\"class\":\"\",\"method\":\"premain\",\"timestamp\":\"2026-07-27T00:00:00Z\","
                + "\"thread\":\"main\",\"detail\":{\"mode\":\"test\"}}\n";
    }

    private static String internalHttp(int sequence, String className, String methodName,
                                       String captureMode, String httpMethod, String route) {
        return "{\"schemaVersion\":1,\"sequence\":" + sequence + ",\"eventType\":\"HTTP\","
                + "\"provenanceKind\":\"AGENT_INSTRUMENTED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                + "\"class\":\"" + className + "\",\"method\":\"" + methodName + "\","
                + "\"timestamp\":\"2026-07-27T00:00:01Z\",\"thread\":\"http-1\","
                + "\"detail\":{\"captureMode\":\"" + captureMode + "\","
                + "\"httpMethod\":\"" + httpMethod + "\",\"route\":\"" + route + "\"}}\n";
    }

    private static String httpProbe(int sequence, String method, String route, String target, String status,
                                    String error, String outcome, String entryHit, String parameterBound) {
        StringBuilder detail = new StringBuilder();
        detail.append("\"captureMode\":\"LOOPBACK_HTTP_PROBE\",")
                .append("\"httpMethod\":\"").append(method).append("\",")
                .append("\"route\":\"").append(route).append("\",")
                .append("\"requestTarget\":\"").append(target).append("\",")
                .append("\"status\":\"").append(status).append("\",")
                .append("\"port\":\"8080\",")
                .append("\"error\":\"").append(error == null ? "" : error).append("\",")
                .append("\"outcomeClass\":\"").append(outcome).append("\",")
                .append("\"track\":\"UNAUTH\"");
        if (entryHit != null) {
            detail.append(",\"entryHit\":\"").append(entryHit).append("\"");
        }
        if (parameterBound != null) {
            detail.append(",\"parameterBound\":\"").append(parameterBound).append("\"");
        }
        return "{\"schemaVersion\":1,\"sequence\":" + sequence + ",\"eventType\":\"HTTP\","
                + "\"provenanceKind\":\"APPLICATION_REPORTED\",\"verificationStatus\":\"DYNAMIC_SUSPECTED\","
                + "\"class\":\"com.aq.jvmsentinel.agent.LoopbackHttpProbe\",\"method\":\"main\","
                + "\"timestamp\":\"2026-07-27T00:00:02Z\",\"thread\":\"main\","
                + "\"detail\":{" + detail + "}}\n";
    }

    private static ApiDtos.PathRunDto projectOne(String scanId, String taskId, String jsonl)
            throws Exception {
        List<ApiDtos.PathRunDto> runs = projectAll(scanId, taskId, jsonl);
        check(!runs.isEmpty(), "PathRun projected for " + scanId);
        return runs.get(0);
    }

    private static List<ApiDtos.PathRunDto> projectAll(String scanId, String taskId, String jsonl)
            throws Exception {
        Clock clock = Clock.fixed(Instant.parse("2026-07-27T00:00:10Z"), ZoneOffset.UTC);
        InMemoryTraceStore traces = new InMemoryTraceStore(clock);
        InMemoryTaskCoordinator tasks = new InMemoryTaskCoordinator(clock, traces);
        TraceProjectionService service = new TraceProjectionService(traces);
        AgentJsonlTraceConverter converter =
                new AgentJsonlTraceConverter(clock, 64 * 1024, 16 * 1024, 100, 16 * 1024);
        WorkerTaskSpec spec = new WorkerTaskSpec(
                1, "project-entry-hit", DIGEST, scanId, taskId, "entry-1",
                true, false, new ResourceBudget(60, 30_000, 128 * 1024 * 1024L,
                64 * 1024 * 1024L, 64 * 1024), NetworkPolicy.denyAll(),
                WorkerCapability.TRUSTED_DOCKER);
        tasks.enqueue(spec, "enqueue-" + taskId);
        WorkerLease lease = tasks.lease(spec.scope(), "worker-1", Set.of(WorkerCapability.TRUSTED_DOCKER),
                Duration.ofMinutes(1), "lease-" + taskId);
        TaskSnapshot active = tasks.start(spec.scope(), lease.leaseId(), "worker-1", "start-" + taskId);
        List<TraceChunk> chunks = converter.convert(
                jsonl.getBytes(StandardCharsets.UTF_8), active.scope(), spec.resourceBudget());
        for (TraceChunk chunk : chunks) {
            traces.append(active.scope(), "chunk-" + chunk.sequence(), chunk);
        }
        TaskSnapshot completed = tasks.complete(
                active.scope(), lease.leaseId(), "worker-1", "complete-" + taskId);
        return service.publishCompleted(completed).pathRuns();
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}
