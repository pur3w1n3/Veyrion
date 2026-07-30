package com.aq.jvmsentinel.ai;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.ai.tool.AiToolRegistry;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolCall;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolResult;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolStatus;
import com.aq.jvmsentinel.ai.tool.ToolDataSource;
import com.aq.jvmsentinel.ai.tool.ToolExecutionContext;
import com.aq.jvmsentinel.provider.AgentRole;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * P0-05：PATH/TRIAGE sandbox_probe 要求 track/objective/(coverageGapRef)。
 */
public final class PathTriageProbeGateAcceptanceTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();
    private static final ToolExecutionContext.Scope SCOPE =
            new ToolExecutionContext.Scope("local", "project-a");

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        pathRequiresGapWhenPresent();
        pathRequiresTrackObjective();
        triageRequiresTrackObjective();
        System.out.println("PathTriageProbeGateAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void pathRequiresGapWhenPresent() throws Exception {
        FakeSource source = new FakeSource(List.of("tp-gap-1"));
        AiToolRegistry registry = new AiToolRegistry(source);
        ToolExecutionContext context = context(AgentRole.PATH_EXPLORATION, "job-path-1");
        ToolResult denied = registry.execute(argsCall(
                "entry:entry-1", "UNAUTH", "close coverage gap", "tp-wrong"), context);
        check(denied.status() == ToolStatus.INVALID_ARGUMENTS, "PATH wrong gap -> INVALID_ARGUMENTS");
        check("COVERAGE_GAP_REQUIRED".equals(denied.errorCode()), "COVERAGE_GAP_REQUIRED");

        ToolResult ok = registry.execute(argsCall(
                "entry:entry-1", "UNAUTH", "close coverage gap", "tp-gap-1"), context);
        check(ok.status() == ToolStatus.SUCCESS, "PATH with matching gap succeeds");
        check(source.probeCalls.get() == 1, "probe executed once");
    }

    private static void pathRequiresTrackObjective() throws Exception {
        FakeSource source = new FakeSource(List.of());
        AiToolRegistry registry = new AiToolRegistry(source);
        ToolExecutionContext context = context(AgentRole.PATH_EXPLORATION, "job-path-2");
        ObjectNode args = JSON.createObjectNode();
        args.put("entrypointRef", "entry:entry-1");
        args.put("objective", "close coverage gap");
        ToolResult denied = registry.execute(new ToolCall(1, "call-1", "sandbox_probe", args), context);
        check(denied.status() == ToolStatus.INVALID_ARGUMENTS, "PATH missing track denied");
        check("PATH_PROBE_FIELDS_REQUIRED".equals(denied.errorCode()), "PATH_PROBE_FIELDS_REQUIRED");
    }

    private static void triageRequiresTrackObjective() throws Exception {
        FakeSource source = new FakeSource(List.of());
        AiToolRegistry registry = new AiToolRegistry(source);
        ToolExecutionContext context = context(AgentRole.VULNERABILITY_TRIAGE, "job-triage-1");
        ObjectNode missing = JSON.createObjectNode();
        missing.put("entrypointRef", "entry:entry-1");
        missing.put("objective", "reproduce finding");
        ToolResult denied = registry.execute(
                new ToolCall(1, "call-1", "sandbox_probe", missing), context);
        check(denied.status() == ToolStatus.INVALID_ARGUMENTS, "TRIAGE missing track denied");
        check("TRIAGE_PROBE_FIELDS_REQUIRED".equals(denied.errorCode()), "TRIAGE_PROBE_FIELDS_REQUIRED");

        ToolResult ok = registry.execute(argsCall(
                "entry:entry-1", "UNAUTH", "reproduce finding", null), context);
        check(ok.status() == ToolStatus.SUCCESS, "TRIAGE with track/objective succeeds");
    }

    private static ToolCall argsCall(String entry, String track, String objective, String gap) {
        ObjectNode node = JSON.createObjectNode();
        node.put("entrypointRef", entry);
        if (track != null) node.put("track", track);
        if (objective != null) node.put("objective", objective);
        if (gap != null) node.put("coverageGapRef", gap);
        return new ToolCall(1, "call-1", "sandbox_probe", node);
    }

    private static ToolExecutionContext context(AgentRole role, String jobId) {
        return ToolExecutionContext.bind(
                SCOPE, "op-1", jobId, role,
                new ToolExecutionContext.Budget(8, 65_536, 16, 65_536, Instant.now().plusSeconds(60)));
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }

    private static final class FakeSource implements ToolDataSource {
        private final List<String> gaps;
        private final AtomicInteger probeCalls = new AtomicInteger();

        FakeSource(List<String> gaps) {
            this.gaps = List.copyOf(gaps);
        }

        @Override
        public List<FactRecord> searchFacts(ToolExecutionContext.Scope scope, String kind, String query, int limit) {
            return List.of();
        }

        @Override
        public Optional<FactRecord> findEvidence(ToolExecutionContext.Scope scope, String evidenceRef) {
            return Optional.empty();
        }

        @Override
        public Optional<FactRecord> resolveEntrypoint(ToolExecutionContext.Scope scope, String entrypointRef) {
            ObjectNode value = JSON.createObjectNode();
            value.put("entrypoint", "app.Controller");
            value.put("route", "/api/x");
            value.put("method", "GET");
            return Optional.of(new FactRecord(scope, "entry:entry-1", value));
        }

        @Override
        public Optional<FactRecord> requestSandboxProbe(
                ToolExecutionContext.Scope scope, String principalId, String jobId, String toolCallId,
                String entrypointRef, List<String> candidateInputs, int maxRequests,
                String techniqueId, String authorizationHeader, String bladeAuthHeader,
                String experimentPlanId) {
            probeCalls.incrementAndGet();
            ObjectNode value = JSON.createObjectNode();
            value.put("state", "COMPLETED");
            value.put("pathRunCount", 1);
            value.put("lifecycle", "COMPLETED");
            if (experimentPlanId != null) value.put("experimentPlanId", experimentPlanId);
            return Optional.of(new FactRecord(scope, "sandbox-probe:" + toolCallId, value));
        }

        @Override
        public List<String> coverageGapIds(ToolExecutionContext.Scope scope) {
            return gaps;
        }
    }
}
