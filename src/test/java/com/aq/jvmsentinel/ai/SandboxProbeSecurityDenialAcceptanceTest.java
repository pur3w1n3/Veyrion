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
 * P0-14: sandbox_probe rejects command/image/mount/network/UID/budget overflow fields
 * (schema additionalProperties=false / UNKNOWN_ARGUMENT).
 */
public final class SandboxProbeSecurityDenialAcceptanceTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();
    private static final ToolExecutionContext.Scope SCOPE =
            new ToolExecutionContext.Scope("local", "project-probe-deny");

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        denyForbiddenFields();
        allowlistedProbeStillWorks();
        System.out.println("SandboxProbeSecurityDenialAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void denyForbiddenFields() throws Exception {
        AiToolRegistry registry = new AiToolRegistry(new FakeSource());
        int index = 0;
        for (String field : List.of("command", "image", "mount", "network", "uid", "budget",
                "hostPath", "dockerImage", "networkMode")) {
            ToolExecutionContext context = ToolExecutionContext.bind(
                    SCOPE, "op-deny-" + index, "job-deny-" + index, AgentRole.DYNAMIC_VERIFICATION,
                    new ToolExecutionContext.Budget(4, 65_536, 16, 65_536, Instant.now().plusSeconds(60)));
            ObjectNode args = JSON.createObjectNode();
            args.put("entrypointRef", "entry:entry-1");
            args.put(field, "attacker-controlled");
            ToolResult denied = registry.execute(
                    new ToolCall(1, "call-deny-" + field, "sandbox_probe", args), context);
            boolean schemaDeny = denied.status() == ToolStatus.INVALID_ARGUMENTS
                    && "UNKNOWN_ARGUMENT".equals(denied.errorCode());
            boolean reservedDeny = denied.status() == ToolStatus.DENIED
                    && "MODEL_CONTROLLED_SCOPE_OR_AUTHORITY".equals(denied.errorCode());
            check(schemaDeny || reservedDeny,
                    field + " overflow denied (status=" + denied.status()
                            + " code=" + denied.errorCode() + ")");
            index++;
        }
    }

    private static void allowlistedProbeStillWorks() throws Exception {
        FakeSource source = new FakeSource();
        AiToolRegistry registry = new AiToolRegistry(source);
        ToolExecutionContext context = ToolExecutionContext.bind(
                SCOPE, "op-1", "job-ok", AgentRole.DYNAMIC_VERIFICATION,
                new ToolExecutionContext.Budget(8, 65_536, 16, 65_536, Instant.now().plusSeconds(60)));
        ObjectNode args = JSON.createObjectNode();
        args.put("entrypointRef", "entry:entry-1");
        args.put("track", "UNAUTH");
        args.put("objective", "baseline probe");
        ToolResult ok = registry.execute(new ToolCall(1, "call-ok", "sandbox_probe", args), context);
        check(ok.status() == ToolStatus.SUCCESS, "allowlisted sandbox_probe succeeds");
        check(source.probeCalls.get() == 1, "probe executor invoked once");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }

    private static final class FakeSource implements ToolDataSource {
        private final AtomicInteger probeCalls = new AtomicInteger();

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
            return Optional.of(new FactRecord(scope, "sandbox-probe:" + toolCallId, value));
        }
    }
}
