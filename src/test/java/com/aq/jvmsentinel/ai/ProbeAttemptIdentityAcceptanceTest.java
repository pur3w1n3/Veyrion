package com.aq.jvmsentinel.ai;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.ai.tool.AiToolRegistry;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolCall;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolResult;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolStatus;
import com.aq.jvmsentinel.ai.tool.ToolDataSource;
import com.aq.jvmsentinel.ai.tool.ToolExecutionContext;
import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.model.AuthBypassCandidate;
import com.aq.jvmsentinel.provider.AgentRole;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * P0-03: independent probeAttemptId, payload-hash conflict, and effective-attempt counting.
 */
public final class ProbeAttemptIdentityAcceptanceTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();
    private static final ToolExecutionContext.Scope SCOPE =
            new ToolExecutionContext.Scope("local", "project-a");

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        probeAttemptIdsAreStableAndDistinct();
        effectiveCountingIgnoresBusyFailedEmpty();
        threeDistinctToolCallsYieldThreeAttempts();
        sameAttemptSamePayloadReplays();
        sameAttemptDifferentPayloadConflicts();
        System.out.println("ProbeAttemptIdentityAcceptanceTest: PASS ("
                + ASSERTIONS.get() + " assertions)");
    }

    private static void probeAttemptIdsAreStableAndDistinct() {
        String a1 = ControlPlaneServer.probeAttemptId("job-a", "call-1");
        String a2 = ControlPlaneServer.probeAttemptId("job-a", "call-1");
        String b1 = ControlPlaneServer.probeAttemptId("job-a", "call-2");
        String c1 = ControlPlaneServer.probeAttemptId("job-b", "call-1");
        check(a1.equals(a2), "same job+toolCallId yields stable probeAttemptId");
        check(!a1.equals(b1), "different toolCallId yields different probeAttemptId");
        check(!a1.equals(c1), "different jobId yields different probeAttemptId");
        check(a1.startsWith("patt-") && a1.length() == 37, "probeAttemptId uses patt- + 32 hex");
        check(ControlPlaneServer.probeAttemptId("job-a", null)
                        .equals(ControlPlaneServer.probeAttemptId("job-a", "  ")),
                "null/blank toolCallId share legacy attempt");
    }

    private static void effectiveCountingIgnoresBusyFailedEmpty() {
        check(!AiJobOrchestrator.isEffectiveSandboxProbeFact(fact("BUSY", 0)),
                "BUSY is not an effective attempt");
        check(!AiJobOrchestrator.isEffectiveSandboxProbeFact(fact("FAILED", 0)),
                "FAILED is not an effective attempt");
        check(!AiJobOrchestrator.isEffectiveSandboxProbeFact(fact("COMPLETED", 0)),
                "COMPLETED with zero PathRuns is not effective");
        check(AiJobOrchestrator.isEffectiveSandboxProbeFact(fact("COMPLETED", 2)),
                "COMPLETED with PathRuns is effective");

        ToolResult busy = successResult("busy", fact("BUSY", 0));
        ToolResult failed = new ToolResult(1, "fail", "sandbox_probe", ToolStatus.DENIED,
                List.of(), "SANDBOX_PROBE_EXECUTION_FAILED", false);
        ToolResult ok = successResult("ok", fact("COMPLETED", 1));
        check(!AiJobOrchestrator.isEffectiveSandboxProbeAttempt(busy), "BUSY tool result ignored");
        check(!AiJobOrchestrator.isEffectiveSandboxProbeAttempt(failed), "non-SUCCESS ignored");
        check(AiJobOrchestrator.isEffectiveSandboxProbeAttempt(ok), "SUCCESS+COMPLETED counted");

        List<AuthBypassCandidate> three = List.of(
                candidate("entry:a"), candidate("entry:b"), candidate("entry:c"));
        check(AiJobOrchestrator.requiredEffectiveProbeCount(three) == 3,
                "required effective probes is DYNAMIC_POC_PROBE_MIN when enough PoCs");
        check(AiJobOrchestrator.requiredEffectiveProbeCount(List.of(candidate("entry:a"))) == 1,
                "required probes capped by available PoCs");
        check(AiJobOrchestrator.requiredEffectiveProbeCount(List.of()) == 0,
                "no PoCs require zero probes");
    }

    private static void threeDistinctToolCallsYieldThreeAttempts() throws Exception {
        RecordingSource source = new RecordingSource();
        AiToolRegistry registry = new AiToolRegistry(source);
        ToolExecutionContext context = context("job-multi");
        Set<String> attemptIds = new LinkedHashSet<>();
        int effective = 0;
        for (int i = 1; i <= 3; i++) {
            ToolCall call = call("call-" + i, "entry:entry-a", "payload-" + i);
            ToolResult result = registry.execute(call, context);
            check(result.status() == ToolStatus.SUCCESS, "probe call-" + i + " succeeds");
            String attemptId = result.outputs().get(0).value().path("probeAttemptId").asText();
            check(!attemptId.isBlank(), "probeAttemptId present on call-" + i);
            attemptIds.add(attemptId);
            if (AiJobOrchestrator.isEffectiveSandboxProbeAttempt(result)) {
                effective++;
            }
        }
        check(attemptIds.size() == 3, "three toolCallIds produce three probeAttemptIds");
        check(effective == 3, "three COMPLETED+PathRun facts count as effective attempts");
        check(source.invocations.size() == 3, "executor invoked once per distinct attempt");
    }

    private static void sameAttemptSamePayloadReplays() throws Exception {
        RecordingSource source = new RecordingSource();
        AiToolRegistry registry = new AiToolRegistry(source);
        ToolExecutionContext context = context("job-replay");
        ToolCall call = call("call-replay", "entry:entry-a", "same-payload");
        ToolResult first = registry.execute(call, context);
        ToolResult second = registry.execute(call, context);
        check(first.status() == ToolStatus.SUCCESS && second.status() == ToolStatus.SUCCESS,
                "replay returns SUCCESS");
        String a1 = first.outputs().get(0).value().path("probeAttemptId").asText();
        String a2 = second.outputs().get(0).value().path("probeAttemptId").asText();
        check(a1.equals(a2), "replay keeps the same probeAttemptId");
        check(source.invocations.size() == 1, "same attempt+payload does not re-execute");
        check(source.replayHits.get() == 1, "second call served from attempt cache");
    }

    private static void sameAttemptDifferentPayloadConflicts() throws Exception {
        RecordingSource source = new RecordingSource();
        AiToolRegistry registry = new AiToolRegistry(source);
        ToolExecutionContext context = context("job-conflict");
        ToolResult first = registry.execute(call("call-conflict", "entry:entry-a", "payload-a"), context);
        check(first.status() == ToolStatus.SUCCESS, "first attempt succeeds");
        ToolResult conflict = registry.execute(call("call-conflict", "entry:entry-a", "payload-b"), context);
        check(conflict.status() == ToolStatus.SUCCESS, "conflict returns FACT envelope");
        String failureCode = conflict.outputs().get(0).value().path("failureCode").asText();
        check("IDEMPOTENCY_CONFLICT".equals(failureCode),
                "payload mismatch surfaces IDEMPOTENCY_CONFLICT");
        check(!AiJobOrchestrator.isEffectiveSandboxProbeAttempt(conflict),
                "conflict fact is not an effective attempt");
    }

    private static ToolExecutionContext context(String jobId) {
        return ToolExecutionContext.bind(SCOPE, "local-admin", jobId,
                AgentRole.DYNAMIC_VERIFICATION,
                new ToolExecutionContext.Budget(16, 64_000, 8, 64_000,
                        Instant.now().plus(Duration.ofMinutes(2))));
    }

    private static ToolCall call(String callId, String entryRef, String payloadHint) {
        ObjectNode args = JSON.createObjectNode();
        args.put("entrypointRef", entryRef);
        args.putArray("candidateInputs").add(payloadHint);
        args.put("maxRequests", 1);
        return new ToolCall(CanonicalToolContracts.SCHEMA_VERSION, callId, "sandbox_probe", args);
    }

    private static ToolResult successResult(String callId, ObjectNode fact) {
        return new ToolResult(CanonicalToolContracts.SCHEMA_VERSION, callId, "sandbox_probe",
                ToolStatus.SUCCESS,
                List.of(new CanonicalToolContracts.ToolOutput(
                        CanonicalToolContracts.OutputKind.FACT,
                        "sandbox-probe:attempt:" + callId, fact)),
                null, false);
    }

    private static ObjectNode fact(String state, int pathRunCount) {
        ObjectNode node = JSON.createObjectNode();
        node.put("schemaVersion", 1);
        node.put("state", state);
        node.put("lifecycle", state);
        node.put("pathRunCount", pathRunCount);
        return node;
    }

    private static AuthBypassCandidate candidate(String entryRef) {
        return AuthBypassCandidate.of(entryRef, "ALG_NONE",
                com.aq.jvmsentinel.model.IdentityTrack.BYPASS_CANDIDATE,
                "fixture", List.of("evidence:fixture"), 0.5,
                "Bearer x.y.", "", "", "");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }

    private static final class RecordingSource implements ToolDataSource {
        final Map<String, Cached> cache = new LinkedHashMap<>();
        final List<String> invocations = new ArrayList<>();
        final AtomicInteger replayHits = new AtomicInteger();

        private record Cached(String payloadKey, FactRecord record) { }

        @Override
        public Optional<FactRecord> resolveEntrypoint(ToolExecutionContext.Scope scope, String entrypointRef) {
            return Optional.of(new FactRecord(scope, entrypointRef,
                    JSON.createObjectNode().put("entrypoint", "fixture.Controller#create")));
        }

        @Override
        public Optional<FactRecord> requestSandboxProbe(ToolExecutionContext.Scope scope,
                                                        String principalId,
                                                        String jobId,
                                                        String toolCallId,
                                                        String entrypointRef,
                                                        List<String> candidateInputs,
                                                        int maxRequests,
                                                        String techniqueId,
                                                        String authorizationHeader,
                                                        String bladeAuthHeader,
                                                        String experimentPlanId) {
            String attemptId = ControlPlaneServer.probeAttemptId(jobId, toolCallId);
            String payloadKey = String.valueOf(candidateInputs) + "|" + maxRequests + "|"
                    + techniqueId + "|" + authorizationHeader + "|" + bladeAuthHeader
                    + "|" + experimentPlanId;
            Cached cached = cache.get(attemptId);
            if (cached != null) {
                if (!cached.payloadKey().equals(payloadKey)) {
                    ObjectNode conflict = JSON.createObjectNode();
                    conflict.put("schemaVersion", 1);
                    conflict.put("state", "FAILED");
                    conflict.put("lifecycle", "FAILED");
                    conflict.put("failureCode", "IDEMPOTENCY_CONFLICT");
                    conflict.put("probeAttemptId", attemptId);
                    conflict.put("pathRunCount", 0);
                    return Optional.of(new FactRecord(scope,
                            "sandbox-probe:failed:" + attemptId, conflict));
                }
                replayHits.incrementAndGet();
                return Optional.of(cached.record());
            }
            invocations.add(attemptId);
            ObjectNode value = JSON.createObjectNode();
            value.put("schemaVersion", 1);
            value.put("probeAttemptId", attemptId);
            value.put("entrypointRef", entrypointRef);
            value.put("networkMode", "DENY");
            value.put("executor", "SERVER_OWNED_TRUSTED_DOCKER");
            value.put("state", "COMPLETED");
            value.put("lifecycle", "COMPLETED");
            value.put("pathRunCount", 1);
            value.putArray("pathRuns").addObject().put("pathRunId", "pr-" + attemptId);
            FactRecord record = new FactRecord(scope, "sandbox-probe:attempt:" + attemptId, value);
            cache.put(attemptId, new Cached(payloadKey, record));
            return Optional.of(record);
        }

        @Override
        public List<FactRecord> searchFacts(ToolExecutionContext.Scope scope, String kind,
                                            String query, int limit) {
            return List.of();
        }

        @Override
        public Optional<FactRecord> findEvidence(ToolExecutionContext.Scope scope, String evidenceRef) {
            return Optional.empty();
        }
    }
}
