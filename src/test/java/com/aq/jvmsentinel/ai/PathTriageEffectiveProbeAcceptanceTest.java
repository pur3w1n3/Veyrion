package com.aq.jvmsentinel.ai;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolResult;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolStatus;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/** P0-05 残余：PATH/TRIAGE 仅可消费已投影 PathRun 进入下一轮结论。 */
public final class PathTriageEffectiveProbeAcceptanceTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        effectiveProbeUnchanged();
        ineffectiveProbeRedacted();
        System.out.println("PathTriageEffectiveProbeAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void effectiveProbeUnchanged() {
        ObjectNode fact = JSON.createObjectNode();
        fact.put("state", "COMPLETED");
        fact.put("lifecycle", "COMPLETED");
        fact.put("pathRunCount", 2);
        fact.putArray("pathRuns").addObject().put("pathRunId", "pr-1");
        ToolResult input = new ToolResult(1, "c1", "sandbox_probe", ToolStatus.SUCCESS,
                List.of(new CanonicalToolContracts.ToolOutput(
                        CanonicalToolContracts.OutputKind.FACT, "sandbox-probe:ok", fact)),
                null, false);
        ToolResult gated = AiJobOrchestrator.gatePathTriageProbeResult(input);
        check(AiJobOrchestrator.isEffectiveSandboxProbeAttempt(gated), "effective remains effective");
        check(gated.outputs().get(0).value().path("pathRunCount").asInt() == 2,
                "effective PathRuns preserved");
        check(!gated.outputs().get(0).value().has("consumableForConclusion")
                        || gated.outputs().get(0).value().path("consumableForConclusion").asBoolean(true),
                "effective not marked gap");
    }

    private static void ineffectiveProbeRedacted() {
        ObjectNode fact = JSON.createObjectNode();
        fact.put("state", "FAILED");
        fact.put("lifecycle", "FAILED");
        fact.put("failureCode", "EMPTY_PROBE_EVENTS");
        fact.put("pathRunCount", 0);
        fact.putArray("pathRuns").addObject().put("pathRunId", "pr-stale");
        ToolResult input = new ToolResult(1, "c2", "sandbox_probe", ToolStatus.SUCCESS,
                List.of(new CanonicalToolContracts.ToolOutput(
                        CanonicalToolContracts.OutputKind.FACT, "sandbox-probe:fail", fact)),
                null, false);
        ToolResult gated = AiJobOrchestrator.gatePathTriageProbeResult(input);
        check(!AiJobOrchestrator.isEffectiveSandboxProbeAttempt(gated), "ineffective stays ineffective");
        ObjectNode value = (ObjectNode) gated.outputs().get(0).value();
        check(!value.path("consumableForConclusion").asBoolean(true), "consumableForConclusion=false");
        check("COUNTEREVIDENCE_OR_GAP".equals(value.path("role").asText()), "role is gap/counterevidence");
        check(value.path("pathRuns").isArray() && value.path("pathRuns").isEmpty(),
                "failed probe PathRuns stripped for model");
        check(value.path("gapReason").asText().contains("INEFFECTIVE_PROBE"), "gapReason present");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}
