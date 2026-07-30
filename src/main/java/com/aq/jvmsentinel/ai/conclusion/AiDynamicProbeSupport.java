package com.aq.jvmsentinel.ai.conclusion;

import com.aq.jvmsentinel.ai.AuthBypassFeasibility;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolResult;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolStatus;
import com.aq.jvmsentinel.ai.tool.ControlPlaneToolDataSource.DynamicProbeExecutor;
import com.aq.jvmsentinel.ai.tool.ToolExecutionContext;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.model.AuthBypassCandidate;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.List;

/** DYNAMIC 结论序列化与 sandbox_probe 有效/无效探针门禁。 */
public final class AiDynamicProbeSupport {
    private final DynamicProbeExecutor dynamicProbeExecutor;

    public AiDynamicProbeSupport(DynamicProbeExecutor dynamicProbeExecutor) {
        this.dynamicProbeExecutor = java.util.Objects.requireNonNull(dynamicProbeExecutor, "dynamicProbeExecutor");
    }

    public int autoEnqueueFocusedPocProbes(
            SQLiteControlPlanePersistence.AiJobData job, String actorId,
            List<AuthBypassCandidate> feasibilityPoCs) {
        List<AuthBypassCandidate> top = AuthBypassFeasibility.selectTopProbeTargets(
                feasibilityPoCs, AuthBypassFeasibility.DYNAMIC_POC_AUTO_PROBE_MAX);
        if (top.isEmpty()) return 0;
        ToolExecutionContext.Scope scope = new ToolExecutionContext.Scope(
                job.workspaceId(), job.projectId());
        int enqueued = 0;
        for (int i = 0; i < top.size(); i++) {
            AuthBypassCandidate candidate = top.get(i);
            String syntheticToolCallId = "dyn-poc-" + i;
            try {
                String blade = candidate.bladeAuthHeader() == null || candidate.bladeAuthHeader().isBlank()
                        ? null : candidate.bladeAuthHeader();
                var fact = dynamicProbeExecutor.request(
                        job.scanId(), scope, actorId, job.aiJobId(), syntheticToolCallId,
                        candidate.entryRef(), List.of(), 1,
                        candidate.techniqueId(),
                        candidate.hasAuthMaterial() ? candidate.authorizationHeader() : null,
                        blade, null);
                if (fact.isPresent() && isEffectiveSandboxProbeFact(fact.get().value())) {
                    enqueued++;
                }
            } catch (Exception ignored) {
                // 服务端自动入队为 best-effort；job 仍带 enforcement 标记完成。
            }
        }
        return enqueued;
    }

    public static String buildDynamicConclusion(
            String summary, List<AuthBypassCandidate> feasibilityPoCs,
            int sandboxProbeCount, boolean reAskTriggered, int autoEnqueued) {
        com.fasterxml.jackson.databind.node.ObjectNode node = AiConclusionJson.JSON.createObjectNode();
        node.put("schemaVersion", 1);
        node.put("classification", "INFERENCE");
        node.put("summary", summary == null ? "" : summary);
        node.putArray("evidenceRefs");
        node.put("verificationStatus", "INFERENCE");
        node.put("feasibilityPocCount", feasibilityPoCs == null ? 0 : feasibilityPoCs.size());
        node.put("sandboxProbeCount", Math.max(0, sandboxProbeCount));
        node.put("autoEnqueuedProbeCount", Math.max(0, autoEnqueued));
        node.put("reAskTriggered", reAskTriggered);
        if (feasibilityPoCs != null && !feasibilityPoCs.isEmpty()) {
            int required = requiredEffectiveProbeCount(feasibilityPoCs);
            if (sandboxProbeCount >= required) {
                node.put("enforcement", AuthBypassFeasibility.DYNAMIC_ATTEMPT_SATISFIED);
            } else if (autoEnqueued > 0) {
                node.put("enforcement", AuthBypassFeasibility.DYNAMIC_ATTEMPT_SEEDED);
            } else {
                node.put("enforcement", AuthBypassFeasibility.DYNAMIC_ATTEMPT_REQUIRED);
            }
        }
        node.put("pocOwnership", "AI_AUTHORS_SERVER_VALIDATES_DYNAMIC_EXECUTES");
        return node.toString();
    }

    /** AUTH 移交 feasibility PoCs 时所需的有效探针数（P0-03 区间）。 */
    public static int requiredEffectiveProbeCount(List<AuthBypassCandidate> feasibilityPoCs) {
        if (feasibilityPoCs == null || feasibilityPoCs.isEmpty()) {
            return 0;
        }
        return Math.min(AuthBypassFeasibility.DYNAMIC_POC_PROBE_MIN, feasibilityPoCs.size());
    }

    /**
     * 仅统计 fact 为 COMPLETED 且至少有一条 PathRun 的 SUCCESS 工具结果。
     * BUSY / FAILED / CANCELLED / 空 / 未投影 fact 不算 attempt。
     */
    public static boolean isEffectiveSandboxProbeAttempt(ToolResult result) {
        if (result == null || result.status() != ToolStatus.SUCCESS) {
            return false;
        }
        for (var output : result.outputs()) {
            if (output != null && output.value() != null && isEffectiveSandboxProbeFact(output.value())) {
                return true;
            }
        }
        return false;
    }

    public static boolean isEffectiveSandboxProbeFact(JsonNode value) {
        if (value == null || !value.isObject()) {
            return false;
        }
        String state = value.path("state").asText("");
        if (!"COMPLETED".equals(state)) {
            return false;
        }
        String lifecycle = value.path("lifecycle").asText("");
        if ("FAILED".equals(lifecycle) || "CANCELLED".equals(lifecycle) || "BLOCKED".equals(lifecycle)) {
            return false;
        }
        return value.path("pathRunCount").asInt(0) > 0;
    }

    /**
     * PATH/TRIAGE：无效探针转为反证/缺口 fact — 从模型可见 envelope 剥离 PathRun，
     * 避免叙事将失败探针当作动态确认。
     */
    public static ToolResult gatePathTriageProbeResult(ToolResult result) {
        if (result == null) return null;
        if (isEffectiveSandboxProbeAttempt(result)) {
            return result;
        }
        List<CanonicalToolContracts.ToolOutput> outputs = new ArrayList<>();
        for (var output : result.outputs() == null ? List.<CanonicalToolContracts.ToolOutput>of()
                : result.outputs()) {
            if (output == null || output.value() == null || !output.value().isObject()) {
                outputs.add(output);
                continue;
            }
            com.fasterxml.jackson.databind.node.ObjectNode copy = ((ObjectNode) output.value()).deepCopy();
            copy.put("consumableForConclusion", false);
            copy.put("role", "COUNTEREVIDENCE_OR_GAP");
            if (copy.path("pathRunCount").asInt(0) > 0 && !isEffectiveSandboxProbeFact(copy)) {
                copy.put("pathRunCount", 0);
            }
            if (copy.has("pathRuns")) {
                copy.putArray("pathRuns");
            }
            if (!copy.has("gapReason") || copy.path("gapReason").asText("").isBlank()) {
                String state = copy.path("state").asText("UNKNOWN");
                String failure = copy.path("failureCode").asText("");
                copy.put("gapReason", failure.isBlank() ? "INEFFECTIVE_PROBE:" + state
                        : "INEFFECTIVE_PROBE:" + failure);
            }
            outputs.add(new CanonicalToolContracts.ToolOutput(
                    output.kind(), output.reference(), copy));
        }
        return new ToolResult(result.schemaVersion(), result.callId(), result.toolName(),
                result.status(), List.copyOf(outputs), result.errorCode(), result.truncated());
    }
}
