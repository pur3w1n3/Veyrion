package com.aq.jvmsentinel.ai.tool;

import com.aq.jvmsentinel.model.ExperimentPlan;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Veyrion 已持有 facts/evidence 的只读适配器。实现不得
 * 执行制品、开网络、调 shell 或反编译代码。
 */
public interface ToolDataSource {
    List<FactRecord> searchFacts(ToolExecutionContext.Scope scope, String kind, String query, int limit)
            throws Exception;

    /**
     * 对已注册制品的有界 auth/config/code 事实查询。
     * 默认空；Control Plane 可扫描已授权 JAR 中的
     * JWT 默认值、skip-url 模式与 auth 相关类名。绝不
     * 执行字节码或返回原始自定义 secret。
     */
    default List<FactRecord> queryCode(ToolExecutionContext.Scope scope, String query, int limit)
            throws Exception {
        return List.of();
    }

    /**
     * 版本化 {@code code_query} kind。默认忽略 {@code kind} 并委托
     * {@link #queryCode(ToolExecutionContext.Scope, String, int)}。
     * 已知 kind：METHOD_VIEW、CALLERS、CALLEES、CFG_VIEW、DATAFLOW_SLICE、
     * GUARD_QUERY、FIELD_USES、CONFIG_SEARCH、AUTH、TAINT_GRAPH。
     */
    default List<FactRecord> queryCode(ToolExecutionContext.Scope scope, String kind,
                                       String query, int limit) throws Exception {
        return queryCode(scope, query, limit);
    }

    Optional<FactRecord> findEvidence(ToolExecutionContext.Scope scope, String evidenceRef)
            throws Exception;

    /**
     * 同 scan 共享 memory 切片，供 AI 角色。默认空；Control Plane 返回 INDEX/FACTS/WORK/…
     */
    default Optional<FactRecord> getScanMemory(ToolExecutionContext.Scope scope, String section, String role)
            throws Exception {
        return Optional.empty();
    }

    /**
     * 将 AI/PathRun entry 别名解析为规范 {@code entry:<scanEntryId>} fact。
     * 默认实现仅接受精确 evidence ref；control-plane 源可
     * 接受裸 scan id 与无歧义 {@code entry:METHOD:route} 别名。
     */
    default Optional<FactRecord> resolveEntrypoint(ToolExecutionContext.Scope scope, String entrypointRef)
            throws Exception {
        return findEvidence(scope, entrypointRef);
    }

    /**
     * 请求服务端拥有、有界的 loopback 探针。模型提供
     * evidence ref、候选输入提示与可选 AI 编写的 auth PoC
     * material；实现从持久化状态推导 route、sandbox、network policy 与 budget，
     * 并校验 PoC 边界。
     */
    default Optional<FactRecord> requestSandboxProbe(ToolExecutionContext.Scope scope,
                                                     String principalId, String jobId,
                                                     String entrypointRef,
                                                     List<String> candidateInputs,
                                                     int maxRequests) throws Exception {
        return requestSandboxProbe(scope, principalId, jobId, entrypointRef, candidateInputs,
                maxRequests, null, null, null);
    }

    default Optional<FactRecord> requestSandboxProbe(ToolExecutionContext.Scope scope,
                                                     String principalId, String jobId,
                                                     String entrypointRef,
                                                     List<String> candidateInputs,
                                                     int maxRequests,
                                                     String techniqueId,
                                                     String authorizationHeader) throws Exception {
        return requestSandboxProbe(scope, principalId, jobId, entrypointRef, candidateInputs,
                maxRequests, techniqueId, authorizationHeader, null);
    }

    default Optional<FactRecord> requestSandboxProbe(ToolExecutionContext.Scope scope,
                                                     String principalId, String jobId,
                                                     String entrypointRef,
                                                     List<String> candidateInputs,
                                                     int maxRequests,
                                                     String techniqueId,
                                                     String authorizationHeader,
                                                     String bladeAuthHeader) throws Exception {
        return requestSandboxProbe(scope, principalId, jobId, null, entrypointRef, candidateInputs,
                maxRequests, techniqueId, authorizationHeader, bladeAuthHeader, null);
    }

    /**
     * attempt 作用域 sandbox probe。{@code toolCallId}（规范 ToolCall.callId）与
     * {@code jobId} 组成 probeAttemptId；null/blank 回退到 legacy job 级 attempt。
     */
    default Optional<FactRecord> requestSandboxProbe(ToolExecutionContext.Scope scope,
                                                     String principalId, String jobId,
                                                     String toolCallId,
                                                     String entrypointRef,
                                                     List<String> candidateInputs,
                                                     int maxRequests,
                                                     String techniqueId,
                                                     String authorizationHeader,
                                                     String bladeAuthHeader) throws Exception {
        return requestSandboxProbe(scope, principalId, jobId, toolCallId, entrypointRef,
                candidateInputs, maxRequests, techniqueId, authorizationHeader, bladeAuthHeader, null);
    }

    default Optional<FactRecord> requestSandboxProbe(ToolExecutionContext.Scope scope,
                                                     String principalId, String jobId,
                                                     String toolCallId,
                                                     String entrypointRef,
                                                     List<String> candidateInputs,
                                                     int maxRequests,
                                                     String techniqueId,
                                                     String authorizationHeader,
                                                     String bladeAuthHeader,
                                                     String experimentPlanId) throws Exception {
        return Optional.empty();
    }

    /**
     * 标签复制进 probe fact 前，对照服务端拥有的 scan 校验模型提供的 hypothesis/experiment 标签。
     * 实现必须 fail-closed。
     */
    default void validateHypothesisBinding(ToolExecutionContext.Scope scope,
                                            String hypothesisId,
                                            String planKind,
                                            String experimentPlanId,
                                            String entrypointRef) throws Exception {
        // Legacy 测试源无 hypothesis store；不能授权 binding。
        if ((hypothesisId != null && !hypothesisId.isBlank())
                || (planKind != null && !planKind.isBlank())
                || (experimentPlanId != null && !experimentPlanId.isBlank())) {
            throw new SecurityException("HYPOTHESIS_BINDING_UNAVAILABLE");
        }
    }

    /** PATH_EXPLORATION sandbox_probe 闸门的 coverage gap id（taintPathId）。 */
    default List<String> coverageGapIds(ToolExecutionContext.Scope scope) throws Exception {
        return List.of();
    }

    /**
     * 接受来自 {@code plan_propose} 的服务端闸门 experiment plan。默认 no-op；
     * Control Plane 源绑定 plan 供后续 flood/focus 执行。
     */
    default void acceptExperimentPlan(ToolExecutionContext.Scope scope, ExperimentPlan plan)
            throws Exception {
        // 可选
    }

    record FactRecord(ToolExecutionContext.Scope scope, String reference, JsonNode value) {
        public FactRecord {
            Objects.requireNonNull(scope, "scope");
            Objects.requireNonNull(reference, "reference");
            if (reference.isBlank() || reference.length() > 1024) {
                throw new IllegalArgumentException("reference is invalid");
            }
            Objects.requireNonNull(value, "value");
        }
    }
}
