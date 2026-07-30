package com.aq.jvmsentinel.ai.tool;

import com.aq.jvmsentinel.model.ExperimentPlan;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Read-only adapter over facts/evidence already held by Veyrion. Implementations
 * must not execute artifacts, open networks, invoke a shell, or decompile code.
 */
public interface ToolDataSource {
    List<FactRecord> searchFacts(ToolExecutionContext.Scope scope, String kind, String query, int limit)
            throws Exception;

    /**
     * Bounded auth/config/code fact query against the registered artifact.
     * Default empty; Control Plane may scan the already-authorized JAR for
     * JWT defaults, skip-url patterns and auth-related class names. Never
     * executes bytecode or returns raw custom secrets.
     */
    default List<FactRecord> queryCode(ToolExecutionContext.Scope scope, String query, int limit)
            throws Exception {
        return List.of();
    }

    /**
     * Versioned {@code code_query} kinds. Default ignores {@code kind} and delegates
     * to {@link #queryCode(ToolExecutionContext.Scope, String, int)}.
     * Known kinds: METHOD_VIEW, CALLERS, CALLEES, CFG_VIEW, DATAFLOW_SLICE,
     * GUARD_QUERY, FIELD_USES, CONFIG_SEARCH, AUTH, TAINT_GRAPH.
     */
    default List<FactRecord> queryCode(ToolExecutionContext.Scope scope, String kind,
                                       String query, int limit) throws Exception {
        return queryCode(scope, query, limit);
    }

    Optional<FactRecord> findEvidence(ToolExecutionContext.Scope scope, String evidenceRef)
            throws Exception;

    /**
     * Same-scan shared memory slice for AI roles. Default empty; Control Plane returns INDEX/FACTS/WORK/…
     */
    default Optional<FactRecord> getScanMemory(ToolExecutionContext.Scope scope, String section, String role)
            throws Exception {
        return Optional.empty();
    }

    /**
     * Resolves an AI/PathRun entry alias onto a canonical {@code entry:&lt;scanEntryId&gt;} fact.
     * Default implementation only accepts an exact evidence ref; control-plane sources may
     * accept bare scan ids and unambiguous {@code entry:METHOD:route} aliases.
     */
    default Optional<FactRecord> resolveEntrypoint(ToolExecutionContext.Scope scope, String entrypointRef)
            throws Exception {
        return findEvidence(scope, entrypointRef);
    }

    /**
     * Requests a server-owned, bounded loopback probe. The model supplies an
     * evidence reference, candidate input hints, and optional AI-authored auth PoC
     * material; the implementation derives route, sandbox, network policy and budget
     * from persisted state and validates PoC bounds.
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
     * Attempt-scoped sandbox probe. {@code toolCallId} (canonical ToolCall.callId) forms the
     * probeAttemptId with {@code jobId}; null/blank falls back to a legacy job-level attempt.
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
     * Validates model-supplied hypothesis/experiment labels against the server-owned scan
     * before labels are copied into a probe fact. Implementations must fail closed.
     */
    default void validateHypothesisBinding(ToolExecutionContext.Scope scope,
                                            String hypothesisId,
                                            String planKind,
                                            String experimentPlanId,
                                            String entrypointRef) throws Exception {
        // Legacy test sources have no hypothesis store; they cannot authorize a binding.
        if ((hypothesisId != null && !hypothesisId.isBlank())
                || (planKind != null && !planKind.isBlank())
                || (experimentPlanId != null && !experimentPlanId.isBlank())) {
            throw new SecurityException("HYPOTHESIS_BINDING_UNAVAILABLE");
        }
    }

    /** Coverage gap ids (taintPathId) for PATH_EXPLORATION sandbox_probe gating. */
    default List<String> coverageGapIds(ToolExecutionContext.Scope scope) throws Exception {
        return List.of();
    }

    /**
     * Accepts a server-gated experiment plan from {@code plan_propose}. Default is no-op;
     * Control Plane sources bind the plan for later flood/focus execution.
     */
    default void acceptExperimentPlan(ToolExecutionContext.Scope scope, ExperimentPlan plan)
            throws Exception {
        // optional
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
