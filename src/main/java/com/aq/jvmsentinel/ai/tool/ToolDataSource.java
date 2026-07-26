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

    Optional<FactRecord> findEvidence(ToolExecutionContext.Scope scope, String evidenceRef)
            throws Exception;

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
        return Optional.empty();
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
