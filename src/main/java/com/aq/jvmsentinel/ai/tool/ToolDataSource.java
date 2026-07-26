package com.aq.jvmsentinel.ai.tool;

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
     * Requests a server-owned, bounded loopback probe. The model supplies only an
     * evidence reference and candidate input hints; the implementation must derive
     * the actual route, sandbox, network policy and budget from persisted state.
     */
    default Optional<FactRecord> requestSandboxProbe(ToolExecutionContext.Scope scope,
                                                     String principalId, String jobId,
                                                     String entrypointRef,
                                                     List<String> candidateInputs,
                                                     int maxRequests) throws Exception {
        return Optional.empty();
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
