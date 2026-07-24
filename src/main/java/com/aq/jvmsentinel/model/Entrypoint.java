package com.aq.jvmsentinel.model;

import java.util.List;
import java.util.Objects;

public record Entrypoint(
        String id,
        String protocol,
        String method,
        String route,
        String declaringClass,
        List<String> parameters,
        List<String> preconditions,
        List<String> evidenceRefs,
        double confidence,
        VerificationStatus status) {
    public Entrypoint {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(protocol, "protocol");
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(route, "route");
        Objects.requireNonNull(declaringClass, "declaringClass");
        Objects.requireNonNull(status, "status");
        parameters = List.copyOf(parameters == null ? List.of() : parameters);
        preconditions = List.copyOf(preconditions == null ? List.of() : preconditions);
        evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
        if (!Double.isFinite(confidence) || confidence < 0 || confidence > 1) throw new IllegalArgumentException("confidence must be between 0 and 1");
    }
}
