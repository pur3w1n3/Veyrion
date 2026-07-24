package com.aq.jvmsentinel.model;

import java.util.Objects;

public record Evidence(
        String evidenceId,
        ProvenanceKind kind,
        String source,
        double confidence,
        String summary) {
    public Evidence {
        Objects.requireNonNull(evidenceId, "evidenceId");
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(summary, "summary");
        if (!Double.isFinite(confidence) || confidence < 0 || confidence > 1) {
            throw new IllegalArgumentException("confidence must be between 0 and 1");
        }
    }
}
