package com.aq.jvmsentinel.model;

import java.util.List;
import java.util.Objects;

public record Sink(String id, String category, String symbol, String source, double confidence,
                   List<String> evidenceRefs, VerificationStatus status) {
    public Sink {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(category, "category");
        Objects.requireNonNull(symbol, "symbol");
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(status, "status");
        evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
        if (!Double.isFinite(confidence) || confidence < 0 || confidence > 1) throw new IllegalArgumentException("confidence must be between 0 and 1");
    }
}
