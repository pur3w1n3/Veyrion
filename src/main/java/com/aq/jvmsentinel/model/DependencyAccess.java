package com.aq.jvmsentinel.model;

import java.util.List;
import java.util.Objects;

public record DependencyAccess(
        String id,
        String kind,
        String target,
        String accessType,
        String mode,
        List<String> fields,
        List<String> evidenceRefs,
        double confidence,
        VerificationStatus status) {
    public DependencyAccess {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(accessType, "accessType");
        Objects.requireNonNull(mode, "mode");
        Objects.requireNonNull(status, "status");
        fields = List.copyOf(fields == null ? List.of() : fields);
        evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
        if (!Double.isFinite(confidence) || confidence < 0 || confidence > 1) throw new IllegalArgumentException("confidence must be between 0 and 1");
    }
}
