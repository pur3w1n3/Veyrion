package com.aq.jvmsentinel.model;

import java.util.List;
import java.util.Objects;

public record PermissionRequirement(String entrypointId, List<String> roles, List<String> tenants,
                                   List<String> states, List<String> evidenceRefs, double confidence) {
    public PermissionRequirement {
        Objects.requireNonNull(entrypointId, "entrypointId");
        roles = List.copyOf(roles == null ? List.of() : roles);
        tenants = List.copyOf(tenants == null ? List.of() : tenants);
        states = List.copyOf(states == null ? List.of() : states);
        evidenceRefs = List.copyOf(evidenceRefs == null ? List.of() : evidenceRefs);
        if (!Double.isFinite(confidence) || confidence < 0 || confidence > 1) throw new IllegalArgumentException("confidence must be between 0 and 1");
    }
}
