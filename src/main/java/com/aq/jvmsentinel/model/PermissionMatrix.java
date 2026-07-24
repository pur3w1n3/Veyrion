package com.aq.jvmsentinel.model;

import java.util.List;

public record PermissionMatrix(List<PermissionRequirement> requirements) {
    public PermissionMatrix {
        requirements = List.copyOf(requirements == null ? List.of() : requirements);
    }
}
