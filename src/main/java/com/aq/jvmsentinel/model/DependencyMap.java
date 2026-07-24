package com.aq.jvmsentinel.model;

import java.util.List;

public record DependencyMap(List<DependencyAccess> accesses) {
    public DependencyMap {
        accesses = List.copyOf(accesses == null ? List.of() : accesses);
    }
}
