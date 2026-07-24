package com.aq.jvmsentinel.analysis;

import com.aq.jvmsentinel.model.*;
import java.util.Objects;

public record PreAnalysisResult(EntryCatalog entryCatalog, DependencyMap dependencyMap,
                                SinkCatalog sinkCatalog, PermissionMatrix permissionMatrix) {
    public PreAnalysisResult {
        Objects.requireNonNull(entryCatalog, "entryCatalog");
        Objects.requireNonNull(dependencyMap, "dependencyMap");
        Objects.requireNonNull(sinkCatalog, "sinkCatalog");
        Objects.requireNonNull(permissionMatrix, "permissionMatrix");
    }
}
