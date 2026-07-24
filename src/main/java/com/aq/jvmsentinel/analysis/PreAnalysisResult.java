package com.aq.jvmsentinel.analysis;

import com.aq.jvmsentinel.model.*;
import java.util.Objects;

public record PreAnalysisResult(EntryCatalog entryCatalog, DependencyMap dependencyMap,
                                SinkCatalog sinkCatalog, PermissionMatrix permissionMatrix,
                                BytecodeFactIndex bytecodeFactIndex) {
    public PreAnalysisResult {
        Objects.requireNonNull(entryCatalog, "entryCatalog");
        Objects.requireNonNull(dependencyMap, "dependencyMap");
        Objects.requireNonNull(sinkCatalog, "sinkCatalog");
        Objects.requireNonNull(permissionMatrix, "permissionMatrix");
        Objects.requireNonNull(bytecodeFactIndex, "bytecodeFactIndex");
    }

    public PreAnalysisResult(EntryCatalog entryCatalog, DependencyMap dependencyMap,
                             SinkCatalog sinkCatalog, PermissionMatrix permissionMatrix) {
        this(entryCatalog, dependencyMap, sinkCatalog, permissionMatrix, BytecodeFactIndex.EMPTY);
    }
}
