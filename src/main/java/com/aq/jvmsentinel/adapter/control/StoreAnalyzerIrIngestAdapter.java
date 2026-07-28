package com.aq.jvmsentinel.adapter.control;

import com.aq.jvmsentinel.application.port.AnalyzerIrIngestPort;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.domain.ir.ProgramNode;

import java.util.List;
import java.util.Objects;

/** Process-local analyzer ProgramNode overlay backed by {@link ControlPlaneStore}. */
public final class StoreAnalyzerIrIngestAdapter implements AnalyzerIrIngestPort {
    private final ControlPlaneStore store;

    public StoreAnalyzerIrIngestAdapter(ControlPlaneStore store) {
        this.store = Objects.requireNonNull(store, "store");
    }

    @Override
    public void ingestProgramNodes(String scanId, List<ProgramNode> nodes) {
        store.saveAnalyzerProgramNodes(scanId, nodes);
    }

    @Override
    public List<ProgramNode> supplementalProgramNodes(String scanId) {
        return store.analyzerProgramNodes(scanId);
    }
}
