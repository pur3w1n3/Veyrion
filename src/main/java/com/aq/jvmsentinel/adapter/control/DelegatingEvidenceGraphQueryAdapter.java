package com.aq.jvmsentinel.adapter.control;

import com.aq.jvmsentinel.application.port.AnalyzerIrIngestPort;
import com.aq.jvmsentinel.application.port.EvidenceGraphQueryPort;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.domain.ir.EvidenceGraph;
import com.aq.jvmsentinel.domain.ir.EvidenceGraphMerge;

import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

/** Projects Evidence Graph then merges analyzer ProgramNode overlays. */
public final class DelegatingEvidenceGraphQueryAdapter implements EvidenceGraphQueryPort {
    private final ControlPlaneStore store;
    private final Function<String, EvidenceGraph> baseProjector;
    private final AnalyzerIrIngestPort analyzerIr;

    public DelegatingEvidenceGraphQueryAdapter(ControlPlaneStore store,
                                               Function<String, EvidenceGraph> baseProjector,
                                               AnalyzerIrIngestPort analyzerIr) {
        this.store = Objects.requireNonNull(store, "store");
        this.baseProjector = Objects.requireNonNull(baseProjector, "baseProjector");
        this.analyzerIr = Objects.requireNonNull(analyzerIr, "analyzerIr");
    }

    @Override
    public Optional<EvidenceGraph> evidenceGraph(String scanId) {
        if (scanId == null || scanId.isBlank() || store.scan(scanId) == null) {
            return Optional.empty();
        }
        EvidenceGraph base = baseProjector.apply(scanId);
        if (base == null) {
            return Optional.empty();
        }
        return Optional.of(EvidenceGraphMerge.withExtraNodes(
                base, analyzerIr.supplementalProgramNodes(scanId)));
    }
}
