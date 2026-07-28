package com.aq.jvmsentinel.adapter.control;

import com.aq.jvmsentinel.application.port.CoverageQueryPort;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.domain.coverage.CoverageMatrix;

import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

/** Thin coverage port over an existing projection function. */
public final class DelegatingCoverageQueryAdapter implements CoverageQueryPort {
    private final ControlPlaneStore store;
    private final Function<String, CoverageMatrix> projector;

    public DelegatingCoverageQueryAdapter(ControlPlaneStore store,
                                          Function<String, CoverageMatrix> projector) {
        this.store = Objects.requireNonNull(store, "store");
        this.projector = Objects.requireNonNull(projector, "projector");
    }

    @Override
    public Optional<CoverageMatrix> coverage(String scanId) {
        if (scanId == null || scanId.isBlank() || store.scan(scanId) == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(projector.apply(scanId));
    }
}
