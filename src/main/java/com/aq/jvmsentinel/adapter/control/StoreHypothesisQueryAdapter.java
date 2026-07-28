package com.aq.jvmsentinel.adapter.control;

import com.aq.jvmsentinel.application.port.HypothesisQueryPort;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;

import java.util.List;
import java.util.Objects;

/** Delegates hypothesis reads to {@link ControlPlaneStore}. */
public final class StoreHypothesisQueryAdapter implements HypothesisQueryPort {
    private final ControlPlaneStore store;

    public StoreHypothesisQueryAdapter(ControlPlaneStore store) {
        this.store = Objects.requireNonNull(store, "store");
    }

    @Override
    public List<SecurityHypothesis> hypotheses(String scanId) {
        if (scanId == null || scanId.isBlank() || store.scan(scanId) == null) {
            return List.of();
        }
        return store.hypotheses(scanId);
    }
}
