package com.aq.jvmsentinel.adapter.control;

import com.aq.jvmsentinel.application.port.ScanQueryPort;
import com.aq.jvmsentinel.control.ControlPlaneStore;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

/** Delegates scan existence/view to {@link ControlPlaneStore} (+ optional map projection). */
public final class StoreScanQueryAdapter implements ScanQueryPort {
    private final ControlPlaneStore store;
    private final Function<String, Map<String, Object>> viewProjector;

    public StoreScanQueryAdapter(ControlPlaneStore store,
                                 Function<String, Map<String, Object>> viewProjector) {
        this.store = Objects.requireNonNull(store, "store");
        this.viewProjector = Objects.requireNonNull(viewProjector, "viewProjector");
    }

    @Override
    public boolean exists(String scanId) {
        return scanId != null && !scanId.isBlank() && store.scan(scanId) != null;
    }

    @Override
    public Optional<Map<String, Object>> scanView(String scanId) {
        if (!exists(scanId)) {
            return Optional.empty();
        }
        Map<String, Object> view = viewProjector.apply(scanId);
        return Optional.of(view == null ? new LinkedHashMap<>() : view);
    }
}
