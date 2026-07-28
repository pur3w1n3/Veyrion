package com.aq.jvmsentinel.adapter.control;

import com.aq.jvmsentinel.application.port.ProviderQueryPort;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

/** Delegates provider list queries to {@link ControlPlaneStore} (+ map projection). */
public final class StoreProviderQueryAdapter implements ProviderQueryPort {
    private final ControlPlaneStore store;
    private final Function<SQLiteControlPlanePersistence.ProviderData, Map<String, Object>> viewProjector;

    public StoreProviderQueryAdapter(
            ControlPlaneStore store,
            Function<SQLiteControlPlanePersistence.ProviderData, Map<String, Object>> viewProjector) {
        this.store = Objects.requireNonNull(store, "store");
        this.viewProjector = Objects.requireNonNull(viewProjector, "viewProjector");
    }

    @Override
    public List<Map<String, Object>> listProviders() {
        List<Map<String, Object>> items = new ArrayList<>();
        for (SQLiteControlPlanePersistence.ProviderData provider : store.providers()) {
            Map<String, Object> view = viewProjector.apply(provider);
            items.add(view == null ? new LinkedHashMap<>() : view);
        }
        return List.copyOf(items);
    }
}
