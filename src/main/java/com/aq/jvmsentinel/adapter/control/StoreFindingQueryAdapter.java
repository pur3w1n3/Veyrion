package com.aq.jvmsentinel.adapter.control;

import com.aq.jvmsentinel.application.port.FindingQueryPort;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

/** Delegates finding queries to {@link ControlPlaneStore} (+ map projection). */
public final class StoreFindingQueryAdapter implements FindingQueryPort {
    private final ControlPlaneStore store;
    private final Function<ApiDtos.FindingDto, Map<String, Object>> viewProjector;

    public StoreFindingQueryAdapter(ControlPlaneStore store,
                                    Function<ApiDtos.FindingDto, Map<String, Object>> viewProjector) {
        this.store = Objects.requireNonNull(store, "store");
        this.viewProjector = Objects.requireNonNull(viewProjector, "viewProjector");
    }

    @Override
    public boolean scanExists(String scanId) {
        return scanId != null && !scanId.isBlank() && store.scan(scanId) != null;
    }

    @Override
    public Optional<List<Map<String, Object>>> findingsForScan(String scanId) {
        if (!scanExists(scanId)) {
            return Optional.empty();
        }
        ControlPlaneStore.ScanRecord scan = store.requireScan(scanId);
        List<Map<String, Object>> items = new ArrayList<>();
        for (ApiDtos.FindingDto finding : scan.findings()) {
            Map<String, Object> view = viewProjector.apply(finding);
            items.add(view == null ? new LinkedHashMap<>() : view);
        }
        return Optional.of(List.copyOf(items));
    }

    @Override
    public Optional<Map<String, Object>> findingView(String findingId) {
        if (findingId == null || findingId.isBlank()) {
            return Optional.empty();
        }
        ApiDtos.FindingDto finding = store.finding(findingId);
        if (finding == null) {
            return Optional.empty();
        }
        Map<String, Object> view = viewProjector.apply(finding);
        return Optional.of(view == null ? new LinkedHashMap<>() : view);
    }
}
