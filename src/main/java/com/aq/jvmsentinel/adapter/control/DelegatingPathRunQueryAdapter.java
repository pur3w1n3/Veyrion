package com.aq.jvmsentinel.adapter.control;

import com.aq.jvmsentinel.application.port.PathRunQueryPort;
import com.aq.jvmsentinel.control.ControlPlaneStore;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

/**
 * 基于 store 存在性 + 服务端 merge 投影回调的 PathRun 查询（P1-08）。
 * merge/trace 投影留在 domain 之外，HTTP 经 port 访问。
 */
public final class DelegatingPathRunQueryAdapter implements PathRunQueryPort {
    private final ControlPlaneStore store;
    private final Function<String, List<Map<String, Object>>> pathRunProjector;

    public DelegatingPathRunQueryAdapter(ControlPlaneStore store,
                                         Function<String, List<Map<String, Object>>> pathRunProjector) {
        this.store = Objects.requireNonNull(store, "store");
        this.pathRunProjector = Objects.requireNonNull(pathRunProjector, "pathRunProjector");
    }

    @Override
    public boolean scanExists(String scanId) {
        return scanId != null && !scanId.isBlank() && store.scan(scanId) != null;
    }

    @Override
    public Optional<List<Map<String, Object>>> pathRunsForScan(String scanId) {
        if (!scanExists(scanId)) {
            return Optional.empty();
        }
        List<Map<String, Object>> runs = pathRunProjector.apply(scanId);
        return Optional.of(runs == null ? List.of() : List.copyOf(runs));
    }
}
