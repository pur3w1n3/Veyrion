package com.aq.jvmsentinel.application.port;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 只读 finding 查询（P1-08）。HTTP adapter 投影为 legacy {@code /api/v1} map。
 * 不提升 verification status。
 */
public interface FindingQueryPort {
    boolean scanExists(String scanId);

    /** scan 的中性 finding 视图 map；scan 缺失时为空。 */
    Optional<List<Map<String, Object>>> findingsForScan(String scanId);

    Optional<Map<String, Object>> findingView(String findingId);
}
