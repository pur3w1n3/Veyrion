package com.aq.jvmsentinel.application.port;

import java.util.Map;
import java.util.Optional;

/**
 * 只读 scan 摘要查询（P1-08）。HTTP adapter 投影为 legacy {@code /api/v1} map。
 */
public interface ScanQueryPort {
    boolean exists(String scanId);

    /** 中性 scan 视图 map；scan 缺失时为空。 */
    Optional<Map<String, Object>> scanView(String scanId);
}
