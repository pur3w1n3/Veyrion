package com.aq.jvmsentinel.application.port;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 只读 PathRun 查询（P1-08）。合并 scan 的持久化与投影 run。
 * MOCK provenance 保持可见；调用方不得升级 verification status。
 */
public interface PathRunQueryPort {
    boolean scanExists(String scanId);

    /** 中性 PathRun 视图 map；scan 缺失时为空。 */
    Optional<List<Map<String, Object>>> pathRunsForScan(String scanId);
}
