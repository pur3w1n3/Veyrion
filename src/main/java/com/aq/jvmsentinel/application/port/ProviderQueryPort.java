package com.aq.jvmsentinel.application.port;

import java.util.List;
import java.util.Map;

/**
 * 只读 AI provider 清单查询（P1-08 增量 port 拆分）。
 * 不暴露原始 credential；map 为 wire-safe 投影。
 */
public interface ProviderQueryPort {
    /** 中性 provider 视图 map（永不包含 apiKey / secret 材料）。 */
    List<Map<String, Object>> listProviders();
}
