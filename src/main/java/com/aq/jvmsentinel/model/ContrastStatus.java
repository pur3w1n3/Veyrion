package com.aq.jvmsentinel.model;

/**
 * sink/entry 行的 static↔dynamic 对比。永不升级 verification：
 * MATCHED 至多仍为 {@code DYNAMIC_SUSPECTED}。
 */
public enum ContrastStatus {
    /** 静态候选与同一 entry×track 的 pass-gate PathRun 对齐。 */
    MATCHED,
    /** entry×track 存在 PathRun 但 bind/sink touch 不完整。 */
    PARTIAL,
    /** 静态 reachability/gap，无可用 pass-gate PathRun（如全部 401）。 */
    STATIC_ONLY,
    /** 静态 taint path 上的 method 至少产生一次 dynamic branch hit。 */
    DYNAMIC_REACHED,
    /** 无匹配静态 sink 行的 PathRun。 */
    DYNAMIC_ONLY,
    /** 数据不足，无法分类。 */
    UNKNOWN
}
