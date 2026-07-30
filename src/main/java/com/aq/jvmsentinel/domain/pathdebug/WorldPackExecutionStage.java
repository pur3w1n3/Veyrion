package com.aq.jvmsentinel.domain.pathdebug;

/**
 * 分阶段执行单个 Docker JVM World Pack dependency mode。
 *
 * <p>一个 sandbox JVM 承载一种 mode。冷启动探索与后续确认
 * 为独立 stage，使 deny-all 应用在 honest dependency exit 重跑前
 * 可在 stub 下绑定 HTTP。选择由 stage 驱动，非 DB-vendor 驱动。</p>
 */
public enum WorldPackExecutionStage {
    /** 主 dynamic task / 冷启动：stub 继续更深 path 探索。 */
    EXPLORATION,
    /** TRIAGE / 显式 observe replay：在 dependency 边界 fail closed。 */
    CONFIRMATION
}
