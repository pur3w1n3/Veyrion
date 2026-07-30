package com.aq.jvmsentinel.worker;

/**
 * 宿主能力在带外配置。任务可要求某值，但不能授予它。
 *
 * <p>{@link #HARDENED_GVISOR} / {@link #HARDENED_KATA} 为 domain {@code GVISOR}/{@code KATA}
 * 能力的 Worker 线名。无 attestation 的启用由 {@link HardenedWorkerEnablement} 拒绝；VERIFIED 保持关闭。
 */
public enum WorkerCapability {
    STATIC_ONLY,
    /** 本地 Docker 后端内部 JAR 的显式操作员授权。 */
    TRUSTED_DOCKER,
    /** gVisor 加固 Worker（domain RuntimeCapability.GVISOR 的线别名）。 */
    HARDENED_GVISOR,
    /** Kata 加固 Worker（domain RuntimeCapability.KATA 的线别名）。 */
    HARDENED_KATA
}
