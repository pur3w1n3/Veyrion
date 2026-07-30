package com.aq.jvmsentinel.domain.runtime;

/**
 * 中立 RuntimeAdapter capability 词汇（P2 scaffolding）。
 *
 * <p>{@link #GVISOR} / {@link #KATA} 命名 hardened Worker runtime。出现在本
 * enum 不启用 production isolation — 启用需 signed attestation 且
 * 经 {@link HardenedRuntimeAttestationGate} 保持 fail-closed。
 */
public enum RuntimeCapability {
    STATIC_ONLY,
    /** 仅本地 trusted Boot JAR 调试 — 永不符合 VERIFIED。 */
    TRUSTED_DOCKER,
    /** Hardened gVisor Worker（scaffolding；启用需 attestation）。 */
    GVISOR,
    /** Hardened Kata Worker（scaffolding；启用需 attestation）。 */
    KATA;

    public boolean isHardened() {
        return this == GVISOR || this == KATA;
    }

    /**
     * WorkerCapability 使用的 wire 兼容名（{@code HARDENED_GVISOR}/{@code HARDENED_KATA}）。
     */
    public String workerWireName() {
        return switch (this) {
            case STATIC_ONLY -> "STATIC_ONLY";
            case TRUSTED_DOCKER -> "TRUSTED_DOCKER";
            case GVISOR -> "HARDENED_GVISOR";
            case KATA -> "HARDENED_KATA";
        };
    }

    public static RuntimeCapability fromWorkerWireName(String name) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("capability required");
        }
        return switch (name.trim()) {
            case "STATIC_ONLY" -> STATIC_ONLY;
            case "TRUSTED_DOCKER" -> TRUSTED_DOCKER;
            case "GVISOR", "HARDENED_GVISOR" -> GVISOR;
            case "KATA", "HARDENED_KATA" -> KATA;
            default -> throw new IllegalArgumentException("unsupported runtime capability: " + name);
        };
    }
}
