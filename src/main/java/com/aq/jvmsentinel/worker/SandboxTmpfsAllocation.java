package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.worker.docker.SandboxLaunchCommandBuilder;

import java.util.Objects;
import java.util.logging.Logger;

/**
 * 沙箱轨迹 tmpfs / disk 对齐：{@code tmpfs >= maxTraceBytes + HEADROOM}，
 * 必要时自动抬升 {@code maxDiskBytes}（仍钳在产品上限内）。
 */
public record SandboxTmpfsAllocation(ResourceBudget resourceBudget, long traceTmpfsBytes,
                                     boolean diskLifted) {
    private static final Logger LOG = Logger.getLogger(SandboxTmpfsAllocation.class.getName());

    public SandboxTmpfsAllocation {
        Objects.requireNonNull(resourceBudget, "resourceBudget");
        if (traceTmpfsBytes <= 0
                || traceTmpfsBytes > ExternalArtifactPaths.MAX_TMPFS_BYTES
                || traceTmpfsBytes > resourceBudget.maxDiskBytes()) {
            throw new IllegalArgumentException("traceTmpfsBytes is outside hardened limits");
        }
        long required = SandboxLaunchCommandBuilder.resolveTraceTmpfsBytes(
                resourceBudget.maxTraceBytes());
        if (traceTmpfsBytes < required) {
            throw new IllegalArgumentException(
                    "traceTmpfsBytes must be at least maxTraceBytes + tmpfs headroom");
        }
    }

    /**
     * 按预算计算轨迹 tmpfs；若 disk 不足以容纳 headroom，在 {@link ExternalArtifactPaths#MAX_DISK_BYTES}
     * 内自动抬升并记日志。无法抬升到所需大小时 fail-closed。
     */
    public static SandboxTmpfsAllocation forBudget(ResourceBudget budget) {
        Objects.requireNonNull(budget, "budget");
        long traceTmpfs = SandboxLaunchCommandBuilder.resolveTraceTmpfsBytes(budget.maxTraceBytes());
        if (traceTmpfs > ExternalArtifactPaths.MAX_TMPFS_BYTES) {
            throw new SecurityException("resolved trace tmpfs exceeds MAX_TMPFS_BYTES");
        }
        if (budget.maxDiskBytes() >= traceTmpfs) {
            return new SandboxTmpfsAllocation(budget, traceTmpfs, false);
        }
        long liftedDisk = Math.min(ExternalArtifactPaths.MAX_DISK_BYTES,
                Math.max(budget.maxDiskBytes(), traceTmpfs));
        if (liftedDisk < traceTmpfs) {
            throw new SecurityException(
                    "maxDiskBytes cannot cover maxTraceBytes + tmpfs headroom even after lift");
        }
        ResourceBudget lifted = new ResourceBudget(
                budget.maxWallClockSeconds(),
                budget.maxCpuMillis(),
                budget.maxMemoryBytes(),
                liftedDisk,
                budget.maxTraceBytes());
        LOG.info(() -> "sandbox disk auto-lifted for tmpfs headroom: maxTraceBytes="
                + budget.maxTraceBytes()
                + " headroom=" + ExternalArtifactPaths.TMPFS_TRACE_HEADROOM_BYTES
                + " traceTmpfs=" + traceTmpfs
                + " maxDiskBytes " + budget.maxDiskBytes() + " -> " + liftedDisk);
        return new SandboxTmpfsAllocation(lifted, traceTmpfs, true);
    }
}
