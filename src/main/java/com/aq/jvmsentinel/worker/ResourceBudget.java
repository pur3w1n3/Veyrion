package com.aq.jvmsentinel.worker;

/** 由控制面提供的硬上限，永不由被分析制品提供。 */
public record ResourceBudget(long maxWallClockSeconds, long maxCpuMillis, long maxMemoryBytes,
                             long maxDiskBytes, long maxTraceBytes) {
    public ResourceBudget {
        WorkerContracts.positive(maxWallClockSeconds, "maxWallClockSeconds");
        WorkerContracts.positive(maxCpuMillis, "maxCpuMillis");
        WorkerContracts.positive(maxMemoryBytes, "maxMemoryBytes");
        WorkerContracts.positive(maxDiskBytes, "maxDiskBytes");
        WorkerContracts.positive(maxTraceBytes, "maxTraceBytes");
    }
}
