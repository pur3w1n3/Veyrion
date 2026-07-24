package com.aq.jvmsentinel.worker;

/** Hard upper bounds supplied by the control plane, never by the analyzed artifact. */
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
