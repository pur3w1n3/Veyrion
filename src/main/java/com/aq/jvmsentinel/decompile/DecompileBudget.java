package com.aq.jvmsentinel.decompile;

import com.aq.jvmsentinel.worker.ResourceBudget;

import java.util.Objects;

/** Control Plane 为单次隔离 decompile 请求提供的限制。 */
public record DecompileBudget(ResourceBudget resources, int maxOutputFiles, long maxOutputBytes) {
    public DecompileBudget {
        Objects.requireNonNull(resources, "resources");
        if (maxOutputFiles <= 0 || maxOutputFiles > 100_000) {
            throw new IllegalArgumentException("maxOutputFiles is outside the supported range");
        }
        if (maxOutputBytes <= 0 || maxOutputBytes > resources.maxDiskBytes()) {
            throw new IllegalArgumentException("maxOutputBytes exceeds the disk budget");
        }
    }
}
