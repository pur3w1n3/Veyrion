package com.aq.jvmsentinel.worker;

import java.time.Instant;
import java.util.Objects;

/** A resumable position that may reference only an already committed trace head. */
public record TaskCheckpoint(int schemaVersion, TaskScope scope, String checkpointId,
                             long traceSequence, String traceHeadDigest, Instant createdAt) {
    public TaskCheckpoint {
        WorkerContracts.schemaVersion(schemaVersion);
        Objects.requireNonNull(scope, "scope");
        checkpointId = WorkerContracts.id(checkpointId, "checkpointId");
        if (traceSequence < -1) throw new IllegalArgumentException("traceSequence cannot be below -1");
        if (traceSequence == -1) {
            if (traceHeadDigest != null) throw new IllegalArgumentException("empty trace cannot have a digest");
        } else {
            traceHeadDigest = WorkerContracts.digest(traceHeadDigest, "traceHeadDigest");
        }
        createdAt = WorkerContracts.instant(createdAt, "createdAt");
    }
}
