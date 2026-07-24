package com.aq.jvmsentinel.worker;

import java.time.Instant;
import java.util.Objects;

public record WorkerLease(int schemaVersion, TaskScope scope, String leaseId, String workerId,
                          WorkerCapability capability, Instant issuedAt, Instant heartbeatAt,
                          Instant expiresAt) {
    public WorkerLease {
        WorkerContracts.schemaVersion(schemaVersion);
        Objects.requireNonNull(scope, "scope");
        leaseId = WorkerContracts.id(leaseId, "leaseId");
        workerId = WorkerContracts.id(workerId, "workerId");
        Objects.requireNonNull(capability, "capability");
        issuedAt = WorkerContracts.instant(issuedAt, "issuedAt");
        heartbeatAt = WorkerContracts.instant(heartbeatAt, "heartbeatAt");
        expiresAt = WorkerContracts.instant(expiresAt, "expiresAt");
        if (heartbeatAt.isBefore(issuedAt) || !expiresAt.isAfter(heartbeatAt)) {
            throw new IllegalArgumentException("invalid lease time range");
        }
    }

    public boolean expiredAt(Instant now) {
        return !expiresAt.isAfter(Objects.requireNonNull(now, "now"));
    }
}
