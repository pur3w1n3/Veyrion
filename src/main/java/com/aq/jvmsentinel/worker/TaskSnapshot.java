package com.aq.jvmsentinel.worker;

import java.time.Instant;
import java.util.Objects;

public record TaskSnapshot(int schemaVersion, WorkerTaskSpec spec, TaskLifecycle lifecycle,
                           WorkerLease lease, TaskCheckpoint checkpoint, StopReason stopReason,
                           String failureCode, Instant updatedAt) {
    public TaskSnapshot {
        WorkerContracts.schemaVersion(schemaVersion);
        Objects.requireNonNull(spec, "spec");
        Objects.requireNonNull(lifecycle, "lifecycle");
        updatedAt = WorkerContracts.instant(updatedAt, "updatedAt");
        if (failureCode != null) failureCode = WorkerContracts.id(failureCode, "failureCode");
        if (lease != null && !lease.scope().equals(spec.scope())) {
            throw new IllegalArgumentException("lease scope does not match task");
        }
        if (checkpoint != null && !checkpoint.scope().equals(spec.scope())) {
            throw new IllegalArgumentException("checkpoint scope does not match task");
        }
        if (SetHolder.TERMINAL.contains(lifecycle) && lease != null) {
            throw new IllegalArgumentException("terminal task cannot retain a lease");
        }
        if (SetHolder.ACTIVE_LEASE.contains(lifecycle) && lease == null) {
            throw new IllegalArgumentException("active task requires a lease");
        }
        if (lifecycle == TaskLifecycle.FAILED && (stopReason == null || failureCode == null)) {
            throw new IllegalArgumentException("failed task requires stopReason and failureCode");
        }
        if (lifecycle == TaskLifecycle.CANCELLED && stopReason == null) {
            throw new IllegalArgumentException("cancelled task requires stopReason");
        }
        if (lifecycle != TaskLifecycle.FAILED && failureCode != null) {
            throw new IllegalArgumentException("only failed tasks can have failureCode");
        }
        if (lifecycle == TaskLifecycle.COMPLETED && stopReason != StopReason.COMPLETED) {
            throw new IllegalArgumentException("completed task requires COMPLETED stopReason");
        }
    }

    public TaskScope scope() {
        return spec.scope();
    }

    private static final class SetHolder {
        private static final java.util.Set<TaskLifecycle> TERMINAL = java.util.Set.of(
                TaskLifecycle.CANCELLED, TaskLifecycle.COMPLETED, TaskLifecycle.FAILED);
        private static final java.util.Set<TaskLifecycle> ACTIVE_LEASE = java.util.Set.of(
                TaskLifecycle.LEASED, TaskLifecycle.RUNNING, TaskLifecycle.PAUSED);
    }
}
