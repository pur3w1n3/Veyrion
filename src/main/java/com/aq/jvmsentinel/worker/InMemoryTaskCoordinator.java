package com.aq.jvmsentinel.worker;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;

/**
 * Synchronized reference coordinator. It provides contract semantics only and does not launch processes
 * or alter a worker host's configured capabilities.
 */
public final class InMemoryTaskCoordinator {
    private static final int MAX_TASKS = 20_000;
    private static final int MAX_REPLAYS = 100_000;
    private static final Duration MAX_LEASE = Duration.ofHours(1);

    private final Clock clock;
    private final InMemoryTraceStore traceStore;
    private final Consumer<TaskSnapshot> persistence;
    private final Map<TaskScope, TaskSnapshot> tasks = new HashMap<>();
    private final Map<ReplayKey, Replay> replays = new LinkedHashMap<>();

    public InMemoryTaskCoordinator(Clock clock, InMemoryTraceStore traceStore) {
        this(clock, traceStore, List.of(), snapshot -> { });
    }

    public InMemoryTaskCoordinator(Clock clock, InMemoryTraceStore traceStore,
                                   List<TaskSnapshot> restored, Consumer<TaskSnapshot> persistence) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.traceStore = Objects.requireNonNull(traceStore, "traceStore");
        this.persistence = Objects.requireNonNull(persistence, "persistence");
        Objects.requireNonNull(restored, "restored");
        if (restored.size() > MAX_TASKS) throw new IllegalStateException("restored task limit exceeded");
        for (TaskSnapshot snapshot : restored) {
            TaskSnapshot recovered = recover(snapshot);
            if (tasks.putIfAbsent(recovered.scope(), recovered) != null) {
                throw new IllegalStateException("duplicate restored task scope");
            }
        }
    }

    public synchronized TaskSnapshot enqueue(WorkerTaskSpec spec, String idempotencyKey) {
        Objects.requireNonNull(spec, "spec");
        if (!spec.authorized()) throw new SecurityException("explicit task authorization is required");
        TaskScope scope = spec.scope();
        Object replay = replay("enqueue", scope, idempotencyKey, spec);
        if (replay != null) return (TaskSnapshot) replay;
        requireReplayCapacity();
        if (tasks.size() >= MAX_TASKS) throw new IllegalStateException("task limit reached");
        if (tasks.containsKey(scope)) throw new IllegalStateException("task already exists");
        TaskSnapshot result = new TaskSnapshot(1, spec, TaskLifecycle.QUEUED, null, null, null, null, now());
        put(result);
        remember("enqueue", scope, idempotencyKey, spec, result);
        return result;
    }

    public synchronized WorkerLease lease(TaskScope scope, String workerId, Set<WorkerCapability> hostCapabilities,
                                           Duration duration, String idempotencyKey) {
        Objects.requireNonNull(scope, "scope");
        workerId = WorkerContracts.id(workerId, "workerId");
        Objects.requireNonNull(hostCapabilities, "hostCapabilities");
        if (hostCapabilities.isEmpty() || hostCapabilities.size() > WorkerContracts.MAX_COLLECTION_SIZE
                || hostCapabilities.stream().anyMatch(Objects::isNull)) {
            throw new IllegalArgumentException("hostCapabilities is empty, oversized, or contains null");
        }
        duration = validDuration(duration);
        reclaimExpired();
        LeaseRequest request = new LeaseRequest(workerId, Set.copyOf(hostCapabilities), duration);
        Object replay = replay("lease", scope, idempotencyKey, request);
        if (replay != null) return (WorkerLease) replay;
        requireReplayCapacity();
        TaskSnapshot current = require(scope);
        if (current.lifecycle() != TaskLifecycle.QUEUED) transitionRejected(current, "lease");
        WorkerCapability required = current.spec().requiredCapability();
        if (!hostCapabilities.contains(required)) throw new SecurityException("worker lacks required capability");
        Instant issued = now();
        WorkerLease lease = new WorkerLease(1, scope, newId("lease"), workerId, required,
                issued, issued, issued.plus(duration));
        put(copy(current, TaskLifecycle.LEASED, lease, current.checkpoint(), null, null));
        remember("lease", scope, idempotencyKey, request, lease);
        return lease;
    }

    public synchronized WorkerLease heartbeat(TaskScope scope, String leaseId, String workerId,
                                               Duration extension, String idempotencyKey) {
        extension = validDuration(extension);
        LeaseAction payload = new LeaseAction(leaseId, workerId, extension.toMillis(), null, null);
        Object replay = replay("heartbeat", scope, idempotencyKey, payload);
        if (replay != null) return (WorkerLease) replay;
        requireReplayCapacity();
        TaskSnapshot current = requireActiveLease(scope, leaseId, workerId);
        Instant heartbeat = now();
        WorkerLease lease = current.lease();
        WorkerLease renewed = new WorkerLease(1, scope, lease.leaseId(), lease.workerId(), lease.capability(),
                lease.issuedAt(), heartbeat, heartbeat.plus(extension));
        put(copy(current, current.lifecycle(), renewed, current.checkpoint(), null, null));
        remember("heartbeat", scope, idempotencyKey, payload, renewed);
        return renewed;
    }

    public synchronized TaskSnapshot start(TaskScope scope, String leaseId, String workerId, String idempotencyKey) {
        return transitionWithLease("start", scope, leaseId, workerId, null, null, idempotencyKey,
                Set.of(TaskLifecycle.LEASED), TaskLifecycle.RUNNING);
    }

    public synchronized TaskSnapshot pause(TaskScope scope, String leaseId, String workerId,
                                           TaskCheckpoint checkpoint, String idempotencyKey) {
        Objects.requireNonNull(checkpoint, "checkpoint");
        if (!scope.equals(checkpoint.scope())) throw new SecurityException("checkpoint scope mismatch");
        return transitionWithLease("pause", scope, leaseId, workerId, checkpoint, null, idempotencyKey,
                Set.of(TaskLifecycle.RUNNING), TaskLifecycle.PAUSED);
    }

    public synchronized TaskSnapshot resume(TaskScope scope, String leaseId, String workerId, String idempotencyKey) {
        return transitionWithLease("resume", scope, leaseId, workerId, null, null, idempotencyKey,
                Set.of(TaskLifecycle.PAUSED), TaskLifecycle.RUNNING);
    }

    public synchronized TaskSnapshot cancel(TaskScope scope, String leaseId, String workerId,
                                            StopReason reason, String idempotencyKey) {
        Objects.requireNonNull(reason, "reason");
        if (reason == StopReason.COMPLETED) throw new IllegalArgumentException("invalid cancellation reason");
        TaskSnapshot current = require(scope);
        LeaseAction payload = new LeaseAction(leaseId, workerId, 0, reason, null);
        Object replay = replay("cancel", scope, idempotencyKey, payload);
        if (replay != null) return (TaskSnapshot) replay;
        requireReplayCapacity();
        if (current.lifecycle() == TaskLifecycle.QUEUED) {
            if (leaseId != null || workerId != null) throw new SecurityException("queued cancellation must not claim a lease");
        } else {
            requireActiveLease(scope, leaseId, workerId);
        }
        if (!Set.of(TaskLifecycle.QUEUED, TaskLifecycle.LEASED, TaskLifecycle.RUNNING, TaskLifecycle.PAUSED)
                .contains(current.lifecycle())) transitionRejected(current, "cancel");
        TaskSnapshot result = copy(current, TaskLifecycle.CANCELLED, null, current.checkpoint(), reason, null);
        put(result);
        remember("cancel", scope, idempotencyKey, payload, result);
        return result;
    }

    /**
     * Control-plane authority cancel: clears QUEUED/LEASED/RUNNING/PAUSED without a worker lease.
     * Used to supersede stuck or abandoned dynamic tasks before an operator stage retry.
     * Terminal tasks are returned unchanged (idempotent).
     */
    public synchronized TaskSnapshot controlPlaneCancel(TaskScope scope, StopReason reason,
                                                        String idempotencyKey) {
        Objects.requireNonNull(reason, "reason");
        if (reason == StopReason.COMPLETED) throw new IllegalArgumentException("invalid cancellation reason");
        TaskSnapshot current = require(scope);
        ControlPlaneCancel payload = new ControlPlaneCancel(reason);
        Object replay = replay("control-plane-cancel", scope, idempotencyKey, payload);
        if (replay != null) return (TaskSnapshot) replay;
        requireReplayCapacity();
        if (Set.of(TaskLifecycle.CANCELLED, TaskLifecycle.COMPLETED, TaskLifecycle.FAILED)
                .contains(current.lifecycle())) {
            remember("control-plane-cancel", scope, idempotencyKey, payload, current);
            return current;
        }
        if (!Set.of(TaskLifecycle.QUEUED, TaskLifecycle.LEASED, TaskLifecycle.RUNNING, TaskLifecycle.PAUSED)
                .contains(current.lifecycle())) {
            transitionRejected(current, "control-plane-cancel");
        }
        TaskSnapshot result = copy(current, TaskLifecycle.CANCELLED, null, current.checkpoint(), reason, null);
        put(result);
        remember("control-plane-cancel", scope, idempotencyKey, payload, result);
        return result;
    }

    /**
     * Marks a still-QUEUED task as FAILED (pre-lease rejection or post-reclaim abandonment).
     * Keeps EXTERNAL_ARTIFACT_REJECTED and similar failures out of the active set.
     */
    public synchronized TaskSnapshot failQueued(TaskScope scope, StopReason reason, String failureCode,
                                                String idempotencyKey) {
        Objects.requireNonNull(reason, "reason");
        if (reason == StopReason.COMPLETED) throw new IllegalArgumentException("invalid failure reason");
        failureCode = WorkerContracts.id(failureCode, "failureCode");
        Failure payload = new Failure(reason, failureCode);
        Object replay = replay("fail-queued", scope, idempotencyKey, payload);
        if (replay != null) return (TaskSnapshot) replay;
        requireReplayCapacity();
        TaskSnapshot current = require(scope);
        if (current.lifecycle() != TaskLifecycle.QUEUED) transitionRejected(current, "fail-queued");
        TaskSnapshot result = copy(current, TaskLifecycle.FAILED, null, current.checkpoint(), reason, failureCode);
        put(result);
        remember("fail-queued", scope, idempotencyKey, payload, result);
        return result;
    }

    public synchronized TaskSnapshot complete(TaskScope scope, String leaseId, String workerId,
                                              String idempotencyKey) {
        return transitionWithLease("complete", scope, leaseId, workerId, null, StopReason.COMPLETED,
                idempotencyKey, Set.of(TaskLifecycle.RUNNING), TaskLifecycle.COMPLETED);
    }

    public synchronized TaskSnapshot fail(TaskScope scope, String leaseId, String workerId, StopReason reason,
                                          String failureCode, String idempotencyKey) {
        Objects.requireNonNull(reason, "reason");
        failureCode = WorkerContracts.id(failureCode, "failureCode");
        return transitionWithLease("fail", scope, leaseId, workerId, null,
                new Failure(reason, failureCode), idempotencyKey,
                Set.of(TaskLifecycle.LEASED, TaskLifecycle.RUNNING, TaskLifecycle.PAUSED), TaskLifecycle.FAILED);
    }

    public synchronized TaskSnapshot get(TaskScope scope) {
        reclaimExpired();
        return require(scope);
    }

    public synchronized List<TaskSnapshot> snapshots() {
        reclaimExpired();
        return List.copyOf(tasks.values());
    }

    private TaskSnapshot transitionWithLease(String operation, TaskScope scope, String leaseId, String workerId,
                                             TaskCheckpoint checkpoint, Object detail, String idempotencyKey,
                                             Set<TaskLifecycle> allowed, TaskLifecycle target) {
        LeaseAction payload = new LeaseAction(leaseId, workerId, 0, detail, checkpoint);
        Object replay = replay(operation, scope, idempotencyKey, payload);
        if (replay != null) return (TaskSnapshot) replay;
        requireReplayCapacity();
        TaskSnapshot current = requireActiveLease(scope, leaseId, workerId);
        if (!allowed.contains(current.lifecycle())) transitionRejected(current, operation);
        if (checkpoint != null) traceStore.requireCommitted(checkpoint);
        StopReason stopReason = detail instanceof StopReason value ? value
                : detail instanceof Failure failure ? failure.reason() : null;
        String failureCode = detail instanceof Failure failure ? failure.failureCode() : null;
        TaskCheckpoint nextCheckpoint = checkpoint == null ? current.checkpoint() : checkpoint;
        WorkerLease nextLease = Set.of(TaskLifecycle.COMPLETED, TaskLifecycle.FAILED, TaskLifecycle.CANCELLED)
                .contains(target) ? null : current.lease();
        TaskSnapshot result = copy(current, target, nextLease, nextCheckpoint, stopReason, failureCode);
        put(result);
        remember(operation, scope, idempotencyKey, payload, result);
        return result;
    }

    private TaskSnapshot requireActiveLease(TaskScope scope, String leaseId, String workerId) {
        TaskSnapshot current = require(scope);
        WorkerLease lease = current.lease();
        if (lease == null) throw new SecurityException("task has no active lease");
        if (!lease.leaseId().equals(WorkerContracts.id(leaseId, "leaseId"))
                || !lease.workerId().equals(WorkerContracts.id(workerId, "workerId"))) {
            throw new SecurityException("lease or worker scope mismatch");
        }
        if (lease.expiredAt(now())) {
            reclaim(current);
            throw new IllegalStateException("lease expired");
        }
        return current;
    }

    private void reclaimExpired() {
        for (TaskSnapshot current : Set.copyOf(tasks.values())) {
            if (current.lease() != null && current.lease().expiredAt(now())) reclaim(current);
        }
    }

    private void reclaim(TaskSnapshot current) {
        TaskSnapshot latest = tasks.get(current.scope());
        if (latest != current) return;
        put(copy(current, TaskLifecycle.QUEUED, null, current.checkpoint(), StopReason.LEASE_EXPIRED, null));
    }

    private TaskSnapshot require(TaskScope scope) {
        Objects.requireNonNull(scope, "scope");
        TaskSnapshot current = tasks.get(scope);
        if (current == null) throw new IllegalArgumentException("task scope not found");
        return current;
    }

    private TaskSnapshot copy(TaskSnapshot current, TaskLifecycle lifecycle, WorkerLease lease,
                              TaskCheckpoint checkpoint, StopReason reason, String failureCode) {
        return new TaskSnapshot(1, current.spec(), lifecycle, lease, checkpoint, reason, failureCode, now());
    }

    private TaskSnapshot recover(TaskSnapshot snapshot) {
        Objects.requireNonNull(snapshot, "restored task");
        if (snapshot.lease() == null) return snapshot;
        StopReason reason = snapshot.lease().expiredAt(now())
                ? StopReason.LEASE_EXPIRED : StopReason.CONTROL_PLANE_RESTART_RECOVERY;
        TaskSnapshot recovered = copy(snapshot, TaskLifecycle.QUEUED, null,
                snapshot.checkpoint(), reason, null);
        persistence.accept(recovered);
        return recovered;
    }

    private void put(TaskSnapshot snapshot) {
        persistence.accept(snapshot);
        tasks.put(snapshot.scope(), snapshot);
    }

    private Object replay(String operation, TaskScope scope, String key, Object payload) {
        Replay existing = replays.get(new ReplayKey(operation, scope, WorkerContracts.id(key, "idempotencyKey")));
        if (existing == null) return null;
        if (!existing.payload().equals(payload)) throw new IllegalStateException("idempotency key payload conflict");
        return existing.result();
    }

    private void remember(String operation, TaskScope scope, String key, Object payload, Object result) {
        replays.put(new ReplayKey(operation, scope, WorkerContracts.id(key, "idempotencyKey")),
                new Replay(payload, result));
    }

    private void requireReplayCapacity() {
        if (replays.size() >= MAX_REPLAYS) throw new IllegalStateException("idempotency key limit reached");
    }

    private static Duration validDuration(Duration duration) {
        Objects.requireNonNull(duration, "duration");
        if (duration.isZero() || duration.isNegative() || duration.compareTo(MAX_LEASE) > 0
                || duration.toMillis() == 0) throw new IllegalArgumentException("invalid lease duration");
        return duration;
    }

    private Instant now() {
        return clock.instant();
    }

    private static String newId(String prefix) {
        return prefix + "-" + UUID.randomUUID().toString().replace("-", "");
    }

    private static void transitionRejected(TaskSnapshot current, String operation) {
        throw new IllegalStateException("cannot " + operation + " task in " + current.lifecycle());
    }

    private record ReplayKey(String operation, TaskScope scope, String key) { }
    private record Replay(Object payload, Object result) { }
    private record LeaseRequest(String workerId, Set<WorkerCapability> hostCapabilities, Duration duration) { }
    private record LeaseAction(String leaseId, String workerId, long durationMillis, Object detail,
                               TaskCheckpoint checkpoint) { }
    private record Failure(StopReason reason, String failureCode) { }
    private record ControlPlaneCancel(StopReason reason) { }
}
