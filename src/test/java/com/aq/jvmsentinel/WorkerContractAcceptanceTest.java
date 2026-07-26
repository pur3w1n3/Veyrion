package com.aq.jvmsentinel;

import com.aq.jvmsentinel.worker.*;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Set;

/** Dependency-free acceptance checks for the phase-2 Worker contract only. */
public final class WorkerContractAcceptanceTest {
    private static final String DIGEST = "a".repeat(64);

    public static void main(String[] args) throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-07-24T00:00:00Z"));
        InMemoryTraceStore traces = new InMemoryTraceStore(clock);
        InMemoryTaskCoordinator coordinator = new InMemoryTaskCoordinator(clock, traces);

        WorkerTaskSpec spec = spec("task-lifecycle", true);
        TaskSnapshot queued = coordinator.enqueue(spec, "enqueue-1");
        check(queued == coordinator.enqueue(spec, "enqueue-1"), "enqueue replay must return original result");
        expect(IllegalStateException.class, () -> coordinator.enqueue(spec("task-lifecycle", true), "enqueue-1-conflict"));
        expect(IllegalArgumentException.class, () -> spec("task-denied", false));

        WorkerLease lease = coordinator.lease(spec.scope(), "worker-1", Set.of(WorkerCapability.TRUSTED_DOCKER),
                Duration.ofSeconds(30), "lease-1");
        expect(SecurityException.class, () -> coordinator.start(spec.scope(), lease.leaseId(), "worker-other", "bad-worker"));
        TaskScope wrongScope = new TaskScope("project-other", DIGEST, "scan-1", "task-lifecycle");
        expect(IllegalArgumentException.class, () -> coordinator.start(wrongScope, lease.leaseId(), "worker-1", "bad-scope"));
        coordinator.start(spec.scope(), lease.leaseId(), "worker-1", "start-1");
        expect(IllegalStateException.class, () -> coordinator.start(spec.scope(), lease.leaseId(), "worker-1", "start-again"));

        TraceChunk first = TraceChunk.create(spec.scope(), 0, null, clock.instant(), "first".getBytes(StandardCharsets.UTF_8));
        check(traces.append("trace-1", first) == traces.append("trace-1", first), "trace replay must deduplicate");
        expect(IllegalStateException.class, () -> traces.append("trace-1",
                TraceChunk.create(spec.scope(), 0, null, clock.instant().plusSeconds(1), "other".getBytes(StandardCharsets.UTF_8))));
        expect(IllegalStateException.class, () -> traces.append("trace-gap",
                TraceChunk.create(spec.scope(), 1, "b".repeat(64), clock.instant(), new byte[0])));
        expect(IllegalArgumentException.class, () -> new TraceChunk(1, spec.scope(), 1, first.digest(),
                clock.instant(), "tampered".getBytes(StandardCharsets.UTF_8), "0".repeat(64)));
        expect(IllegalArgumentException.class, () -> TraceChunk.create(spec.scope(), 1, first.digest(),
                clock.instant(), new byte[1024 * 1024 + 1]));

        TaskCheckpoint checkpoint = new TaskCheckpoint(1, spec.scope(), "checkpoint-1", 0, first.digest(), clock.instant());
        coordinator.pause(spec.scope(), lease.leaseId(), "worker-1", checkpoint, "pause-1");
        coordinator.resume(spec.scope(), lease.leaseId(), "worker-1", "resume-1");
        WorkerLease renewed = coordinator.heartbeat(spec.scope(), lease.leaseId(), "worker-1",
                Duration.ofSeconds(40), "heartbeat-1");
        check(renewed.expiresAt().equals(clock.instant().plusSeconds(40)), "heartbeat must renew from current time");
        TaskSnapshot completed = coordinator.complete(spec.scope(), lease.leaseId(), "worker-1", "complete-1");
        check(completed.lifecycle() == TaskLifecycle.COMPLETED, "legal lifecycle must complete");
        expect(SecurityException.class, () -> coordinator.heartbeat(spec.scope(), lease.leaseId(), "worker-1",
                Duration.ofSeconds(1), "heartbeat-after-complete"));

        WorkerTaskSpec cancelledSpec = spec("task-cancel", true);
        coordinator.enqueue(cancelledSpec, "enqueue-cancel");
        WorkerLease cancelLease = coordinator.lease(cancelledSpec.scope(), "worker-2",
                Set.of(WorkerCapability.TRUSTED_DOCKER), Duration.ofSeconds(10), "lease-cancel");
        coordinator.start(cancelledSpec.scope(), cancelLease.leaseId(), "worker-2", "start-cancel");
        check(coordinator.cancel(cancelledSpec.scope(), cancelLease.leaseId(), "worker-2",
                StopReason.USER_CANCELLED, "cancel-1").lifecycle() == TaskLifecycle.CANCELLED, "cancel transition");

        WorkerTaskSpec expirySpec = spec("task-expiry", true);
        coordinator.enqueue(expirySpec, "enqueue-expiry");
        WorkerLease expiredLease = coordinator.lease(expirySpec.scope(), "worker-3",
                Set.of(WorkerCapability.TRUSTED_DOCKER), Duration.ofSeconds(5), "lease-expiry");
        clock.advance(Duration.ofSeconds(5));
        expect(IllegalStateException.class, () -> coordinator.start(expirySpec.scope(), expiredLease.leaseId(),
                "worker-3", "expired-start"));
        check(coordinator.get(expirySpec.scope()).lifecycle() == TaskLifecycle.QUEUED, "expired lease must be reclaimed");
        WorkerLease replacement = coordinator.lease(expirySpec.scope(), "worker-4",
                Set.of(WorkerCapability.TRUSTED_DOCKER), Duration.ofSeconds(5), "replacement-lease");
        check(!replacement.leaseId().equals(expiredLease.leaseId()), "reclaimed task must receive a new lease");

        TraceManifest manifest = traces.manifest(spec.scope());
        check(manifest.chunks().size() == 1 && manifest.headDigest().equals(first.digest()), "trace manifest");
        TaskCheckpoint uncommitted = new TaskCheckpoint(1, spec.scope(), "checkpoint-bad", 1,
                "b".repeat(64), clock.instant());
        expect(IllegalStateException.class, () -> traces.requireCommitted(uncommitted));

        System.out.println("WorkerContractAcceptanceTest: PASS");
    }

    private static WorkerTaskSpec spec(String taskId, boolean authorized) {
        return new WorkerTaskSpec(1, "project-1", DIGEST, "scan-1", taskId, "entry-1", authorized, false,
                new ResourceBudget(60, 10_000, 256 * 1024 * 1024L, 64 * 1024 * 1024L, 8 * 1024 * 1024L),
                NetworkPolicy.denyAll(), WorkerCapability.TRUSTED_DOCKER);
    }

    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }

    private static <T extends Throwable> void expect(Class<T> type, ThrowingRunnable runnable) throws Exception {
        try {
            runnable.run();
        } catch (Throwable actual) {
            if (type.isInstance(actual)) return;
            throw actual;
        }
        throw new AssertionError("expected " + type.getSimpleName());
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    private static final class MutableClock extends Clock {
        private Instant instant;

        private MutableClock(Instant instant) {
            this.instant = instant;
        }

        void advance(Duration duration) {
            instant = instant.plus(duration);
        }

        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return instant; }
    }
}
