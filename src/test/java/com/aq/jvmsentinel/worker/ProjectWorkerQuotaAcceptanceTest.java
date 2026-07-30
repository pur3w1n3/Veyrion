package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.policy.NetworkMode;
import com.aq.jvmsentinel.sandbox.CommandRequest;
import com.aq.jvmsentinel.sandbox.CommandResult;
import com.aq.jvmsentinel.sandbox.SandboxHandle;
import com.aq.jvmsentinel.sandbox.SandboxRequest;
import com.aq.jvmsentinel.sandbox.SandboxRuntimeClient;
import com.aq.jvmsentinel.worker.session.RetainedSandboxSessions;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * per-project worker 调度与保留沙箱配额：跨工作区不互堵、不跨 project 误杀。
 */
public final class ProjectWorkerQuotaAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();
    private static final String DIGEST_A = "a".repeat(64);
    private static final String DIGEST_B = "b".repeat(64);
    private static final String DIGEST_C = "c".repeat(64);

    private ProjectWorkerQuotaAcceptanceTest() { }

    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);

        LocalWorkerQuota quota = new LocalWorkerQuota(3, 1, 4, 2);
        check(quota.maxGlobalConcurrency() == 3 && quota.maxPerProjectConcurrency() == 1,
                "default-shaped concurrency quota");
        check(quota.maxGlobalRetainedSessions() == 4 && quota.maxPerProjectRetainedSessions() == 2,
                "default-shaped retained quota");

        testFairDispatcherDoesNotStarveSecondProject();
        testPerProjectConcurrencyCap();
        testRetainedEvictsSameProjectOnly();
        testRetainedRejectsWithoutCrossProjectKill();

        System.out.println("ProjectWorkerQuotaAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void testFairDispatcherDoesNotStarveSecondProject() {
        LocalWorkerQuota quota = new LocalWorkerQuota(2, 1, 8, 2);
        List<WorkerControlPlaneClient.TaskDescriptor> tasks = List.of(
                queued("project-a", DIGEST_A, "scan-a1", "task-a1"),
                queued("project-a", DIGEST_A, "scan-a2", "task-a2"),
                queued("project-a", DIGEST_A, "scan-a3", "task-a3"),
                queued("project-b", DIGEST_B, "scan-b1", "task-b1"),
                queued("project-b", DIGEST_B, "scan-b2", "task-b2"));

        List<TaskScope> first = ProjectFairTaskDispatcher.select(
                tasks, Set.of(), Map.of(), quota, null);
        check(first.size() == 2, "first wave uses global concurrency 2");
        check(first.get(0).projectId().equals("project-a")
                        && first.get(1).projectId().equals("project-b"),
                "first wave picks one task from each project (no global single queue stall)");

        Set<TaskScope> inFlight = ConcurrentHashMap.newKeySet();
        inFlight.addAll(first);
        Map<String, Integer> running = Map.of("project-a", 1, "project-b", 1);
        List<TaskScope> blocked = ProjectFairTaskDispatcher.select(
                tasks, inFlight, running, quota, "project-b");
        check(blocked.isEmpty(), "no more dispatch while both project slots are full");

        inFlight.remove(first.get(0));
        running = Map.of("project-b", 1);
        List<TaskScope> afterA = ProjectFairTaskDispatcher.select(
                tasks, inFlight, running, quota, "project-b");
        check(afterA.size() == 1 && afterA.get(0).projectId().equals("project-a"),
                "when A frees a slot, A continues without waiting for B to drain");
    }

    private static void testPerProjectConcurrencyCap() {
        LocalWorkerQuota quota = new LocalWorkerQuota(3, 1, 8, 2);
        List<WorkerControlPlaneClient.TaskDescriptor> tasks = List.of(
                queued("project-a", DIGEST_A, "scan-1", "task-1"),
                queued("project-a", DIGEST_A, "scan-2", "task-2"),
                queued("project-a", DIGEST_A, "scan-3", "task-3"));
        List<TaskScope> selected = ProjectFairTaskDispatcher.select(
                tasks, Set.of(), Map.of(), quota, null);
        check(selected.size() == 1 && selected.get(0).taskId().equals("task-1"),
                "same project cannot exceed per-project concurrency even with global headroom");
    }

    private static void testRetainedEvictsSameProjectOnly() {
        LocalWorkerQuota quota = new LocalWorkerQuota(3, 1, 8, 2);
        RecordingSandbox sandbox = new RecordingSandbox();
        RetainedSandboxSessions sessions = new RetainedSandboxSessions(Duration.ofMinutes(20), quota);

        check(sessions.retain(scope("project-a", DIGEST_A, "scan-1", "t1"),
                DIGEST_A, "sb-a1", 8080, sandbox), "retain A1");
        pauseNanos();
        check(sessions.retain(scope("project-a", DIGEST_A, "scan-2", "t2"),
                DIGEST_A, "sb-a2", 8080, sandbox), "retain A2");
        pauseNanos();
        check(sessions.retain(scope("project-b", DIGEST_B, "scan-1", "t3"),
                DIGEST_B, "sb-b1", 8080, sandbox), "retain B1");
        pauseNanos();
        check(sessions.retain(scope("project-a", DIGEST_A, "scan-3", "t4"),
                DIGEST_A, "sb-a3", 8080, sandbox), "retain A3 under per-project cap");

        check(sessions.sizeForProject("project-a") == 2, "project A stays at per-project retained cap");
        check(sessions.contains("project-b", DIGEST_B, "scan-1"),
                "project B retained session survives A's overflow eviction");
        check(!sessions.contains("project-a", DIGEST_A, "scan-1"),
                "project A LRU (oldest) was evicted within A");
        check(sandbox.deleted.contains("sb-a1"), "evicted A sandbox deleted");
        check(!sandbox.deleted.contains("sb-b1"), "B sandbox was not deleted for A's retain");
    }

    private static void testRetainedRejectsWithoutCrossProjectKill() {
        LocalWorkerQuota quota = new LocalWorkerQuota(3, 1, 2, 2);
        RecordingSandbox sandbox = new RecordingSandbox();
        RetainedSandboxSessions sessions = new RetainedSandboxSessions(Duration.ofMinutes(20), quota);

        check(sessions.retain(scope("project-a", DIGEST_A, "scan-1", "t1"),
                DIGEST_A, "sb-a1", 8080, sandbox), "retain A at global capacity");
        pauseNanos();
        check(sessions.retain(scope("project-b", DIGEST_B, "scan-1", "t2"),
                DIGEST_B, "sb-b1", 8080, sandbox), "retain B at global capacity");
        pauseNanos();
        boolean accepted = sessions.retain(scope("project-c", DIGEST_C, "scan-1", "t3"),
                DIGEST_C, "sb-c1", 8080, sandbox);
        check(!accepted, "global hard cap rejects C instead of kicking A/B");
        check(sessions.contains("project-a", DIGEST_A, "scan-1"), "A retained after C reject");
        check(sessions.contains("project-b", DIGEST_B, "scan-1"), "B retained after C reject");
        check(!sessions.contains("project-c", DIGEST_C, "scan-1"), "C was not retained");
        check(!sandbox.deleted.contains("sb-a1") && !sandbox.deleted.contains("sb-b1"),
                "reject path never deletes other projects' sandboxes");
        check(sessions.size() == 2, "global retained count stays at hard cap");
    }

    private static WorkerControlPlaneClient.TaskDescriptor queued(
            String projectId, String digest, String scanId, String taskId) {
        return new WorkerControlPlaneClient.TaskDescriptor(
                scope(projectId, digest, scanId, taskId),
                TaskLifecycle.QUEUED,
                "entry-1",
                true,
                false,
                WorkerCapability.TRUSTED_DOCKER,
                new ResourceBudget(120, 120_000, 256L * 1024 * 1024,
                        64L * 1024 * 1024, 8L * 1024 * 1024),
                new NetworkPolicy(NetworkMode.DENY, List.of()),
                null,
                Instant.parse("2026-07-30T00:00:00Z"));
    }

    private static TaskScope scope(String projectId, String digest, String scanId, String taskId) {
        return new TaskScope(projectId, digest, scanId, taskId);
    }

    private static void pauseNanos() {
        // expiresAtNanos 用作 LRU 近似；同纳秒写入时顺序不稳定，略作间隔。
        try {
            Thread.sleep(2);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private static void check(boolean condition, String label) {
        if (!condition) {
            throw new AssertionError(label);
        }
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }

    private static final class RecordingSandbox implements SandboxRuntimeClient {
        private final List<String> deleted = new CopyOnWriteArrayList<>();

        @Override
        public SandboxHandle create(SandboxRequest request) {
            throw new UnsupportedOperationException("create unused in retained quota fixture");
        }

        @Override
        public CommandResult command(String sandboxId, CommandRequest request) {
            throw new UnsupportedOperationException("command unused in retained quota fixture");
        }

        @Override
        public void delete(String sandboxId) {
            deleted.add(sandboxId);
        }
    }
}
