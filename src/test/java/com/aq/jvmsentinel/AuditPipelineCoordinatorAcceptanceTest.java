package com.aq.jvmsentinel;

import com.aq.jvmsentinel.ai.AuditPipelineCoordinator;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.AiJobData;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.aq.jvmsentinel.worker.NetworkPolicy;
import com.aq.jvmsentinel.worker.ResourceBudget;
import com.aq.jvmsentinel.worker.StopReason;
import com.aq.jvmsentinel.worker.TaskLifecycle;
import com.aq.jvmsentinel.worker.TaskSnapshot;
import com.aq.jvmsentinel.worker.WorkerCapability;
import com.aq.jvmsentinel.worker.WorkerTaskSpec;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/** Verifies server-owned audit pipeline advancement without model authority. */
public final class AuditPipelineCoordinatorAcceptanceTest {
    public static void main(String[] args) throws Exception {
        List<String> actions = new CopyOnWriteArrayList<>();
        CountDownLatch auth = new CountDownLatch(1);
        CountDownLatch path = new CountDownLatch(1);
        CountDownLatch dynamic = new CountDownLatch(1);
        CountDownLatch verify = new CountDownLatch(1);
        AtomicInteger authJobs = new AtomicInteger();
        AtomicBoolean dynamicCompleted = new AtomicBoolean();
        AuditPipelineCoordinator coordinator = new AuditPipelineCoordinator(
                new AuditPipelineCoordinator.Actions() {
                    @Override
                    public boolean hasRoleJob(String projectId, String scanId, AgentRole role) {
                        return actions.stream().anyMatch(value -> value.equals("role:" + role.name()));
                    }

                    @Override
                    public int countRoleJobs(String projectId, String scanId, AgentRole role) {
                        if (role == AgentRole.AUTH_ANALYSIS) return authJobs.get();
                        return hasRoleJob(projectId, scanId, role) ? 1 : 0;
                    }

                    @Override
                    public boolean hasBusyDynamicTask(String scanId) {
                        return actions.contains("dynamic") && !dynamicCompleted.get();
                    }

                    @Override
                    public boolean hasCompletedDynamicTask(String scanId) {
                        return dynamicCompleted.get();
                    }

                    @Override
                    public void enqueueRole(String projectId, String scanId, AgentRole role,
                                            AiOutputLanguage language, String actorId) {
                        actions.add("role:" + role.name());
                        if (role == AgentRole.AUTH_ANALYSIS) authJobs.incrementAndGet();
                        if (role == AgentRole.AUTH_ANALYSIS && authJobs.get() == 1) auth.countDown();
                        if (role == AgentRole.PATH_EXPLORATION) path.countDown();
                        if (role == AgentRole.DYNAMIC_VERIFICATION) verify.countDown();
                    }

                    @Override
                    public void enqueueDynamic(String scanId, String actorId) {
                        actions.add("dynamic");
                        dynamic.countDown();
                    }
                });
        coordinator.arm(new AuditPipelineCoordinator.Arm(
                "scan-a", "project-a", "operator-a", AiOutputLanguage.ZH_CN));
        coordinator.onAiJobFinished(job("scan-a", AgentRole.PRE_ANALYSIS, "COMPLETED"));
        check(auth.await(3, TimeUnit.SECONDS), "PRE_ANALYSIS completion enqueues AUTH_ANALYSIS");
        coordinator.onAiJobFinished(job("scan-a", AgentRole.AUTH_ANALYSIS, "COMPLETED"));
        check(dynamic.await(3, TimeUnit.SECONDS), "AUTH_ANALYSIS completion enqueues Docker dynamic");
        WorkerTaskSpec spec = new WorkerTaskSpec(
                1, "project-a", "a".repeat(64), "scan-a", "task-a", "entry-a", true,
                new ResourceBudget(60, 30_000, 1024L * 1024 * 1024, 64L * 1024 * 1024, 512L * 1024),
                NetworkPolicy.denyAll(), WorkerCapability.TRUSTED_DOCKER);
        dynamicCompleted.set(true);
        coordinator.onDynamicTaskFinished(new TaskSnapshot(
                1, spec, TaskLifecycle.COMPLETED, null, null, StopReason.COMPLETED, null, Instant.now()));
        Thread.sleep(300);
        check(authJobs.get() >= 2, "dynamic completion enqueues AUTH bypass confirm");
        coordinator.onAiJobFinished(job("scan-a", AgentRole.AUTH_ANALYSIS, "COMPLETED"));
        check(verify.await(3, TimeUnit.SECONDS), "AUTH bypass confirm enqueues DYNAMIC_VERIFICATION");
        coordinator.onAiJobFinished(job("scan-a", AgentRole.DYNAMIC_VERIFICATION, "COMPLETED"));
        check(path.await(3, TimeUnit.SECONDS), "DYNAMIC_VERIFICATION completion enqueues PATH_EXPLORATION");
        coordinator.onAiJobFinished(job("scan-a", AgentRole.PATH_EXPLORATION, "FAILED"));
        Thread.sleep(200);
        List<String> snapshot = new ArrayList<>(actions);
        coordinator.onAiJobFinished(job("scan-a", AgentRole.VULNERABILITY_TRIAGE, "COMPLETED"));
        Thread.sleep(200);
        check(actions.equals(snapshot), "failed stage stops the armed pipeline");
        System.out.println("AuditPipelineCoordinatorAcceptanceTest passed");
    }

    private static AiJobData job(String scanId, AgentRole role, String status) {
        return new AiJobData(
                "ai-job-" + role.name().toLowerCase() + "-" + System.nanoTime(), "local", "project-a", scanId,
                "a".repeat(64),
                role, "provider-a", "model-a", "{\"schemaVersion\":1}", true, status, status,
                "[]", null, 0, 0, "[]", null, Instant.now().toString(), Instant.now().toString());
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
