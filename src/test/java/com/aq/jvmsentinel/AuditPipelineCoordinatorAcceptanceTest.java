package com.aq.jvmsentinel;

import com.aq.jvmsentinel.ai.AuditPipelineCoordinator;
import com.aq.jvmsentinel.ai.AuditPipelineCoordinator.Cursor;
import com.aq.jvmsentinel.ai.AuditPipelineCoordinator.PipelineStage;
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
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Verifies server-owned audit pipeline advancement with run/stage/expected-resource identity.
 */
public final class AuditPipelineCoordinatorAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) throws Exception {
        happyPathAdvancesOnce();
        foreignManualAndDuplicateDoNotAdvance();
        staleAttemptAndRetryInvalidateOldCallbacks();
        failedExpectedJobDisarmsWithoutEnqueue();
        triageCompletionReleasesRetainedSandbox();
        skipsAuthBypassConfirmWithoutEvidence();
        staticContinuesWhenDynamicWorkerUnavailable();
        pathLoopsToObservationThenTriage();
        check(AuditPipelineCoordinator.resolveObservationLoopMax() >= 0, "obs loop max resolves");
        System.out.println("AuditPipelineCoordinatorAcceptanceTest passed ("
                + ASSERTIONS.get() + " assertions)");
    }

    private static void happyPathAdvancesOnce() throws Exception {
        Fixture fixture = new Fixture();
        AuditPipelineCoordinator coordinator = fixture.coordinator;
        String preJob = "job-pre";
        coordinator.armForJob("scan-a", "project-a", "operator-a", AiOutputLanguage.ZH_CN,
                PipelineStage.PRE_ANALYSIS, preJob);
        coordinator.onAiJobFinished(job(preJob, "scan-a", AgentRole.PRE_ANALYSIS, "COMPLETED"));
        check(fixture.authCreated.await(3, TimeUnit.SECONDS), "PRE_ANALYSIS completion enqueues AUTH_ANALYSIS");
        String authJob = fixture.lastJobId(AgentRole.AUTH_ANALYSIS);
        coordinator.onAiJobFinished(job(authJob, "scan-a", AgentRole.AUTH_ANALYSIS, "COMPLETED"));
        check(fixture.dynamicCreated.await(3, TimeUnit.SECONDS), "AUTH_ANALYSIS completion enqueues Docker dynamic");
        String taskId = fixture.lastTaskId;
        dynamicFinished(coordinator, "scan-a", taskId);
        check(fixture.authBypassCreated.await(3, TimeUnit.SECONDS), "dynamic completion enqueues AUTH bypass confirm");
        String bypassJob = fixture.lastJobId(AgentRole.AUTH_ANALYSIS);
        check(!authJob.equals(bypassJob), "bypass confirm uses a new AUTH job identity");
        coordinator.onAiJobFinished(job(bypassJob, "scan-a", AgentRole.AUTH_ANALYSIS, "COMPLETED"));
        check(fixture.verifyCreated.await(3, TimeUnit.SECONDS), "AUTH bypass confirm enqueues DYNAMIC_VERIFICATION");
        String verifyJob = fixture.lastJobId(AgentRole.DYNAMIC_VERIFICATION);
        coordinator.onAiJobFinished(job(verifyJob, "scan-a", AgentRole.DYNAMIC_VERIFICATION, "COMPLETED"));
        check(fixture.pathCreated.await(3, TimeUnit.SECONDS), "DYNAMIC_VERIFICATION completion enqueues PATH_EXPLORATION");
        int enqueuesBeforeDuplicate = fixture.roleEnqueues.get();
        coordinator.onAiJobFinished(job(verifyJob, "scan-a", AgentRole.DYNAMIC_VERIFICATION, "COMPLETED"));
        Thread.sleep(200);
        check(fixture.roleEnqueues.get() == enqueuesBeforeDuplicate,
                "duplicate correct job completion advances at most once");
    }

    private static void foreignManualAndDuplicateDoNotAdvance() throws Exception {
        Fixture fixture = new Fixture();
        AuditPipelineCoordinator coordinator = fixture.coordinator;
        coordinator.armForJob("scan-b", "project-a", "operator-a", AiOutputLanguage.ZH_CN,
                PipelineStage.PRE_ANALYSIS, "job-expected-pre");
        List<String> before = List.copyOf(fixture.actions);
        coordinator.onAiJobFinished(job("job-manual-pre", "scan-b", AgentRole.PRE_ANALYSIS, "COMPLETED"));
        Thread.sleep(150);
        check(fixture.actions.equals(before), "manual same-role job does not advance main cursor");
        coordinator.onAiJobFinished(job("job-expected-pre", "scan-other", AgentRole.PRE_ANALYSIS, "COMPLETED"));
        Thread.sleep(150);
        check(fixture.actions.equals(before), "foreign scan job does not advance cursor");
        coordinator.onAiJobFinished(job("job-expected-pre", "scan-b", AgentRole.AUTH_ANALYSIS, "COMPLETED"));
        Thread.sleep(150);
        check(fixture.actions.equals(before), "wrong-role expected id does not advance cursor");
        dynamicFinished(coordinator, "scan-b", "task-focus-probe");
        Thread.sleep(150);
        check(fixture.actions.equals(before), "focus/sandbox probe task does not advance cursor");
        coordinator.onAiJobFinished(job("job-expected-pre", "scan-b", AgentRole.PRE_ANALYSIS, "COMPLETED"));
        check(fixture.authCreated.await(3, TimeUnit.SECONDS), "only expected job advances once");
        int after = fixture.roleEnqueues.get();
        coordinator.onAiJobFinished(job("job-expected-pre", "scan-b", AgentRole.PRE_ANALYSIS, "COMPLETED"));
        Thread.sleep(150);
        check(fixture.roleEnqueues.get() == after, "duplicate expected completion does not re-enqueue");
    }

    private static void staleAttemptAndRetryInvalidateOldCallbacks() throws Exception {
        Fixture fixture = new Fixture();
        AuditPipelineCoordinator coordinator = fixture.coordinator;
        coordinator.armForJob("scan-c", "project-a", "operator-a", AiOutputLanguage.ZH_CN,
                PipelineStage.PRE_ANALYSIS, "job-old-run");
        Cursor old = coordinator.cursor("scan-c");
        check(old != null, "armed cursor exists");
        coordinator.armForJob("scan-c", "project-a", "operator-a", AiOutputLanguage.ZH_CN,
                PipelineStage.PRE_ANALYSIS, "job-new-run");
        Cursor newer = coordinator.cursor("scan-c");
        check(newer != null && !newer.arm().pipelineRunId().equals(old.arm().pipelineRunId()),
                "retry creates a new pipelineRunId");
        check(!newer.stageAttemptId().equals(old.stageAttemptId()),
                "retry creates a new stageAttemptId");
        List<String> before = List.copyOf(fixture.actions);
        coordinator.onAiJobFinished(job("job-old-run", "scan-c", AgentRole.PRE_ANALYSIS, "COMPLETED"));
        Thread.sleep(150);
        check(fixture.actions.equals(before), "old run callback cannot advance the new cursor");
        boolean cas = fixture.actionsApi.compareAndAdvance(
                old,
                new Cursor(old.arm(), PipelineStage.AUTH_ANALYSIS, AuditPipelineCoordinator.newStageAttemptId(),
                        "ghost", null),
                true, null);
        check(!cas, "CAS against superseded attempt fails and keeps the current cursor");
        check(coordinator.cursor("scan-c").stageAttemptId().equals(newer.stageAttemptId()),
                "failed CAS keeps original cursor attempt");
        coordinator.onAiJobFinished(job("job-new-run", "scan-c", AgentRole.PRE_ANALYSIS, "COMPLETED"));
        check(fixture.authCreated.await(3, TimeUnit.SECONDS), "new run expected job still advances");
    }

    private static void triageCompletionReleasesRetainedSandbox() throws Exception {
        Fixture fixture = new Fixture();
        AuditPipelineCoordinator coordinator = fixture.coordinator;
        coordinator.armForJob("scan-triage", "project-a", "operator-a", AiOutputLanguage.ZH_CN,
                PipelineStage.VULNERABILITY_TRIAGE, "job-triage");
        check(fixture.actions.stream().noneMatch(value -> value.startsWith("release-sandbox:")),
                "arming TRIAGE does not release retained sandbox");
        coordinator.onAiJobFinished(job("job-triage", "scan-triage", AgentRole.VULNERABILITY_TRIAGE, "COMPLETED"));
        check(fixture.triageReleased.await(3, TimeUnit.SECONDS),
                "TRIAGE completion releases retained sandbox before REPORT");
        check(fixture.sandboxReleases.get() == 1, "TRIAGE completion releases exactly once");
        check(fixture.reportCreated.await(3, TimeUnit.SECONDS),
                "TRIAGE completion enqueues REPORT_GENERATION");
    }

    private static void skipsAuthBypassConfirmWithoutEvidence() throws Exception {
        Fixture fixture = new Fixture();
        fixture.hasAuthEvidence = false;
        AuditPipelineCoordinator coordinator = fixture.coordinator;
        coordinator.armForJob("scan-skip-auth", "project-a", "operator-a", AiOutputLanguage.ZH_CN,
                PipelineStage.AUTH_ANALYSIS, "job-auth-skip");
        coordinator.onAiJobFinished(job("job-auth-skip", "scan-skip-auth", AgentRole.AUTH_ANALYSIS, "COMPLETED"));
        check(fixture.dynamicCreated.await(3, TimeUnit.SECONDS), "AUTH enqueues dynamic");
        String taskId = fixture.lastTaskId;
        dynamicFinished(coordinator, "scan-skip-auth", taskId);
        check(fixture.verifyCreated.await(3, TimeUnit.SECONDS),
                "no auth evidence skips AUTH_BYPASS_CONFIRM and goes to DYNAMIC_VERIFICATION");
        check(fixture.authBypassCreated.getCount() == 1,
                "AUTH_BYPASS_CONFIRM latch remains unreleased when skipped");
    }

    private static void staticContinuesWhenDynamicWorkerUnavailable() throws Exception {
        Fixture fixture = new Fixture();
        fixture.hasAuthEvidence = false;
        AuditPipelineCoordinator coordinator = fixture.coordinator;
        coordinator.armForJob("scan-static-cont", "project-a", "operator-a", AiOutputLanguage.ZH_CN,
                PipelineStage.AUTH_ANALYSIS, "job-auth-static");
        coordinator.onAiJobFinished(job("job-auth-static", "scan-static-cont", AgentRole.AUTH_ANALYSIS, "COMPLETED"));
        check(fixture.dynamicCreated.await(3, TimeUnit.SECONDS), "AUTH enqueues dynamic");
        String taskId = fixture.lastTaskId;
        WorkerTaskSpec spec = new WorkerTaskSpec(
                1, "project-a", "a".repeat(64), "scan-static-cont", taskId, "entry-a", true,
                new ResourceBudget(60, 30_000, 1024L * 1024 * 1024, 64L * 1024 * 1024, 512L * 1024),
                NetworkPolicy.denyAll(), WorkerCapability.TRUSTED_DOCKER);
        coordinator.onDynamicTaskFinished(new TaskSnapshot(
                1, spec, TaskLifecycle.FAILED, null, null, StopReason.WALL_CLOCK_TIMEOUT,
                "WORKER_UNAVAILABLE", Instant.now()));
        check(fixture.verifyCreated.await(3, TimeUnit.SECONDS),
                "WORKER_UNAVAILABLE continues to DYNAMIC_VERIFICATION instead of disarm");
        check(coordinator.isArmed("scan-static-cont"), "pipeline stays armed after static continue");
    }

    private static void pathLoopsToObservationThenTriage() throws Exception {
        Fixture fixture = new Fixture();
        fixture.pendingObsWork = true;
        fixture.obsLoopMax = 1;
        AuditPipelineCoordinator coordinator = fixture.coordinator;
        coordinator.armForJob("scan-loop", "project-a", "operator-a", AiOutputLanguage.ZH_CN,
                PipelineStage.PATH_EXPLORATION, "job-path-loop");
        coordinator.onAiJobFinished(job("job-path-loop", "scan-loop", AgentRole.PATH_EXPLORATION, "COMPLETED"));
        check(fixture.dynamicCreated.await(3, TimeUnit.SECONDS),
                "PATH with pending OBS work re-enters DYNAMIC_OBSERVATION");
        check(fixture.recomputeCalls.get() >= 1, "IR2 recompute runs before OBS loop");
        String taskId = fixture.lastTaskId;
        dynamicFinished(coordinator, "scan-loop", taskId);
        check(fixture.pathCreated.await(3, TimeUnit.SECONDS),
                "OBS loop resumes PATH_EXPLORATION");
        String pathJob2 = fixture.lastJobId(AgentRole.PATH_EXPLORATION);
        fixture.pendingObsWork = false;
        coordinator.onAiJobFinished(job(pathJob2, "scan-loop", AgentRole.PATH_EXPLORATION, "COMPLETED"));
        check(fixture.triageCreated.await(3, TimeUnit.SECONDS),
                "PATH without pending work advances to TRIAGE");
    }

    private static void failedExpectedJobDisarmsWithoutEnqueue() throws Exception {
        Fixture fixture = new Fixture();
        AuditPipelineCoordinator coordinator = fixture.coordinator;
        coordinator.armForJob("scan-d", "project-a", "operator-a", AiOutputLanguage.ZH_CN,
                PipelineStage.PATH_EXPLORATION, "job-path");
        int enqueuesBefore = fixture.roleEnqueues.get();
        coordinator.onAiJobFinished(job("job-path", "scan-d", AgentRole.PATH_EXPLORATION, "FAILED"));
        Thread.sleep(150);
        check(!coordinator.isArmed("scan-d"), "failed stage stops the armed pipeline");
        check(fixture.roleEnqueues.get() == enqueuesBefore,
                "failed stage does not enqueue downstream roles");
        int actionsAfterFail = fixture.actions.size();
        coordinator.onAiJobFinished(job("job-path", "scan-d", AgentRole.PATH_EXPLORATION, "COMPLETED"));
        Thread.sleep(150);
        check(fixture.actions.size() == actionsAfterFail,
                "late success after disarm does not revive cursor");
        check(fixture.roleEnqueues.get() == enqueuesBefore,
                "late success after disarm does not enqueue");
    }

    private static void dynamicFinished(AuditPipelineCoordinator coordinator, String scanId, String taskId) {
        WorkerTaskSpec spec = new WorkerTaskSpec(
                1, "project-a", "a".repeat(64), scanId, taskId, "entry-a", true,
                new ResourceBudget(60, 30_000, 1024L * 1024 * 1024, 64L * 1024 * 1024, 512L * 1024),
                NetworkPolicy.denyAll(), WorkerCapability.TRUSTED_DOCKER);
        coordinator.onDynamicTaskFinished(new TaskSnapshot(
                1, spec, TaskLifecycle.COMPLETED, null, null, StopReason.COMPLETED, null, Instant.now()));
    }

    private static AiJobData job(String jobId, String scanId, AgentRole role, String status) {
        return new AiJobData(
                jobId, "local", "project-a", scanId, "a".repeat(64),
                role, "provider-a", "model-a", "{\"schemaVersion\":1}", true, status, status,
                "[]", null, 0, 0, "[]", null, Instant.now().toString(), Instant.now().toString());
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
    }

    private static final class Fixture {
        private final List<String> actions = new CopyOnWriteArrayList<>();
        private final CountDownLatch authCreated = new CountDownLatch(1);
        private final CountDownLatch authBypassCreated = new CountDownLatch(1);
        private final CountDownLatch pathCreated = new CountDownLatch(1);
        private final CountDownLatch dynamicCreated = new CountDownLatch(1);
        private final CountDownLatch verifyCreated = new CountDownLatch(1);
        private final CountDownLatch triageCreated = new CountDownLatch(1);
        private final CountDownLatch triageReleased = new CountDownLatch(1);
        private final CountDownLatch reportCreated = new CountDownLatch(1);
        private final AtomicInteger sandboxReleases = new AtomicInteger();
        private final AtomicInteger roleEnqueues = new AtomicInteger();
        private final AtomicInteger authJobs = new AtomicInteger();
        private final AtomicInteger recomputeCalls = new AtomicInteger();
        private volatile boolean hasAuthEvidence = true;
        private volatile boolean pendingObsWork = false;
        private volatile int obsLoopMax = 3;
        private final Map<String, Cursor> persisted = new ConcurrentHashMap<>();
        private volatile String lastTaskId;
        private final ActionsApi actionsApi = new ActionsApi();
        private final AuditPipelineCoordinator coordinator = new AuditPipelineCoordinator(actionsApi);

        private String lastJobId(AgentRole role) {
            for (int i = actions.size() - 1; i >= 0; i--) {
                String value = actions.get(i);
                if (value.startsWith("role:" + role.name() + ":")) {
                    return value.substring(value.lastIndexOf(':') + 1);
                }
            }
            throw new AssertionError("missing job for " + role);
        }

        private final class ActionsApi implements AuditPipelineCoordinator.Actions {
            @Override
            public String createRoleJob(String projectId, String scanId, AgentRole role,
                                        AiOutputLanguage language, String actorId) {
                String jobId = "job-" + role.name().toLowerCase() + "-" + roleEnqueues.incrementAndGet();
                actions.add("role:" + role.name() + ":" + jobId);
                if (role == AgentRole.AUTH_ANALYSIS) {
                    int count = authJobs.incrementAndGet();
                    if (count == 1) {
                        authCreated.countDown();
                    } else if (count == 2) {
                        authBypassCreated.countDown();
                    }
                }
                if (role == AgentRole.PATH_EXPLORATION) {
                    pathCreated.countDown();
                }
                if (role == AgentRole.DYNAMIC_VERIFICATION) {
                    verifyCreated.countDown();
                }
                if (role == AgentRole.VULNERABILITY_TRIAGE) {
                    triageCreated.countDown();
                }
                if (role == AgentRole.REPORT_GENERATION) {
                    reportCreated.countDown();
                }
                return jobId;
            }

            @Override
            public void submitRoleJob(String jobId, String actorId) {
                actions.add("submit:" + jobId);
            }

            @Override
            public String enqueueDynamic(String scanId, String actorId) {
                lastTaskId = "task-" + scanId + "-" + actions.size();
                actions.add("dynamic:" + lastTaskId);
                dynamicCreated.countDown();
                return lastTaskId;
            }

            @Override
            public boolean hasRunningDynamicTask(String scanId) {
                return false;
            }

            @Override
            public void replaceCursor(Cursor cursor, boolean armed, String stopReason) {
                if (armed) {
                    persisted.put(cursor.arm().scanId(), cursor);
                } else {
                    persisted.remove(cursor.arm().scanId());
                }
                actions.add("persist:" + cursor.stage() + ":" + armed + ":" + cursor.stageAttemptId());
            }

            @Override
            public boolean compareAndAdvance(Cursor expected, Cursor next, boolean armed, String stopReason) {
                Cursor current = persisted.get(expected.arm().scanId());
                if (current == null) {
                    return false;
                }
                if (!current.arm().pipelineRunId().equals(expected.arm().pipelineRunId())) {
                    return false;
                }
                if (!current.stageAttemptId().equals(expected.stageAttemptId())) {
                    return false;
                }
                if (current.stage() != expected.stage()) {
                    return false;
                }
                String currentJob = current.expectedJobId();
                String expectedJob = expected.expectedJobId();
                if (currentJob == null ? expectedJob != null : !currentJob.equals(expectedJob)) {
                    return false;
                }
                String currentTask = current.expectedTaskId();
                String expectedTask = expected.expectedTaskId();
                if (currentTask == null ? expectedTask != null : !currentTask.equals(expectedTask)) {
                    return false;
                }
                if (armed) {
                    persisted.put(next.arm().scanId(), next);
                } else {
                    persisted.remove(expected.arm().scanId());
                }
                actions.add("cas:" + expected.stage() + "->" + next.stage() + ":" + armed);
                return true;
            }

            @Override
            public void releaseRetainedSandbox(AuditPipelineCoordinator.Arm arm) {
                actions.add("release-sandbox:" + arm.scanId());
                sandboxReleases.incrementAndGet();
                triageReleased.countDown();
            }

            @Override
            public boolean hasDynamicAuthEvidence(String scanId) {
                return hasAuthEvidence;
            }

            @Override
            public void recomputeDetectorsAfterObservation(String scanId) {
                recomputeCalls.incrementAndGet();
                actions.add("ir2:" + scanId);
            }

            @Override
            public boolean hasPendingObservationLoopWork(String scanId) {
                return pendingObsWork;
            }

            @Override
            public int observationLoopMax() {
                return obsLoopMax;
            }
        }
    }
}
