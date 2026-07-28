package com.aq.jvmsentinel.ai;

import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.AiJobData;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.aq.jvmsentinel.worker.TaskLifecycle;
import com.aq.jvmsentinel.worker.TaskSnapshot;

import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.function.Predicate;

/**
 * Server-owned audit stage machine. Model output cannot arm, skip, or expand stages.
 * Advancement requires an armed pipeline from an authorized audit-run and a CAS match on
 * {@code pipelineRunId}, {@code stageAttemptId}, and the expected job/task identity.
 *
 * <p>Path-debug order: PRE → AUTH → DYNAMIC_OBSERVATION → AUTH bypass confirm →
 * DYNAMIC_VERIFICATION → PATH → TRIAGE → REPORT.</p>
 */
public final class AuditPipelineCoordinator {
    private static final Set<String> BUSY = Set.of("QUEUED", "RUNNING", "COMPLETED");
    private static final Set<String> JOB_SUCCESS = Set.of("COMPLETED");
    private static final Set<String> JOB_FAILURE = Set.of("FAILED", "CANCELLED", "BLOCKED");

    public record Arm(
            String scanId,
            String projectId,
            String actorId,
            AiOutputLanguage outputLanguage,
            String pipelineRunId
    ) {
        public Arm {
            Objects.requireNonNull(scanId, "scanId");
            Objects.requireNonNull(projectId, "projectId");
            Objects.requireNonNull(actorId, "actorId");
            Objects.requireNonNull(outputLanguage, "outputLanguage");
            Objects.requireNonNull(pipelineRunId, "pipelineRunId");
            if (pipelineRunId.isBlank()) {
                throw new IllegalArgumentException("pipelineRunId");
            }
        }
    }

    public record Cursor(
            Arm arm,
            PipelineStage stage,
            String stageAttemptId,
            String expectedJobId,
            String expectedTaskId
    ) {
        public Cursor {
            Objects.requireNonNull(arm, "arm");
            Objects.requireNonNull(stage, "stage");
            Objects.requireNonNull(stageAttemptId, "stageAttemptId");
            if (stageAttemptId.isBlank()) {
                throw new IllegalArgumentException("stageAttemptId");
            }
            if (expectedJobId != null && expectedJobId.isBlank()) {
                expectedJobId = null;
            }
            if (expectedTaskId != null && expectedTaskId.isBlank()) {
                expectedTaskId = null;
            }
            if (expectedJobId != null && expectedTaskId != null) {
                throw new IllegalArgumentException("cursor cannot wait on both job and task");
            }
        }
    }

    public interface Actions {
        /** Create a QUEUED AI job; caller binds identity before submit. */
        String createRoleJob(String projectId, String scanId, AgentRole role,
                             AiOutputLanguage language, String actorId);

        void submitRoleJob(String jobId, String actorId);

        /** Enqueue the pipeline dynamic observation task and return its taskId. */
        String enqueueDynamic(String scanId, String actorId);

        boolean hasRunningDynamicTask(String scanId);

        /**
         * Replace the scan cursor with a new armed run/attempt. Always succeeds for a
         * well-formed write; used on arm and retry.
         */
        void replaceCursor(Cursor cursor, boolean armed, String stopReason);

        /**
         * CAS: advance only when scan/run/attempt and expected resource still match.
         * Returns false when foreign, stale, duplicate, or late.
         */
        boolean compareAndAdvance(Cursor expected, Cursor next, boolean armed, String stopReason);

        /** Observe current job status for restart reconciliation. */
        default String jobStatus(String jobId) { return null; }

        /** Observe job stopReason (e.g. PROCESS_RESTARTED) for precise disarm labels. */
        default String jobStopReason(String jobId) { return null; }

        /** Observe current task lifecycle name for restart reconciliation. */
        default String taskLifecycle(String projectId, String scanId, String taskId) { return null; }
    }

    public enum PipelineStage {
        PRE_ANALYSIS,
        AUTH_ANALYSIS,
        DYNAMIC_OBSERVATION,
        AUTH_BYPASS_CONFIRM,
        DYNAMIC_VERIFICATION,
        PATH_EXPLORATION,
        VULNERABILITY_TRIAGE,
        REPORT_GENERATION,
        COMPLETE
    }

    private final ConcurrentHashMap<String, Cursor> cursors = new ConcurrentHashMap<>();
    private final Actions actions;
    private final Executor async = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "audit-pipeline");
        thread.setDaemon(true);
        return thread;
    });

    public AuditPipelineCoordinator(Actions actions) {
        this.actions = Objects.requireNonNull(actions, "actions");
    }

    public static String newPipelineRunId() {
        return "prun-" + compactUuid();
    }

    public static String newStageAttemptId() {
        return "sattempt-" + compactUuid();
    }

    /**
     * Arms a new pipeline run that is already waiting on a caller-created AI job.
     * Invalidates any prior run for the scan.
     */
    public synchronized Arm armForJob(String scanId, String projectId, String actorId,
                         AiOutputLanguage language, PipelineStage stage, String jobId) {
        Objects.requireNonNull(stage, "stage");
        Objects.requireNonNull(jobId, "jobId");
        if (jobId.isBlank()) {
            throw new IllegalArgumentException("jobId");
        }
        if (!isAiStage(stage)) {
            throw new IllegalArgumentException("stage does not wait on an AI job: " + stage);
        }
        Arm arm = new Arm(scanId, projectId, actorId, language, newPipelineRunId());
        Cursor cursor = new Cursor(arm, stage, newStageAttemptId(), jobId, null);
        cursors.put(scanId, cursor);
        actions.replaceCursor(cursor, true, null);
        return arm;
    }

    /**
     * Arms a new pipeline run that is already waiting on a caller-created dynamic task.
     * Invalidates any prior run for the scan.
     */
    public synchronized Arm armForTask(String scanId, String projectId, String actorId,
                          AiOutputLanguage language, PipelineStage stage, String taskId) {
        Objects.requireNonNull(stage, "stage");
        Objects.requireNonNull(taskId, "taskId");
        if (taskId.isBlank()) {
            throw new IllegalArgumentException("taskId");
        }
        if (stage != PipelineStage.DYNAMIC_OBSERVATION) {
            throw new IllegalArgumentException("stage does not wait on a dynamic task: " + stage);
        }
        Arm arm = new Arm(scanId, projectId, actorId, language, newPipelineRunId());
        Cursor cursor = new Cursor(arm, stage, newStageAttemptId(), null, taskId);
        cursors.put(scanId, cursor);
        actions.replaceCursor(cursor, true, null);
        return arm;
    }

    /**
     * Restores a persisted cursor exactly. Does not infer stage from scan-wide jobs/tasks.
     * Reconciles already-terminal expected resources; otherwise waits without re-enqueue.
     */
    public synchronized void resume(Cursor cursor) {
        Objects.requireNonNull(cursor, "cursor");
        if (cursor.stage() == PipelineStage.COMPLETE) {
            cursors.remove(cursor.arm().scanId());
            actions.replaceCursor(cursor, false, "COMPLETE");
            return;
        }
        cursors.put(cursor.arm().scanId(), cursor);
        async.execute(() -> reconcileResumed(cursor));
    }

    public boolean isArmed(String scanId) {
        return scanId != null && cursors.containsKey(scanId);
    }

    public Cursor cursor(String scanId) {
        return scanId == null ? null : cursors.get(scanId);
    }

    public void onAiJobFinished(AiJobData job) {
        if (job == null || job.scanId() == null || job.aiJobId() == null) {
            return;
        }
        Cursor cursor = cursors.get(job.scanId());
        if (cursor == null) {
            return;
        }
        if (!cursor.arm().projectId().equals(job.projectId())) {
            return;
        }
        if (cursor.expectedJobId() == null || !cursor.expectedJobId().equals(job.aiJobId())) {
            return;
        }
        if (!roleMatchesStage(job.role(), cursor.stage())) {
            return;
        }
        if (JOB_FAILURE.contains(job.status())) {
            String stop = job.stopReason() == null || job.stopReason().isBlank()
                    ? job.status() : job.stopReason();
            disarm(cursor, cursor.stage().name() + "_" + stop);
            return;
        }
        if (!JOB_SUCCESS.contains(job.status())) {
            return;
        }
        async.execute(() -> advanceAfterJob(cursor, job));
    }

    public void onDynamicTaskFinished(TaskSnapshot snapshot) {
        if (snapshot == null || snapshot.scope() == null) {
            return;
        }
        String scanId = snapshot.scope().scanId();
        Cursor cursor = cursors.get(scanId);
        if (cursor == null) {
            return;
        }
        if (!cursor.arm().projectId().equals(snapshot.scope().projectId())) {
            return;
        }
        if (cursor.expectedTaskId() == null
                || !cursor.expectedTaskId().equals(snapshot.scope().taskId())) {
            return;
        }
        if (cursor.stage() != PipelineStage.DYNAMIC_OBSERVATION) {
            return;
        }
        if (snapshot.lifecycle() != TaskLifecycle.COMPLETED) {
            disarm(cursor, PipelineStage.DYNAMIC_OBSERVATION.name() + "_" + snapshot.lifecycle().name());
            return;
        }
        async.execute(() -> advanceAfterDynamic(cursor));
    }

    private void reconcileResumed(Cursor cursor) {
        Cursor live = cursors.get(cursor.arm().scanId());
        if (live == null || !sameAttempt(live, cursor)) {
            return;
        }
        if (cursor.expectedJobId() != null) {
            String status = actions.jobStatus(cursor.expectedJobId());
            if (status == null) {
                disarm(cursor, cursor.stage().name() + "_EXPECTED_JOB_MISSING");
                return;
            }
            if (JOB_SUCCESS.contains(status)) {
                AiJobData synthetic = syntheticJob(cursor, status);
                advanceAfterJob(cursor, synthetic);
                return;
            }
            if (JOB_FAILURE.contains(status)) {
                String stop = actions.jobStopReason(cursor.expectedJobId());
                disarm(cursor, cursor.stage().name() + "_"
                        + (stop == null || stop.isBlank() ? status : stop));
                return;
            }
            // Still QUEUED/RUNNING — wait; do not re-enqueue.
            return;
        }
        if (cursor.expectedTaskId() != null) {
            String lifecycle = actions.taskLifecycle(
                    cursor.arm().projectId(), cursor.arm().scanId(), cursor.expectedTaskId());
            if (lifecycle == null) {
                disarm(cursor, cursor.stage().name() + "_EXPECTED_TASK_MISSING");
                return;
            }
            if (TaskLifecycle.COMPLETED.name().equals(lifecycle)) {
                advanceAfterDynamic(cursor);
                return;
            }
            if (isTerminalTaskLifecycle(lifecycle) && !TaskLifecycle.COMPLETED.name().equals(lifecycle)) {
                disarm(cursor, cursor.stage().name() + "_" + lifecycle);
                return;
            }
            return;
        }
        // Armed stage without expected resource: recover by enqueueing once for this attempt.
        enqueueForStage(cursor);
    }

    private void advanceAfterJob(Cursor cursor, AiJobData job) {
        Cursor live = cursors.get(cursor.arm().scanId());
        if (live == null || !sameAttempt(live, cursor)) {
            return;
        }
        if (live.expectedJobId() == null || !live.expectedJobId().equals(job.aiJobId())) {
            return;
        }
        switch (live.stage()) {
            case PRE_ANALYSIS -> beginRoleStage(live, PipelineStage.AUTH_ANALYSIS, AgentRole.AUTH_ANALYSIS);
            case AUTH_ANALYSIS -> beginDynamicStage(live);
            case AUTH_BYPASS_CONFIRM -> beginRoleStage(live,
                    PipelineStage.DYNAMIC_VERIFICATION, AgentRole.DYNAMIC_VERIFICATION);
            case DYNAMIC_VERIFICATION -> waitForDynamicIdleThenPath(live);
            case PATH_EXPLORATION -> beginRoleStage(live,
                    PipelineStage.VULNERABILITY_TRIAGE, AgentRole.VULNERABILITY_TRIAGE);
            case VULNERABILITY_TRIAGE -> beginRoleStage(live,
                    PipelineStage.REPORT_GENERATION, AgentRole.REPORT_GENERATION);
            case REPORT_GENERATION -> disarm(live, PipelineStage.COMPLETE.name());
            default -> { }
        }
    }

    private void advanceAfterDynamic(Cursor cursor) {
        Cursor live = cursors.get(cursor.arm().scanId());
        if (live == null || !sameAttempt(live, cursor)) {
            return;
        }
        if (live.stage() != PipelineStage.DYNAMIC_OBSERVATION) {
            return;
        }
        beginRoleStage(live, PipelineStage.AUTH_BYPASS_CONFIRM, AgentRole.AUTH_ANALYSIS);
    }

    private synchronized void beginRoleStage(Cursor from, PipelineStage stage, AgentRole role) {
        Arm arm = from.arm();
        String attemptId = newStageAttemptId();
        Cursor binding = new Cursor(arm, stage, attemptId, null, null);
        if (!actions.compareAndAdvance(from, binding, true, null)) {
            return;
        }
        if (!cursors.replace(arm.scanId(), from, binding)) {
            return;
        }
        try {
            String jobId = actions.createRoleJob(arm.projectId(), arm.scanId(), role,
                    arm.outputLanguage(), arm.actorId());
            Cursor waiting = new Cursor(arm, stage, attemptId, jobId, null);
            if (!actions.compareAndAdvance(binding, waiting, true, null)) {
                return;
            }
            if (!cursors.replace(arm.scanId(), binding, waiting)) {
                return;
            }
            String status = actions.jobStatus(jobId);
            if (status != null && JOB_FAILURE.contains(status)) {
                String stop = actions.jobStopReason(jobId);
                disarm(waiting, stage.name() + "_"
                        + (stop == null || stop.isBlank() ? status : stop));
                return;
            }
            actions.submitRoleJob(jobId, arm.actorId());
        } catch (RuntimeException failure) {
            disarm(binding, stage.name() + "_ENQUEUE_FAILED");
        }
    }

    private synchronized void beginDynamicStage(Cursor from) {
        Arm arm = from.arm();
        String attemptId = newStageAttemptId();
        Cursor binding = new Cursor(arm, PipelineStage.DYNAMIC_OBSERVATION, attemptId, null, null);
        if (!actions.compareAndAdvance(from, binding, true, null)) {
            return;
        }
        if (!cursors.replace(arm.scanId(), from, binding)) {
            return;
        }
        try {
            if (actions.hasRunningDynamicTask(arm.scanId())) {
                // A non-pipeline dynamic task is still running; keep the stage attempt and wait
                // until the pipeline-owned enqueue can proceed. Do not bind foreign task ids.
                async.execute(() -> waitToEnqueueDynamic(binding));
                return;
            }
            String taskId = actions.enqueueDynamic(arm.scanId(), arm.actorId());
            Cursor waiting = new Cursor(arm, PipelineStage.DYNAMIC_OBSERVATION, attemptId, null, taskId);
            if (!actions.compareAndAdvance(binding, waiting, true, null)) {
                return;
            }
            if (!cursors.replace(arm.scanId(), binding, waiting)) {
                return;
            }
            // A terminal callback can arrive before expectedTaskId is bound.
            // Reconcile the exact task after binding so it cannot be lost.
            String lifecycle = actions.taskLifecycle(arm.projectId(), arm.scanId(), taskId);
            if (lifecycle != null && isTerminalTaskLifecycle(lifecycle)) {
                if (TaskLifecycle.COMPLETED.name().equals(lifecycle)) {
                    advanceAfterDynamic(waiting);
                } else {
                    disarm(waiting, PipelineStage.DYNAMIC_OBSERVATION.name() + "_" + lifecycle);
                }
            }
        } catch (RuntimeException failure) {
            disarm(binding, PipelineStage.DYNAMIC_OBSERVATION.name() + "_ENQUEUE_FAILED");
        }
    }

    private void waitToEnqueueDynamic(Cursor binding) {
        long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.MINUTES.toNanos(10);
        while (System.nanoTime() < deadline) {
            Cursor live = cursors.get(binding.arm().scanId());
            if (live == null || !sameAttempt(live, binding)) {
                return;
            }
            if (!actions.hasRunningDynamicTask(binding.arm().scanId())) {
                try {
                    String taskId = actions.enqueueDynamic(binding.arm().scanId(), binding.arm().actorId());
                    Cursor waiting = new Cursor(binding.arm(), PipelineStage.DYNAMIC_OBSERVATION,
                            binding.stageAttemptId(), null, taskId);
                    if (!actions.compareAndAdvance(binding, waiting, true, null)) {
                        return;
                    }
                    if (!cursors.replace(binding.arm().scanId(), binding, waiting)) {
                        return;
                    }
                    String lifecycle = actions.taskLifecycle(binding.arm().projectId(),
                            binding.arm().scanId(), taskId);
                    if (lifecycle != null && isTerminalTaskLifecycle(lifecycle)) {
                        if (TaskLifecycle.COMPLETED.name().equals(lifecycle)) {
                            advanceAfterDynamic(waiting);
                        } else {
                            disarm(waiting, PipelineStage.DYNAMIC_OBSERVATION.name() + "_" + lifecycle);
                        }
                    }
                } catch (RuntimeException failure) {
                    disarm(binding, PipelineStage.DYNAMIC_OBSERVATION.name() + "_ENQUEUE_FAILED");
                }
                return;
            }
            try {
                Thread.sleep(250L);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                disarm(binding, PipelineStage.DYNAMIC_OBSERVATION.name() + "_INTERRUPTED");
                return;
            }
        }
        disarm(binding, PipelineStage.DYNAMIC_OBSERVATION.name() + "_TIMEOUT");
    }

    private void waitForDynamicIdleThenPath(Cursor from) {
        if (!actions.hasRunningDynamicTask(from.arm().scanId())) {
            beginRoleStage(from, PipelineStage.PATH_EXPLORATION, AgentRole.PATH_EXPLORATION);
            return;
        }
        async.execute(() -> {
            long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.MINUTES.toNanos(10);
            while (System.nanoTime() < deadline) {
                Cursor live = cursors.get(from.arm().scanId());
                if (live == null || !sameAttempt(live, from)) {
                    return;
                }
                if (!actions.hasRunningDynamicTask(from.arm().scanId())) {
                    beginRoleStage(live, PipelineStage.PATH_EXPLORATION, AgentRole.PATH_EXPLORATION);
                    return;
                }
                try {
                    Thread.sleep(250L);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    disarm(live, PipelineStage.PATH_EXPLORATION.name() + "_INTERRUPTED");
                    return;
                }
            }
            Cursor live = cursors.get(from.arm().scanId());
            if (live != null && sameAttempt(live, from)) {
                disarm(live, PipelineStage.PATH_EXPLORATION.name() + "_TIMEOUT");
            }
        });
    }

    private void enqueueForStage(Cursor cursor) {
        switch (cursor.stage()) {
            case PRE_ANALYSIS -> beginRoleStage(cursor, PipelineStage.PRE_ANALYSIS, AgentRole.PRE_ANALYSIS);
            case AUTH_ANALYSIS -> beginRoleStage(cursor, PipelineStage.AUTH_ANALYSIS, AgentRole.AUTH_ANALYSIS);
            case DYNAMIC_OBSERVATION -> beginDynamicStage(cursor);
            case AUTH_BYPASS_CONFIRM -> beginRoleStage(cursor,
                    PipelineStage.AUTH_BYPASS_CONFIRM, AgentRole.AUTH_ANALYSIS);
            case DYNAMIC_VERIFICATION -> beginRoleStage(cursor,
                    PipelineStage.DYNAMIC_VERIFICATION, AgentRole.DYNAMIC_VERIFICATION);
            case PATH_EXPLORATION -> beginRoleStage(cursor,
                    PipelineStage.PATH_EXPLORATION, AgentRole.PATH_EXPLORATION);
            case VULNERABILITY_TRIAGE -> beginRoleStage(cursor,
                    PipelineStage.VULNERABILITY_TRIAGE, AgentRole.VULNERABILITY_TRIAGE);
            case REPORT_GENERATION -> beginRoleStage(cursor,
                    PipelineStage.REPORT_GENERATION, AgentRole.REPORT_GENERATION);
            case COMPLETE -> disarm(cursor, PipelineStage.COMPLETE.name());
        }
    }

    private synchronized void disarm(Cursor cursor, String stopReason) {
        Cursor live = cursors.get(cursor.arm().scanId());
        if (live == null || !sameAttempt(live, cursor)) {
            return;
        }
        Cursor terminal = new Cursor(live.arm(), live.stage(), live.stageAttemptId(),
                live.expectedJobId(), live.expectedTaskId());
        if (!actions.compareAndAdvance(live, terminal, false, stopReason)) {
            return;
        }
        cursors.remove(cursor.arm().scanId(), live);
    }

    private static boolean sameAttempt(Cursor left, Cursor right) {
        return left.arm().pipelineRunId().equals(right.arm().pipelineRunId())
                && left.stageAttemptId().equals(right.stageAttemptId())
                && left.stage() == right.stage();
    }

    private static boolean isAiStage(PipelineStage stage) {
        return stage == PipelineStage.PRE_ANALYSIS
                || stage == PipelineStage.AUTH_ANALYSIS
                || stage == PipelineStage.AUTH_BYPASS_CONFIRM
                || stage == PipelineStage.DYNAMIC_VERIFICATION
                || stage == PipelineStage.PATH_EXPLORATION
                || stage == PipelineStage.VULNERABILITY_TRIAGE
                || stage == PipelineStage.REPORT_GENERATION;
    }

    private static boolean roleMatchesStage(AgentRole role, PipelineStage stage) {
        return switch (stage) {
            case PRE_ANALYSIS -> role == AgentRole.PRE_ANALYSIS;
            case AUTH_ANALYSIS, AUTH_BYPASS_CONFIRM -> role == AgentRole.AUTH_ANALYSIS;
            case DYNAMIC_VERIFICATION -> role == AgentRole.DYNAMIC_VERIFICATION;
            case PATH_EXPLORATION -> role == AgentRole.PATH_EXPLORATION;
            case VULNERABILITY_TRIAGE -> role == AgentRole.VULNERABILITY_TRIAGE;
            case REPORT_GENERATION -> role == AgentRole.REPORT_GENERATION;
            default -> false;
        };
    }

    private static boolean isTerminalTaskLifecycle(String lifecycle) {
        return TaskLifecycle.COMPLETED.name().equals(lifecycle)
                || TaskLifecycle.FAILED.name().equals(lifecycle)
                || TaskLifecycle.CANCELLED.name().equals(lifecycle);
    }

    private static AiJobData syntheticJob(Cursor cursor, String status) {
        AgentRole role = switch (cursor.stage()) {
            case PRE_ANALYSIS -> AgentRole.PRE_ANALYSIS;
            case AUTH_ANALYSIS, AUTH_BYPASS_CONFIRM -> AgentRole.AUTH_ANALYSIS;
            case DYNAMIC_VERIFICATION -> AgentRole.DYNAMIC_VERIFICATION;
            case PATH_EXPLORATION -> AgentRole.PATH_EXPLORATION;
            case VULNERABILITY_TRIAGE -> AgentRole.VULNERABILITY_TRIAGE;
            case REPORT_GENERATION -> AgentRole.REPORT_GENERATION;
            default -> AgentRole.PRE_ANALYSIS;
        };
        return new AiJobData(
                cursor.expectedJobId(), "local", cursor.arm().projectId(), cursor.arm().scanId(),
                "0".repeat(64), role, "recovered", "recovered", "{\"schemaVersion\":1}", true,
                status, status, "[]", null, 0, 0, "[]", null,
                java.time.Instant.EPOCH.toString(), java.time.Instant.EPOCH.toString());
    }

    private static String compactUuid() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    public static Predicate<AiJobData> busyOrDoneFor(String scanId, AgentRole role) {
        return job -> scanId.equals(job.scanId())
                && job.role() == role
                && BUSY.contains(job.status());
    }
}
