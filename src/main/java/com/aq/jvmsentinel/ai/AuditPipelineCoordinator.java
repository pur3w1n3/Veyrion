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
 * 服务端拥有的审计阶段状态机。模型输出不能 arm、跳过或扩展阶段。
 * 推进需来自已授权 audit-run 的 armed pipeline，且对
 * {@code pipelineRunId}、{@code stageAttemptId} 与预期 job/task 身份 CAS 匹配。
 *
 * <p>Path-debug 顺序：PRE → AUTH → DYNAMIC_OBSERVATION → AUTH bypass 确认（仅证据）→
 * DYNAMIC_VERIFICATION → PATH ↔ OBS 循环 → TRIAGE ↔ OBS 循环 → REPORT。
 * OBS 反馈循环有上限（{@code VEYRION_AUDIT_OBS_LOOP_MAX} / {@code veyrion.audit.obsLoopMax}，
 * 默认 3）。</p>
 */
public final class AuditPipelineCoordinator {
    private static final Set<String> BUSY = Set.of("QUEUED", "RUNNING", "COMPLETED");
    private static final Set<String> JOB_SUCCESS = Set.of("COMPLETED");
    private static final Set<String> JOB_FAILURE = Set.of("FAILED", "CANCELLED", "BLOCKED");
    /** PATH/TRIAGE → OBS 反馈循环上限的 env / system property（AUDIT_FLOW mermaid）。 */
    public static final String OBS_LOOP_MAX_ENV = "VEYRION_AUDIT_OBS_LOOP_MAX";
    public static final String OBS_LOOP_MAX_PROP = "veyrion.audit.obsLoopMax";
    private static final int OBS_LOOP_MAX_DEFAULT = 3;
    private static final int OBS_LOOP_MAX_HARD_CAP = 10;

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
        /** 创建 QUEUED AI job；调用方在 submit 前绑定身份。 */
        String createRoleJob(String projectId, String scanId, AgentRole role,
                             AiOutputLanguage language, String actorId);

        void submitRoleJob(String jobId, String actorId);

        /** 入队 pipeline dynamic observation task 并返回 taskId。 */
        String enqueueDynamic(String scanId, String actorId);

        boolean hasRunningDynamicTask(String scanId);

        /**
 * 用新 armed run/attempt 替换 scan cursor。格式良好的写入总是成功；用于 arm 与重试。
 */
        void replaceCursor(Cursor cursor, boolean armed, String stopReason);

        /**
 * CAS：仅当 scan/run/attempt 与预期资源仍匹配时推进。
 * 外来、过期、重复或迟到时返回 false。
 */
        boolean compareAndAdvance(Cursor expected, Cursor next, boolean armed, String stopReason);

        /** 观察当前 job 状态以供重启协调。 */
        default String jobStatus(String jobId) { return null; }

        /** 观察 job stopReason（如 PROCESS_RESTARTED）以精确 disarm 标签。 */
        default String jobStopReason(String jobId) { return null; }

        /** 观察当前 task lifecycle 名称以供重启协调。 */
        default String taskLifecycle(String projectId, String scanId, String taskId) { return null; }

        /**
 * PATH/TRIAGE 动态验证完成或 pipeline 放弃可能持有 sandbox 的阶段后，
 * best-effort 释放 scan 作用域内保留的 deny-all sandbox。
 */
        default void releaseRetainedSandbox(Arm arm) { }

        /**
 * 仅当 PathRun 显示 AUTH_CHALLENGE 或过闸时才 AUTH_BYPASS_CONFIRM（AUDIT_FLOW §4）。
 * 默认 true 以保留未接入 PathRun 的单元测试 fixture。
 */
        default boolean hasDynamicAuthEvidence(String scanId) {
            return true;
        }

        /** IR2：PathTrace/PathRun 观测后全量 detector 重算（AUDIT_FLOW mermaid）。 */
        default void recomputeDetectorsAfterObservation(String scanId) { }

        /**
 * PATH/TRIAGE 是否应重新进入 DYNAMIC_OBSERVATION（coverage gap / STATIC_ONLY /
 * 未验证 hypothesis 工作仍剩）。
 */
        default boolean hasPendingObservationLoopWork(String scanId) {
            return false;
        }

        /** PATH/TRIAGE ↔ OBS 反馈循环上限；默认来自 env/prop 或 3。 */
        default int observationLoopMax() {
            return resolveObservationLoopMax();
        }
    }

    /** 测试可见：先从 env 再从 system property 解析循环上限。 */
    public static int resolveObservationLoopMax() {
        String raw = System.getenv(OBS_LOOP_MAX_ENV);
        if (raw == null || raw.isBlank()) {
            raw = System.getenv("VEYRIION_AUDIT_OBS_LOOP_MAX"); // 常见拼写别名
        }
        if (raw == null || raw.isBlank()) {
            raw = System.getProperty(OBS_LOOP_MAX_PROP, String.valueOf(OBS_LOOP_MAX_DEFAULT));
        }
        try {
            int value = Integer.parseInt(raw.trim());
            if (value < 0) {
                return 0;
            }
            return Math.min(value, OBS_LOOP_MAX_HARD_CAP);
        } catch (NumberFormatException ignored) {
            return OBS_LOOP_MAX_DEFAULT;
        }
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
    /** PATH/TRIAGE 驱动的 OBS 循环后，恢复此 AI 阶段（非 AUTH_BYPASS_CONFIRM）。 */
    private final ConcurrentHashMap<String, PipelineStage> afterDynamicResume = new ConcurrentHashMap<>();
    /** 每 scan 已消耗的 PATH/TRIAGE → OBS 反馈循环次数。 */
    private final ConcurrentHashMap<String, Integer> observationLoopCounts = new ConcurrentHashMap<>();
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
 * Arm 新 pipeline run，已等待调用方创建的 AI job。
 * 使该 scan 上任何先前 run 失效。
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
        resetLoopState(scanId);
        cursors.put(scanId, cursor);
        actions.replaceCursor(cursor, true, null);
        return arm;
    }

    /**
 * Arm 新 pipeline run，已等待调用方创建的 dynamic task。
 * 使该 scan 上任何先前 run 失效。
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
        resetLoopState(scanId);
        cursors.put(scanId, cursor);
        actions.replaceCursor(cursor, true, null);
        return arm;
    }

    private void resetLoopState(String scanId) {
        afterDynamicResume.remove(scanId);
        observationLoopCounts.remove(scanId);
    }

    /**
 * 精确恢复已持久化 cursor。不从 scan 级 job/task 推断阶段。
 * 协调已终态的预期资源；否则等待且不重新入队。
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

    /** 操作员暂停 armed pipeline 时的持久化 stopReason。 */
    public static final String STOP_OPERATOR_PAUSED = "OPERATOR_PAUSED";
    /** 操作员取消/停止 armed pipeline 时的持久化 stopReason。 */
    public static final String STOP_OPERATOR_CANCELLED = "OPERATOR_CANCELLED";

    /**
 * 操作员暂停：丢弃 live cursor 使阶段完成无法推进，并持久化
 * {@link #STOP_OPERATOR_PAUSED} 与当前阶段身份（清空预期 job/task）。
 * 调用方须在返回后取消在途预期资源。
 *
 * @return 暂停快照；scan 未 armed 时为 null
 */
    public synchronized Cursor operatorPause(String scanId) {
        if (scanId == null || scanId.isBlank()) {
            return null;
        }
        Cursor live = cursors.get(scanId);
        if (live == null) {
            return null;
        }
        if (!cursors.remove(scanId, live)) {
            return null;
        }
        Cursor paused = new Cursor(live.arm(), live.stage(), live.stageAttemptId(), null, null);
        actions.releaseRetainedSandbox(live.arm());
        actions.replaceCursor(paused, false, STOP_OPERATOR_PAUSED);
        return paused;
    }

    /**
 * 操作员取消/停止：丢弃 live cursor 并持久化 {@link #STOP_OPERATOR_CANCELLED}。
 *
 * @return armed cursor 被取消时为 true
 */
    public synchronized boolean operatorCancel(String scanId) {
        if (scanId == null || scanId.isBlank()) {
            return false;
        }
        Cursor live = cursors.get(scanId);
        if (live == null) {
            return false;
        }
        if (!cursors.remove(scanId, live)) {
            return false;
        }
        actions.releaseRetainedSandbox(live.arm());
        Cursor terminal = new Cursor(live.arm(), live.stage(), live.stageAttemptId(), null, null);
        actions.replaceCursor(terminal, false, STOP_OPERATOR_CANCELLED);
        resetLoopState(scanId);
        return true;
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
            if (isStaticContinueDynamicTerminal(snapshot)) {
                // AUDIT_FLOW：DYNAMIC_DISABLED 保留静态叙事——勿中止 pipeline。
                async.execute(() -> advanceStaticOnlyAfterDynamic(cursor));
                return;
            }
            afterDynamicResume.remove(scanId);
            disarm(cursor, PipelineStage.DYNAMIC_OBSERVATION.name() + "_" + snapshot.lifecycle().name());
            return;
        }
        async.execute(() -> advanceAfterDynamic(cursor));
    }

    /** Worker 缺失 / dynamic 禁用：仅基于静态 fact 继续 AI 阶段。 */
    static boolean isStaticContinueDynamicTerminal(TaskSnapshot snapshot) {
        if (snapshot == null) {
            return false;
        }
        if (snapshot.lifecycle() != TaskLifecycle.FAILED
                && snapshot.lifecycle() != TaskLifecycle.CANCELLED) {
            return false;
        }
        String code = snapshot.failureCode() == null ? "" : snapshot.failureCode().trim().toUpperCase();
        String stop = snapshot.stopReason() == null ? "" : snapshot.stopReason().name();
        return code.contains("WORKER_UNAVAILABLE")
                || code.contains("DYNAMIC_DISABLED")
                || "WORKER_UNAVAILABLE".equals(code)
                || stop.contains("WALL_CLOCK");
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
            // 仍 QUEUED/RUNNING——等待；勿重新入队。
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
                if ("FAILED".equals(lifecycle) || "CANCELLED".equals(lifecycle)) {
                    advanceStaticOnlyAfterDynamic(cursor);
                } else {
                    disarm(cursor, cursor.stage().name() + "_" + lifecycle);
                }
                return;
            }
            return;
        }
        // armed 阶段无预期资源：本 attempt 入队一次以恢复。
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
            case PATH_EXPLORATION -> afterPathOrTriageMaybeLoop(live, PipelineStage.PATH_EXPLORATION);
            case VULNERABILITY_TRIAGE -> afterPathOrTriageMaybeLoop(live, PipelineStage.VULNERABILITY_TRIAGE);
            case REPORT_GENERATION -> disarm(live, PipelineStage.COMPLETE.name());
            default -> { }
        }
    }

    /**
 * AUDIT_FLOW mermaid：PATH/TRIAGE 最多可回到 OBS（sandbox_probe / 新 PathRun）
 * {@link Actions#observationLoopMax()} 次，然后 IR2 重算，再进入下一阶段。
 */
    private void afterPathOrTriageMaybeLoop(Cursor live, PipelineStage completedStage) {
        String scanId = live.arm().scanId();
        try {
            actions.recomputeDetectorsAfterObservation(scanId);
        } catch (RuntimeException ignored) {
            // IR2 为 best-effort；阶段推进不得卡住。
        }
        int max = Math.max(0, actions.observationLoopMax());
        int used = observationLoopCounts.getOrDefault(scanId, 0);
        if (used < max && actions.hasPendingObservationLoopWork(scanId)) {
            observationLoopCounts.put(scanId, used + 1);
            afterDynamicResume.put(scanId, completedStage);
            beginDynamicStage(live);
            return;
        }
        if (completedStage == PipelineStage.PATH_EXPLORATION) {
            beginRoleStage(live, PipelineStage.VULNERABILITY_TRIAGE, AgentRole.VULNERABILITY_TRIAGE);
            return;
        }
        actions.releaseRetainedSandbox(live.arm());
        beginRoleStage(live, PipelineStage.REPORT_GENERATION, AgentRole.REPORT_GENERATION);
    }

    private void advanceAfterDynamic(Cursor cursor) {
        Cursor live = cursors.get(cursor.arm().scanId());
        if (live == null || !sameAttempt(live, cursor)) {
            return;
        }
        if (live.stage() != PipelineStage.DYNAMIC_OBSERVATION) {
            return;
        }
        String scanId = live.arm().scanId();
        try {
            actions.recomputeDetectorsAfterObservation(scanId);
        } catch (RuntimeException ignored) {
            // IR2 best-effort。
        }
        PipelineStage resume = afterDynamicResume.remove(scanId);
        if (resume == PipelineStage.PATH_EXPLORATION) {
            beginRoleStage(live, PipelineStage.PATH_EXPLORATION, AgentRole.PATH_EXPLORATION);
            return;
        }
        if (resume == PipelineStage.VULNERABILITY_TRIAGE) {
            beginRoleStage(live, PipelineStage.VULNERABILITY_TRIAGE, AgentRole.VULNERABILITY_TRIAGE);
            return;
        }
        // AUTH 后首次观测：仅当存在动态 auth 证据时才确认。
        if (actions.hasDynamicAuthEvidence(scanId)) {
            beginRoleStage(live, PipelineStage.AUTH_BYPASS_CONFIRM, AgentRole.AUTH_ANALYSIS);
            return;
        }
        beginRoleStage(live, PipelineStage.DYNAMIC_VERIFICATION, AgentRole.DYNAMIC_VERIFICATION);
    }

    /** dynamic 不可用：跳过 AUTH 确认（无证据）并继续可静态 AI 阶段。 */
    private void advanceStaticOnlyAfterDynamic(Cursor cursor) {
        Cursor live = cursors.get(cursor.arm().scanId());
        if (live == null || !sameAttempt(live, cursor)) {
            return;
        }
        if (live.stage() != PipelineStage.DYNAMIC_OBSERVATION) {
            return;
        }
        String scanId = live.arm().scanId();
        PipelineStage resume = afterDynamicResume.remove(scanId);
        if (resume == PipelineStage.PATH_EXPLORATION) {
            beginRoleStage(live, PipelineStage.PATH_EXPLORATION, AgentRole.PATH_EXPLORATION);
            return;
        }
        if (resume == PipelineStage.VULNERABILITY_TRIAGE) {
            beginRoleStage(live, PipelineStage.VULNERABILITY_TRIAGE, AgentRole.VULNERABILITY_TRIAGE);
            return;
        }
        beginRoleStage(live, PipelineStage.DYNAMIC_VERIFICATION, AgentRole.DYNAMIC_VERIFICATION);
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
                // 非 pipeline dynamic task 仍在运行；保持阶段 attempt 并等待
                // 直至 pipeline 拥有的入队可继续。勿绑定外来 task id。
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
            // 终态回调可能在 expectedTaskId 绑定前到达。
            // 绑定后协调精确 task，避免丢失。
            String lifecycle = actions.taskLifecycle(arm.projectId(), arm.scanId(), taskId);
            if (lifecycle != null && isTerminalTaskLifecycle(lifecycle)) {
                if (TaskLifecycle.COMPLETED.name().equals(lifecycle)) {
                    advanceAfterDynamic(waiting);
                } else if ("FAILED".equals(lifecycle) || "CANCELLED".equals(lifecycle)) {
                    // 已入队 task 已终态且非 COMPLETED——尽可能静态继续。
                    advanceStaticOnlyAfterDynamic(waiting);
                } else {
                    disarm(waiting, PipelineStage.DYNAMIC_OBSERVATION.name() + "_" + lifecycle);
                }
            }
        } catch (RuntimeException failure) {
            // 入队时 sandbox/worker 不可用：保留静态 AI 叙事（AUDIT_FLOW）。
            advanceStaticOnlyAfterDynamic(binding);
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
                        } else if ("FAILED".equals(lifecycle) || "CANCELLED".equals(lifecycle)) {
                            advanceStaticOnlyAfterDynamic(waiting);
                        } else {
                            disarm(waiting, PipelineStage.DYNAMIC_OBSERVATION.name() + "_" + lifecycle);
                        }
                    }
                } catch (RuntimeException failure) {
                    advanceStaticOnlyAfterDynamic(binding);
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
        actions.releaseRetainedSandbox(live.arm());
        Cursor terminal = new Cursor(live.arm(), live.stage(), live.stageAttemptId(),
                live.expectedJobId(), live.expectedTaskId());
        if (!actions.compareAndAdvance(live, terminal, false, stopReason)) {
            return;
        }
        resetLoopState(cursor.arm().scanId());
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
