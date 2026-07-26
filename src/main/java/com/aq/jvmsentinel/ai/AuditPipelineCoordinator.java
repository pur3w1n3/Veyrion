package com.aq.jvmsentinel.ai;

import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.AiJobData;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.AiOutputLanguage;
import com.aq.jvmsentinel.worker.TaskLifecycle;
import com.aq.jvmsentinel.worker.TaskSnapshot;

import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.function.Predicate;

/**
 * Server-owned audit stage machine. Model output cannot arm, skip, or expand stages.
 * Advancement requires an armed pipeline from an authorized audit-run.
 */
public final class AuditPipelineCoordinator {
    private static final Set<String> BUSY = Set.of("QUEUED", "RUNNING", "COMPLETED");

    public record Arm(
            String scanId,
            String projectId,
            String actorId,
            AiOutputLanguage outputLanguage
    ) {
        public Arm {
            Objects.requireNonNull(scanId, "scanId");
            Objects.requireNonNull(projectId, "projectId");
            Objects.requireNonNull(actorId, "actorId");
            Objects.requireNonNull(outputLanguage, "outputLanguage");
        }
    }

    public interface Actions {
        boolean hasRoleJob(String projectId, String scanId, AgentRole role);

        boolean hasBusyDynamicTask(String scanId);

        /** True only while a dynamic task still needs to finish (QUEUED..PAUSED). */
        default boolean hasRunningDynamicTask(String scanId) { return false; }

        /** True when at least one dynamic task for the scan has completed successfully. */
        default boolean hasCompletedDynamicTask(String scanId) { return false; }

        void enqueueRole(String projectId, String scanId, AgentRole role,
                         AiOutputLanguage language, String actorId);

        void enqueueDynamic(String scanId, String actorId);

        default void persistState(Arm arm, String nextStage, boolean armed) { }
    }

    public enum PipelineStage {
        PRE_ANALYSIS,
        DYNAMIC_OBSERVATION,
        DYNAMIC_VERIFICATION,
        PATH_EXPLORATION,
        VULNERABILITY_TRIAGE,
        REPORT_GENERATION,
        COMPLETE
    }

    private final ConcurrentHashMap<String, Arm> armed = new ConcurrentHashMap<>();
    private final Actions actions;
    private final Executor async = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "audit-pipeline");
        thread.setDaemon(true);
        return thread;
    });

    public AuditPipelineCoordinator(Actions actions) {
        this.actions = Objects.requireNonNull(actions, "actions");
    }

    public void arm(Arm arm) {
        armed.put(arm.scanId(), arm);
        actions.persistState(arm, PipelineStage.PRE_ANALYSIS.name(), true);
    }

    /** Restores a server-persisted arm and advances only the next derived stage. */
    public void resumeAt(Arm arm, PipelineStage stage) {
        Objects.requireNonNull(stage, "stage");
        armed.put(arm.scanId(), arm);
        actions.persistState(arm, stage.name(), stage != PipelineStage.COMPLETE);
        async.execute(() -> {
            switch (stage) {
                case PRE_ANALYSIS -> safeEnqueueRole(arm, AgentRole.PRE_ANALYSIS);
                case DYNAMIC_OBSERVATION -> safeEnqueueDynamic(arm);
                case DYNAMIC_VERIFICATION -> safeEnqueueRole(arm, AgentRole.DYNAMIC_VERIFICATION);
                case PATH_EXPLORATION -> waitForDynamicIdleThenPath(arm);
                case VULNERABILITY_TRIAGE -> safeEnqueueRole(arm, AgentRole.VULNERABILITY_TRIAGE);
                case REPORT_GENERATION -> safeEnqueueRole(arm, AgentRole.REPORT_GENERATION);
                case COMPLETE -> disarm(arm, PipelineStage.COMPLETE.name());
            }
        });
    }

    public boolean isArmed(String scanId) {
        return scanId != null && armed.containsKey(scanId);
    }

    public void onAiJobFinished(AiJobData job) {
        if (job == null || job.scanId() == null) return;
        Arm arm = armed.get(job.scanId());
        if (arm == null) return;
        if (!"COMPLETED".equals(job.status())) {
            disarm(arm, job.role().name() + "_FAILED");
            return;
        }
        async.execute(() -> advanceAfterRole(arm, job.role()));
    }

    public void onDynamicTaskFinished(TaskSnapshot snapshot) {
        if (snapshot == null) return;
        String scanId = snapshot.scope().scanId();
        Arm arm = armed.get(scanId);
        if (arm == null) return;
        if (snapshot.lifecycle() != TaskLifecycle.COMPLETED) {
            disarm(arm, PipelineStage.DYNAMIC_OBSERVATION.name() + "_FAILED");
            return;
        }
        // The first sandbox pass is driven by the static/pre-analysis entry
        // catalog. The dynamic role interprets those observations before path
        // modeling is allowed to consume them.
        actions.persistState(arm, PipelineStage.DYNAMIC_VERIFICATION.name(), true);
        async.execute(() -> safeEnqueueRole(arm, AgentRole.DYNAMIC_VERIFICATION));
    }

    private void advanceAfterRole(Arm arm, AgentRole completed) {
        switch (completed) {
            case PRE_ANALYSIS -> safeEnqueueDynamic(arm);
            case DYNAMIC_VERIFICATION -> waitForDynamicIdleThenPath(arm);
            case PATH_EXPLORATION -> safeEnqueueRole(arm, AgentRole.VULNERABILITY_TRIAGE);
            case VULNERABILITY_TRIAGE -> safeEnqueueRole(arm, AgentRole.REPORT_GENERATION);
            case REPORT_GENERATION -> disarm(arm, PipelineStage.COMPLETE.name());
        }
    }

    private void safeEnqueueRole(Arm arm, AgentRole role) {
        try {
            actions.persistState(arm, role.name(), true);
            if (actions.hasRoleJob(arm.projectId(), arm.scanId(), role)) return;
            actions.enqueueRole(arm.projectId(), arm.scanId(), role, arm.outputLanguage(), arm.actorId());
        } catch (RuntimeException ignored) {
            disarm(arm, role.name() + "_ENQUEUE_FAILED");
        }
    }

    private void safeEnqueueDynamic(Arm arm) {
        try {
            actions.persistState(arm, PipelineStage.DYNAMIC_OBSERVATION.name(), true);
            if (actions.hasRunningDynamicTask(arm.scanId())) {
                return;
            }
            if (actions.hasCompletedDynamicTask(arm.scanId())) {
                // Observation already finished (recovery / prior pass); do not start a second Docker task.
                actions.persistState(arm, PipelineStage.DYNAMIC_VERIFICATION.name(), true);
                safeEnqueueRole(arm, AgentRole.DYNAMIC_VERIFICATION);
                return;
            }
            if (actions.hasBusyDynamicTask(arm.scanId())) {
                // Compatibility for stubs that only implement hasBusyDynamicTask after enqueue.
                return;
            }
            actions.enqueueDynamic(arm.scanId(), arm.actorId());
        } catch (RuntimeException ignored) {
            disarm(arm, PipelineStage.DYNAMIC_OBSERVATION.name() + "_ENQUEUE_FAILED");
        }
    }

    private void waitForDynamicIdleThenPath(Arm arm) {
        if (!actions.hasRunningDynamicTask(arm.scanId())) {
            actions.persistState(arm, PipelineStage.PATH_EXPLORATION.name(), true);
            safeEnqueueRole(arm, AgentRole.PATH_EXPLORATION);
            return;
        }
        async.execute(() -> {
            long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.MINUTES.toNanos(10);
            while (System.nanoTime() < deadline && armed.containsKey(arm.scanId())) {
                if (!actions.hasRunningDynamicTask(arm.scanId())) {
                    safeEnqueueRole(arm, AgentRole.PATH_EXPLORATION);
                    return;
                }
                try {
                    Thread.sleep(250L);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    disarm(arm, PipelineStage.PATH_EXPLORATION.name() + "_INTERRUPTED");
                    return;
                }
            }
            disarm(arm, PipelineStage.PATH_EXPLORATION.name() + "_TIMEOUT");
        });
    }

    private void disarm(Arm arm, String nextStage) {
        armed.remove(arm.scanId());
        actions.persistState(arm, nextStage, false);
    }

    public static Predicate<AiJobData> busyOrDoneFor(String scanId, AgentRole role) {
        return job -> scanId.equals(job.scanId())
                && job.role() == role
                && BUSY.contains(job.status());
    }
}
