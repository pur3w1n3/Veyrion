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

        void enqueueRole(String projectId, String scanId, AgentRole role,
                         AiOutputLanguage language, String actorId);

        void enqueueDynamic(String scanId, String actorId);
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
    }

    public boolean isArmed(String scanId) {
        return scanId != null && armed.containsKey(scanId);
    }

    public void onAiJobFinished(AiJobData job) {
        if (job == null || job.scanId() == null) return;
        Arm arm = armed.get(job.scanId());
        if (arm == null) return;
        if (!"COMPLETED".equals(job.status())) {
            armed.remove(job.scanId());
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
            armed.remove(scanId);
            return;
        }
        async.execute(() -> safeEnqueueRole(arm, AgentRole.DYNAMIC_VERIFICATION));
    }

    private void advanceAfterRole(Arm arm, AgentRole completed) {
        switch (completed) {
            case PRE_ANALYSIS -> safeEnqueueRole(arm, AgentRole.PATH_EXPLORATION);
            case PATH_EXPLORATION -> safeEnqueueDynamic(arm);
            case DYNAMIC_VERIFICATION -> safeEnqueueRole(arm, AgentRole.VULNERABILITY_TRIAGE);
            case VULNERABILITY_TRIAGE -> safeEnqueueRole(arm, AgentRole.REPORT_GENERATION);
            case REPORT_GENERATION -> armed.remove(arm.scanId());
        }
    }

    private void safeEnqueueRole(Arm arm, AgentRole role) {
        try {
            if (actions.hasRoleJob(arm.projectId(), arm.scanId(), role)) return;
            actions.enqueueRole(arm.projectId(), arm.scanId(), role, arm.outputLanguage(), arm.actorId());
        } catch (RuntimeException ignored) {
            armed.remove(arm.scanId());
        }
    }

    private void safeEnqueueDynamic(Arm arm) {
        try {
            if (actions.hasBusyDynamicTask(arm.scanId())) {
                // Dynamic already running/done; if completed, role stage will be armed by dynamic hook.
                return;
            }
            actions.enqueueDynamic(arm.scanId(), arm.actorId());
        } catch (RuntimeException ignored) {
            armed.remove(arm.scanId());
        }
    }

    public static Predicate<AiJobData> busyOrDoneFor(String scanId, AgentRole role) {
        return job -> scanId.equals(job.scanId())
                && job.role() == role
                && BUSY.contains(job.status());
    }
}
