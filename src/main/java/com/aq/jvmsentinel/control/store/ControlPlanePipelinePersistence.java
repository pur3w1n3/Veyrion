package com.aq.jvmsentinel.control.store;

import com.aq.jvmsentinel.artifact.ArtifactUploadService;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.event.VersionedEvent;
import com.aq.jvmsentinel.worker.TaskSnapshot;
import com.aq.jvmsentinel.worker.TraceChunk;

import java.util.List;

/** Store 辅助类。 */
public final class ControlPlanePipelinePersistence {
    private final SQLiteControlPlanePersistence persistence;

    public ControlPlanePipelinePersistence(SQLiteControlPlanePersistence persistence) {
        this.persistence = persistence;
    }

    public boolean persistent() {
        return persistence != null;
    }

    public List<SQLiteControlPlanePersistence.IdempotencyData> loadIdempotency() {
        return persistence == null ? List.of() : persistence.loadIdempotency();
    }

    public SQLiteControlPlanePersistence.IdempotencyData persistIdempotency(
            SQLiteControlPlanePersistence.IdempotencyData candidate) {
        if (persistence == null) {
            return candidate;
        }
        return persistence.putIdempotency(candidate);
    }

    public List<SQLiteControlPlanePersistence.PipelineRunData> loadPipelineRuns() {
        return persistence == null ? List.of() : persistence.loadPipelineRuns();
    }

    public void persistPipelineRun(SQLiteControlPlanePersistence.PipelineRunData run) {
        if (persistence != null) {
            persistence.savePipelineRun(run);
        }
    }

    /**
     * 流水线游标推进的持久化 CAS。内存模式始终接受写入，便于无 SQLite 的单测。
     */
    public boolean compareAndAdvancePipelineRun(
            SQLiteControlPlanePersistence.PipelineRunData expected,
            SQLiteControlPlanePersistence.PipelineRunData next) {
        if (persistence == null) {
            persistPipelineRun(next);
            return true;
        }
        return persistence.compareAndAdvancePipelineRun(expected, next);
    }

    public List<SQLiteControlPlanePersistence.ProbePlanData> loadProbePlans() {
        return persistence == null ? List.of() : persistence.loadProbePlans();
    }

    public void persistProbePlan(SQLiteControlPlanePersistence.ProbePlanData plan) {
        if (persistence != null) {
            persistence.saveProbePlan(plan);
        }
    }

    public List<SQLiteControlPlanePersistence.ExperimentPlanData> loadExperimentPlans() {
        return persistence == null ? List.of() : persistence.loadExperimentPlans();
    }

    public List<SQLiteControlPlanePersistence.ExperimentPlanData> loadExperimentPlansForScan(String scanId) {
        return persistence == null ? List.of() : persistence.loadExperimentPlansForScan(scanId);
    }

    public void persistExperimentPlan(SQLiteControlPlanePersistence.ExperimentPlanData plan) {
        if (persistence != null) {
            persistence.saveExperimentPlan(plan);
        }
    }

    public void persistTracePlan(SQLiteControlPlanePersistence.TracePlanData plan) {
        if (persistence != null) {
            persistence.saveTracePlan(plan);
        }
    }

    public List<SQLiteControlPlanePersistence.TracePlanData> loadTracePlansForScan(String scanId) {
        return persistence == null ? List.of() : persistence.loadTracePlansForScan(scanId);
    }

    public void persistWorldPack(SQLiteControlPlanePersistence.WorldPackData pack) {
        if (persistence != null) {
            persistence.saveWorldPack(pack);
        }
    }

    public List<SQLiteControlPlanePersistence.WorldPackData> loadWorldPacksForScan(String scanId) {
        return persistence == null ? List.of() : persistence.loadWorldPacksForScan(scanId);
    }

    public SQLiteControlPlanePersistence.WorkerState loadWorkerState() {
        return persistence == null
                ? SQLiteControlPlanePersistence.WorkerState.empty()
                : persistence.loadWorkerState();
    }

    public void persistWorkerTask(TaskSnapshot snapshot) {
        if (persistence != null) {
            persistence.persistWorkerTask(snapshot);
        }
    }

    public void persistWorkerTrace(String idempotencyKey, TraceChunk chunk) {
        if (persistence != null) {
            persistence.persistWorkerTrace(idempotencyKey, chunk);
        }
    }

    public ArtifactUploadService.UploadPersistence artifactUploadPersistence() {
        if (persistence == null) {
            return ArtifactUploadService.UploadPersistence.NONE;
        }
        return new ArtifactUploadService.UploadPersistence() {
            @Override
            public List<ArtifactUploadService.PersistedSession> load() {
                return persistence.loadArtifactUploads();
            }

            @Override
            public void save(ArtifactUploadService.PersistedSession session) {
                persistence.persistArtifactUpload(session);
            }

            @Override
            public void delete(String uploadId) {
                persistence.deleteArtifactUpload(uploadId);
            }
        };
    }

    public List<VersionedEvent> loadSseEvents() {
        return persistence == null ? List.of() : persistence.loadSseEvents();
    }

    public void persistSseEvent(String scanId, VersionedEvent event) {
        if (persistence != null) {
            persistence.persistSseEvent(scanId, event);
        }
    }
}
