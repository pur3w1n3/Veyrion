-- Bind each audit pipeline cursor to an immutable run and stage attempt, plus the
-- single expected AI job or worker task that may advance it. Legacy armed rows
-- that lack pipeline_run_id / stage_attempt_id must fail closed on recovery.
ALTER TABLE audit_pipeline_runs ADD COLUMN pipeline_run_id TEXT;
ALTER TABLE audit_pipeline_runs ADD COLUMN stage_attempt_id TEXT;
ALTER TABLE audit_pipeline_runs ADD COLUMN expected_job_id TEXT;
ALTER TABLE audit_pipeline_runs ADD COLUMN expected_task_id TEXT;
ALTER TABLE audit_pipeline_runs ADD COLUMN stop_reason TEXT;

CREATE INDEX IF NOT EXISTS audit_pipeline_runs_pipeline_run_idx
    ON audit_pipeline_runs(pipeline_run_id);
CREATE INDEX IF NOT EXISTS audit_pipeline_runs_expected_job_idx
    ON audit_pipeline_runs(expected_job_id);
CREATE INDEX IF NOT EXISTS audit_pipeline_runs_expected_task_idx
    ON audit_pipeline_runs(expected_task_id);
