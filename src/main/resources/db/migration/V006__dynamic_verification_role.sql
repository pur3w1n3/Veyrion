-- Expand fixed agent roles with DYNAMIC_VERIFICATION (sandbox evidence interpretation).
-- SQLite cannot alter CHECK constraints in place, so recreate affected tables.
-- Foreign keys are disabled by the migrator around each migration transaction.

CREATE TABLE project_ai_role_bindings_v006 (
    project_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN (
        'PRE_ANALYSIS','PATH_EXPLORATION','DYNAMIC_VERIFICATION',
        'VULNERABILITY_TRIAGE','REPORT_GENERATION'
    )),
    workspace_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    model TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (project_id, role),
    FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE,
    FOREIGN KEY (workspace_id, provider_id)
        REFERENCES providers(workspace_id, provider_id)
);

INSERT INTO project_ai_role_bindings_v006
SELECT project_id, role, workspace_id, provider_id, model, updated_at
FROM project_ai_role_bindings;

DROP TABLE project_ai_role_bindings;
ALTER TABLE project_ai_role_bindings_v006 RENAME TO project_ai_role_bindings;

CREATE TABLE ai_jobs_v006 (
    ai_job_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    scan_id TEXT,
    artifact_digest TEXT,
    role TEXT NOT NULL CHECK (role IN (
        'PRE_ANALYSIS','PATH_EXPLORATION','DYNAMIC_VERIFICATION',
        'VULNERABILITY_TRIAGE','REPORT_GENERATION'
    )),
    provider_id TEXT,
    model TEXT,
    policy_snapshot_json TEXT NOT NULL,
    authorized INTEGER NOT NULL CHECK (authorized IN (0,1)),
    status TEXT NOT NULL CHECK (status IN (
        'QUEUED','RUNNING','COMPLETED','FAILED','CANCELLED','BLOCKED'
    )),
    stop_reason TEXT NOT NULL,
    stages_json TEXT NOT NULL,
    provider_request_id TEXT,
    elapsed_ms INTEGER NOT NULL CHECK (elapsed_ms >= 0),
    rounds INTEGER NOT NULL CHECK (rounds >= 0),
    tool_summary_json TEXT NOT NULL,
    conclusion_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE
);

INSERT INTO ai_jobs_v006(
    ai_job_id, workspace_id, project_id, scan_id, artifact_digest, role,
    provider_id, model, policy_snapshot_json, authorized, status, stop_reason,
    stages_json, provider_request_id, elapsed_ms, rounds, tool_summary_json,
    conclusion_json, created_at, updated_at
)
SELECT ai_job_id, workspace_id, project_id, scan_id, artifact_digest, role,
       provider_id, model, policy_snapshot_json, authorized, status, stop_reason,
       stages_json, provider_request_id, elapsed_ms, rounds, tool_summary_json,
       conclusion_json, created_at, updated_at
FROM ai_jobs;

DROP TABLE ai_jobs;
ALTER TABLE ai_jobs_v006 RENAME TO ai_jobs;
CREATE INDEX ai_jobs_project_idx ON ai_jobs(project_id, created_at);
CREATE INDEX ai_jobs_status_idx ON ai_jobs(status, updated_at);
