CREATE TABLE ai_jobs_v004 (
    ai_job_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    scan_id TEXT,
    artifact_digest TEXT,
    role TEXT NOT NULL CHECK (role IN (
        'PRE_ANALYSIS','PATH_EXPLORATION','VULNERABILITY_TRIAGE','REPORT_GENERATION'
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

INSERT INTO ai_jobs_v004(
    ai_job_id,workspace_id,project_id,role,policy_snapshot_json,authorized,
    status,stop_reason,stages_json,elapsed_ms,rounds,tool_summary_json,
    created_at,updated_at
)
SELECT ai_job_id,'local',project_id,role,'{"schemaVersion":1,"legacy":true}',0,
       status,error_code,stages_json,0,0,'[]',created_at,updated_at
FROM ai_jobs;

DROP TABLE ai_jobs;
ALTER TABLE ai_jobs_v004 RENAME TO ai_jobs;
CREATE INDEX ai_jobs_project_idx ON ai_jobs(project_id, created_at);
CREATE INDEX ai_jobs_status_idx ON ai_jobs(status, updated_at);
