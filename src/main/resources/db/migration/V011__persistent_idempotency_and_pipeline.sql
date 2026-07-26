-- Idempotency records are immutable request-to-resource bindings. A reused key
-- with a different payload hash must fail closed instead of creating a second
-- local resource after restart.
CREATE TABLE control_plane_idempotency (
    scope TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    result_ref TEXT NOT NULL,
    result_json TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (scope, idempotency_key)
);
CREATE INDEX control_plane_idempotency_created_idx
    ON control_plane_idempotency(created_at);

-- One cursor per immutable scan. The cursor is advisory state for recovery;
-- persisted AI jobs and worker tasks remain the source of stage evidence.
CREATE TABLE audit_pipeline_runs (
    scan_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    output_language TEXT NOT NULL CHECK (output_language IN ('ZH_CN', 'EN')),
    armed INTEGER NOT NULL CHECK (armed IN (0, 1)),
    next_stage TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
    FOREIGN KEY (project_id) REFERENCES projects(project_id)
);
CREATE INDEX audit_pipeline_runs_project_idx ON audit_pipeline_runs(project_id);

-- Probe inputs are server-generated hints. The JSON is bounded metadata, not a
-- command or network policy, and is revalidated against the scan on recovery.
CREATE TABLE dynamic_probe_plans (
    task_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    target_entry_id TEXT NOT NULL,
    candidate_inputs_json TEXT NOT NULL,
    max_requests INTEGER NOT NULL CHECK (max_requests BETWEEN 1 AND 8),
    plan_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX dynamic_probe_plans_scan_idx ON dynamic_probe_plans(project_id, scan_id);
