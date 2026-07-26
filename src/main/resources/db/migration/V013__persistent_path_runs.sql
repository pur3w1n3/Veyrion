-- Durable PathRun projection. Worker traces remain the immutable source; this table
-- is a queryable, restart-safe view for GUI and AI facts_search.
CREATE TABLE path_runs (
    path_run_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE
);
CREATE INDEX path_runs_scan_idx ON path_runs(project_id, artifact_digest, scan_id);
CREATE INDEX path_runs_task_idx ON path_runs(task_id);
