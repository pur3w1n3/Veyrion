-- Server-gated experiment plans from plan_propose. Bound metadata only; never
-- stores network/mount/command policy. Restored into process memory on restart.
CREATE TABLE experiment_plans (
    plan_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (scan_id, plan_id),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
    FOREIGN KEY (project_id) REFERENCES projects(project_id)
);
CREATE INDEX experiment_plans_scan_idx ON experiment_plans(project_id, scan_id);
CREATE INDEX experiment_plans_created_idx ON experiment_plans(created_at);
