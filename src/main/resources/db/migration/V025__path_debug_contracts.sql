-- P0-21: durable TracePlan / PathTrace / WorldPack payloads (JSON contracts).
-- Existing path_runs / experiment_plans remain; these tables store path-debug extensions.
-- Append-only migration; never rewrite prior versions.

CREATE TABLE IF NOT EXISTS trace_plans (
    trace_plan_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    entry_ref TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (scan_id, trace_plan_id),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
    FOREIGN KEY (project_id) REFERENCES projects(project_id)
);
CREATE INDEX IF NOT EXISTS trace_plans_scan_idx ON trace_plans(project_id, scan_id);
CREATE INDEX IF NOT EXISTS trace_plans_entry_idx ON trace_plans(scan_id, entry_ref);

CREATE TABLE IF NOT EXISTS world_packs (
    world_pack_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    dependency_mode TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (scan_id, world_pack_id),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
    FOREIGN KEY (project_id) REFERENCES projects(project_id)
);
CREATE INDEX IF NOT EXISTS world_packs_scan_idx ON world_packs(project_id, scan_id);

CREATE TABLE IF NOT EXISTS path_traces (
    path_trace_id TEXT PRIMARY KEY,
    path_run_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    task_id TEXT NOT NULL,
    experiment_plan_id TEXT,
    trace_plan_id TEXT,
    world_pack_id TEXT,
    posture_kind TEXT,
    exit_reason TEXT,
    legacy_incomplete INTEGER NOT NULL DEFAULT 0,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS path_traces_scan_idx ON path_traces(project_id, artifact_digest, scan_id);
CREATE INDEX IF NOT EXISTS path_traces_path_run_idx ON path_traces(path_run_id);
CREATE INDEX IF NOT EXISTS path_traces_task_idx ON path_traces(task_id);
