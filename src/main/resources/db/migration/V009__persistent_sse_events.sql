CREATE TABLE IF NOT EXISTS sse_events (
    event_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    occurred_at TEXT NOT NULL,
    project_id TEXT,
    artifact_digest TEXT,
    task_id TEXT,
    idempotency_scope TEXT NOT NULL,
    idempotency_value TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS sse_events_scan_time_idx ON sse_events(scan_id, occurred_at);
