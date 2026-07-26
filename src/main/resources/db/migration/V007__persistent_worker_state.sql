CREATE TABLE worker_tasks (
    project_id TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    target_entry_id TEXT NOT NULL,
    authorized INTEGER NOT NULL CHECK (authorized IN (0, 1)),
    max_wall_clock_seconds INTEGER NOT NULL CHECK (max_wall_clock_seconds > 0),
    max_cpu_millis INTEGER NOT NULL CHECK (max_cpu_millis > 0),
    max_memory_bytes INTEGER NOT NULL CHECK (max_memory_bytes > 0),
    max_disk_bytes INTEGER NOT NULL CHECK (max_disk_bytes > 0),
    max_trace_bytes INTEGER NOT NULL CHECK (max_trace_bytes > 0),
    network_mode TEXT NOT NULL CHECK (network_mode IN ('DENY', 'ALLOWLIST')),
    network_allowlist TEXT NOT NULL,
    required_capability TEXT NOT NULL,
    lifecycle TEXT NOT NULL,
    lease_id TEXT,
    lease_worker_id TEXT,
    lease_capability TEXT,
    lease_issued_at TEXT,
    lease_heartbeat_at TEXT,
    lease_expires_at TEXT,
    checkpoint_id TEXT,
    checkpoint_trace_sequence INTEGER,
    checkpoint_trace_head_digest TEXT,
    checkpoint_created_at TEXT,
    stop_reason TEXT,
    failure_code TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (project_id, artifact_digest, scan_id, task_id),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
    FOREIGN KEY (project_id, artifact_digest) REFERENCES artifacts(project_id, artifact_digest)
);
CREATE INDEX worker_tasks_scan_idx ON worker_tasks(project_id, scan_id);

CREATE TABLE worker_trace_chunks (
    project_id TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    idempotency_key TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    previous_digest TEXT,
    emitted_at TEXT NOT NULL,
    payload BLOB NOT NULL,
    digest TEXT NOT NULL,
    PRIMARY KEY (project_id, artifact_digest, scan_id, task_id, sequence),
    UNIQUE (project_id, artifact_digest, scan_id, task_id, idempotency_key),
    FOREIGN KEY (project_id, artifact_digest, scan_id, task_id)
        REFERENCES worker_tasks(project_id, artifact_digest, scan_id, task_id)
);
CREATE INDEX worker_trace_chunks_scope_idx
    ON worker_trace_chunks(project_id, artifact_digest, scan_id, task_id, sequence);
