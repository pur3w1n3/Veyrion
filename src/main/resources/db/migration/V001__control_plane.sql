CREATE TABLE projects (
    project_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'ARCHIVED', 'DELETED')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted_at TEXT
);

CREATE TABLE artifacts (
    project_id TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    normalized_path TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    static_only INTEGER NOT NULL CHECK (static_only IN (0, 1)),
    registered_at TEXT NOT NULL,
    PRIMARY KEY (project_id, artifact_digest),
    FOREIGN KEY (project_id) REFERENCES projects(project_id)
);
CREATE INDEX artifacts_project_id_idx ON artifacts(project_id);

CREATE TABLE scans (
    scan_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(project_id),
    FOREIGN KEY (project_id, artifact_digest) REFERENCES artifacts(project_id, artifact_digest)
);
CREATE INDEX scans_project_id_idx ON scans(project_id);

CREATE TABLE evidence (
    evidence_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
    FOREIGN KEY (project_id) REFERENCES projects(project_id)
);
CREATE INDEX evidence_scan_id_idx ON evidence(scan_id);

CREATE TABLE findings (
    finding_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
    FOREIGN KEY (project_id) REFERENCES projects(project_id)
);
CREATE INDEX findings_scan_id_idx ON findings(scan_id);

CREATE TABLE attack_chains (
    chain_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
    FOREIGN KEY (project_id) REFERENCES projects(project_id)
);
CREATE INDEX attack_chains_project_id_idx ON attack_chains(project_id);
