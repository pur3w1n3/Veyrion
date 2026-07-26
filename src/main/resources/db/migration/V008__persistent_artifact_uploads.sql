CREATE TABLE IF NOT EXISTS artifact_upload_sessions (
    upload_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    file_name TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes > 0),
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    next_offset INTEGER NOT NULL CHECK (next_offset >= 0 AND next_offset <= size_bytes),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(project_id)
);
CREATE INDEX IF NOT EXISTS artifact_upload_sessions_project_idx ON artifact_upload_sessions(project_id);
