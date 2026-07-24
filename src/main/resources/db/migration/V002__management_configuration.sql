CREATE TABLE operators (
    operator_id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (role IN ('VIEWER','ANALYST','OPERATOR','ADMINISTRATOR')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE operator_tokens (
    token_id TEXT PRIMARY KEY,
    operator_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64),
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    FOREIGN KEY (operator_id) REFERENCES operators(operator_id) ON DELETE CASCADE
);
CREATE INDEX operator_tokens_operator_idx ON operator_tokens(operator_id);

CREATE TABLE providers (
    provider_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('OPENAI_COMPATIBLE','AZURE_OPENAI','LOCAL')),
    base_url TEXT NOT NULL,
    model TEXT,
    enabled INTEGER NOT NULL CHECK (enabled IN (0,1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (workspace_id, name),
    UNIQUE (workspace_id, provider_id)
);

CREATE TABLE provider_credentials (
    credential_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    format_version INTEGER NOT NULL,
    credential_version INTEGER NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (workspace_id, provider_id),
    FOREIGN KEY (workspace_id, provider_id) REFERENCES providers(workspace_id, provider_id) ON DELETE CASCADE
);

CREATE TABLE project_ai_role_bindings (
    project_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('PRE_ANALYSIS','PATH_EXPLORATION','VULNERABILITY_TRIAGE','REPORT_GENERATION')),
    workspace_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    model TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (project_id, role),
    FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE,
    FOREIGN KEY (workspace_id, provider_id) REFERENCES providers(workspace_id, provider_id)
);

CREATE TABLE ai_jobs (
    ai_job_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('PRE_ANALYSIS','PATH_EXPLORATION','VULNERABILITY_TRIAGE','REPORT_GENERATION')),
    status TEXT NOT NULL CHECK (status IN ('BLOCKED','CANCELLED')),
    error_code TEXT NOT NULL,
    stages_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE
);
CREATE INDEX ai_jobs_project_idx ON ai_jobs(project_id, created_at);

CREATE TABLE audit_events (
    audit_event_id TEXT PRIMARY KEY,
    project_id TEXT,
    operator_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('SUCCESS','DENIED')),
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(project_id),
    FOREIGN KEY (operator_id) REFERENCES operators(operator_id)
);
CREATE INDEX audit_events_project_idx ON audit_events(project_id, created_at);
CREATE INDEX audit_events_created_idx ON audit_events(created_at);
