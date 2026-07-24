CREATE TABLE providers_v003 (
    provider_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN (
        'OPENAI_CHAT',
        'ANTHROPIC_MESSAGES',
        'OPENAI_COMPATIBLE',
        'AZURE_OPENAI',
        'LOCAL'
    )),
    base_url TEXT NOT NULL,
    model TEXT,
    enabled INTEGER NOT NULL CHECK (enabled IN (0,1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (workspace_id, name),
    UNIQUE (workspace_id, provider_id)
);

INSERT INTO providers_v003(
    provider_id,workspace_id,name,kind,base_url,model,enabled,created_at,updated_at
)
SELECT provider_id,workspace_id,name,kind,base_url,model,enabled,created_at,updated_at
FROM providers;

CREATE TABLE provider_credentials_v003 (
    credential_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    format_version INTEGER NOT NULL,
    credential_version INTEGER NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (workspace_id, provider_id),
    FOREIGN KEY (workspace_id, provider_id)
        REFERENCES providers_v003(workspace_id, provider_id) ON DELETE CASCADE
);

INSERT INTO provider_credentials_v003
SELECT credential_id,workspace_id,provider_id,format_version,credential_version,
       nonce,ciphertext,updated_at
FROM provider_credentials;

CREATE TABLE project_ai_role_bindings_v003 (
    project_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN (
        'PRE_ANALYSIS','PATH_EXPLORATION','VULNERABILITY_TRIAGE','REPORT_GENERATION'
    )),
    workspace_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    model TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (project_id, role),
    FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE,
    FOREIGN KEY (workspace_id, provider_id)
        REFERENCES providers_v003(workspace_id, provider_id)
);

INSERT INTO project_ai_role_bindings_v003
SELECT project_id,role,workspace_id,provider_id,model,updated_at
FROM project_ai_role_bindings;

DROP TABLE project_ai_role_bindings;
DROP TABLE provider_credentials;
DROP TABLE providers;

ALTER TABLE providers_v003 RENAME TO providers;
ALTER TABLE provider_credentials_v003 RENAME TO provider_credentials;
ALTER TABLE project_ai_role_bindings_v003 RENAME TO project_ai_role_bindings;
