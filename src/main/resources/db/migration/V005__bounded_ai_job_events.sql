CREATE TABLE ai_job_events (
    ai_job_id TEXT NOT NULL,
    sequence_no INTEGER NOT NULL CHECK (sequence_no >= 1 AND sequence_no <= 128),
    workspace_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    stage TEXT NOT NULL CHECK (length(stage) BETWEEN 1 AND 64),
    status TEXT NOT NULL CHECK (length(status) BETWEEN 1 AND 64),
    provider_request_summary TEXT CHECK (provider_request_summary IS NULL OR length(provider_request_summary) <= 2048),
    provider_result_summary TEXT CHECK (provider_result_summary IS NULL OR length(provider_result_summary) <= 2048),
    tool_call_name TEXT CHECK (tool_call_name IS NULL OR length(tool_call_name) <= 128),
    tool_arguments_summary TEXT CHECK (tool_arguments_summary IS NULL OR length(tool_arguments_summary) <= 1024),
    tool_result_status TEXT CHECK (tool_result_status IS NULL OR length(tool_result_status) <= 64),
    model_inference_summary TEXT CHECK (model_inference_summary IS NULL OR length(model_inference_summary) <= 16384),
    failure_diagnostic TEXT CHECK (failure_diagnostic IS NULL OR length(failure_diagnostic) <= 1024),
    created_at TEXT NOT NULL,
    PRIMARY KEY (ai_job_id, sequence_no),
    FOREIGN KEY (ai_job_id) REFERENCES ai_jobs(ai_job_id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE
);

CREATE INDEX ai_job_events_project_idx
ON ai_job_events(project_id, ai_job_id, sequence_no);

INSERT INTO ai_job_events(
    ai_job_id,sequence_no,workspace_id,project_id,stage,status,
    failure_diagnostic,created_at
)
SELECT ai_job_id,1,workspace_id,project_id,'MIGRATED_SNAPSHOT',status,
       CASE WHEN status='FAILED'
            THEN 'Historical job: ' || stop_reason || ' - provider response body was not retained before event schema v5'
            ELSE NULL END,
       updated_at
FROM ai_jobs;
