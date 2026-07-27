-- Backfill schemaVersion into JSON payloads that predate the read guard.
-- worker_tasks already stores schema_version as a column (not JSON).

UPDATE experiment_plans
SET payload_json = json_set(payload_json, '$.schemaVersion', 1)
WHERE json_extract(payload_json, '$.schemaVersion') IS NULL;

UPDATE path_runs
SET payload_json = json_set(payload_json, '$.schemaVersion', 1)
WHERE json_extract(payload_json, '$.schemaVersion') IS NULL;

UPDATE worker_tasks
SET schema_version = 1
WHERE schema_version IS NULL OR schema_version < 1;
