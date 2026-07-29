-- Persist compiled probe-plan payloads so Control Plane startup can hydrate
-- the in-memory cache without re-running identity harvest over JAR bytes.
-- Append-only migration; never rewrite prior versions.
-- Existing rows keep NULL payload_json and are skipped on restore (fail closed).

ALTER TABLE dynamic_probe_plans ADD COLUMN payload_json TEXT;
