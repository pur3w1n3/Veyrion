-- MVP-5: structured root-cause JSON on findings.

ALTER TABLE findings ADD COLUMN root_cause_json TEXT;
