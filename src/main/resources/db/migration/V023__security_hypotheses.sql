-- P0-12: first-class SecurityHypothesis rows (JSON payload + scan/hypothesis indexes).
-- Does not alter findings table; Finding.hypothesisId is stored in finding payload_json.

CREATE TABLE IF NOT EXISTS security_hypotheses (
    hypothesis_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);
CREATE INDEX IF NOT EXISTS security_hypotheses_scan_idx ON security_hypotheses(scan_id);
CREATE INDEX IF NOT EXISTS security_hypotheses_id_idx ON security_hypotheses(hypothesis_id);
