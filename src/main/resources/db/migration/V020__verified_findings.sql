-- MVP-6: VERIFIED findings are stored separately from ordinary findings.
-- Rows may only be inserted after VerifiedStatusGate allows VERIFIED (currently fail-closed).

CREATE TABLE IF NOT EXISTS verified_findings (
    finding_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    root_cause_json TEXT NOT NULL,
    replay_evidence_refs TEXT NOT NULL,
    verified_at TEXT NOT NULL,
    attestation_ref TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);
CREATE INDEX IF NOT EXISTS verified_findings_scan_idx ON verified_findings(scan_id);
