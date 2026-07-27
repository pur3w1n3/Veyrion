-- MVP-1: denormalized branch coverage column + durable ContrastLedger round snapshots.
-- PathRun payload_json already carries branchHitMap; this column aids SQL-side inspection.

ALTER TABLE path_runs ADD COLUMN branch_hit_map_json TEXT;

CREATE TABLE IF NOT EXISTS contrast_ledger_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    round_index INTEGER NOT NULL CHECK (round_index >= 0),
    ledger_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (scan_id, round_index),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);
CREATE INDEX contrast_ledger_snapshots_scan_idx
    ON contrast_ledger_snapshots(scan_id, round_index);
