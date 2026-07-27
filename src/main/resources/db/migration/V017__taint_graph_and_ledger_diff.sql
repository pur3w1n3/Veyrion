-- MVP-3: multi-round ledger hit tracking + optional taint graph cache.

ALTER TABLE contrast_ledger_snapshots ADD COLUMN first_seen_round INTEGER;
ALTER TABLE contrast_ledger_snapshots ADD COLUMN last_hit_round INTEGER;
ALTER TABLE contrast_ledger_snapshots ADD COLUMN hit_count INTEGER DEFAULT 0;

CREATE TABLE IF NOT EXISTS taint_graphs (
    scan_id TEXT PRIMARY KEY,
    graph_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);
