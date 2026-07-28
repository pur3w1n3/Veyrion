-- P1-06: hypothesis identifiers are scoped by scan; same local detector id may recur per scan.
CREATE TABLE security_hypotheses_v024 (
    hypothesis_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    PRIMARY KEY (scan_id, hypothesis_id),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);
INSERT INTO security_hypotheses_v024(hypothesis_id, scan_id, payload_json)
    SELECT hypothesis_id, scan_id, payload_json FROM security_hypotheses;
DROP TABLE security_hypotheses;
ALTER TABLE security_hypotheses_v024 RENAME TO security_hypotheses;
CREATE INDEX security_hypotheses_scan_idx ON security_hypotheses(scan_id);
CREATE INDEX security_hypotheses_id_idx ON security_hypotheses(hypothesis_id);