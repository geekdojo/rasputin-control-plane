package firewall

const schema = `
CREATE TABLE IF NOT EXISTS firewall_intents (
    id         TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    name       TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1,
    spec       TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_firewall_intents_kind ON firewall_intents(kind);

CREATE TABLE IF NOT EXISTS firewall_state (
    target_node_id  TEXT PRIMARY KEY,
    intent_hash     TEXT NOT NULL DEFAULT '',
    observed_hash   TEXT NOT NULL DEFAULT '',
    last_applied    INTEGER,
    last_reconciled INTEGER
);

-- firewall_baseline_seeded records that the stock-equivalent baseline rules
-- have been seeded for a given firewall node at least once. The row's mere
-- existence is the marker; we never delete it. This is what guarantees a
-- baseline rule the operator later DELETES does not silently resurrect on the
-- next agent reconnect / DB-reattach — see MarkBaselineSeeded.
CREATE TABLE IF NOT EXISTS firewall_baseline_seeded (
    node_id   TEXT PRIMARY KEY,
    seeded_at INTEGER NOT NULL
);
`
