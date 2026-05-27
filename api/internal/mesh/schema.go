package mesh

const schema = `
CREATE TABLE IF NOT EXISTS mesh_intents (
    id         TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    name       TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1,
    spec       TEXT NOT NULL,
    hs_id      TEXT NOT NULL DEFAULT '',  -- Headscale id once created
    hs_value   TEXT NOT NULL DEFAULT '',  -- e.g. the plaintext preauth key
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mesh_intents_kind ON mesh_intents(kind);

CREATE TABLE IF NOT EXISTS mesh_state (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    intent_hash     TEXT NOT NULL DEFAULT '',
    observed_hash   TEXT NOT NULL DEFAULT '',
    last_applied    INTEGER,
    last_reconciled INTEGER
);

CREATE TABLE IF NOT EXISTS mesh_devices (
    -- One row per Headscale node — both Rasputin-node enrollments and
    -- user devices live here. Joined with the inventory.nodes table by
    -- rasputin_node_id when present.
    hs_id            TEXT PRIMARY KEY,
    user             TEXT NOT NULL,
    hostname         TEXT NOT NULL DEFAULT '',
    tailnet_ip       TEXT NOT NULL DEFAULT '',
    tags             TEXT NOT NULL DEFAULT '[]',     -- JSON array
    advertised_routes TEXT NOT NULL DEFAULT '[]',    -- JSON array of CIDRs
    rasputin_node_id TEXT NOT NULL DEFAULT '',       -- '' for user devices
    kind             TEXT NOT NULL DEFAULT 'user',   -- 'rasputin' | 'user'
    first_seen       INTEGER NOT NULL,
    last_seen        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mesh_devices_rasputin ON mesh_devices(rasputin_node_id);
CREATE INDEX IF NOT EXISTS idx_mesh_devices_kind ON mesh_devices(kind);
`
