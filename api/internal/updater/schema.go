package updater

const schema = `
CREATE TABLE IF NOT EXISTS bundles (
    sha256        TEXT PRIMARY KEY,
    version       TEXT NOT NULL,
    compatible    TEXT NOT NULL,
    architecture  TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    build_date    TEXT NOT NULL DEFAULT '',
    size_bytes    INTEGER NOT NULL,
    signed_by     TEXT NOT NULL DEFAULT '',
    storage_path  TEXT NOT NULL,
    uploaded_at   INTEGER NOT NULL,
    uploaded_by   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_bundles_compat ON bundles(compatible);
CREATE INDEX IF NOT EXISTS idx_bundles_uploaded_at ON bundles(uploaded_at DESC);

CREATE TABLE IF NOT EXISTS node_updates (
    job_id          TEXT PRIMARY KEY,
    node_id         TEXT NOT NULL,
    bundle_sha256   TEXT NOT NULL,
    from_slot       TEXT NOT NULL DEFAULT 'unknown',
    to_slot         TEXT NOT NULL DEFAULT 'unknown',
    from_version    TEXT NOT NULL DEFAULT '',
    to_version      TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL,  -- 'in_progress' | 'committed' | 'rolled_back' | 'failed'
    started_at      INTEGER NOT NULL,
    finished_at     INTEGER,
    error           TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_node_updates_node ON node_updates(node_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_node_updates_status ON node_updates(status);
`
