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
    error           TEXT NOT NULL DEFAULT '',
    unverified_boot    INTEGER NOT NULL DEFAULT 0,
    unverified_version INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_node_updates_node ON node_updates(node_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_node_updates_status ON node_updates(status);
`

// migrations are forward-only DDL that CREATE TABLE IF NOT EXISTS cannot
// express — adding a column to a table that already exists on a live cluster.
// Applied after schema; "duplicate column" is the expected outcome on a fresh
// install where the CREATE above already covered it. Same shape as the
// inventory store's, deliberately: two stores inventing two migration idioms is
// how one of them ends up untested.
var migrations = []string{
	// unverified_boot / unverified_version: which conjuncts of the verify
	// contract could NOT be evaluated for this update (ADR-0005 Decision 3).
	// Default 0 for rows that predate the columns, which is correct in the only
	// sense available — those updates were verified by whatever the contract
	// was at the time, and claiming they were degraded would be inventing
	// history.
	`ALTER TABLE node_updates ADD COLUMN unverified_boot INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE node_updates ADD COLUMN unverified_version INTEGER NOT NULL DEFAULT 0`,
}
