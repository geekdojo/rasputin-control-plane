package mesh

const schema = `
CREATE TABLE IF NOT EXISTS mesh_intents (
    id         TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    name       TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1,
    spec       TEXT NOT NULL,
    hs_id      TEXT NOT NULL DEFAULT '',  -- Headscale id once created
    hs_value   TEXT NOT NULL DEFAULT '',  -- unused: always ''; see migrations
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

// migrations run after schema on every open. Each must be idempotent on an
// already-migrated database; "duplicate column name" is expected and swallowed.
var migrations = []string{
	`ALTER TABLE mesh_devices ADD COLUMN online INTEGER NOT NULL DEFAULT 0`,
	// User pre-auth key values are shown once, in the create response, and
	// never stored. Releases before that kept the plaintext in hs_value;
	// clear it. Runs on every open, so a database restored from an older
	// archive is cleared too. The column stays (dropping it gains nothing
	// and an older api rolled back onto this DB still expects it).
	`UPDATE mesh_intents SET hs_value = '' WHERE hs_value != ''`,
	// The mesh.enroll_node job whose record step bound this device to its
	// node. Empty on an unbound row, and on a binding an older release made
	// without an enrol (VerifyBindings proves or clears those at startup).
	`ALTER TABLE mesh_devices ADD COLUMN enrol_job_id TEXT NOT NULL DEFAULT ''`,
	// One device per node. On a database that still holds duplicate bindings
	// this fails (and is logged); VerifyBindings resolves the duplicates at
	// startup and then creates it.
	bindingIndexDDL,
}

// bindingIndexDDL makes a second device bound to the same node a constraint
// violation rather than something a reader has to pick between.
const bindingIndexDDL = `CREATE UNIQUE INDEX IF NOT EXISTS ux_mesh_devices_bound_node
    ON mesh_devices(rasputin_node_id) WHERE rasputin_node_id != ''`
