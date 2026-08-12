package inventory

const schema = `
CREATE TABLE IF NOT EXISTS nodes (
    id            TEXT PRIMARY KEY,
    role          TEXT NOT NULL,
    hostname      TEXT NOT NULL DEFAULT '',
    agent_version TEXT NOT NULL DEFAULT '',
    image_version TEXT NOT NULL DEFAULT '',
    image_version_confirmed_at INTEGER NOT NULL DEFAULT 0,
    capabilities  TEXT NOT NULL DEFAULT '[]',
    metadata      TEXT NOT NULL DEFAULT '{}',
    storage       TEXT NOT NULL DEFAULT '',
    lan_ip        TEXT NOT NULL DEFAULT '',
    first_seen    INTEGER NOT NULL,
    last_seen     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nodes_role      ON nodes(role);
CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes(last_seen);
`

// migrations applied after schema. Each statement must be idempotent on its
// own — failures due to "duplicate column name" / "already exists" are
// silently swallowed by applyMigrations (they're expected on fresh installs
// where the CREATE TABLE above already covered the change).
var migrations = []string{
	`ALTER TABLE nodes ADD COLUMN image_version TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE nodes ADD COLUMN architecture TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE nodes ADD COLUMN storage TEXT NOT NULL DEFAULT ''`,
	// lan_ip: the node's agent-reported LAN IPv4 (ADR-0004 §8 / E3 AA-2), the
	// address the CP nameserver answers the node's and its apps' names with.
	`ALTER TABLE nodes ADD COLUMN lan_ip TEXT NOT NULL DEFAULT ''`,
	addImageVersionConfirmedAt,
}

// addImageVersionConfirmedAt: when image_version was last CONFIRMED, in unix
// millis; 0 means unconfirmed (ADR-0005 Decision 4). Named because the backfill
// below is conditional on this ALTER actually applying.
const addImageVersionConfirmedAt = `ALTER TABLE nodes ADD COLUMN image_version_confirmed_at INTEGER NOT NULL DEFAULT 0`

// backfillImageVersionConfirmedAt seeds existing rows at their last_seen.
//
// It runs ONCE, only in the api start where the column is first added, and that
// is load-bearing rather than an optimisation: running it on every start would
// silently re-confirm any row an update outcome had deliberately unconfirmed,
// so a stranded node's doubt would evaporate at the next api restart — turning
// the honest state this column exists to record back into the optimistic lie it
// replaced.
//
// The value is truthful: whatever image_version holds arrived from a
// registration, and last_seen is the best evidence of when that node was last
// heard from. Backfilling as CONFIRMED rather than leaving pre-existing rows
// unconfirmed is deliberate — "unconfirmed" must mean "an update outcome told
// us to doubt this", not "the api restarted" or "this node is switched off". A
// default that made every powered-down node poison its component's status would
// make the signal noise within a week.
const backfillImageVersionConfirmedAt = `
UPDATE nodes SET image_version_confirmed_at = last_seen
WHERE image_version_confirmed_at = 0 AND image_version != ''`
