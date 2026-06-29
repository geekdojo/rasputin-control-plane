package inventory

const schema = `
CREATE TABLE IF NOT EXISTS nodes (
    id            TEXT PRIMARY KEY,
    role          TEXT NOT NULL,
    hostname      TEXT NOT NULL DEFAULT '',
    agent_version TEXT NOT NULL DEFAULT '',
    image_version TEXT NOT NULL DEFAULT '',
    capabilities  TEXT NOT NULL DEFAULT '[]',
    metadata      TEXT NOT NULL DEFAULT '{}',
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
}
