package apps

const schema = `
CREATE TABLE IF NOT EXISTS apps (
    id              TEXT PRIMARY KEY,         -- ULID
    name            TEXT NOT NULL UNIQUE,
    compose_yaml    TEXT NOT NULL,
    target_node     TEXT NOT NULL,            -- node id; resolved against inventory
    published_port  INTEGER NOT NULL DEFAULT 0, -- primary host port for the reverse proxy (0 = none)
    source_tile     TEXT NOT NULL DEFAULT '',  -- catalog tile id this app was installed from ('' = custom compose)
    last_status     TEXT NOT NULL DEFAULT 'stopped',
    last_detail     TEXT NOT NULL DEFAULT '',
    last_deployed   INTEGER,
    last_stopped    INTEGER,
    last_status_at  INTEGER,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_apps_target_node ON apps(target_node);
CREATE INDEX IF NOT EXISTS idx_apps_status      ON apps(last_status);
`

// migrations are forward-only DDL applied after schema on every open. They must
// tolerate re-runs — applyMigrations swallows "duplicate column" errors, which
// is the expected outcome on a DB that already has the column (and on a fresh
// DB where schema above already created it).
//
// published_port: Guard #1 from app-access.md — the reverse proxy needs the
// app's primary host port as structured data, not buried in compose_yaml text.
// Seeded from the catalog tile at install; 0 for hand-authored compose apps
// until we extract it (or the user sets it).
var migrations = []string{
	`ALTER TABLE apps ADD COLUMN published_port INTEGER NOT NULL DEFAULT 0`,
	// source_tile: the catalog tile an app was installed from (AP-9). Lets the
	// UI show the tile's docs / description / first-run note for a running app.
	// '' for hand-authored (custom compose) apps.
	`ALTER TABLE apps ADD COLUMN source_tile TEXT NOT NULL DEFAULT ''`,
}
