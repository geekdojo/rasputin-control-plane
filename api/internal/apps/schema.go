package apps

const schema = `
CREATE TABLE IF NOT EXISTS apps (
    id              TEXT PRIMARY KEY,         -- ULID
    name            TEXT NOT NULL UNIQUE,
    compose_yaml    TEXT NOT NULL,
    target_node     TEXT NOT NULL,            -- node id; resolved against inventory
    published_port  INTEGER NOT NULL DEFAULT 0, -- primary host port for the reverse proxy (0 = none)
    source_tile     TEXT NOT NULL DEFAULT '',  -- catalog tile id this app was installed from ('' = custom compose)
    deploy_budget_s INTEGER NOT NULL DEFAULT 0, -- per-app deploy budget in seconds from the tile (0 = default)
    expose_lan      INTEGER NOT NULL DEFAULT 0, -- LAN exposure opt-in (0 = tailnet-only default); ADR-0004 §9
    web_tls         INTEGER NOT NULL DEFAULT 0, -- the app serves HTTPS on published_port, so dial the upstream over TLS (#387)
    last_status     TEXT NOT NULL DEFAULT 'stopped',
    last_detail     TEXT NOT NULL DEFAULT '',
    last_deployed   INTEGER,
    last_stopped    INTEGER,
    last_status_at  INTEGER,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    backup_ack_at   INTEGER,                  -- §4.4 install-time no-backup acknowledgement (#299); NULL = none was needed
    backup_ack_by   TEXT NOT NULL DEFAULT ''  -- the acknowledging user's name (never a token)
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
	// expose_lan: LAN exposure is an explicit per-app opt-in (ADR-0004 §9).
	// Default 0 = tailnet-only: the app gets only the bare (tailnet) FQDN and
	// its node-local proxy binds the tailnet interface only. 1 adds the .lan
	// FQDN + the LAN-interface bind.
	`ALTER TABLE apps ADD COLUMN expose_lan INTEGER NOT NULL DEFAULT 0`,
	// deploy_budget_s: how long the agent may spend bringing THIS app up, from
	// its catalog tile. 0 means the tile declared nothing, which is every app
	// installed before this column existed — and 0 maps to the default, not to
	// zero patience. See proto.AppDeployWorkFor.
	`ALTER TABLE apps ADD COLUMN deploy_budget_s INTEGER NOT NULL DEFAULT 0`,
	// web_tls: the app speaks HTTPS on published_port, so the node-local proxy
	// must dial its upstream over TLS (#387). 0 — plain HTTP — is right for
	// every app installed before this column existed and for nearly every app
	// since; a tile has to declare it, because the port number does not imply
	// it. Only the Caddy→container leg is affected.
	`ALTER TABLE apps ADD COLUMN web_tls INTEGER NOT NULL DEFAULT 0`,
	// backup_ack_at / backup_ack_by: the §4.4 install-time acknowledgement
	// (#299) — a tile with a `critical` volume installed while no backup target
	// was claimed. NULL for every app installed before this column existed and
	// for every install that needed no acknowledgement; the two are the same
	// answer ("nobody was asked"), and the nag does not read this column, so
	// an old install with no target is nagged exactly like a new one.
	`ALTER TABLE apps ADD COLUMN backup_ack_at INTEGER`,
	`ALTER TABLE apps ADD COLUMN backup_ack_by TEXT NOT NULL DEFAULT ''`,
}
