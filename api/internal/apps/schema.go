package apps

const schema = `
CREATE TABLE IF NOT EXISTS apps (
    id              TEXT PRIMARY KEY,         -- ULID
    name            TEXT NOT NULL UNIQUE,
    compose_yaml    TEXT NOT NULL,
    target_node     TEXT NOT NULL,            -- node id; resolved against inventory
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
