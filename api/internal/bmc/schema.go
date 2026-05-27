package bmc

const schema = `
CREATE TABLE IF NOT EXISTS bmc_state (
    target_node_id  TEXT PRIMARY KEY,
    power_state     TEXT NOT NULL DEFAULT 'unknown',
    last_cmd        TEXT NOT NULL DEFAULT '',
    last_cmd_at     INTEGER,
    last_cmd_result TEXT NOT NULL DEFAULT '',
    updated_at      INTEGER NOT NULL
);
`
