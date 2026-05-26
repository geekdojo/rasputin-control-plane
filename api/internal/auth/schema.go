package auth

const schema = `
CREATE TABLE IF NOT EXISTS users (
    id            BLOB PRIMARY KEY,        -- 16-byte WebAuthn user handle
    name          TEXT NOT NULL UNIQUE,    -- login-name slug
    display_name  TEXT NOT NULL,           -- human-friendly name
    created_at    INTEGER NOT NULL,
    last_login_at INTEGER
);

CREATE TABLE IF NOT EXISTS credentials (
    id              BLOB PRIMARY KEY,      -- the credential's raw ID
    user_id         BLOB NOT NULL,
    public_key      BLOB NOT NULL,         -- COSE-encoded public key
    attestation     TEXT NOT NULL DEFAULT '',
    transports      TEXT NOT NULL DEFAULT '[]',
    aaguid          BLOB,
    sign_count      INTEGER NOT NULL DEFAULT 0,
    clone_warning   INTEGER NOT NULL DEFAULT 0,
    nickname        TEXT NOT NULL DEFAULT '',
    created_at      INTEGER NOT NULL,
    last_used_at    INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials(user_id);

CREATE TABLE IF NOT EXISTS sessions (
    token          TEXT PRIMARY KEY,       -- random 32-byte hex
    user_id        BLOB NOT NULL,
    created_at     INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    last_active_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id    ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
`
