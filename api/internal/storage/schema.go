package storage

// schema is the backup_targets ledger: one row per claim ATTEMPT, keyed by the
// job that made it.
//
// Keyed by job_id rather than by partition UUID, deliberately. A row is created
// at step 1, before any disk has been touched and therefore before a partition
// UUID exists — and a failed claim still needs a row, because "the claim you
// started an hour ago failed at enumerate" is the single most useful thing the
// Backup view can say. The partition UUID arrives at step 5 and is the
// identifier everything DOWNSTREAM of a successful claim uses.
//
// Rows are never deleted. A superseded target becomes `replaced`, because the
// disk it names may still be on a shelf holding the only copy of an archive,
// and this row is the only place an operator can learn that it exists.
const schema = `
CREATE TABLE IF NOT EXISTS backup_targets (
    job_id                   TEXT PRIMARY KEY,
    node_id                  TEXT NOT NULL,
    label                    TEXT NOT NULL DEFAULT '',
    part_uuid                TEXT NOT NULL DEFAULT '',
    device_path              TEXT NOT NULL DEFAULT '',
    mount_path               TEXT NOT NULL DEFAULT '',
    fs_type                  TEXT NOT NULL DEFAULT '',
    size_bytes               INTEGER NOT NULL DEFAULT 0,
    fingerprint              TEXT NOT NULL DEFAULT '',
    key_id                   TEXT NOT NULL DEFAULT '',
    key_alg                  TEXT NOT NULL DEFAULT '',
    wrapped_by_passphrase    TEXT NOT NULL DEFAULT '',
    wrapped_by_recovery_code TEXT NOT NULL DEFAULT '',
    adopted                  INTEGER NOT NULL DEFAULT 0,
    wiped                    INTEGER NOT NULL DEFAULT 0,  -- §4.8's second, separate choice: this claim destroyed an existing backup set
    status                   TEXT NOT NULL,  -- 'pending' | 'claimed' | 'replaced' | 'failed'
    created_at               INTEGER NOT NULL,
    claimed_at               INTEGER,
    error                    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_backup_targets_status ON backup_targets(status);
CREATE INDEX IF NOT EXISTS idx_backup_targets_node ON backup_targets(node_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_backup_targets_partuuid ON backup_targets(part_uuid);
`

// migrations are forward-only DDL applied after schema on every open, and must
// tolerate re-runs — applyMigrations swallows "duplicate column", which is the
// expected outcome both on a DB that already has the column and on a fresh one
// where the CREATE TABLE above already made it.
//
// wiped: the counterpart of `adopted`. Present in the CREATE TABLE for a new
// ledger and added here for one that was created before the wipe verb existed —
// a developer database from the claim branch. 0 is right for every row written
// before the column existed: none of them could have wiped anything, because
// nothing could.
var migrations = []string{
	`ALTER TABLE backup_targets ADD COLUMN wiped INTEGER NOT NULL DEFAULT 0`,
}
