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
    public_key               TEXT NOT NULL DEFAULT '',  -- §4.6's X25519 public key: in clear, deliberately, and the only key material here
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

-- backup_runs: one row per backup.run job (design/storage.md §4.1), created by
-- step 1 and given a terminal status on every path the job can end on.
--
-- Keyed by job_id for the same reason backup_targets is: the row exists before
-- there is a generation to name it by, and a FAILED run needs a row most of all.
-- §4.4 requires failure to be loud in three places — the app tile, the alert
-- path and the job feed. This table is what the first two will read (#298) and
-- what makes "when did a backup last actually succeed?" answerable without
-- walking the job ledger's step results.
--
-- scope is the honest half. Every generation this build writes is
-- 'controlplane-local' (proto.BackupScopeControlplaneLocal): the §4.5 contents
-- list calls for every volume classed critical or state on ANY node, and this
-- build can only reach the ones on the controlplane. app_volumes_captured and
-- app_volumes_skipped are the two halves of that sentence, and the complete
-- column is 1 only when the second is zero.
CREATE TABLE IF NOT EXISTS backup_runs (
    job_id               TEXT PRIMARY KEY,
    target_job_id        TEXT NOT NULL DEFAULT '',  -- the backup_targets row this run wrote to
    part_uuid            TEXT NOT NULL DEFAULT '',
    node_id              TEXT NOT NULL DEFAULT '',
    reason               TEXT NOT NULL DEFAULT '',  -- 'scheduled' | 'manual'
    scope                TEXT NOT NULL DEFAULT '',  -- 'identity-only' | 'full'
    generation_id        TEXT NOT NULL DEFAULT '',
    key_id               TEXT NOT NULL DEFAULT '',
    digest               TEXT NOT NULL DEFAULT '',  -- sha256 over the SEALED bytes; never a key
    size_bytes           INTEGER NOT NULL DEFAULT 0,
    app_volumes_captured INTEGER NOT NULL DEFAULT 0,
    app_volumes_skipped  INTEGER NOT NULL DEFAULT 0,  -- classified volumes NOT captured
    complete             INTEGER NOT NULL DEFAULT 0,  -- 1 only when nothing classified was missed
    warning              TEXT NOT NULL DEFAULT '',    -- a caveat on a row that is not failed
    generations_kept     INTEGER NOT NULL DEFAULT 0,
    generations_pruned   INTEGER NOT NULL DEFAULT 0,
    status               TEXT NOT NULL,  -- 'running' | 'succeeded' | 'failed'
    started_at           INTEGER NOT NULL,
    finished_at          INTEGER,
    error                TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_backup_runs_status ON backup_runs(status, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_backup_runs_started ON backup_runs(started_at DESC);
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
//
// public_key: §4.6's 2026-09-02 amendment. Empty is right for every row written
// before the column existed — those targets were claimed under the symmetric
// design and genuinely have no public key, which is the same thing their
// on-disk markers say. Nothing back-fills it; a target gets one by being
// claimed again.
//
// app_volumes_skipped, complete and warning: #290's second half. 0/0/” is right
// for every row written before the columns existed — those runs captured no app
// volumes and skipped none, because the fan-out enumerated nothing at all, and
// they were honest about it in the only field they had (scope 'identity-only').
// Nothing back-fills them; a row gets them by being written by this build.
var migrations = []string{
	`ALTER TABLE backup_targets ADD COLUMN wiped INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE backup_targets ADD COLUMN public_key TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE backup_runs ADD COLUMN app_volumes_skipped INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE backup_runs ADD COLUMN complete INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE backup_runs ADD COLUMN warning TEXT NOT NULL DEFAULT ''`,
}
