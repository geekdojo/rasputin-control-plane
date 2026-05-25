package jobs

const schema = `
CREATE TABLE IF NOT EXISTS jobs (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    spec        TEXT NOT NULL,
    status      TEXT NOT NULL,
    created_by  TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    started_at  INTEGER,
    finished_at INTEGER,
    parent_id   TEXT,
    error       TEXT
);
CREATE INDEX IF NOT EXISTS idx_jobs_status     ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs(created_at);

CREATE TABLE IF NOT EXISTS job_steps (
    job_id      TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    name        TEXT NOT NULL,
    status      TEXT NOT NULL,
    started_at  INTEGER,
    finished_at INTEGER,
    attempt     INTEGER NOT NULL DEFAULT 0,
    result      TEXT,
    error       TEXT,
    PRIMARY KEY (job_id, seq)
);

CREATE TABLE IF NOT EXISTS job_events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT    NOT NULL,
    ts     INTEGER NOT NULL,
    type   TEXT    NOT NULL,
    data   TEXT
);
CREATE INDEX IF NOT EXISTS idx_job_events_job_id ON job_events(job_id, id);
`
