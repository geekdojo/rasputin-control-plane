package metrics

const schema = `
CREATE TABLE IF NOT EXISTS metrics (
    node_id TEXT NOT NULL,
    name    TEXT NOT NULL,
    ts      INTEGER NOT NULL,
    value   REAL NOT NULL,
    PRIMARY KEY (node_id, name, ts)
);
-- Range queries scan (node_id, name, ts ascending). The primary key covers it.
`
