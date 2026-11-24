package obs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// fixedDatasourceUIDs is each provisioned datasource's name and the uid the
// provisioning gives it (grafanaDatasourcesYAML).
var fixedDatasourceUIDs = []struct{ name, uid string }{
	{"VictoriaMetrics", vmDatasourceUID},
	{"Loki", lokiDatasourceUID},
}

// carryDatasourceUIDs moves a provisioned datasource still stored under a
// uid Grafana derived from its name (a cluster never updated past v2026.09.4,
// see the comment on vmDatasourceUID) to its fixed uid, in Grafana's own
// database, before Grafana starts on it.
//
// Grafana 11.5.1 did this itself: it matched the provisioned datasource to
// the stored row by name and rewrote the uid. Grafana 13.3.1 refuses
// instead: provisioning fails with "Datasource provisioning error: data
// source not found", and Grafana never opens its socket (measured,
// TestGrafanaDatasourceUID_TransitionFromAutoUID). So the supervisor makes
// the same one-row change 11.5.1 made, with the same row id kept.
//
// The trigger is the stored fact, read on every Start: a row with the name
// and a different uid. When there is none (a fresh install, or a database
// already carried) nothing is written. Each carried row is logged once, on
// the Start that carries it.
//
// The database is opened with Grafana's own journal mode untouched: Rasputin's
// dbutil pragmas (WAL) would change it, and leave sidecar files Grafana's
// unprivileged user cannot open.
func carryDatasourceUIDs(ctx context.Context, dbPath string) error {
	if _, err := os.Stat(dbPath); errors.Is(err, fs.ErrNotExist) {
		return nil // Grafana has never run here: nothing to carry.
	} else if err != nil {
		return fmt.Errorf("grafana datasource uid carry: %w", err)
	}
	db, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return fmt.Errorf("grafana datasource uid carry: open %s: %w", dbPath, err)
	}
	defer db.Close()

	var tables int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'data_source'`).Scan(&tables); err != nil {
		return fmt.Errorf("grafana datasource uid carry: read %s: %w", dbPath, err)
	}
	if tables == 0 {
		return nil // Grafana never got as far as its datasource table.
	}
	for _, ds := range fixedDatasourceUIDs {
		var old string
		err := db.QueryRowContext(ctx,
			`SELECT uid FROM data_source WHERE org_id = 1 AND name = ?`, ds.name).Scan(&old)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && old == ds.uid) {
			continue
		}
		if err != nil {
			return fmt.Errorf("grafana datasource uid carry: read datasource %q: %w", ds.name, err)
		}
		if _, err := db.ExecContext(ctx,
			`UPDATE data_source SET uid = ? WHERE org_id = 1 AND name = ? AND uid = ?`,
			ds.uid, ds.name, old); err != nil {
			return fmt.Errorf("grafana datasource uid carry: datasource %q from uid %q to %q: %w",
				ds.name, old, ds.uid, err)
		}
		log.Printf("obs supervisor: carried Grafana datasource %q from its derived uid %q to the fixed uid %q (%s)",
			ds.name, old, ds.uid, filepath.Base(dbPath))
	}
	return nil
}
