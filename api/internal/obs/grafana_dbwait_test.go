//go:build linux || supervisor

package obs

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// starterDashboardUID is the fixed uid in the provisioned cluster-overview
// dashboard JSON.
const starterDashboardUID = "rasputin-cluster-overview"

// waitForProvisionedDashboardRow waits until Grafana has committed the starter
// dashboard to its OWN database. That is the checkable fact every test that
// searches Grafana must wait on before its first authenticated request.
//
// Why a fact and not a timeout: on a fresh Grafana 11.5.1 database, an
// authenticated request that arrives before first-boot provisioning has
// finished leaves the dashboard invisible to search for a while afterwards —
// a fixed 60s on an idle host (measured: 7 of 8 racing trials), but longer
// when provisioning itself is slow (one run under load exceeded 120s). The
// same happens with main's configuration, so it predates the socket change.
// Once the row is committed, the FIRST authenticated search sees the
// dashboard (measured: 8 of 8), so after this the tests read once, with no
// deadline deciding the outcome.
//
// The deadline here bounds only how long provisioning may take to commit
// the row at all; it reads <state>/grafana-data/grafana.db read-only.
func waitForProvisionedDashboardRow(t *testing.T, stateDir string, within time.Duration) {
	t.Helper()
	dbPath := filepath.Join(stateDir, grafanaDataDir, "grafana.db")
	deadline := time.Now().Add(within)
	var lastErr error
	for {
		if found, err := dashboardRowExists(dbPath); err == nil && found {
			return
		} else if err != nil {
			lastErr = err
		}
		if time.Now().After(deadline) {
			t.Fatalf("Grafana never committed dashboard %q to %s within %s (last error: %v)",
				starterDashboardUID, dbPath, within, lastErr)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func dashboardRowExists(dbPath string) (bool, error) {
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro&_pragma=busy_timeout(2000)")
	if err != nil {
		return false, err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var n int
	err = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM dashboard WHERE uid = ?`, starterDashboardUID).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}
