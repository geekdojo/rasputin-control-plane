package obs

import (
	"bytes"
	"context"
	"database/sql"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// legacyGrafanaDB writes a grafana.db holding the data_source rows given, in
// the shape of Grafana's table (the columns the carry reads and writes).
func legacyGrafanaDB(t *testing.T, rows map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "grafana.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE data_source (id INTEGER PRIMARY KEY AUTOINCREMENT,
		org_id INTEGER NOT NULL, name TEXT NOT NULL, uid TEXT NOT NULL DEFAULT 0)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db.Exec(`CREATE UNIQUE INDEX UQE_data_source_org_id_uid ON data_source (org_id, uid)`); err != nil {
		t.Fatalf("index: %v", err)
	}
	for name, uid := range rows {
		if _, err := db.Exec(`INSERT INTO data_source (org_id, name, uid) VALUES (1, ?, ?)`, name, uid); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	return path
}

// storedDatasources reads back name -> (id, uid).
func storedDatasources(t *testing.T, path string) map[string][2]string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT id, name, uid FROM data_source`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	out := map[string][2]string{}
	for rows.Next() {
		var id, name, uid string
		if err := rows.Scan(&id, &name, &uid); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[name] = [2]string{id, uid}
	}
	return out
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prev); log.SetFlags(flags) })
	return &buf
}

// TC-999-07 (the datasource-uid transition from the derived uid): a database
// holding both datasources under Grafana's derived uids gets the fixed uids,
// in the same rows, logged once each; the next Start writes and logs nothing.
func TestCarryDatasourceUIDs_DerivedUIDsTakeTheFixedOnesInPlace(t *testing.T) {
	path := legacyGrafanaDB(t, map[string]string{
		"VictoriaMetrics": "P4169E866C3094E38",
		"Loki":            "P8E80F9AEF21F6940",
	})
	before := storedDatasources(t, path)
	logs := captureLog(t)

	if err := carryDatasourceUIDs(context.Background(), path); err != nil {
		t.Fatalf("carry: %v", err)
	}
	after := storedDatasources(t, path)
	for name, uid := range map[string]string{"VictoriaMetrics": vmDatasourceUID, "Loki": lokiDatasourceUID} {
		if after[name][1] != uid {
			t.Errorf("%s uid = %q, want %q", name, after[name][1], uid)
		}
		if after[name][0] != before[name][0] {
			t.Errorf("%s row id %s -> %s; want the same row", name, before[name][0], after[name][0])
		}
	}
	for _, want := range []string{
		`carried Grafana datasource "VictoriaMetrics" from its derived uid "P4169E866C3094E38" to the fixed uid "rasputin-victoriametrics"`,
		`carried Grafana datasource "Loki" from its derived uid "P8E80F9AEF21F6940" to the fixed uid "rasputin-loki"`,
	} {
		if strings.Count(logs.String(), want) != 1 {
			t.Errorf("log does not say once: %s\n---\n%s", want, logs)
		}
	}

	logs.Reset()
	if err := carryDatasourceUIDs(context.Background(), path); err != nil {
		t.Fatalf("second carry: %v", err)
	}
	if logs.Len() != 0 {
		t.Errorf("a carried database was carried again: %s", logs)
	}
}

// A fresh install (no database yet), a database Grafana never got as far as
// its datasource table in, and one already at the fixed uids are left alone
// and logged about by nothing.
func TestCarryDatasourceUIDs_NothingToCarry(t *testing.T) {
	logs := captureLog(t)

	missing := filepath.Join(t.TempDir(), "grafana.db")
	if err := carryDatasourceUIDs(context.Background(), missing); err != nil {
		t.Errorf("no database: %v", err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Errorf("the carry created %s (stat: %v)", missing, err)
	}

	empty := filepath.Join(t.TempDir(), "grafana.db")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := carryDatasourceUIDs(context.Background(), empty); err != nil {
		t.Errorf("database without data_source: %v", err)
	}

	fixed := legacyGrafanaDB(t, map[string]string{"VictoriaMetrics": vmDatasourceUID})
	if err := carryDatasourceUIDs(context.Background(), fixed); err != nil {
		t.Errorf("already fixed: %v", err)
	}
	if got := storedDatasources(t, fixed)["VictoriaMetrics"][1]; got != vmDatasourceUID {
		t.Errorf("fixed uid changed to %q", got)
	}
	if logs.Len() != 0 {
		t.Errorf("nothing to carry, but logged: %s", logs)
	}
}

// ERR-WRAP: a database that cannot be read stops Start with an error naming
// it, instead of letting Grafana start on a datasource it cannot provision.
func TestCarryDatasourceUIDs_UnreadableDatabaseIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grafana.db")
	if err := os.WriteFile(path, []byte("this is not a sqlite database, it is long enough to have a header"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := carryDatasourceUIDs(context.Background(), path)
	if err == nil || !strings.Contains(err.Error(), "grafana datasource uid carry") {
		t.Fatalf("err = %v, want a carry error", err)
	}
}
