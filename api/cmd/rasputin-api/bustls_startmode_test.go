package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bustls"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// busTLSStartMode is the resolver that runs against the real database: it
// opens the settings store and the inventory itself, so every way either can
// be absent, empty, malformed or unreadable is exercised here on disk rather
// than through bustls.ResolveStartMode's interfaces (R06 in
// .github/security-resolvers.tsv; the rules are geekdojo/geekdojo-brain#510).
//
// The CLOSED outcome for a bus mode is never a weaker rung than the one the
// cluster is owed:
//
//   - a recorded mode, or a valid RASPUTIN_BUS_TLS pin, is honoured;
//   - nothing recorded on a fresh cluster is require;
//   - anything malformed or unreadable — the mode, the env pin, the settings
//     store, or the inventory the facts come from — is require when every
//     enrolled node has reported bus TLS and migrate otherwise, always with a
//     fault, and NEVER offer.
//
// offer, the rung that accepts plaintext from anyone and hands out no pin, is
// owed in exactly one case: an existing fleet, read cleanly, that has recorded
// nothing and has not climbed the ladder yet. It is the first row, so that the
// no-offer assertion below is visibly an exception of one.
func TestBusTLSStartMode_FailsClosedOnEveryShapeOfInput(t *testing.T) {
	const absent = "\x00absent"
	for _, tc := range []struct {
		name string
		env  string // absent means RASPUTIN_BUS_TLS is not in the environment at all
		tls  bool   // whether the bus key loaded
		// db prepares the database at path: the settings row, the fleet, or
		// the fault. It may replace path with something that is not a
		// database at all.
		db func(t *testing.T, path string)

		want     bustls.Mode
		pinned   bool
		derived  bool
		faulted  bool
		mayOffer bool // true only on the one row where offer is owed
	}{
		// --- absent -------------------------------------------------------
		{name: "absent: nothing recorded, a fleet not all on TLS — the ladder's gates decide",
			env: absent, tls: true, db: fleet(false),
			want: bustls.ModeOffer, mayOffer: true},
		{name: "absent: nothing recorded, a fresh cluster",
			env: absent, tls: true, db: fleet0,
			want: bustls.ModeRequire, derived: true},
		{name: "absent: nothing recorded, a fresh cluster whose bus key did not load",
			env: absent, tls: false, db: fleet0,
			want: bustls.ModeMigrate, derived: true},
		{name: "absent: a recorded require on a fleet not all on TLS is kept",
			env: absent, tls: true, db: both(fleet(false), setting("require")),
			want: bustls.ModeRequire},

		// --- empty --------------------------------------------------------
		{name: "empty env pin: the recorded require is still read",
			env: "", tls: true, db: both(fleet(false), setting("require")),
			want: bustls.ModeRequire},
		{name: "blank env pin: the recorded require is still read",
			env: " \t ", tls: true, db: both(fleet(false), setting("require")),
			want: bustls.ModeRequire},
		{name: "blank env pin on a fresh cluster",
			env: "  ", tls: true, db: fleet0,
			want: bustls.ModeRequire, derived: true},
		{name: "blank setting row on a fresh cluster",
			env: absent, tls: true, db: both(fleet0, setting("   ")),
			want: bustls.ModeRequire, derived: true},

		// --- malformed ----------------------------------------------------
		{name: "malformed setting, every node on TLS",
			env: absent, tls: true, db: both(fleet(true), setting("bogus")),
			want: bustls.ModeRequire, derived: true, faulted: true},
		{name: "malformed setting, a node not on TLS",
			env: absent, tls: true, db: both(fleet(false), setting("bogus")),
			want: bustls.ModeMigrate, derived: true, faulted: true},
		{name: "malformed setting, bus key did not load",
			env: absent, tls: false, db: both(fleet(true), setting("bogus")),
			want: bustls.ModeMigrate, derived: true, faulted: true},
		{name: "malformed env pin, every node on TLS",
			env: "yes", tls: true, db: fleet(true),
			want: bustls.ModeRequire, derived: true, faulted: true},
		{name: "malformed env pin, a node not on TLS",
			env: "off", tls: true, db: fleet(false),
			want: bustls.ModeMigrate, derived: true, faulted: true},
		{name: "a valid env pin is the operator's escape hatch and is honoured",
			env: " Migrate ", tls: true, db: both(fleet(true), setting("require")),
			want: bustls.ModeMigrate, pinned: true},
		{name: "a node whose recorded bus TLS is not a bool counts as not on TLS",
			env: absent, tls: true, db: both(nodesWith(true, "yes"), setting("bogus")),
			want: bustls.ModeMigrate, derived: true, faulted: true},

		// --- unreadable ---------------------------------------------------
		{name: "settings row unreadable, every node on TLS",
			env: absent, tls: true, db: both(unreadableSettingsTable, fleet(true)),
			want: bustls.ModeRequire, derived: true, faulted: true},
		{name: "settings row unreadable, a node not on TLS",
			env: absent, tls: true, db: both(unreadableSettingsTable, fleet(false)),
			want: bustls.ModeMigrate, derived: true, faulted: true},
		{name: "settings store will not open, every node on TLS",
			env: absent, tls: true, db: both(fleet(true), unopenableSettingsStore),
			want: bustls.ModeRequire, derived: true, faulted: true},
		{name: "settings store will not open, a node not on TLS",
			env: absent, tls: true, db: both(fleet(false), unopenableSettingsStore),
			want: bustls.ModeMigrate, derived: true, faulted: true},
		{name: "settings store will not open on a fresh cluster",
			env: absent, tls: true, db: both(fleet0, unopenableSettingsStore),
			want: bustls.ModeRequire, derived: true, faulted: true},
		{name: "database will not open at all",
			env: absent, tls: true, db: notADatabase,
			want: bustls.ModeMigrate, derived: true, faulted: true},

		// --- probe error: the inventory the facts come from ---------------
		{name: "inventory unreadable, nothing recorded",
			env: absent, tls: true, db: unreadableInventory,
			want: bustls.ModeMigrate, derived: true, faulted: true},
		{name: "inventory unreadable, malformed setting",
			env: absent, tls: true, db: both(unreadableInventory, setting("bogus")),
			want: bustls.ModeMigrate, derived: true, faulted: true},
		{name: "inventory unreadable, a recorded require is kept",
			env: absent, tls: true, db: both(unreadableInventory, setting("require")),
			want: bustls.ModeRequire},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.env == absent {
				t.Setenv(bustls.EnvMode, "") // registers the restore
				if err := os.Unsetenv(bustls.EnvMode); err != nil {
					t.Fatal(err)
				}
			} else {
				t.Setenv(bustls.EnvMode, tc.env)
			}
			path := filepath.Join(t.TempDir(), "rasputin.db")
			tc.db(t, path)

			got := busTLSStartMode(context.Background(), path, tc.tls)

			if got.Mode == bustls.ModeOffer && !tc.mayOffer {
				t.Fatalf("resolved to offer: %+v", got)
			}
			if got.Mode != tc.want || got.Pinned != tc.pinned || got.Derived != tc.derived || (got.Fault != "") != tc.faulted {
				t.Fatalf("got %+v\nwant mode=%s pinned=%t derived=%t faulted=%t", got, tc.want, tc.pinned, tc.derived, tc.faulted)
			}
			if !tc.tls && got.Mode == bustls.ModeRequire {
				t.Fatalf("resolved to require with no bus key to serve TLS: %+v", got)
			}
		})
	}
}

// --- database fixtures --------------------------------------------------------

func both(fs ...func(*testing.T, string)) func(*testing.T, string) {
	return func(t *testing.T, path string) {
		for _, f := range fs {
			f(t, path)
		}
	}
}

func setting(v string) func(*testing.T, string) {
	return func(t *testing.T, path string) {
		t.Helper()
		st, err := setup.OpenStore(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = st.Close() }()
		if err := st.Set(context.Background(), bustls.SettingKey, v); err != nil {
			t.Fatal(err)
		}
	}
}

// fleet0 is a fresh cluster: an inventory that opens and holds no node.
func fleet0(t *testing.T, path string) { nodesWith()(t, path) }

// fleet is two enrolled nodes, both on bus TLS or one not.
func fleet(allTLS bool) func(*testing.T, string) {
	if allTLS {
		return nodesWith(true, true)
	}
	return nodesWith(true, false)
}

// nodesWith enrolls one node per value, each recording that value as its bus
// TLS report.
func nodesWith(busTLS ...any) func(*testing.T, string) {
	return func(t *testing.T, path string) {
		t.Helper()
		inv, err := inventory.OpenStore(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = inv.Close() }()
		now := time.Now()
		for i, v := range busTLS {
			n := &proto.Node{
				ID: "n" + string(rune('a'+i)), Role: proto.RoleCompute, Hostname: "n",
				Metadata:  map[string]any{proto.MetadataBusTLS: v},
				FirstSeen: now, LastSeen: now,
			}
			if err := inv.Insert(context.Background(), n); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// unreadableSettingsTable leaves a settings table the store opens against
// (its CREATE TABLE IF NOT EXISTS is a no-op) but cannot read a value from.
func unreadableSettingsTable(t *testing.T, path string) {
	t.Helper()
	rawExec(t, path, `CREATE TABLE settings (key TEXT PRIMARY KEY, updated_at INTEGER NOT NULL DEFAULT 0)`)
}

// unopenableSettingsStore takes the settings table's name with an index, so
// the settings store's schema will not apply and the store will not open,
// while the inventory beside it still reads.
func unopenableSettingsStore(t *testing.T, path string) {
	t.Helper()
	rawExec(t, path, `CREATE INDEX settings ON nodes(id)`)
}

// unreadableInventory leaves an inventory holding a row that cannot be
// scanned, so neither opening it nor listing it yields the fleet.
func unreadableInventory(t *testing.T, path string) {
	t.Helper()
	nodesWith(true)(t, path)
	rawExec(t, path, `UPDATE nodes SET first_seen = 'not a time'`)
}

// notADatabase puts a directory where the database file should be.
func notADatabase(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func rawExec(t *testing.T, path, stmt string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(context.Background(), stmt); err != nil {
		t.Fatal(err)
	}
}
