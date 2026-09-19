//go:build unix

package atrest_test

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bustls"
	"github.com/geekdojo/rasputin-control-plane/api/internal/dbutil"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The at-rest inventory: every secret file and secret directory the api
// writes, produced by the real code path that writes it, with the mode it
// must have. It is the unit-level seed of the at-rest gate in the QEMU smoke
// test (geekdojo/geekdojo-brain#494), which asserts the same modes on an
// image. A new secret file joins this table in the change that adds it.
//
// Two files the api writes are asserted in their own packages, because the
// code that writes them is not exported: the observability compose file
// (api/internal/obs, TestAtRestModes) and the matched-set seeds written by
// rasputin-provision (api/cmd/rasputin-provision, TestGenerate_AtRestModes).
//
// Every row runs twice. "fresh" starts from an empty data dir, under a zero
// umask, so a loose create mode would show. "existing install" first lays
// the same paths down the way an older api did (directories 0755, files
// 0644) and checks that the next start brings them to the rule.

type want struct {
	rel  string
	mode fs.FileMode
}

type row struct {
	name string
	// seed lays down what an older api left behind, for the existing-install
	// run. Paths are relative to the data dir.
	seedDirs  []string
	seedFiles []string
	// write runs the api code path that owns the files.
	write func(t *testing.T, dataDir string)
	want  []want
}

const (
	dirMode    fs.FileMode = 0o700
	secretMode fs.FileMode = 0o600
	publicMode fs.FileMode = 0o644
)

func rows() []row {
	return []row{
		{
			name:     "bus issuer seed",
			seedDirs: []string{"bus"},
			write: func(t *testing.T, d string) {
				if _, err := busauth.EnsureIssuer(filepath.Join(d, "bus")); err != nil {
					t.Fatal(err)
				}
			},
			want: []want{{"bus", dirMode}, {"bus/" + busauth.IssuerFileName, secretMode}},
		},
		{
			name:     "bus TLS key",
			seedDirs: []string{"bus"},
			write: func(t *testing.T, d string) {
				if _, _, err := bustls.EnsureKey(filepath.Join(d, "bus")); err != nil {
					t.Fatal(err)
				}
			},
			want: []want{{"bus", dirMode}, {"bus/" + bustls.KeyFileName, secretMode}},
		},
		{
			// An existing key laid down 0644 (a seed consumer that forgot the
			// mode) is tightened on load, never replaced.
			name:     "bus TLS key, loosened by a seed consumer",
			seedDirs: []string{"bus"},
			write: func(t *testing.T, d string) {
				dir := filepath.Join(d, "bus")
				if _, _, err := bustls.EnsureKey(dir); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(filepath.Join(dir, bustls.KeyFileName), 0o644); err != nil {
					t.Fatal(err)
				}
				if _, generated, err := bustls.EnsureKey(dir); err != nil || generated {
					t.Fatalf("reload: generated=%v err=%v", generated, err)
				}
			},
			want: []want{{"bus", dirMode}, {"bus/" + bustls.KeyFileName, secretMode}},
		},
		{
			name:     "controlplane agent token",
			seedDirs: []string{"bus"},
			write: func(t *testing.T, d string) {
				st := openBusStore(t, d)
				if _, err := st.EnsureAgentToken(context.Background(), filepath.Join(d, "bus", proto.BusAgentTokenFileName), "cp-1"); err != nil {
					t.Fatal(err)
				}
			},
			want: []want{{"bus/" + proto.BusAgentTokenFileName, secretMode}},
		},
		{
			name:     "revocation tombstones",
			seedDirs: []string{"bus"},
			write: func(t *testing.T, d string) {
				from := filepath.Join(t.TempDir(), "archive-revoked.json")
				if err := os.WriteFile(from, []byte(`{"version":1,"tombstones":[{"hash":"abc","revokedAt":"2026-09-19T00:00:00Z"}]}`), 0o600); err != nil {
					t.Fatal(err)
				}
				if _, err := busauth.MergeTombstoneFiles(filepath.Join(d, "bus", busauth.TombstoneFileName), from); err != nil {
					t.Fatal(err)
				}
			},
			want: []want{{"bus/" + busauth.TombstoneFileName, secretMode}},
		},
		{
			name:     "mesh CA",
			seedDirs: []string{"trust"},
			write: func(t *testing.T, d string) {
				if _, err := mesh.EnsureMeshCA(filepath.Join(d, "trust"), "test"); err != nil {
					t.Fatal(err)
				}
			},
			want: []want{
				{"trust", dirMode},
				{"trust/" + mesh.MeshCAKeyFileName, secretMode},
				{"trust/" + mesh.MeshCAFileName, publicMode}, // a certificate: public by construction
			},
		},
		{
			name:     "api HTTPS leaf and collector leaves",
			seedDirs: []string{"tls", "tls/api", "tls/collectors", "tls/collectors/n1"},
			write: func(t *testing.T, d string) {
				ca := meshCA(t)
				for _, sub := range []string{"tls/api", "tls/collectors/n1"} {
					if _, err := mesh.MintLeafToDisk(ca, filepath.Join(d, sub), mesh.LeafSpec{CommonName: "x", DNSNames: []string{"x"}}); err != nil {
						t.Fatal(err)
					}
				}
			},
			want: []want{
				{"tls/api", dirMode},
				{"tls/api/leaf.key", secretMode},
				{"tls/api/leaf.pem", publicMode},
				{"tls/collectors/n1", dirMode},
				{"tls/collectors/n1/leaf.key", secretMode},
			},
		},
		{
			name:     "app leaf",
			seedDirs: []string{"tls", "tls/apps", "tls/apps/web"},
			write: func(t *testing.T, d string) {
				cert, key, err := mesh.MintLeaf(meshCA(t), mesh.LeafSpec{CommonName: "web", DNSNames: []string{"web"}})
				if err != nil {
					t.Fatal(err)
				}
				if err := mesh.CommitAppLeaf(filepath.Join(d, "tls/apps/web"), cert, key); err != nil {
					t.Fatal(err)
				}
			},
			want: []want{{"tls/apps/web", dirMode}, {"tls/apps/web/leaf.key", secretMode}},
		},
		{
			name:     "mock mesh state (pre-auth keys)",
			seedDirs: []string{"mesh"},
			write: func(t *testing.T, d string) {
				if _, err := mesh.NewMockClient(filepath.Join(d, "mesh")); err != nil {
					t.Fatal(err)
				}
			},
			want: []want{{"mesh", dirMode}, {"mesh/headscale.json", secretMode}},
		},
		{
			name:      "database, WAL and SHM",
			seedFiles: []string{"rasputin.db", "rasputin.db-wal", "rasputin.db-shm"},
			write: func(t *testing.T, d string) {
				p := filepath.Join(d, "rasputin.db")
				// A leftover -wal/-shm pair from an older api is garbage to
				// SQLite unless it matches the database; drop the seeded bytes
				// but keep the files and their loose mode.
				for _, s := range []string{"", "-wal", "-shm"} {
					if _, err := os.Stat(p + s); err == nil {
						if err := os.Truncate(p+s, 0); err != nil {
							t.Fatal(err)
						}
					}
				}
				db, err := dbutil.Open(context.Background(), p, `CREATE TABLE IF NOT EXISTS t (x TEXT)`, "test")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				if _, err := db.Exec(`INSERT INTO t VALUES ('secret')`); err != nil {
					t.Fatal(err)
				}
			},
			// Asserted while the handle is open: -wal and -shm exist only then.
			want: []want{
				{"rasputin.db", secretMode},
				{"rasputin.db-wal", secretMode},
				{"rasputin.db-shm", secretMode},
			},
		},
		{
			name:     "database snapshot for a backup",
			seedDirs: []string{"staging"},
			write: func(t *testing.T, d string) {
				db, err := dbutil.Open(context.Background(), filepath.Join(t.TempDir(), "live.db"), `CREATE TABLE IF NOT EXISTS t (x TEXT)`, "test")
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = db.Close() }()
				if _, err := db.Exec(`INSERT INTO t VALUES ('secret')`); err != nil {
					t.Fatal(err)
				}
				if err := storage.EnsureStagingDir(filepath.Join(d, "staging")); err != nil {
					t.Fatal(err)
				}
				if _, err := storage.SnapshotDB(context.Background(), db, filepath.Join(d, "staging", "snap.db")); err != nil {
					t.Fatal(err)
				}
			},
			want: []want{{"staging/snap.db", secretMode}},
		},
	}
}

func TestAtRestModes(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	for _, r := range rows() {
		for _, existing := range []bool{false, true} {
			name := r.name + "/fresh"
			if existing {
				name = r.name + "/existing install"
			}
			t.Run(name, func(t *testing.T) {
				d := t.TempDir()
				if existing {
					for _, sd := range r.seedDirs {
						if err := os.MkdirAll(filepath.Join(d, sd), 0o755); err != nil {
							t.Fatal(err)
						}
						if err := os.Chmod(filepath.Join(d, sd), 0o755); err != nil {
							t.Fatal(err)
						}
					}
					for _, sf := range r.seedFiles {
						p := filepath.Join(d, sf)
						if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(p, []byte("left by an older api"), 0o644); err != nil {
							t.Fatal(err)
						}
					}
				}
				r.write(t, d)
				for _, w := range r.want {
					info, err := os.Lstat(filepath.Join(d, w.rel))
					if err != nil {
						t.Fatalf("%s: %v", w.rel, err)
					}
					if got := info.Mode().Perm(); got != w.mode {
						t.Errorf("%s: mode %#o, want %#o", w.rel, got, w.mode)
					}
				}
			})
		}
	}
}

func openBusStore(t *testing.T, dataDir string) *busauth.Store {
	t.Helper()
	st, err := busauth.OpenStore(context.Background(), filepath.Join(dataDir, "rasputin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func meshCA(t *testing.T) *mesh.MeshCA {
	t.Helper()
	ca, err := mesh.EnsureMeshCA(t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	return ca
}
