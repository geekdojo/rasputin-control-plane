//go:build unix

package atrest_test

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/bmc"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/docker"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/hostsync"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/openwrt"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/proxy"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/tailscale"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/updater"
)

// The at-rest inventory: every file and directory the agent writes, produced
// by the real code path that writes it, with the mode it must have. It is the
// unit-level seed of the at-rest gate in the QEMU smoke test
// (geekdojo/geekdojo-brain#494), which asserts the same modes on an image. A
// new file the agent writes joins this table in the change that adds it.
//
// The rule the table encodes: everything the agent keeps in its own state tree
// is 0600 in 0700 directories, and the only files another process reads — the
// systemd-resolved drop-in and the dnsmasq hosts file, both written OUTSIDE
// that tree — are 0644 in 0755 directories, set explicitly rather than left to
// the umask.
//
// Four writes are asserted in their own packages, because the code that writes
// them is not exported:
//   - the app compose file and the anonymous-volume record, by the real docker
//     backend (agent/internal/docker, TestAtRestModes), which also covers
//     TightenAppState over an existing install;
//   - the systemd-resolved drop-in (agent/internal/clusterdns, TestAtRestModes);
//   - the openwrt manifest (agent/internal/openwrt, TestAtRestModes);
//   - the BMC selection pushed by settings (agent/internal/bmc, TestAtRestModes).
//
// The agent's state ROOT is created in main() (agent/cmd/rasputin-agent), which
// no test can import; it is covered by the functional run recorded on the PR.
//
// Every row runs twice. "fresh" starts from an empty state dir, under a zero
// umask, so a loose create mode would show. "existing install" first lays the
// same paths down the way an older agent did (directories 0755, files 0644)
// and checks that writing them again brings them to the rule.

type want struct {
	rel  string
	mode fs.FileMode
}

type row struct {
	name string
	// seed lays down what an older agent left behind, for the
	// existing-install run. Paths are relative to the state dir.
	seedDirs  []string
	seedFiles []string
	// write runs the agent code path that owns the files.
	write func(t *testing.T, stateDir string)
	want  []want
}

const (
	dirMode       fs.FileMode = 0o700
	secretMode    fs.FileMode = 0o600
	publicDirMode fs.FileMode = 0o755
	publicMode    fs.FileMode = 0o644
)

func rows() []row {
	return []row{
		{
			name:     "app compose and state, mock backend",
			seedDirs: []string{"apps", "apps/app1"},
			seedFiles: []string{
				"apps/app1/docker-compose.yml",
				"apps/app1/state.json",
			},
			write: func(t *testing.T, d string) {
				b, err := docker.NewMockBackend(filepath.Join(d, "apps"))
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := b.Deploy(context.Background(), "app1", "app one", "services: {}\n"); err != nil {
					t.Fatal(err)
				}
			},
			want: []want{
				{"apps", dirMode},
				{"apps/app1", dirMode},
				// The compose can carry a private key: the api renders the
				// observability collector's with that node's mesh leaf inline.
				{"apps/app1/docker-compose.yml", secretMode},
				{"apps/app1/state.json", secretMode},
			},
		},
		{
			name:      "app TLS leaf",
			seedDirs:  []string{"proxy", "proxy/certs", "proxy/certs/app1"},
			seedFiles: []string{"proxy/certs/app1/leaf.key", "proxy/certs/app1/leaf.pem", "proxy/certs/app1/meta.json"},
			write: func(t *testing.T, d string) {
				st := proxy.NewLeafStore(filepath.Join(d, "proxy"))
				err := st.Write("app1", []byte("-----BEGIN CERTIFICATE-----\n"), []byte("-----BEGIN PRIVATE KEY-----\n"),
					proxy.RouteMeta{TailnetFQDN: "app1.tailnet", UpstreamPort: 8080})
				if err != nil {
					t.Fatal(err)
				}
			},
			want: []want{
				{"proxy/certs/app1", dirMode},
				{"proxy/certs/app1/leaf.key", secretMode},
				{"proxy/certs/app1/leaf.pem", publicMode}, // a certificate: public by construction
				{"proxy/certs/app1/meta.json", secretMode},
			},
		},
		{
			name:      "mesh CA bundle and tailscale state",
			seedDirs:  []string{"mesh"},
			seedFiles: []string{"mesh/tailscale.json", "mesh/tailscaled-ca.pem"},
			write: func(t *testing.T, d string) {
				b, err := tailscale.NewMockBackend(filepath.Join(d, "mesh"))
				if err != nil {
					t.Fatal(err)
				}
				// Enroll is what installs a delivered Mesh CA, through the same
				// installMeshCA the real backend uses (agent/internal/
				// tailscale/trust.go) — the directory in
				// geekdojo/geekdojo-brain#144.
				if _, err := b.Enroll(context.Background(), tailscale.EnrollInput{
					AuthKey:   "tskey-auth-test",
					Hostname:  "node-1",
					MeshCAPEM: []byte("-----BEGIN CERTIFICATE-----\nmesh\n-----END CERTIFICATE-----\n"),
				}); err != nil {
					t.Fatal(err)
				}
			},
			want: []want{
				{"mesh", dirMode},
				{"mesh/tailscale.json", secretMode},
				{"mesh/tailscaled-ca.pem", publicMode}, // a CA certificate: public by construction
			},
		},
		{
			name:      "BMC mock state",
			seedDirs:  []string{"bmc"},
			seedFiles: []string{"bmc/bmc.json"},
			write: func(t *testing.T, d string) {
				if _, err := bmc.NewMockBackend(filepath.Join(d, "bmc")); err != nil {
					t.Fatal(err)
				}
			},
			want: []want{{"bmc", dirMode}, {"bmc/bmc.json", secretMode}},
		},
		{
			name:      "firewall state, mock backend",
			seedDirs:  []string{"openwrt"},
			seedFiles: []string{"openwrt/firewall.json", "openwrt/active"},
			write: func(t *testing.T, d string) {
				c, err := openwrt.NewMockClient(filepath.Join(d, "openwrt"))
				if err != nil {
					t.Fatal(err)
				}
				// The pushed state carries the WAN credentials when the owner
				// has set them.
				if _, err := c.Apply(context.Background(), map[string]any{
					"network": map[string]any{"proto": "pppoe", "username": "isp-user", "password": "isp-secret"},
				}); err != nil {
					t.Fatal(err)
				}
				if err := c.SetActive(context.Background(), true); err != nil {
					t.Fatal(err)
				}
			},
			want: []want{
				{"openwrt", dirMode},
				{"openwrt/firewall.json", secretMode},
				{"openwrt/active", secretMode},
			},
		},
		{
			name:      "updater state and bundle cache",
			seedDirs:  []string{"updater", "updater/bundles"},
			seedFiles: []string{"updater/state.json"},
			write: func(t *testing.T, d string) {
				if _, err := updater.NewMockBackend(filepath.Join(d, "updater")); err != nil {
					t.Fatal(err)
				}
			},
			want: []want{
				{"updater/bundles", dirMode},
				{"updater/state.json", secretMode},
			},
		},
		{
			// PUBLIC by design, and outside the state tree: dnsmasq reads this
			// directory after dropping to its own user. An owner-only mode here
			// stops the control plane's name resolving on the firewall's LAN.
			name:      "dnsmasq hosts entry",
			seedDirs:  []string{"hosts"},
			seedFiles: []string{"hosts/rasputin.local"},
			write: func(t *testing.T, d string) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				dir := filepath.Join(d, "hosts")
				done := make(chan struct{})
				go func() {
					defer close(done)
					hostsync.Run(ctx, "rasputin.local", dir, time.Hour, "",
						func() string { return "10.0.0.9" })
				}()
				waitForFile(t, filepath.Join(dir, "rasputin.local"), "10.0.0.9 rasputin.local\n")
				cancel()
				<-done
			},
			want: []want{
				{"hosts", publicDirMode},
				{"hosts/rasputin.local", publicMode},
			},
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
					seedOldInstall(t, d, r)
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

// seedOldInstall lays down what an agent before this change left on disk:
// directories 0755 and files 0644, holding content the new write must replace
// or leave alone without leaving the old mode behind.
func seedOldInstall(t *testing.T, dataDir string, r row) {
	t.Helper()
	for _, sd := range r.seedDirs {
		p := filepath.Join(dataDir, sd)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, sf := range r.seedFiles {
		p := filepath.Join(dataDir, sf)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// waitForFile blocks until path holds want, or the deadline passes. The
// hostsync row runs a loop in a goroutine, so there is nothing else to
// synchronise on; the wait is bounded so a regression fails rather than hangs.
func waitForFile(t *testing.T, path, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil && string(b) == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s never held %q", path, want)
}
