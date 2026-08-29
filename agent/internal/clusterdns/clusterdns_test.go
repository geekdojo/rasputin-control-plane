package clusterdns

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testCfg(t *testing.T, reloads *int) Config {
	t.Helper()
	return Config{
		ClusterID: "rasputin",
		ServerIP:  "192.168.197.224",
		Dir:       filepath.Join(t.TempDir(), "resolved.conf.d"),
		reload:    func(context.Context) error { *reloads++; return nil },
	}
}

func TestDomainsAreRoutingOnly(t *testing.T) {
	// The "~" prefix is the whole safety argument: without it this would make
	// the control plane the node's resolver for everything, and the CP
	// nameserver REFUSEs off-zone names — general DNS on the node would break.
	for _, d := range Domains("rasputin") {
		if !strings.HasPrefix(d, "~") {
			t.Errorf("domain %q is not routing-only; it would capture all DNS", d)
		}
	}
	want := []string{"~rasputin.local", "~rasputin.internal"}
	got := Domains("rasputin")
	if len(got) != len(want) {
		t.Fatalf("Domains() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Domains()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRenderContainsDNSAndDomains(t *testing.T) {
	body := Render("home1", "10.0.0.5")
	for _, want := range []string{
		"[Resolve]",
		"DNS=10.0.0.5",
		"Domains=~home1.local ~home1.internal",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered config missing %q:\n%s", want, body)
		}
	}
}

func TestApplyWritesAndReloads(t *testing.T) {
	reloads := 0
	cfg := testCfg(t, &reloads)

	changed, err := Apply(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !changed {
		t.Error("first Apply reported no change")
	}
	if reloads != 1 {
		t.Errorf("reloads = %d, want 1", reloads)
	}

	body, err := os.ReadFile(filepath.Join(cfg.Dir, fileName))
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	if string(body) != Render(cfg.ClusterID, cfg.ServerIP) {
		t.Errorf("written body does not match Render():\n%s", body)
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	// The steady-state call must not restart systemd-resolved. A restart
	// flushes the DNS cache, so an unconditional rewrite on a 5-minute ticker
	// would be a self-inflicted cache flush forever.
	reloads := 0
	cfg := testCfg(t, &reloads)

	if _, err := Apply(context.Background(), cfg); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	changed, err := Apply(context.Background(), cfg)
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if changed {
		t.Error("second Apply reported a change with identical config")
	}
	if reloads != 1 {
		t.Errorf("reloads = %d after two identical Applies, want 1", reloads)
	}
}

func TestApplyRewritesWhenServerMoves(t *testing.T) {
	reloads := 0
	cfg := testCfg(t, &reloads)
	if _, err := Apply(context.Background(), cfg); err != nil {
		t.Fatalf("first Apply: %v", err)
	}

	cfg.ServerIP = "192.168.197.9"
	changed, err := Apply(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Apply after move: %v", err)
	}
	if !changed {
		t.Error("Apply reported no change after the control plane moved")
	}
	if reloads != 2 {
		t.Errorf("reloads = %d, want 2", reloads)
	}
	body, _ := os.ReadFile(filepath.Join(cfg.Dir, fileName))
	if !strings.Contains(string(body), "DNS=192.168.197.9") {
		t.Errorf("drop-in still points at the old address:\n%s", body)
	}
}

func TestApplyRequiresClusterAndServer(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"no cluster id", Config{ServerIP: "10.0.0.1", Dir: t.TempDir()}},
		{"no server ip", Config{ClusterID: "rasputin", Dir: t.TempDir()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Apply(context.Background(), tc.cfg); err == nil {
				t.Error("Apply succeeded with incomplete config")
			}
		})
	}
}

func TestApplyReportsReloadFailureButKeepsFile(t *testing.T) {
	// A failed reload still leaves correct config on disk — it takes effect at
	// the next resolved restart. Removing it would be strictly worse.
	cfg := testCfg(t, new(int))
	cfg.reload = func(context.Context) error { return errors.New("boom") }

	changed, err := Apply(context.Background(), cfg)
	if err == nil {
		t.Error("Apply hid a reload failure")
	}
	if !changed {
		t.Error("Apply reported no change despite writing the file")
	}
	if _, serr := os.Stat(filepath.Join(cfg.Dir, fileName)); serr != nil {
		t.Errorf("drop-in was removed after a failed reload: %v", serr)
	}
}

func TestRunStopsWhenResolvedIsAbsent(t *testing.T) {
	// The OpenWrt firewall and dev boxes have no systemd-resolved. Run must
	// notice and return rather than spin writing files nothing will read.
	cfg := Config{
		ClusterID: "rasputin",
		ServerIP:  "10.0.0.1",
		Dir:       filepath.Join(t.TempDir(), "definitely", "absent", "resolved.conf.d"),
		reload:    func(context.Context) error { t.Error("reloaded on a host with no resolved"); return nil },
	}
	done := make(chan struct{})
	go func() { Run(context.Background(), cfg); close(done) }()
	<-done // Run returning at all is the assertion; it would block otherwise.
}
