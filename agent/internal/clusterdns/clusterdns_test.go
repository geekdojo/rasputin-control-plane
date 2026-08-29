package clusterdns

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestApplyDefaultsInterval(t *testing.T) {
	// The re-check period must never end up zero or negative: time.NewTicker
	// panics on a non-positive duration, so a caller that left Interval unset
	// would take the agent down at startup rather than degrade.
	for _, tc := range []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"unset", 0, DefaultInterval},
		{"negative", -time.Second, DefaultInterval},
		{"positive is preserved", 90 * time.Second, 90 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{ClusterID: "rasputin", ServerIP: "10.0.0.1", Interval: tc.in}
			cfg.applyDefaults()
			if cfg.Interval != tc.want {
				t.Errorf("Interval = %s, want %s", cfg.Interval, tc.want)
			}
		})
	}
}

func TestApplyDefaultsDirAndReload(t *testing.T) {
	cfg := Config{ClusterID: "rasputin", ServerIP: "10.0.0.1"}
	cfg.applyDefaults()
	if cfg.Dir != DefaultDir {
		t.Errorf("Dir = %q, want %q", cfg.Dir, DefaultDir)
	}
	if cfg.reload == nil {
		t.Error("applyDefaults left reload nil; Apply would panic")
	}
}

func TestRunRefusesIncompleteConfig(t *testing.T) {
	// Run must return, not spin, when it has nothing usable. Each field is
	// checked separately so a mutation that drops one half of the guard is
	// caught: with only a both-empty case, either half alone still passes.
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"no cluster id", Config{ServerIP: "10.0.0.1"}},
		{"no server ip", Config{ClusterID: "rasputin"}},
		{"neither", Config{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			// A real dir, so the absent-resolved guard cannot be what stops it.
			cfg.Dir = filepath.Join(t.TempDir(), "resolved.conf.d")
			cfg.reload = func(context.Context) error {
				t.Error("Run acted on an incomplete config")
				return nil
			}
			done := make(chan struct{})
			go func() { Run(context.Background(), cfg); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Run did not return on an incomplete config")
			}
		})
	}
}

func TestRunAppliesThenHonoursContext(t *testing.T) {
	// One pass through the loop body — including the error branch — then a
	// clean exit when the context ends.
	reloads := 0
	cfg := testCfg(t, &reloads)
	cfg.Interval = time.Hour // never fires; the context is what ends this
	cfg.reload = func(context.Context) error {
		reloads++
		return errors.New("reload unavailable")
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Dir), 0o755); err != nil {
		t.Fatalf("prepare parent dir: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Run(ctx, cfg); close(done) }()

	// The drop-in should appear even though the reload failed.
	path := filepath.Join(cfg.Dir, fileName)
	deadline := time.After(5 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		select {
		case <-deadline:
			t.Fatal("Run never wrote the drop-in")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run ignored context cancellation")
	}
	if reloads == 0 {
		t.Error("Run never attempted a reload")
	}
}
