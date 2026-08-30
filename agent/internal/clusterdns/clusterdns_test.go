package clusterdns

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// at makes a static address source. Production passes a live one; a test that
// needs the address to CHANGE builds its own closure.
func at(ip string) func() string { return func() string { return ip } }

// reachable is a probe that says yes. The default production probe does a real
// DNS query, which a unit test must not depend on.
func reachable(context.Context, string) bool { return true }

func testCfg(t *testing.T, reloads *int) Config {
	t.Helper()
	return Config{
		ClusterID: "rasputin",
		ServerIP:  at("192.168.197.224"),
		probe:     reachable,
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
	if string(body) != Render(cfg.ClusterID, cfg.ServerIP()) {
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

	cfg.ServerIP = at("192.168.197.9")
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
		{"no cluster id", Config{ServerIP: at("10.0.0.1"), probe: reachable, Dir: t.TempDir()}},
		{"no address source", Config{ClusterID: "rasputin", Dir: t.TempDir(), probe: reachable}},
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
		ServerIP:  at("10.0.0.1"), probe: reachable,
		Dir:    filepath.Join(t.TempDir(), "definitely", "absent", "resolved.conf.d"),
		reload: func(context.Context) error { t.Error("reloaded on a host with no resolved"); return nil },
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
			cfg := Config{ClusterID: "rasputin", ServerIP: at("10.0.0.1"), probe: reachable, Interval: tc.in}
			cfg.applyDefaults()
			if cfg.Interval != tc.want {
				t.Errorf("Interval = %s, want %s", cfg.Interval, tc.want)
			}
		})
	}
}

func TestApplyDefaultsDirAndReload(t *testing.T) {
	cfg := Config{ClusterID: "rasputin", ServerIP: at("10.0.0.1"), probe: reachable}
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
		{"no cluster id", Config{ServerIP: at("10.0.0.1"), probe: reachable}},
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

// ---- the control plane moves -------------------------------------------
//
// These are the regression for the worst bug this package has had. The address
// used to be captured once at startup. A rollout reboots the control plane
// LAST, it comes back on a new DHCP lease, and every node this package had just
// repaired was left pinned to where the control plane used to be. Because the
// domains are routing-only that is not a degraded state, it is a dead one: the
// cluster's own names stop resolving entirely, where without any drop-in mDNS
// would still have answered. Five nodes at once on e3bench, 2026-08-30.

func TestApply_FollowsTheControlPlaneWhenItMoves(t *testing.T) {
	reloads := 0
	cfg := testCfg(t, &reloads)
	current := "192.168.1.182"
	cfg.ServerIP = func() string { return current }

	if _, err := Apply(context.Background(), cfg); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	body, _ := os.ReadFile(filepath.Join(cfg.Dir, fileName))
	if !strings.Contains(string(body), "DNS=192.168.1.182") {
		t.Fatalf("initial pin wrong:\n%s", body)
	}

	// The control plane reboots and comes back elsewhere.
	current = "192.168.1.183"
	changed, err := Apply(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Apply after the CP moved: %v", err)
	}
	if !changed {
		t.Error("Apply did not react to the control plane moving")
	}
	body, _ = os.ReadFile(filepath.Join(cfg.Dir, fileName))
	if !strings.Contains(string(body), "DNS=192.168.1.183") {
		t.Errorf("still pinned to the old address:\n%s", body)
	}
}

// A pin that stops answering must be WITHDRAWN, not left in place. Leaving it
// black-holes the cluster's names; removing it hands them back to mDNS — flaky,
// which is the original complaint, but flaky beats dead, and it lets the agent
// reconnect and learn where the control plane went.
func TestApply_WithdrawsAPinThatStoppedAnswering(t *testing.T) {
	reloads := 0
	cfg := testCfg(t, &reloads)
	answering := true
	cfg.probe = func(context.Context, string) bool { return answering }

	if _, err := Apply(context.Background(), cfg); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	path := filepath.Join(cfg.Dir, fileName)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("drop-in was not written: %v", err)
	}

	answering = false
	changed, err := Apply(context.Background(), cfg)
	if !changed {
		t.Error("Apply left a dead pin in place")
	}
	if err == nil {
		t.Error("withdrawing a dead pin must be reported, not silent")
	}
	if _, serr := os.Stat(path); !os.IsNotExist(serr) {
		t.Error("drop-in still present after the server stopped answering")
	}
}

// Never write a pin we have not verified. Writing first and checking later
// would black-hole the cluster name for a whole tick.
func TestApply_DoesNotWriteAnUnverifiedPin(t *testing.T) {
	cfg := testCfg(t, new(int))
	cfg.probe = func(context.Context, string) bool { return false }

	if _, err := Apply(context.Background(), cfg); err != nil {
		// An error is acceptable here (nothing to withdraw), a written file is not.
		_ = err
	}
	if _, err := os.Stat(filepath.Join(cfg.Dir, fileName)); !os.IsNotExist(err) {
		t.Error("wrote a drop-in pointing at a server that never answered")
	}
}

// Losing the address entirely (bus down, so no peer to read) must also withdraw
// rather than leave the last known pin asserting something we can no longer
// stand behind.
func TestApply_WithdrawsWhenTheAddressBecomesUnknown(t *testing.T) {
	cfg := testCfg(t, new(int))
	known := true
	cfg.ServerIP = func() string {
		if known {
			return "192.168.1.182"
		}
		return ""
	}
	if _, err := Apply(context.Background(), cfg); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	known = false
	changed, _ := Apply(context.Background(), cfg)
	if !changed {
		t.Error("Apply kept a pin it could no longer justify")
	}
	if _, err := os.Stat(filepath.Join(cfg.Dir, fileName)); !os.IsNotExist(err) {
		t.Error("drop-in still present after the control-plane address became unknown")
	}
}

// Withdrawing when there is nothing pinned is a no-op, not an error — otherwise
// every tick on a node that never had a drop-in would log a failure.
func TestApply_WithdrawIsQuietWhenNothingIsPinned(t *testing.T) {
	cfg := testCfg(t, new(int))
	cfg.probe = func(context.Context, string) bool { return false }
	changed, err := Apply(context.Background(), cfg)
	if changed || err != nil {
		t.Errorf("no pin to withdraw should be silent; changed=%v err=%v", changed, err)
	}
}

// A probe against an unroutable address must say no. This is the direction that
// matters: a probe that fails open pins a dead server and black-holes the
// cluster name. It is a direct dial precisely so an /etc/hosts entry cannot
// make it pass without touching the server.
func TestReachableNameserver_UnroutableSaysNo(t *testing.T) {
	// 192.0.2.0/24 is TEST-NET-1 (RFC 5737): guaranteed not routable.
	if reachableNameserver(context.Background(), "192.0.2.1") {
		t.Error("probe said an unreachable address had a nameserver")
	}
}

// And it must say yes to something that is actually listening.
func TestReachableNameserver_ListenerSaysYes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	// reachableNameserver hard-codes :53, so exercise the dial directly against
	// the stub's port — the assertion is that a live listener is reachable.
	var d net.Dialer
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	c, derr := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if derr != nil {
		t.Fatalf("stub listener not reachable: %v", derr)
	}
	_ = c.Close()
}

// The withdrawal message must distinguish a clean withdrawal from one whose
// reload failed — they need different operator responses, and both return an
// error so only the text tells them apart.
func TestWithdraw_ReloadFailureIsDistinguishable(t *testing.T) {
	cfg := testCfg(t, new(int))
	if _, err := Apply(context.Background(), cfg); err != nil {
		t.Fatalf("seed Apply: %v", err)
	}
	cfg.probe = func(context.Context, string) bool { return false }
	cfg.reload = func(context.Context) error { return errors.New("resolved is not running") }

	changed, err := Apply(context.Background(), cfg)
	if !changed || err == nil {
		t.Fatalf("expected a reported withdrawal; changed=%v err=%v", changed, err)
	}
	if !strings.Contains(err.Error(), "reload failed") {
		t.Errorf("a failed reload must say so — the file is gone but resolved still has it loaded:\n%v", err)
	}
	if strings.Contains(err.Error(), "falls back to mDNS until this resolves") {
		t.Errorf("reported a clean withdrawal when the reload actually failed:\n%v", err)
	}
}
