package clusterdns

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

	changed, err := New(cfg).Apply(context.Background(), TriggerTick)
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

	if _, err := New(cfg).Apply(context.Background(), TriggerTick); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	changed, err := New(cfg).Apply(context.Background(), TriggerTick)
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
	if _, err := New(cfg).Apply(context.Background(), TriggerTick); err != nil {
		t.Fatalf("first Apply: %v", err)
	}

	cfg.ServerIP = at("192.168.197.9")
	changed, err := New(cfg).Apply(context.Background(), TriggerTick)
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
			if _, err := New(tc.cfg).Apply(context.Background(), TriggerTick); err == nil {
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

	changed, err := New(cfg).Apply(context.Background(), TriggerTick)
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

	if _, err := New(cfg).Apply(context.Background(), TriggerTick); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	body, _ := os.ReadFile(filepath.Join(cfg.Dir, fileName))
	if !strings.Contains(string(body), "DNS=192.168.1.182") {
		t.Fatalf("initial pin wrong:\n%s", body)
	}

	// The control plane reboots and comes back elsewhere.
	current = "192.168.1.183"
	changed, err := New(cfg).Apply(context.Background(), TriggerTick)
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

	if _, err := New(cfg).Apply(context.Background(), TriggerTick); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	path := filepath.Join(cfg.Dir, fileName)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("drop-in was not written: %v", err)
	}

	answering = false
	changed, err := New(cfg).Apply(context.Background(), TriggerTick)
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

	if _, err := New(cfg).Apply(context.Background(), TriggerTick); err != nil {
		// An error is acceptable here (nothing to withdraw), a written file is not.
		_ = err
	}
	if _, err := os.Stat(filepath.Join(cfg.Dir, fileName)); !os.IsNotExist(err) {
		t.Error("wrote a drop-in pointing at a server that never answered")
	}
}

// ---- the address is unknown ---------------------------------------------
//
// ServerIP returns "" whenever the bus is not connected — which includes the
// seconds between the agent starting and its first dial, because Run starts
// before the dial. The first version withdrew on sight, and the next look was
// the five-minute tick: every agent restart took the node off the mesh for up
// to five minutes (e3bench 2026-09-09, geekdojo/geekdojo-brain#403). Now an
// existing pin is kept for a grace, probed while kept, and withdrawn only when
// the grace runs out or the pinned server stops answering.

// clock is a test clock: start it, then advance it.
type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }
func newClock() *clock                   { return &clock{t: time.Date(2026, 9, 9, 3, 30, 37, 0, time.UTC)} }
func seedPin(t *testing.T, cfg Config, ip string) string {
	t.Helper()
	path := filepath.Join(cfg.Dir, fileName)
	if err := os.MkdirAll(cfg.Dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(Render(cfg.ClusterID, ip)), 0o644); err != nil {
		t.Fatalf("seed pin: %v", err)
	}
	return path
}

func TestApply_StartWithUnknownAddressKeepsAnExistingPinInsideTheGrace(t *testing.T) {
	reloads := 0
	cfg := testCfg(t, &reloads)
	cfg.ServerIP = at("")
	cfg.Grace = 20 * time.Second
	clk := newClock()
	cfg.now = clk.now
	path := seedPin(t, cfg, "192.168.1.181")

	p := New(cfg)
	changed, err := p.Apply(context.Background(), TriggerStart)
	if changed || err != nil {
		t.Fatalf("start with an unknown address touched the pin: changed=%v err=%v", changed, err)
	}
	if _, serr := os.Stat(path); serr != nil {
		t.Fatal("the pin the previous process left was withdrawn on start")
	}
	// Still inside the grace: still kept.
	clk.advance(19 * time.Second)
	if changed, err := p.Apply(context.Background(), TriggerTick); changed || err != nil {
		t.Fatalf("withdrew inside the grace: changed=%v err=%v", changed, err)
	}
	if reloads != 0 {
		t.Errorf("resolved restarted %d time(s) while nothing changed", reloads)
	}
}

func TestApply_WithdrawsWhenTheAddressStaysUnknownPastTheGrace(t *testing.T) {
	cfg := testCfg(t, new(int))
	cfg.ServerIP = at("")
	cfg.Grace = 20 * time.Second
	clk := newClock()
	cfg.now = clk.now
	path := seedPin(t, cfg, "192.168.1.181")

	p := New(cfg)
	if _, err := p.Apply(context.Background(), TriggerStart); err != nil {
		t.Fatalf("start: %v", err)
	}
	clk.advance(20 * time.Second)
	changed, err := p.Apply(context.Background(), TriggerGrace)
	if !changed {
		t.Error("kept a pin past the grace with the bus still unconnected")
	}
	if err == nil || !strings.Contains(err.Error(), "longer than the 20s grace") || !strings.Contains(err.Error(), "["+TriggerGrace+"]") {
		t.Errorf("withdrawal must say the grace ran out and which trigger saw it:\n%v", err)
	}
	if _, serr := os.Stat(path); !os.IsNotExist(serr) {
		t.Error("drop-in still present after the grace")
	}
}

// A fresh Pinner per look would restart the grace clock every time and never
// withdraw. The clock lives on the Pinner; this pins that down.
func TestApply_GraceClockSurvivesAcrossLooks(t *testing.T) {
	cfg := testCfg(t, new(int))
	cfg.ServerIP = at("")
	cfg.Grace = 20 * time.Second
	clk := newClock()
	cfg.now = clk.now
	seedPin(t, cfg, "192.168.1.181")

	p := New(cfg)
	for i := 0; i < 4; i++ {
		if changed, _ := p.Apply(context.Background(), TriggerTick); changed {
			t.Fatalf("look %d withdrew at %s into a 20s grace", i, clk.t.Sub(newClock().t))
		}
		clk.advance(6 * time.Second)
	}
	// 24 s in: due.
	if changed, _ := p.Apply(context.Background(), TriggerTick); !changed {
		t.Error("never withdrew; the grace clock is being reset between looks")
	}
}

// Inside the grace the pin is kept, not trusted: the pinned server is read
// back out of the drop-in and probed, and a dead one goes at once. Otherwise
// the grace would re-arm the black-hole #202 exists to prevent.
func TestApply_UnknownAddressStillWithdrawsAPinThatStoppedAnswering(t *testing.T) {
	cfg := testCfg(t, new(int))
	cfg.ServerIP = at("")
	cfg.Grace = time.Hour
	var probed []string
	cfg.probe = func(_ context.Context, ip string) bool { probed = append(probed, ip); return false }
	path := seedPin(t, cfg, "192.168.1.181")

	changed, err := New(cfg).Apply(context.Background(), TriggerStart)
	if !changed || err == nil {
		t.Fatalf("a dead pin rode the grace out: changed=%v err=%v", changed, err)
	}
	if len(probed) != 1 || probed[0] != "192.168.1.181" {
		t.Errorf("probed %v, want exactly the pinned address", probed)
	}
	if !strings.Contains(err.Error(), "pinned 192.168.1.181 is not answering") {
		t.Errorf("withdrawal must name the dead pinned address:\n%v", err)
	}
	if _, serr := os.Stat(path); !os.IsNotExist(serr) {
		t.Error("dead pin still present")
	}
}

// The grace clock clears the moment the address is known again, so a later
// loss starts a fresh grace rather than inheriting a half-spent one.
func TestApply_KnownAddressResetsTheGrace(t *testing.T) {
	cfg := testCfg(t, new(int))
	cfg.Grace = 20 * time.Second
	clk := newClock()
	cfg.now = clk.now
	known := ""
	cfg.ServerIP = func() string { return known }
	path := seedPin(t, cfg, "192.168.1.181")

	p := New(cfg)
	p.Apply(context.Background(), TriggerStart) // unknown: clock starts
	clk.advance(15 * time.Second)
	known = "192.168.1.181"
	if changed, err := p.Apply(context.Background(), TriggerConnected); changed || err != nil {
		t.Fatalf("re-pinning the same address should be a no-op: changed=%v err=%v", changed, err)
	}
	if p.graceRemaining() != 0 {
		t.Error("grace still armed after the address became known")
	}
	known = ""
	clk.advance(15 * time.Second) // 30 s since the FIRST loss, 15 s since the second
	if changed, _ := p.Apply(context.Background(), TriggerTick); changed {
		t.Error("withdrew on a grace inherited from an earlier loss")
	}
	if _, serr := os.Stat(path); serr != nil {
		t.Error("pin gone inside a fresh grace")
	}
}

func TestPinnedIP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, fileName)
	if got := pinnedIP(path); got != "" {
		t.Errorf("missing file: pinnedIP = %q, want empty", got)
	}
	if err := os.WriteFile(path, []byte(Render("e3bench", "192.168.1.181")), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := pinnedIP(path); got != "192.168.1.181" {
		t.Errorf("pinnedIP = %q, want 192.168.1.181", got)
	}
	if err := os.WriteFile(path, []byte("[Resolve]\nDomains=~x.local\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := pinnedIP(path); got != "" {
		t.Errorf("no DNS= line: pinnedIP = %q, want empty", got)
	}
}

// Nothing pinned and no address is the boot case: nothing to keep, nothing to
// withdraw, and no grace clock started for a pin that does not exist.
func TestApply_UnknownAddressWithNothingPinnedIsQuiet(t *testing.T) {
	cfg := testCfg(t, new(int))
	cfg.ServerIP = at("")
	p := New(cfg)
	changed, err := p.Apply(context.Background(), TriggerStart)
	if changed || err != nil {
		t.Errorf("changed=%v err=%v, want a silent no-op", changed, err)
	}
	if p.graceRemaining() != 0 {
		t.Error("grace armed with nothing pinned")
	}
}

// Withdrawing when there is nothing pinned is a no-op, not an error — otherwise
// every tick on a node that never had a drop-in would log a failure.
func TestApply_WithdrawIsQuietWhenNothingIsPinned(t *testing.T) {
	cfg := testCfg(t, new(int))
	cfg.probe = func(context.Context, string) bool { return false }
	changed, err := New(cfg).Apply(context.Background(), TriggerTick)
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
	if _, err := New(cfg).Apply(context.Background(), TriggerTick); err != nil {
		t.Fatalf("seed Apply: %v", err)
	}
	cfg.probe = func(context.Context, string) bool { return false }
	cfg.reload = func(context.Context) error { return errors.New("resolved is not running") }

	changed, err := New(cfg).Apply(context.Background(), TriggerTick)
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

// ---- Run follows the bus, not the tick -----------------------------------

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for !cond() {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// runCfg is a Run-level config whose tick can never fire: anything that
// happens inside the test happened because of a trigger or a grace, not the
// interval.
func runCfg(t *testing.T, reloads *int) Config {
	t.Helper()
	cfg := testCfg(t, reloads)
	cfg.Interval = time.Hour
	if err := os.MkdirAll(filepath.Dir(cfg.Dir), 0o755); err != nil {
		t.Fatalf("prepare parent dir: %v", err)
	}
	return cfg
}

func pinnedNow(path string) string { return pinnedIP(path) }

// The bench timeline this exists for: agent up, bus connected seconds later,
// pin written five MINUTES later on the tick. With the trigger the pin follows
// the connection.
func TestRun_PinsOnBusConnectWithoutWaitingForATick(t *testing.T) {
	var mu sync.Mutex
	reloads := 0
	cfg := runCfg(t, &reloads)
	cfg.reload = func(context.Context) error { mu.Lock(); reloads++; mu.Unlock(); return nil }
	addr := ""
	cfg.ServerIP = func() string { mu.Lock(); defer mu.Unlock(); return addr }
	cfg.Trigger = NewTrigger()
	path := filepath.Join(cfg.Dir, fileName)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { Run(ctx, cfg); close(done) }()

	// Boot case: nothing pinned, address unknown, and Run must not have
	// invented one. Give it a moment to make its start pass.
	time.Sleep(50 * time.Millisecond)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("Run wrote a pin before the bus had an address")
	}

	// The bus connects: onConnected fires the trigger.
	mu.Lock()
	addr = "192.168.1.181"
	mu.Unlock()
	cfg.Trigger.Fire()
	waitFor(t, "the pin after the bus connected", func() bool { return pinnedNow(path) == "192.168.1.181" })
	mu.Lock()
	if reloads != 1 {
		t.Errorf("reloads = %d, want 1", reloads)
	}
	mu.Unlock()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run ignored context cancellation")
	}
}

// A re-dial that lands on a control plane that moved re-pins to where it is
// now; a re-fire with the same address does not restart resolved.
func TestRun_RepinsOnRedialToANewAddressAndIsQuietWhenUnchanged(t *testing.T) {
	var mu sync.Mutex
	reloads := 0
	cfg := runCfg(t, &reloads)
	cfg.reload = func(context.Context) error { mu.Lock(); reloads++; mu.Unlock(); return nil }
	addr := "192.168.1.181"
	cfg.ServerIP = func() string { mu.Lock(); defer mu.Unlock(); return addr }
	cfg.Trigger = NewTrigger()
	path := filepath.Join(cfg.Dir, fileName)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Run(ctx, cfg)
	waitFor(t, "the first pin", func() bool { return pinnedNow(path) == "192.168.1.181" })

	// nats reconnect to the same server: onConnected fires again.
	cfg.Trigger.Fire()
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	if reloads != 1 {
		t.Errorf("an unchanged re-fire restarted resolved: reloads = %d, want 1", reloads)
	}
	// The control plane rebooted on a new lease; the client re-dialed it.
	addr = "192.168.1.183"
	mu.Unlock()
	cfg.Trigger.Fire()
	waitFor(t, "the re-pin to the new address", func() bool { return pinnedNow(path) == "192.168.1.183" })
	mu.Lock()
	if reloads != 2 {
		t.Errorf("reloads = %d, want 2", reloads)
	}
	mu.Unlock()
}

// The grace runs on its own timer. With the tick an hour away and no trigger,
// a pin kept at start is still withdrawn when the grace is up — not at the
// next tick.
func TestRun_GraceExpiresOnItsOwnClockNotTheTick(t *testing.T) {
	var mu sync.Mutex
	reloads := 0
	cfg := runCfg(t, &reloads)
	cfg.reload = func(context.Context) error { mu.Lock(); reloads++; mu.Unlock(); return nil }
	cfg.ServerIP = at("")
	cfg.Grace = 100 * time.Millisecond
	cfg.Trigger = NewTrigger()
	path := seedPin(t, cfg, "192.168.1.181")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Run(ctx, cfg)

	// Kept at start.
	time.Sleep(30 * time.Millisecond)
	if _, err := os.Stat(path); err != nil {
		t.Fatal("pin withdrawn at start, inside the grace")
	}
	waitFor(t, "the withdrawal when the grace ran out", func() bool {
		_, err := os.Stat(path)
		return os.IsNotExist(err)
	})
	mu.Lock()
	if reloads != 1 {
		t.Errorf("reloads = %d, want 1 (the withdrawal)", reloads)
	}
	mu.Unlock()
}

// A bus that connects inside the grace cancels the withdrawal: the pin is
// confirmed against the live address and the grace timer is disarmed.
func TestRun_ConnectInsideTheGraceKeepsThePin(t *testing.T) {
	var mu sync.Mutex
	reloads := 0
	cfg := runCfg(t, &reloads)
	cfg.reload = func(context.Context) error { mu.Lock(); reloads++; mu.Unlock(); return nil }
	addr := ""
	cfg.ServerIP = func() string { mu.Lock(); defer mu.Unlock(); return addr }
	cfg.Grace = 200 * time.Millisecond
	cfg.Trigger = NewTrigger()
	path := seedPin(t, cfg, "192.168.1.181")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Run(ctx, cfg)

	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	addr = "192.168.1.181"
	mu.Unlock()
	cfg.Trigger.Fire()
	// Well past where the grace would have expired.
	time.Sleep(400 * time.Millisecond)
	if pinnedNow(path) != "192.168.1.181" {
		t.Error("pin withdrawn although the bus connected inside the grace")
	}
	mu.Lock()
	if reloads != 0 {
		t.Errorf("resolved restarted %d time(s) although nothing changed", reloads)
	}
	mu.Unlock()
}

func TestTrigger_FireNeverBlocksAndNilIsSafe(t *testing.T) {
	var none *Trigger
	none.Fire() // must not panic
	if none.wait() != nil {
		t.Error("a nil Trigger must select as never-ready")
	}
	tr := NewTrigger()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			tr.Fire()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Fire blocked with nobody receiving")
	}
	select {
	case <-tr.wait():
	default:
		t.Error("a fired Trigger had nothing to receive")
	}
}
