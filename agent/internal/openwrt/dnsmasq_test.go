package openwrt

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// ----- simulated running dnsmasq ------------------------------------------------

// simDnsmasq models the dnsmasq PROCESS on a simulated OpenWrt box, separately
// from its UCI configuration in simUCI. It is the half of the simulator #436 was
// about: the running process holds what it read at its last start, a restart
// re-reads UCI, and a reload changes nothing — which is what SIGHUP does to
// server= and rebind-domain-ok= on real hardware.
type simDnsmasq struct {
	runServers []string // server= entries the running process forwards with
	runRebind  []string // rebind-domain-ok= zones the running process whitelists

	restarts   int
	restartErr error // the init script fails
	// onRestart replaces the default restart: it returns the log lines the
	// "restarted" process writes, and decides itself whether runServers moves.
	onRestart func(s *simUCI) []string

	followErr error // logread cannot be started
	noBacklog bool  // logread produces no backlog line
	logCh     chan string

	deadUpstreams map[string]bool // forward targets that never answer
	lookups       []string
}

const simBacklog = "Sun Sep 13 20:00:00 2026 kern.info kernel: [ 1.0] backlog"

func simLogLine(msg string) string {
	return "Sun Sep 13 20:00:01 2026 daemon.info dnsmasq[1]: " + msg
}

// restart models `/etc/init.d/dnsmasq restart`: the new process reads UCI and
// logs its startup, including one "using nameserver" line per domain forward.
func (s *simUCI) restart() error {
	s.restarts++
	if s.restartErr != nil {
		return s.restartErr
	}
	var lines []string
	if s.onRestart != nil {
		lines = s.onRestart(s)
	} else {
		s.runServers = slices.Clone(s.dnsmasq)
		s.runRebind = slices.Clone(s.rebindDomain)
		lines = append(lines, simLogLine("started, version 2.90 cachesize 150"))
		for _, e := range s.runServers {
			if zone, target, ok := splitDNSForward(e); ok {
				lines = append(lines, simLogLine("using nameserver "+target+"#53 for domain "+zone))
			}
		}
	}
	for _, l := range lines {
		s.emit(l)
	}
	return nil
}

func (s *simUCI) emit(line string) {
	if s.logCh != nil {
		s.logCh <- line
	}
}

func (s *simUCI) FollowLog(context.Context) (io.ReadCloser, error) {
	s.calls = append(s.calls, []string{"logread", "-f", "-l", "1"})
	if s.followErr != nil {
		return nil, s.followErr
	}
	pr, pw := io.Pipe()
	ch := make(chan string, 128)
	done := make(chan struct{})
	go func() {
		defer pw.Close()
		for {
			select {
			case l := <-ch:
				if _, err := io.WriteString(pw, l+"\n"); err != nil {
					return
				}
			case <-done:
				return
			}
		}
	}()
	s.logCh = ch
	if !s.noBacklog {
		ch <- simBacklog
	}
	return &simLogStream{PipeReader: pr, done: done}, nil
}

type simLogStream struct {
	*io.PipeReader
	done chan struct{}
	once sync.Once
}

func (l *simLogStream) Close() error {
	l.once.Do(func() {
		close(l.done)
		_ = l.PipeReader.Close()
	})
	return nil
}

// LookupA models the apex query through the running dnsmasq: the control
// plane's nameserver at the forward target answers the apex with its own
// address; a dead target never answers; without the rebind whitelist dnsmasq
// drops the private answer.
func (s *simUCI) LookupA(_ context.Context, name string) ([]netip.Addr, error) {
	s.lookups = append(s.lookups, name)
	for _, e := range s.runServers {
		zone, target, ok := splitDNSForward(e)
		if !ok || zone != name {
			continue
		}
		if s.deadUpstreams[target] {
			return nil, errors.New("read udp 127.0.0.1:53: i/o timeout")
		}
		if !slices.Contains(s.runRebind, zone) {
			return nil, nil // rebind protection stripped the answer
		}
		return []netip.Addr{netip.MustParseAddr(target)}, nil
	}
	return nil, errors.New("127.0.0.1:53 answered RCodeRefused")
}

// ----- helpers ------------------------------------------------------------------

const (
	fwdOld = "/e12bench.internal/192.168.1.228"
	fwdNew = "/e12bench.internal/192.168.1.223"
)

func indexOfCall(calls [][]string, want ...string) int {
	return slices.IndexFunc(calls, func(c []string) bool { return slices.Equal(c, want) })
}

func dnsmasqActions(reloads []string) []string {
	var out []string
	for _, r := range reloads {
		if strings.HasPrefix(r, "dnsmasq") {
			out = append(out, r)
		}
	}
	return out
}

func applyForward(t *testing.T, c *UCIRealClient, fwd string) (string, error) {
	t.Helper()
	st := stateWith(nil, nil, nil)
	if fwd != "" {
		st = stateWithForward(fwd)
	}
	return c.Apply(context.Background(), jsonRoundTrip(t, st))
}

func getServer(t *testing.T, c *UCIRealClient) (server any, hasDHCP bool, hash string) {
	t.Helper()
	got, h, err := c.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	dhcp, ok := got["dhcp"].(map[string]any)
	if !ok {
		return nil, false, h
	}
	return dhcp["server"], true, h
}

// ----- Apply: the forward reaches the running process ---------------------------

// The #436 scenario: the control plane moves from .228 to .223. The running
// dnsmasq must end up forwarding to .223, which only a restart achieves.
func TestApply_DNSForwardChangeRestartsRunningDnsmasq(t *testing.T) {
	sim := stockSim()
	c, dir := newSimClient(t, sim)

	if _, err := applyForward(t, c, fwdOld); err != nil {
		t.Fatalf("apply old: %v", err)
	}
	sim.calls, sim.reloads = nil, nil
	h, err := applyForward(t, c, fwdNew)
	if err != nil {
		t.Fatalf("apply new: %v", err)
	}

	if want := []string{"dnsmasq restart"}; !slices.Equal(dnsmasqActions(sim.reloads), want) {
		t.Errorf("dnsmasq actions for the change = %v, want %v (never reload: SIGHUP does not re-read server=)",
			dnsmasqActions(sim.reloads), want)
	}
	if sim.restarts != 2 {
		t.Errorf("restarts = %d, want 2 (one per forward change)", sim.restarts)
	}
	if !slices.Equal(sim.runServers, []string{fwdNew}) {
		t.Errorf("running dnsmasq forwards with %v, want [%s]", sim.runServers, fwdNew)
	}
	// The log is followed BEFORE the restart, so its startup lines can't be missed.
	follow := indexOfCall(sim.calls, "logread", "-f", "-l", "1")
	restart := indexOfCall(sim.calls, "/etc/init.d/dnsmasq", "restart")
	if follow < 0 || restart < 0 || follow > restart {
		t.Errorf("logread follow at %d, restart at %d: follow must precede restart\n%s", follow, restart, fmtCalls(sim.calls))
	}
	if m := loadManifestFile(t, dir); m.DNSForward != fwdNew || m.DNSForwardUnverified {
		t.Errorf("manifest = %+v, want forward %s verified", m, fwdNew)
	}
	server, _, gh := getServer(t, c)
	if server != fwdNew || gh != h {
		t.Errorf("Get server=%v hash=%s, want %s in sync with apply hash %s", server, gh, fwdNew, h)
	}
}

func TestApply_UnchangedDNSForwardLeavesDnsmasqAlone(t *testing.T) {
	sim := stockSim()
	c, _ := newSimClient(t, sim)
	if _, err := applyForward(t, c, fwdNew); err != nil {
		t.Fatalf("apply 1: %v", err)
	}
	sim.calls, sim.reloads, sim.lookups = nil, nil, nil

	// A different firewall change, same forward.
	st := stateWith([]map[string]any{redirectMinecraft()}, nil, nil)
	st["dhcp"] = map[string]any{"server": fwdNew}
	if _, err := c.Apply(context.Background(), jsonRoundTrip(t, st)); err != nil {
		t.Fatalf("apply 2: %v", err)
	}
	if got := dnsmasqActions(sim.reloads); len(got) != 0 {
		t.Errorf("dnsmasq touched on an apply that didn't change the forward: %v", got)
	}
	if sim.restarts != 1 {
		t.Errorf("restarts = %d, want 1", sim.restarts)
	}
	if indexOfCall(sim.calls, "logread", "-f", "-l", "1") >= 0 {
		t.Errorf("log followed on an apply that didn't change the forward:\n%s", fmtCalls(sim.calls))
	}
	if len(sim.lookups) != 0 {
		t.Errorf("apply probed the resolver: %v", sim.lookups)
	}
}

// ----- Apply: verification failure --------------------------------------------

// A restart whose new process does not announce the new forward is not success.
// The failure is remembered: Get reports drift, and the next apply — even with
// the forward unchanged — restarts again.
func TestApply_VerifyFailsWhenRestartedDnsmasqKeepsOldForward(t *testing.T) {
	sim := stockSim()
	c, dir := newSimClient(t, sim)
	if _, err := applyForward(t, c, fwdOld); err != nil {
		t.Fatalf("apply old: %v", err)
	}
	c.logTimeout = 100 * time.Millisecond

	sim.onRestart = func(s *simUCI) []string { // the process comes back on the old config
		return []string{
			simLogLine("started, version 2.90 cachesize 150"),
			simLogLine("using nameserver 192.168.1.228#53 for domain e12bench.internal"),
		}
	}
	applied, err := applyForward(t, c, fwdNew)
	if err == nil {
		t.Fatal("apply reported success though the running dnsmasq never used the new forward")
	}
	if !strings.Contains(err.Error(), "192.168.1.223") {
		t.Errorf("error should name the forward it waited for: %v", err)
	}
	if applied != "" {
		t.Errorf("failed apply returned hash %q", applied)
	}
	if m := loadManifestFile(t, dir); m.DNSForward != fwdNew || !m.DNSForwardUnverified {
		t.Errorf("manifest = %+v, want forward %s UNverified", m, fwdNew)
	}

	sim.lookups = nil
	server, hasDHCP, gh := getServer(t, c)
	if !hasDHCP || server != "" {
		t.Errorf("Get dhcp server = %v (present=%v), want \"\": an unverified forward is drift", server, hasDHCP)
	}
	if gh == mustHash(t, stateWithForward(fwdNew)) {
		t.Error("Get hash equals the intent hash while the running forward is unverified")
	}
	if len(sim.lookups) != 0 {
		t.Errorf("Get probed despite a known-unverified restart: %v", sim.lookups)
	}

	// The next apply of the SAME state restarts again, and this time it lands.
	sim.onRestart = nil
	c.logTimeout = dnsmasqLogTimeout
	h, err := applyForward(t, c, fwdNew)
	if err != nil {
		t.Fatalf("retry apply: %v", err)
	}
	if sim.restarts != 3 {
		t.Errorf("restarts = %d, want 3 (the unverified forward is restarted again)", sim.restarts)
	}
	if m := loadManifestFile(t, dir); m.DNSForwardUnverified {
		t.Errorf("manifest still unverified after a verified restart: %+v", m)
	}
	if server, _, gh := getServer(t, c); server != fwdNew || gh != h {
		t.Errorf("Get after verified retry: server=%v hash=%s, want in sync", server, gh)
	}
}

func TestApply_VerifyFailsFastWhenDnsmasqFailsToStart(t *testing.T) {
	sim := stockSim()
	c, _ := newSimClient(t, sim)
	c.logTimeout = time.Minute // the failure line, not the timeout, must end the wait
	sim.onRestart = func(*simUCI) []string {
		return []string{simLogLine("FAILED to start up")}
	}
	start := time.Now()
	_, err := applyForward(t, c, fwdNew)
	if err == nil || !strings.Contains(err.Error(), "FAILED to start up") {
		t.Fatalf("apply error = %v, want the FAILED to start up line", err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("apply took %s: it waited out the timeout instead of acting on the failure line", elapsed)
	}
}

func TestApply_VerifyTimesOutWithoutStartupLines(t *testing.T) {
	sim := stockSim()
	c, _ := newSimClient(t, sim)
	c.logTimeout = 50 * time.Millisecond
	sim.onRestart = func(*simUCI) []string { return nil }
	_, err := applyForward(t, c, fwdNew)
	if err == nil || !strings.Contains(err.Error(), "logged within 50ms") {
		t.Fatalf("apply error = %v, want a bounded wait for the startup lines", err)
	}
}

// The forward line counts only after the NEW process's "started" line, and only
// when dnsmasq itself wrote it.
func TestApply_VerifyIgnoresForwardLinesNotFromTheRestartedDnsmasq(t *testing.T) {
	for name, lines := range map[string][]string{
		"before started": {
			simLogLine("using nameserver 192.168.1.223#53 for domain e12bench.internal"),
			simLogLine("started, version 2.90 cachesize 150"),
		},
		"another program": {
			simLogLine("started, version 2.90 cachesize 150"),
			"Sun Sep 13 20:00:01 2026 user.notice root: using nameserver 192.168.1.223#53 for domain e12bench.internal",
		},
		"a longer zone": {
			simLogLine("started, version 2.90 cachesize 150"),
			simLogLine("using nameserver 192.168.1.223#53 for domain e12bench.internal.example"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			sim := stockSim()
			c, _ := newSimClient(t, sim)
			c.logTimeout = 50 * time.Millisecond
			sim.onRestart = func(*simUCI) []string { return lines }
			if _, err := applyForward(t, c, fwdNew); err == nil {
				t.Fatal("apply verified on a line that doesn't prove the restarted dnsmasq uses the forward")
			}
		})
	}
}

// Without a way to watch the log the restart still happens — the committed
// config is right and the running process is not — but the apply fails.
func TestApply_RestartsEvenWhenLogCannotBeFollowed(t *testing.T) {
	for name, breakLog := range map[string]func(*simUCI){
		"logread fails":   func(s *simUCI) { s.followErr = errors.New("exec: logread: not found") },
		"no backlog line": func(s *simUCI) { s.noBacklog = true },
	} {
		t.Run(name, func(t *testing.T) {
			sim := stockSim()
			c, dir := newSimClient(t, sim)
			c.logTimeout = 50 * time.Millisecond
			breakLog(sim)
			_, err := applyForward(t, c, fwdNew)
			if err == nil || !strings.Contains(err.Error(), "cannot be verified") {
				t.Fatalf("apply error = %v, want restarted-but-unverified", err)
			}
			if sim.restarts != 1 || !slices.Equal(sim.runServers, []string{fwdNew}) {
				t.Errorf("restarts=%d running=%v: the restart must still happen", sim.restarts, sim.runServers)
			}
			if m := loadManifestFile(t, dir); !m.DNSForwardUnverified {
				t.Errorf("manifest = %+v, want unverified", m)
			}
		})
	}
}

func TestApply_RestartFailureReturnsError(t *testing.T) {
	sim := stockSim()
	c, dir := newSimClient(t, sim)
	sim.restartErr = errors.New("exit status 1")
	_, err := applyForward(t, c, fwdNew)
	if err == nil || !strings.Contains(err.Error(), "dnsmasq restart") {
		t.Fatalf("apply error = %v, want the restart failure", err)
	}
	if m := loadManifestFile(t, dir); !m.DNSForwardUnverified {
		t.Errorf("manifest = %+v, want unverified", m)
	}
}

// Removing the forward restarts too (the running process would otherwise keep
// forwarding); the proof is the new process's start, since nothing is logged
// for a forward that no longer exists.
func TestApply_RemovingDNSForwardRestartsAndWaitsForStart(t *testing.T) {
	sim := stockSim()
	c, dir := newSimClient(t, sim)
	if _, err := applyForward(t, c, fwdNew); err != nil {
		t.Fatalf("apply add: %v", err)
	}
	h, err := applyForward(t, c, "")
	if err != nil {
		t.Fatalf("apply remove: %v", err)
	}
	if sim.restarts != 2 || len(sim.runServers) != 0 {
		t.Errorf("restarts=%d running=%v, want 2 and no running forward", sim.restarts, sim.runServers)
	}
	if server, hasDHCP, gh := getServer(t, c); hasDHCP || gh != h {
		t.Errorf("Get after verified removal: dhcp=%v/%v hash=%s, want no dhcp key, in sync", server, hasDHCP, gh)
	}

	// A removal whose restart can't be verified is drift, not silently in sync.
	if _, err := applyForward(t, c, fwdNew); err != nil {
		t.Fatalf("apply re-add: %v", err)
	}
	c.logTimeout = 50 * time.Millisecond
	sim.onRestart = func(*simUCI) []string { return nil }
	if _, err := applyForward(t, c, ""); err == nil {
		t.Fatal("removal verified without the new process starting")
	}
	if m := loadManifestFile(t, dir); m.DNSForward != "" || !m.DNSForwardUnverified {
		t.Errorf("manifest = %+v, want no forward, unverified", m)
	}
	if server, hasDHCP, gh := getServer(t, c); !hasDHCP || server != "" || gh == mustHash(t, stateWith(nil, nil, nil)) {
		t.Errorf("Get after unverified removal: dhcp=%v/%v, want server \"\" and drift", server, hasDHCP)
	}
}

// ----- Get: drift against the running process -----------------------------------

func TestGet_DNSForwardInSyncProbesRunningDnsmasq(t *testing.T) {
	sim := stockSim()
	c, _ := newSimClient(t, sim)
	h, err := applyForward(t, c, fwdNew)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if server, _, gh := getServer(t, c); server != fwdNew || gh != h {
		t.Errorf("Get server=%v hash=%s, want in sync", server, gh)
	}
	if !slices.Equal(sim.lookups, []string{"e12bench.internal"}) {
		t.Errorf("lookups = %v, want one apex probe of the zone", sim.lookups)
	}
}

// UCI holds the new forward but the running dnsmasq still forwards elsewhere —
// the exact state the e12bench firewall was in, which read as in sync before.
func TestGet_DNSForwardDriftWhenRunningForwardDiffersFromUCI(t *testing.T) {
	for name, diverge := range map[string]func(*simUCI){
		"live old upstream": func(s *simUCI) { s.runServers = []string{fwdOld} },
		"dead upstream": func(s *simUCI) {
			s.deadUpstreams = map[string]bool{"192.168.1.223": true}
		},
		"no running forward":      func(s *simUCI) { s.runServers = nil },
		"no running rebind allow": func(s *simUCI) { s.runRebind = nil },
	} {
		t.Run(name, func(t *testing.T) {
			sim := stockSim()
			c, _ := newSimClient(t, sim)
			applied, err := applyForward(t, c, fwdNew)
			if err != nil {
				t.Fatalf("apply: %v", err)
			}
			diverge(sim)
			if !slices.Contains(sim.dnsmasq, fwdNew) {
				t.Fatalf("precondition: UCI should still hold %s, has %v", fwdNew, sim.dnsmasq)
			}
			server, _, gh := getServer(t, c)
			if server != "" || gh == applied {
				t.Errorf("Get server=%v, hash equal to applied=%v: running forward divergence not reported as drift", server, gh == applied)
			}
		})
	}
}

func TestDNSForwardServing_RejectsMalformedEntries(t *testing.T) {
	sim := stockSim()
	c, _ := newSimClient(t, sim)
	for _, entry := range []string{"", "e12bench.internal/192.168.1.223", "/e12bench.internal/", "/e12bench.internal/not-an-ip"} {
		if c.dnsForwardServing(context.Background(), entry) {
			t.Errorf("dnsForwardServing(%q) = true", entry)
		}
	}
	if len(sim.lookups) != 0 {
		t.Errorf("malformed entries were probed: %v", sim.lookups)
	}
}

func TestRestartDnsmasq_RejectsMalformedForward(t *testing.T) {
	sim := stockSim()
	c, _ := newSimClient(t, sim)
	if err := c.restartDnsmasq(context.Background(), "no-slashes"); err == nil {
		t.Fatal("malformed forward accepted")
	}
	if sim.restarts != 0 {
		t.Errorf("restarted for a malformed forward")
	}
}

// ----- log-line matching --------------------------------------------------------

func TestSplitDNSForward(t *testing.T) {
	for entry, want := range map[string][3]string{
		"/e12bench.internal/192.168.1.223": {"e12bench.internal", "192.168.1.223", "ok"},
		"e12bench.internal/192.168.1.223":  {},
		"//192.168.1.223":                  {},
		"/e12bench.internal/":              {},
		"/e12bench.internal":               {},
		"":                                 {},
	} {
		zone, target, ok := splitDNSForward(entry)
		if got := [3]string{zone, target, map[bool]string{true: "ok"}[ok]}; got != want {
			t.Errorf("splitDNSForward(%q) = %v, want %v", entry, got, want)
		}
	}
}

func TestDnsmasqMessage(t *testing.T) {
	type result struct {
		msg string
		ok  bool
	}
	for line, want := range map[string]result{
		"Sun Sep 13 19:37:14 2026 daemon.info dnsmasq[1]: started, version 2.90 cachesize 150": {"started, version 2.90 cachesize 150", true},
		"Sun Sep 13 19:37:14 2026 daemon.info dnsmasq[4242]: using nameserver 1.1.1.1#53 \t\r": {"using nameserver 1.1.1.1#53", true},
		"Sun Sep 13 19:37:14 2026 user.notice root: started, version 2.90":                     {"", false},
		"Sun Sep 13 19:37:14 2026 daemon.info dnsmasq[1] started, version 2.90":                {"", false},
		"dnsmasq[":            {"", false},
		"dnsmasq[1]: ":        {"", true},
		"x dnsmasq[1]: hello": {"hello", true},
	} {
		msg, ok := dnsmasqMessage(line)
		if (result{msg, ok}) != want {
			t.Errorf("dnsmasqMessage(%q) = %q, %v; want %q, %v", line, msg, ok, want.msg, want.ok)
		}
	}
}

func TestIsForwardInUse(t *testing.T) {
	const zone, target = "e12bench.internal", "192.168.1.223"
	for msg, want := range map[string]bool{
		"using nameserver 192.168.1.223#53 for domain e12bench.internal":             true,
		"using nameserver 192.168.1.223#53 for domain e12bench.internal (no DNSSEC)": true,
		"using nameserver 192.168.1.22#53 for domain e12bench.internal":              false,
		"using nameserver 192.168.1.2233#53 for domain e12bench.internal":            false,
		"using nameserver 192.168.1.223#5353 for domain e12bench.internal":           false,
		"using nameserver 192.168.1.223#53 for domain e12bench.internalx":            false,
		"using nameserver 192.168.1.223#53 for domain x.e12bench.internal":           false,
		"using nameserver 192.168.1.223#53":                                          false,
	} {
		if got := isForwardInUse(msg, zone, target); got != want {
			t.Errorf("isForwardInUse(%q) = %v, want %v", msg, got, want)
		}
	}
	if !isForwardInUse("using nameserver 192.168.1.223#5353 for domain z", "z", "192.168.1.223#5353") {
		t.Error("an explicit port in the target must be matched as written")
	}
}

func TestAwaitLine_EndsOnStreamCloseAndContext(t *testing.T) {
	closed := make(chan string)
	close(closed)
	if err := awaitLine(context.Background(), closed, time.Minute, "x", func(string) (bool, error) { return false, nil }); err == nil ||
		!strings.Contains(err.Error(), "ended before x") {
		t.Errorf("closed stream: err = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := awaitLine(ctx, make(chan string), time.Minute, "x", func(string) (bool, error) { return false, nil }); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled context: err = %v", err)
	}
}

// ----- the real observer --------------------------------------------------------

// realDnsmasq.FollowLog runs `logread -f -l 1` from PATH; a stand-in logread
// proves the argv, that lines stream as they are written, and that Close stops
// a logread that would otherwise follow forever.
func TestRealDnsmasq_FollowLogStreamsAndStops(t *testing.T) {
	bin := t.TempDir()
	script := "#!/bin/sh\necho \"args: $*\"\necho second\nexec sleep 60\n"
	if err := os.WriteFile(filepath.Join(bin, "logread"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	c, err := newRealClient(t.TempDir(), realRunner{})
	if err != nil {
		t.Fatal(err)
	}
	if c.dnsmasq != (realDnsmasq{server: "127.0.0.1:53"}) {
		t.Errorf("production observer = %#v, want realDnsmasq at 127.0.0.1:53", c.dnsmasq)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lines, err := c.followLines(ctx)
	if err != nil {
		t.Fatalf("followLines: %v", err)
	}
	for _, want := range []string{"args: -f -l 1", "second"} {
		if err := awaitLine(ctx, lines, 10*time.Second, want, func(l string) (bool, error) {
			if l != want {
				return false, errors.New("got line " + l)
			}
			return true, nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	cancel()
	if err := awaitLine(context.Background(), lines, 10*time.Second, "stream end", func(l string) (bool, error) {
		return false, errors.New("unexpected line " + l)
	}); err == nil || !strings.Contains(err.Error(), "ended before") {
		t.Errorf("after cancel: %v, want the stream to end", err)
	}
}

func TestRealDnsmasq_FollowLogMissingBinary(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, err := (realDnsmasq{}).FollowLog(context.Background()); err == nil {
		t.Fatal("FollowLog succeeded with no logread on PATH")
	}
}

// dnsServer answers each query on a loopback UDP socket with reply(query).
func dnsServer(t *testing.T, reply func(q dnsmessage.Message) []byte) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if err := q.Unpack(buf[:n]); err != nil {
				continue
			}
			if b := reply(q); b != nil {
				_, _ = pc.WriteTo(b, addr)
			}
		}
	}()
	return pc.LocalAddr().String()
}

func buildReply(t *testing.T, q dnsmessage.Message, edit func(*dnsmessage.Message)) []byte {
	t.Helper()
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: q.ID, Response: true, RecursionDesired: q.RecursionDesired},
		Questions: q.Questions,
	}
	if edit != nil {
		edit(&m)
	}
	b, err := m.Pack()
	if err != nil {
		t.Fatalf("pack reply: %v", err)
	}
	return b
}

func TestLookupA(t *testing.T) {
	aRecord := func(name dnsmessage.Name, ip [4]byte) dnsmessage.Resource {
		return dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30},
			Body:   &dnsmessage.AResource{A: ip},
		}
	}
	cases := map[string]struct {
		reply   func(q dnsmessage.Message) []byte
		want    []netip.Addr
		wantErr string
	}{
		"answers": {
			reply: func(q dnsmessage.Message) []byte {
				return buildReply(t, q, func(m *dnsmessage.Message) {
					if len(q.Questions) != 1 || q.Questions[0].Type != dnsmessage.TypeA ||
						q.Questions[0].Name.String() != "e12bench.internal." || !q.RecursionDesired {
						m.RCode = dnsmessage.RCodeFormatError
						return
					}
					m.Answers = []dnsmessage.Resource{
						{
							Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET},
							Body:   &dnsmessage.TXTResource{TXT: []string{"skip me"}},
						},
						aRecord(q.Questions[0].Name, [4]byte{192, 168, 1, 223}),
					}
				})
			},
			want: []netip.Addr{netip.MustParseAddr("192.168.1.223")},
		},
		"nxdomain": {
			reply: func(q dnsmessage.Message) []byte {
				return buildReply(t, q, func(m *dnsmessage.Message) { m.RCode = dnsmessage.RCodeNameError })
			},
			wantErr: "RCodeNameError",
		},
		"wrong id": {
			reply: func(q dnsmessage.Message) []byte {
				q.ID++
				return buildReply(t, q, nil)
			},
			wantErr: "not the answer",
		},
		"not a response": {
			reply: func(q dnsmessage.Message) []byte {
				return buildReply(t, q, func(m *dnsmessage.Message) { m.Response = false })
			},
			wantErr: "not the answer",
		},
		"garbage": {
			reply:   func(dnsmessage.Message) []byte { return []byte{1, 2, 3} },
			wantErr: "parse reply",
		},
		"no reply": {
			reply:   func(dnsmessage.Message) []byte { return nil },
			wantErr: "read reply",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			server := dnsServer(t, tc.reply)
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			got, err := (realDnsmasq{server: server}).LookupA(ctx, "e12bench.internal")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("LookupA: %v", err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("LookupA = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLookupA_AcceptsFullyQualifiedNameAndRejectsBadName(t *testing.T) {
	server := dnsServer(t, func(q dnsmessage.Message) []byte {
		return buildReply(t, q, func(m *dnsmessage.Message) {
			m.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
				Body:   &dnsmessage.AResource{A: [4]byte{10, 0, 0, 1}},
			}}
		})
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := lookupA(ctx, server, "e12bench.internal.")
	if err != nil || !slices.Equal(got, []netip.Addr{netip.MustParseAddr("10.0.0.1")}) {
		t.Errorf("lookupA(fqdn) = %v, %v", got, err)
	}
	if _, err := lookupA(ctx, server, strings.Repeat("a", 300)); err == nil {
		t.Error("an over-long name was accepted")
	}
}
