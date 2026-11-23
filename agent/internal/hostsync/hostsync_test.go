package hostsync

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// The two names the firewall agent publishes, in its order.
var benchNames = []string{"bench.local", "sso-bench.local"}

func twoLines(ip string) string {
	return ip + " bench.local\n" + ip + " sso-bench.local\n"
}

// seq returns a ServerIP that walks the given addresses and then repeats the
// last one — a stand-in for the live bus connection's peer — and the number of
// times it has been asked. A test waits on that count, a fact, never a sleep:
// once ask N has begun, everything Run did for ask N-1 (write, log, reload)
// has finished, because one goroutine does them in order.
func seq(ips ...string) (ServerIP, *atomic.Int32) {
	var calls atomic.Int32
	return func() string {
		i := int(calls.Add(1) - 1)
		if i >= len(ips) {
			return ips[len(ips)-1]
		}
		return ips[i]
	}, &calls
}

// rig starts Run for benchNames over a fresh directory, with a reload command
// that appends one byte to a marker kept OUTSIDE the hosts directory (so the
// directory listing is only what Run wrote).
type rig struct {
	dir, file, marker string
	calls             *atomic.Int32
	rec               *logkittest.Recorder
}

func startRig(t *testing.T, dir string, serverIP ServerIP, calls *atomic.Int32) *rig {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "reload.count")
	logger, rec := logkittest.New()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() { cancel(); <-done })
	go func() {
		defer close(done)
		Run(ctx, Config{
			Names:     benchNames,
			Dir:       dir,
			Interval:  10 * time.Millisecond,
			ReloadCmd: "printf x >> " + marker,
			ServerIP:  serverIP,
			Logger:    logger,
		})
	}()
	return &rig{dir: dir, file: filepath.Join(dir, "bench.local"), marker: marker, calls: calls, rec: rec}
}

func (r *rig) waitAsks(t *testing.T, n int32) {
	t.Helper()
	waitFor(t, func() bool { return r.calls.Load() >= n })
}

func (r *rig) reloads() int { return len(readHost(r.marker)) }

// TC-997-01: both names, one line each, in the one file dir/<cid>.local, at
// the address the bus reports; one reload, one INFO record.
func TestRunWritesBothNamesAtTheBusAddress(t *testing.T) {
	serverIP, calls := seq("192.168.1.50")
	r := startRig(t, t.TempDir(), serverIP, calls)
	r.waitAsks(t, 3)

	if got := readHost(r.file); got != twoLines("192.168.1.50") {
		t.Fatalf("hosts file = %q, want %q", got, twoLines("192.168.1.50"))
	}
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "bench.local" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("hosts dir holds %v, want exactly [bench.local] (no per-name sso-bench.local file)", names)
	}
	if n := r.reloads(); n != 1 {
		t.Fatalf("reload ran %d times, want 1", n)
	}
	pub := r.rec.Matching(slog.LevelInfo, "hostsync published")
	if len(pub) != 1 {
		t.Fatalf("got %d INFO 'hostsync published' records, want 1:\n%s", len(pub), r.rec.Text())
	}
	if ip, _ := logkittest.Attr(pub[0], "ip"); ip != "192.168.1.50" {
		t.Errorf("published record ip = %q, want 192.168.1.50", ip)
	}
	if names, ok := logkittest.Attr(pub[0], "names"); !ok || !strings.Contains(names, "sso-bench.local") {
		t.Errorf("published record names = %q (present %v), want both names", names, ok)
	}
	if dir, _ := logkittest.Attr(pub[0], "dir"); dir != r.dir {
		t.Errorf("published record dir = %q, want %q", dir, r.dir)
	}
}

// TC-997-02: an address change moves both names together, in one write; the
// reload runs per change, not per look.
func TestRunMovesBothNamesTogether(t *testing.T) {
	serverIP, calls := seq("192.168.1.50", "192.168.1.50", "192.168.1.77")
	r := startRig(t, t.TempDir(), serverIP, calls)
	r.waitAsks(t, 4) // ask 3 (the change) has been fully handled

	got := readHost(r.file)
	if got != twoLines("192.168.1.77") {
		t.Fatalf("hosts file = %q, want %q", got, twoLines("192.168.1.77"))
	}
	if strings.Contains(got, "192.168.1.50") {
		t.Fatalf("a line still carries the old address: %q", got)
	}
	if n := r.reloads(); n != 2 {
		t.Fatalf("reload ran %d times, want 2 (first write + the change)", n)
	}
}

// TC-997-03: NOT KNOWING is not LOSING. Once published, a bus that goes down
// withdraws neither name.
func TestRunKeepsBothNamesWhileTheAddressIsUnknown(t *testing.T) {
	serverIP, calls := seq("192.168.1.50", "", "", "")
	r := startRig(t, t.TempDir(), serverIP, calls)
	r.waitAsks(t, 5) // the 4th ask (third empty one) has been fully handled

	if got := readHost(r.file); got != twoLines("192.168.1.50") {
		t.Fatalf("published entry should survive a bus outage; got %q", got)
	}
	if n := r.reloads(); n != 1 {
		t.Fatalf("reload ran %d times, want 1", n)
	}
}

// TC-997-04: the previous release's one-line file is rewritten to two lines on
// the first bus address, even when the address on disk is the same; with no
// bus address it is left exactly as it was.
func TestRunUpgradesThePreviousReleasesFile(t *testing.T) {
	const previous = "192.168.1.50 bench.local\n"
	seed := func(t *testing.T) string {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "bench.local"), []byte(previous), 0o644); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	t.Run("same address on disk", func(t *testing.T) {
		serverIP, calls := seq("192.168.1.50")
		r := startRig(t, seed(t), serverIP, calls)
		r.waitAsks(t, 2) // ask 1 has been fully handled

		if got := readHost(r.file); got != twoLines("192.168.1.50") {
			t.Fatalf("hosts file = %q, want %q", got, twoLines("192.168.1.50"))
		}
		if n := r.reloads(); n != 1 {
			t.Fatalf("reload ran %d times, want 1", n)
		}
	})

	t.Run("no bus address", func(t *testing.T) {
		serverIP, calls := seq("")
		r := startRig(t, seed(t), serverIP, calls)
		r.waitAsks(t, 4)

		if got := readHost(r.file); got != previous {
			t.Fatalf("hosts file = %q, want the previous release's %q untouched", got, previous)
		}
		if _, err := os.Stat(r.marker); !os.IsNotExist(err) {
			t.Fatalf("reload ran with no bus address (marker err=%v)", err)
		}
	})
}

// TC-997-05: a failed write is logged, not reloaded, and retried on the next
// look — never half-applied.
func TestRunReportsAndRetriesAFailedWrite(t *testing.T) {
	dir := t.TempDir()
	block := filepath.Join(dir, "bench.local")
	if err := os.Mkdir(block, 0o755); err != nil { // the rename onto it fails
		t.Fatal(err)
	}
	serverIP, calls := seq("192.168.1.50")
	r := startRig(t, dir, serverIP, calls)
	r.waitAsks(t, 3) // asks 1 and 2 have been fully handled

	errs := r.rec.Matching(slog.LevelError, "hostsync write failed")
	if len(errs) == 0 {
		t.Fatalf("no ERROR record for the failed write:\n%s", r.rec.Text())
	}
	if f, _ := logkittest.Attr(errs[0], "file"); !strings.HasSuffix(f, "bench.local") {
		t.Errorf("ERROR record file = %q, want it to end bench.local", f)
	}
	if e, ok := logkittest.Attr(errs[0], "err"); !ok || e == "" {
		t.Errorf("ERROR record carries no err field")
	}
	if _, err := os.Stat(r.marker); !os.IsNotExist(err) {
		t.Fatalf("reload ran after a failed write (marker err=%v)", err)
	}

	if err := os.Remove(block); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return readHost(r.file) == twoLines("192.168.1.50") })
	waitFor(t, func() bool { return r.reloads() >= 1 })
	r.waitAsks(t, r.calls.Load()+1) // one more full look: still exactly one reload
	if n := r.reloads(); n != 1 {
		t.Fatalf("reload ran %d times after the repair, want 1", n)
	}
}

// The bus has never connected, so nothing can say where the control plane is.
// Nothing is published: an entry is only ever written from an address the bus
// itself reported.
func TestRunPublishesNothingWithoutABusAddress(t *testing.T) {
	serverIP, calls := seq("")
	r := startRig(t, t.TempDir(), serverIP, calls)
	r.waitAsks(t, 3)
	if _, err := os.Stat(r.file); !os.IsNotExist(err) {
		t.Fatalf("expected no hosts file while the bus address is unknown, got err=%v", err)
	}
}

// A nil address source, or no names, is a wiring bug, not a reason to fall
// back to resolving the name — that fallback is the mDNS republish this
// package no longer does. Run returns at once, writes nothing, says why.
func TestRunRefusesAWiringBug(t *testing.T) {
	always := func() string { return "192.168.1.50" }
	for name, cfg := range map[string]Config{
		"no address source": {Names: benchNames},
		"no names":          {ServerIP: always},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			logger, rec := logkittest.New()
			cfg.Dir, cfg.Interval, cfg.Logger = dir, 10*time.Millisecond, logger
			done := make(chan struct{})
			go func() { Run(context.Background(), cfg); close(done) }()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("Run should return immediately on a wiring bug")
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 0 {
				t.Fatalf("expected no hosts file, got %d entries", len(entries))
			}
			errs := rec.Matching(slog.LevelError, "hostsync not started")
			if len(errs) != 1 {
				t.Fatalf("got %d ERROR 'hostsync not started' records, want 1:\n%s", len(errs), rec.Text())
			}
			if reason, _ := logkittest.Attr(errs[0], "reason"); reason == "" {
				t.Error("ERROR record carries no reason")
			}
		})
	}
}

// A non-positive interval must be clamped to the 30s default, not used verbatim.
// With interval == 0 the ticker would otherwise fire immediately every loop,
// hammering the address source in a hot spin. We prove the clamp by showing that after
// the first (immediate) tick, no second look happens for a long stretch —
// which only holds if interval was replaced with a large default. Guards the
// `interval <= 0` clamp against being narrowed to `interval < 0`.
func TestRunClampsNonPositiveInterval(t *testing.T) {
	calls := make(chan struct{}, 64)
	serverIP := func() string {
		calls <- struct{}{}
		return "192.168.1.50"
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Run(ctx, Config{Names: benchNames, Dir: t.TempDir(), ServerIP: serverIP}) // interval == 0

	<-calls // the immediate first tick
	select {
	case <-calls:
		t.Fatal("interval <= 0 must clamp to the 30s default; got an immediate second look (hot spin)")
	case <-time.After(300 * time.Millisecond):
		// No second look — the interval was clamped to a long default.
	}
}

// When the reload command fails, Run must say so at ERROR, naming the command.
// Guards the `rerr != nil` check against being flipped (which would log only
// on success and swallow real reload failures).
func TestRunLogsReloadFailure(t *testing.T) {
	logger, rec := logkittest.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// "exit 3" makes CombinedOutput return a non-nil error on the very first
	// (immediate) tick.
	go Run(ctx, Config{
		Names:     benchNames,
		Dir:       t.TempDir(),
		Interval:  10 * time.Millisecond,
		ReloadCmd: "exit 3",
		ServerIP:  func() string { return "192.168.1.50" },
		Logger:    logger,
	})

	waitFor(t, func() bool { return len(rec.Matching(slog.LevelError, "hostsync reload failed")) > 0 })
	got := rec.Matching(slog.LevelError, "hostsync reload failed")[0]
	if cmd, _ := logkittest.Attr(got, "cmd"); cmd != "exit 3" {
		t.Errorf("reload ERROR cmd = %q, want %q", cmd, "exit 3")
	}
}

func readHost(file string) string {
	b, err := os.ReadFile(file)
	if err != nil {
		return ""
	}
	return string(b)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}
