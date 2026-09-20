package hostsync

import (
	"bytes"
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// seq returns a ServerIP that walks the given addresses and then repeats the
// last one — a stand-in for the live bus connection's peer.
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

func TestRunWritesAndRefreshes(t *testing.T) {
	dir := t.TempDir()
	serverIP, _ := seq("192.168.1.50", "192.168.1.50", "192.168.1.77") // unchanged, then changed

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// reloadCmd writes a marker each time it runs, so we can assert it fires on
	// every address change (first write + the change), not every tick.
	marker := filepath.Join(dir, "reload.count")
	reloadCmd := "printf x >> " + marker
	go Run(ctx, "rasputin.local", dir, 10*time.Millisecond, reloadCmd, serverIP)

	file := filepath.Join(dir, "rasputin.local")
	// First write: 192.168.1.50
	waitFor(t, func() bool { return readHost(file) == "192.168.1.50 rasputin.local\n" })
	// After the address changes, the file follows.
	waitFor(t, func() bool { return readHost(file) == "192.168.1.77 rasputin.local\n" })
	// reloadCmd ran on each change (first write + the change) = 2 markers,
	// not once per tick.
	waitFor(t, func() bool { return len(readHost(marker)) == 2 })
}

// The bus has never connected, so nothing can say where the control plane is.
// Nothing is published: an entry is only ever written from an address the bus
// itself reported.
func TestRunPublishesNothingWithoutABusAddress(t *testing.T) {
	dir := t.TempDir()
	serverIP := func() string { return "" }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Run(ctx, "rasputin.local", dir, 10*time.Millisecond, "", serverIP)
	time.Sleep(50 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(dir, "rasputin.local")); !os.IsNotExist(err) {
		t.Fatalf("expected no hosts file while the bus address is unknown, got err=%v", err)
	}
}

// NOT KNOWING is not LOSING: once an address has been published, a bus that
// goes down must not withdraw it. Withdrawing would take this box's own
// tailscaled off the mesh for as long as the bus was down and put nothing
// better in its place.
func TestRunKeepsThePublishedEntryWhenTheBusGoesDown(t *testing.T) {
	dir := t.TempDir()
	serverIP, _ := seq("192.168.1.50", "", "", "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Run(ctx, "rasputin.local", dir, 10*time.Millisecond, "", serverIP)

	file := filepath.Join(dir, "rasputin.local")
	waitFor(t, func() bool { return readHost(file) == "192.168.1.50 rasputin.local\n" })
	time.Sleep(60 * time.Millisecond) // several ticks with no address
	if got := readHost(file); got != "192.168.1.50 rasputin.local\n" {
		t.Fatalf("published entry should survive a bus outage; got %q", got)
	}
}

// A nil address source is a wiring bug, not a reason to fall back to resolving
// the name — that fallback is the mDNS republish this package no longer does.
func TestRunRefusesWithoutAnAddressSource(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { Run(ctx, "rasputin.local", dir, 10*time.Millisecond, "", nil); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run should return immediately when it has no address source")
	}
	if _, err := os.Stat(filepath.Join(dir, "rasputin.local")); !os.IsNotExist(err) {
		t.Fatalf("expected no hosts file, got err=%v", err)
	}
}

// A non-positive interval must be clamped to the 30s default, not used verbatim.
// With interval == 0 the ticker would otherwise fire immediately every loop,
// hammering the address source in a hot spin. We prove the clamp by showing that after
// the first (immediate) tick, no second look happens for a long stretch —
// which only holds if interval was replaced with a large default. Guards the
// `interval <= 0` clamp against being narrowed to `interval < 0`.
func TestRunClampsNonPositiveInterval(t *testing.T) {
	dir := t.TempDir()
	calls := make(chan struct{}, 64)
	serverIP := func() string {
		calls <- struct{}{}
		return "192.168.1.50"
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Run(ctx, "rasputin.local", dir, 0, "", serverIP) // interval == 0

	<-calls // the immediate first tick
	select {
	case <-calls:
		t.Fatal("interval <= 0 must clamp to the 30s default; got an immediate second look (hot spin)")
	case <-time.After(300 * time.Millisecond):
		// No second look — the interval was clamped to a long default.
	}
}

// When reloadCmd fails, Run must log the failure. Guards the `rerr != nil` check
// against being flipped to `rerr == nil` (which would log only on success and
// swallow real reload failures).
func TestRunLogsReloadFailure(t *testing.T) {
	dir := t.TempDir()
	var buf safeBuffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	serverIP := func() string { return "192.168.1.50" }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// "exit 3" makes CombinedOutput return a non-nil error, exercising the
	// failure branch on the very first (immediate) tick.
	go Run(ctx, "rasputin.local", dir, 10*time.Millisecond, "exit 3", serverIP)

	waitFor(t, func() bool {
		s := buf.String()
		return strings.Contains(s, "reload") && strings.Contains(s, "failed")
	})
}

// safeBuffer is a concurrency-safe io.Writer for capturing log output written by
// the Run goroutine while the test reads it.
type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
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
