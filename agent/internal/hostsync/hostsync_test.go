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

func TestRunWritesAndRefreshes(t *testing.T) {
	dir := t.TempDir()
	var calls atomic.Int32
	ips := []string{"192.168.1.50", "192.168.1.50", "192.168.1.77"} // unchanged, then changed
	resolve := func(name string, _ time.Duration) (string, error) {
		i := calls.Add(1) - 1
		if int(i) >= len(ips) {
			return ips[len(ips)-1], nil
		}
		return ips[i], nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// reloadCmd writes a marker each time it runs, so we can assert it fires on
	// every address change (first write + the change), not every tick.
	marker := filepath.Join(dir, "reload.count")
	reloadCmd := "printf x >> " + marker
	go Run(ctx, "rasputin.local", dir, 10*time.Millisecond, reloadCmd, resolve)

	file := filepath.Join(dir, "rasputin.local")
	// First write: 192.168.1.50
	waitFor(t, func() bool { return readHost(file) == "192.168.1.50 rasputin.local\n" })
	// After the address changes, the file follows.
	waitFor(t, func() bool { return readHost(file) == "192.168.1.77 rasputin.local\n" })
	// reloadCmd ran on each change (first write + the change) = 2 markers,
	// not once per tick.
	waitFor(t, func() bool { return len(readHost(marker)) == 2 })
}

func TestRunNoopOnResolveError(t *testing.T) {
	dir := t.TempDir()
	resolve := func(string, time.Duration) (string, error) { return "", os.ErrDeadlineExceeded }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Run(ctx, "rasputin.local", dir, 10*time.Millisecond, "", resolve)
	time.Sleep(50 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(dir, "rasputin.local")); !os.IsNotExist(err) {
		t.Fatalf("expected no hosts file on resolve error, got err=%v", err)
	}
}

// Run must call the resolver with a 3s per-attempt timeout. Guards the
// `3*time.Second` argument against arithmetic mutation (e.g. to `3/time.Second`,
// which is 0).
func TestRunPassesResolveTimeout(t *testing.T) {
	dir := t.TempDir()
	var gotTimeout atomic.Int64
	resolve := func(name string, timeout time.Duration) (string, error) {
		gotTimeout.Store(int64(timeout))
		return "192.168.1.50", nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Run(ctx, "rasputin.local", dir, 10*time.Millisecond, "", resolve)

	file := filepath.Join(dir, "rasputin.local")
	waitFor(t, func() bool { return readHost(file) != "" }) // resolver has run
	if got := time.Duration(gotTimeout.Load()); got != 3*time.Second {
		t.Fatalf("resolve timeout = %v, want 3s", got)
	}
}

// A non-positive interval must be clamped to the 30s default, not used verbatim.
// With interval == 0 the ticker would otherwise fire immediately every loop,
// hammering the resolver in a hot spin. We prove the clamp by showing that after
// the first (immediate) tick, no second resolve happens for a long stretch —
// which only holds if interval was replaced with a large default. Guards the
// `interval <= 0` clamp against being narrowed to `interval < 0`.
func TestRunClampsNonPositiveInterval(t *testing.T) {
	dir := t.TempDir()
	calls := make(chan struct{}, 64)
	resolve := func(string, time.Duration) (string, error) {
		calls <- struct{}{}
		return "192.168.1.50", nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Run(ctx, "rasputin.local", dir, 0, "", resolve) // interval == 0

	<-calls // the immediate first tick
	select {
	case <-calls:
		t.Fatal("interval <= 0 must clamp to the 30s default; got an immediate second resolve (hot spin)")
	case <-time.After(300 * time.Millisecond):
		// No second resolve — the interval was clamped to a long default.
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

	resolve := func(string, time.Duration) (string, error) { return "192.168.1.50", nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// "exit 3" makes CombinedOutput return a non-nil error, exercising the
	// failure branch on the very first (immediate) tick.
	go Run(ctx, "rasputin.local", dir, 10*time.Millisecond, "exit 3", resolve)

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
