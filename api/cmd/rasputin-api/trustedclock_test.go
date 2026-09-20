package main

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Already synchronized: every caller returns true, and nothing waits.
func TestTrustedClock_LatchesAndDoesNotWait(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "synchronized")
	if err := os.WriteFile(marker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	withClockPaths(t, dir, marker)

	c := newTrustedClock(context.Background(), 10*time.Second)
	start := time.Now()
	for i := range 3 {
		if !c.ok() {
			t.Fatalf("call %d: got false, want true", i)
		}
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("waited %s; a synchronized clock must answer immediately", elapsed)
	}
	// Latched: the answer survives the marker going away, because a clock
	// that has synchronized does not become untrustworthy again.
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if !c.ok() {
		t.Error("the answer un-latched")
	}
}

// The wait is spent ONCE. A renewal sweep over a fleet of leaves on a node
// with no NTP must not stall once per leaf.
func TestTrustedClock_WaitsOnlyOnce(t *testing.T) {
	dir := t.TempDir()
	withClockPaths(t, dir, filepath.Join(dir, "synchronized"))

	c := newTrustedClock(context.Background(), 300*time.Millisecond)
	start := time.Now()
	if c.ok() {
		t.Fatal("got true with no synchronized marker")
	}
	first := time.Since(start)
	if first < 250*time.Millisecond {
		t.Fatalf("the first call returned in %s; it should have waited out the budget", first)
	}
	start = time.Now()
	for range 5 {
		if c.ok() {
			t.Fatal("got true with no synchronized marker")
		}
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("later calls waited %s; the budget is spent once", elapsed)
	}
}

// A clock that synchronizes AFTER the one wait gave up is picked up by the
// next mint, rather than being written off for the life of the process.
func TestTrustedClock_NoticesALateSync(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "synchronized")
	withClockPaths(t, dir, marker)

	c := newTrustedClock(context.Background(), 200*time.Millisecond)
	if c.ok() {
		t.Fatal("got true before the marker existed")
	}
	if err := os.WriteFile(marker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if !c.ok() {
		t.Error("a clock that synchronized after the wait was not noticed")
	}
}

// Shutdown: nothing blocks for the budget, and the answer is false rather
// than an optimistic true.
func TestTrustedClock_ContextCancelled(t *testing.T) {
	dir := t.TempDir()
	withClockPaths(t, dir, filepath.Join(dir, "synchronized"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := newTrustedClock(ctx, 10*time.Second)
	start := time.Now()
	if c.ok() {
		t.Error("got true on a cancelled context")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("waited %s after cancellation", elapsed)
	}
}

// Concurrent callers — a sweep renewing several leaves at once — see one
// wait between them, not one each.
func TestTrustedClock_ConcurrentCallersShareTheWait(t *testing.T) {
	dir := t.TempDir()
	withClockPaths(t, dir, filepath.Join(dir, "synchronized"))

	c := newTrustedClock(context.Background(), 300*time.Millisecond)
	var wg sync.WaitGroup
	var trues atomic.Int32
	start := time.Now()
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.ok() {
				trues.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := trues.Load(); n != 0 {
		t.Errorf("%d callers got true with no synchronized marker", n)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("eight callers took %s; they must share one wait", elapsed)
	}
}
