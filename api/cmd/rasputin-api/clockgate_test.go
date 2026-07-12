package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// withClockPaths points the package-level clock-sync paths at a temp dir for
// the duration of a test, restoring them afterward.
func withClockPaths(t *testing.T, dir, marker string) {
	t.Helper()
	origDir, origMarker := clockSyncDir, clockSyncMarker
	clockSyncDir, clockSyncMarker = dir, marker
	t.Cleanup(func() { clockSyncDir, clockSyncMarker = origDir, origMarker })
}

// No systemd-timesyncd on this host (the dir does not exist) → return true
// immediately without waiting. This is the dev/CI path.
func TestWaitForTrustworthyClock_NoTimesyncd(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	withClockPaths(t, missing, filepath.Join(missing, "synchronized"))

	start := time.Now()
	if !waitForTrustworthyClock(context.Background(), 10*time.Second) {
		t.Fatal("expected true when timesyncd is absent")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("expected an immediate return, waited %s", elapsed)
	}
}

// timesyncd present and already synchronized (marker exists) → true immediately.
func TestWaitForTrustworthyClock_AlreadySynced(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "synchronized")
	if err := os.WriteFile(marker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	withClockPaths(t, dir, marker)

	start := time.Now()
	if !waitForTrustworthyClock(context.Background(), 10*time.Second) {
		t.Fatal("expected true when the sync marker is present")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("expected an immediate return, waited %s", elapsed)
	}
}

// timesyncd present but never synchronizes → return false at the deadline
// (degraded path: mint anyway, logged loudly).
func TestWaitForTrustworthyClock_TimesOut(t *testing.T) {
	dir := t.TempDir()
	withClockPaths(t, dir, filepath.Join(dir, "synchronized"))

	if waitForTrustworthyClock(context.Background(), 50*time.Millisecond) {
		t.Fatal("expected false when the clock never synchronizes")
	}
}

// The marker appearing mid-wait unblocks the gate before the deadline.
func TestWaitForTrustworthyClock_SyncsDuringWait(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "synchronized")
	withClockPaths(t, dir, marker)

	go func() {
		time.Sleep(1500 * time.Millisecond)
		_ = os.WriteFile(marker, nil, 0o644)
	}()

	if !waitForTrustworthyClock(context.Background(), 10*time.Second) {
		t.Fatal("expected true once the marker appears mid-wait")
	}
}

// A cancelled context returns false promptly even if the clock never syncs.
func TestWaitForTrustworthyClock_ContextCancel(t *testing.T) {
	dir := t.TempDir()
	withClockPaths(t, dir, filepath.Join(dir, "synchronized"))

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	if waitForTrustworthyClock(ctx, 10*time.Second) {
		t.Fatal("expected false when the context is cancelled")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("expected a prompt return on cancel, waited %s", elapsed)
	}
}
