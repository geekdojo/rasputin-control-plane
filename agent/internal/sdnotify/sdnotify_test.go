package sdnotify

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// notify must actually send the datagram when NOTIFY_SOCKET points at a
// listening socket. Kills CONDITIONALS_NEGATION at sdnotify.go:32
// (`if sock == ""`): the negated form (`sock != ""`) would return a nil
// no-op precisely when the socket IS configured, so nothing would arrive.
func TestNotify_SendsWhenSocketSet(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "notify.sock")
	ln, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sockPath, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen unixgram: %v", err)
	}
	defer ln.Close()

	t.Setenv("NOTIFY_SOCKET", sockPath)
	if err := notify("READY=1"); err != nil {
		t.Fatalf("notify: %v", err)
	}

	if err := ln.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 64)
	n, _, err := ln.ReadFromUnix(buf)
	if err != nil {
		t.Fatalf("read datagram: %v (notify sent nothing?)", err)
	}
	if got := string(buf[:n]); got != "READY=1" {
		t.Errorf("datagram = %q, want %q", got, "READY=1")
	}
}

// notify is a silent nil no-op when NOTIFY_SOCKET is unset — dev runs, tests,
// non-systemd platforms. Documents the `sock == ""` true branch.
func TestNotify_NoopWhenSocketUnset(t *testing.T) {
	// t.Setenv restores the prior value after the test; unset for this run.
	t.Setenv("NOTIFY_SOCKET", "")
	if err := os.Unsetenv("NOTIFY_SOCKET"); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}
	if err := notify("READY=1"); err != nil {
		t.Errorf("notify with no NOTIFY_SOCKET should be a nil no-op, got %v", err)
	}
}

// StartWatchdog must return true (arming the pet loop) for a valid positive
// WATCHDOG_USEC. Kills two survivors on sdnotify.go:61 and :65:
//   - CONDITIONALS_NEGATION at 61:13 (`usecStr == ""` → `!=`): the negated form
//     returns false immediately when usecStr is the non-empty value we set.
//   - CONDITIONALS_NEGATION at 65:9 (`err != nil` → `err == nil`): on a clean
//     parse err is nil, so the negated form returns false instead of arming.
func TestStartWatchdog_ArmsForValidUsec(t *testing.T) {
	// 10s → the pet ticker fires at 5s intervals, well past this test's life.
	t.Setenv("WATCHDOG_USEC", "10000000")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // stop the background pet goroutine

	if !StartWatchdog(ctx, func(context.Context) error { return nil }) {
		t.Error("StartWatchdog should return true for a valid positive WATCHDOG_USEC")
	}
}

// StartWatchdog must reject a non-positive WATCHDOG_USEC. Kills both survivors
// on the `usec <= 0` guard (sdnotify.go:65:24):
//   - CONDITIONALS_BOUNDARY (`<= 0` → `< 0`): 0 would then slip through and arm.
//   - CONDITIONALS_NEGATION (`<= 0` → `> 0`): 0 would then slip through and arm.
//
// Either mutation makes StartWatchdog return true for WATCHDOG_USEC=0.
func TestStartWatchdog_RejectsZeroUsec(t *testing.T) {
	t.Setenv("WATCHDOG_USEC", "0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if StartWatchdog(ctx, func(context.Context) error { return nil }) {
		t.Error("StartWatchdog should return false for WATCHDOG_USEC=0")
	}
}
