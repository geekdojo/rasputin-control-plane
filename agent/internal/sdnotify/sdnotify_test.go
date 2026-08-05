package sdnotify

import (
	"bytes"
	"context"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
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

// The pet interval must be exactly half of WATCHDOG_USEC: systemd kills a
// process that misses its deadline, so a too-long interval SIGABRTs a healthy
// agent and a too-short one wastes wakeups on the firewall's modest N100. The
// arm/reject tests above only assert the bool return, leaving the interval
// arithmetic on sdnotify.go:69 (`time.Duration(usec) * time.Microsecond / 2`)
// unchecked — two ARITHMETIC_BASE survivors LIVED there. StartWatchdog logs the
// computed interval when it arms, so asserting that line pins the math:
//   - 69:34 (`*` → `/`): WATCHDOG_USEC=10000000 would yield a 5µs interval.
//   - 69:53 (`/ 2` → `* 2`): it would yield a 20s interval.
//
// Only the correct code prints "petting every 5s" (half of 10s).
func TestStartWatchdog_PetIntervalIsHalfOfUsec(t *testing.T) {
	var buf bytes.Buffer
	oldOut, oldFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(oldOut)
		log.SetFlags(oldFlags)
	}()

	// 10s expressed in microseconds; the pet interval must be exactly 5s.
	t.Setenv("WATCHDOG_USEC", "10000000")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel so the pet goroutine exits before it can log anything

	if !StartWatchdog(ctx, func(context.Context) error { return nil }) {
		t.Fatal("StartWatchdog should arm for a valid positive WATCHDOG_USEC")
	}
	if got := buf.String(); !strings.Contains(got, "petting every 5s") {
		t.Errorf("armed log = %q, want it to report a 5s pet interval (half of WATCHDOG_USEC=10s)", got)
	}
}
