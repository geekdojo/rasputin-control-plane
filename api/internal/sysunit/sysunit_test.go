package sysunit

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// RestartUnits resets every listed unit, then restarts the one named; a
// failed reset stops before the restart.
func TestRestartUnits(t *testing.T) {
	var calls []string
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	}
	if err := RestartUnits(t.Context(), run, []string{"a.service", "b.service"}, "b.service"); err != nil {
		t.Fatal(err)
	}
	want := []string{"systemctl reset-failed a.service b.service", "systemctl restart b.service"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %q, want %q", calls, want)
	}

	calls = nil
	boom := errors.New("boom")
	failReset := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, boom
	}
	if err := RestartUnits(t.Context(), failReset, []string{"a.service"}, "a.service"); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the reset's", err)
	}
	if len(calls) != 1 {
		t.Fatalf("calls after a failed reset = %q, want the reset only", calls)
	}

	restartErr := errors.New("restart")
	failRestart := func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[0] == "restart" {
			return nil, restartErr
		}
		return nil, nil
	}
	if err := RestartUnits(t.Context(), failRestart, nil, "a.service"); !errors.Is(err, restartErr) {
		t.Fatalf("err = %v, want the restart's", err)
	}
}

// Show makes one systemctl show call naming the units in order and parses
// one block per unit; no unit, a failed call and a block count that does not
// match are errors (geekdojo/geekdojo-brain#1132).
func TestShow(t *testing.T) {
	var calls []string
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return []byte("ActiveState=active\nSubState=running\nInvocationID=0123456789abcdef0123456789abcdef\n"), nil
	}
	u, err := Show(t.Context(), run, "openbao.service")
	if err != nil {
		t.Fatal(err)
	}
	want := []Unit{{ActiveState: "active", SubState: "running", InvocationID: "0123456789abcdef0123456789abcdef"}}
	if !reflect.DeepEqual(u, want) {
		t.Fatalf("units = %+v, want %+v", u, want)
	}
	if len(calls) != 1 || calls[0] != "systemctl show --property=ActiveState,SubState,InvocationID openbao.service" {
		t.Fatalf("calls = %q", calls)
	}
	if _, err := Show(t.Context(), run); err == nil {
		t.Error("no unit named: no error")
	}
	if _, err := Show(t.Context(), run, "a.service", "b.service"); err == nil {
		t.Error("one block for two units: no error")
	}
	fail := func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("no bus") }
	if _, err := Show(t.Context(), fail, "openbao.service"); err == nil || !strings.Contains(err.Error(), "no bus") {
		t.Errorf("err = %v, want the run error wrapped", err)
	}
}

// TC-321-72: ActiveUnits runs the one list-units call, returns the active
// units it printed, and fails closed on any line it can't read (F-321-45)
// and on a failed run, which it wraps naming the pattern.
func TestActiveUnits(t *testing.T) {
	const pattern = "serial-getty@*.service"
	const ama10 = "serial-getty@ttyAMA10.service loaded active running Serial Getty on ttyAMA10"
	var calls []string
	out := func(s string) func(context.Context, string, ...string) ([]byte, error) {
		return func(_ context.Context, name string, args ...string) ([]byte, error) {
			calls = append(calls, name+" "+strings.Join(args, " "))
			return []byte(s), nil
		}
	}
	got, err := ActiveUnits(t.Context(), out(ama10+"\n"), pattern)
	if err != nil || !reflect.DeepEqual(got, []string{"serial-getty@ttyAMA10.service"}) {
		t.Fatalf("one line: %q, %v", got, err)
	}
	want := "systemctl list-units --type=service --state=active --plain --no-legend serial-getty@*.service"
	if len(calls) != 1 || calls[0] != want {
		t.Fatalf("calls = %q, want %q", calls, want)
	}
	two := ama10 + "\nserial-getty@ttyS0.service loaded active running Serial Getty on ttyS0\n"
	if got, err := ActiveUnits(t.Context(), out(two), pattern); err != nil ||
		!reflect.DeepEqual(got, []string{"serial-getty@ttyAMA10.service", "serial-getty@ttyS0.service"}) {
		t.Errorf("two lines: %q, %v", got, err)
	}
	for name, s := range map[string]string{"empty": "", "blank lines": "\n  \n"} {
		if got, err := ActiveUnits(t.Context(), out(s), pattern); err != nil || got == nil || len(got) != 0 {
			t.Errorf("%s: %q, %v; want an empty result and no error", name, got, err)
		}
	}
	for name, s := range map[string]string{
		"one field":           "serial-getty@ttyAMA10.service\n",
		"three fields":        "serial-getty@ttyAMA10.service loaded active\n",
		"not-found":           "serial-getty@ttyAMA10.service not-found active running x\n",
		"inactive":            "serial-getty@ttyAMA10.service loaded inactive dead x\n",
		"outside the pattern": "getty@tty1.service loaded active running Getty on tty1\n",
		"a stray stderr line": ama10 + "\nWarning: The unit file, source configuration file or drop-ins of x changed on disk.\n",
	} {
		if got, err := ActiveUnits(t.Context(), out(s), pattern); err == nil || got != nil {
			t.Errorf("%s: %q, %v; want an error and no names", name, got, err)
		}
	}
	calls = nil
	if got, err := ActiveUnits(t.Context(), out(ama10), "serial-getty@[.service"); err == nil || got != nil || len(calls) != 0 {
		t.Errorf("a malformed pattern: %q, %v, %d calls; want an error and no run", got, err, len(calls))
	}
	boom := errors.New("no bus")
	fail := func(context.Context, string, ...string) ([]byte, error) { return []byte("x"), boom }
	if got, err := ActiveUnits(t.Context(), fail, pattern); !errors.Is(err, boom) || got != nil || !strings.Contains(err.Error(), pattern) {
		t.Errorf("a failed run: %q, %v; want the run error wrapped, naming the pattern", got, err)
	}
}
