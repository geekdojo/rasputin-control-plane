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
