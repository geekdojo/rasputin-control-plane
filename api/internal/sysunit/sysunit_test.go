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
