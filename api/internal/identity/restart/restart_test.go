package restart

import (
	"context"
	"errors"
	"log/slog"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

type runRec struct {
	calls []string
	fail  map[string]error
}

func (r *runRec) run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	return nil, r.fail[args[0]]
}

func newRestarter(t *testing.T, run *runRec, held bool, restoring bool) *Restarter {
	t.Helper()
	r, err := New(Deps{
		Run: run.run, Held: func(context.Context) bool { return held },
		Restoring: func() (string, bool) { return "J-restore", restoring },
		DBUnit:    "keycloak-db.service", Unit: "keycloak.service", Log: slog.New(slog.DiscardHandler), StepTimeout: 15 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func step(r *Restarter) error {
	_, err := r.Workflow().Steps[0].Do(&jobs.StepCtx{Ctx: context.Background(), JobID: "J1", CreatedBy: "break-glass"})
	return err
}

// TC-321-20: the step runs systemctl reset-failed on the pair, then
// systemctl restart on the service, never retried, with a long bound; a
// failing systemctl fails the job with its exit status.
func TestRestart_TC321_20(t *testing.T) {
	run := &runRec{}
	r := newRestarter(t, run, false, false)
	wf := r.Workflow()
	if wf.Kind != "identity.restart" || len(wf.Steps) != 1 || wf.Steps[0].Retries != 0 || wf.Steps[0].Timeout != 15*time.Minute || wf.System {
		t.Fatalf("workflow %+v", wf)
	}
	if err := step(r); err != nil {
		t.Fatal(err)
	}
	want := []string{"systemctl reset-failed keycloak-db.service keycloak.service", "systemctl restart keycloak.service"}
	if strings.Join(run.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls %q, want %q", run.calls, want)
	}

	exitErr := exec.Command("sh", "-c", "exit 3").Run()
	run = &runRec{fail: map[string]error{"restart": exitErr}}
	err := step(newRestarter(t, run, false, false))
	if err == nil || err.Error() != "The sign-in service couldn't be restarted: systemctl exited with status 3." {
		t.Fatalf("a failing restart: %v", err)
	}
	run = &runRec{fail: map[string]error{"reset-failed": errors.New("no systemctl")}}
	if err := step(newRestarter(t, run, false, false)); err == nil || err.Error() != "The sign-in service couldn't be restarted." {
		t.Fatalf("a failing reset: %v", err)
	}
	if len(run.calls) != 1 {
		t.Errorf("the restart ran after a failed reset: %q", run.calls)
	}
}

// F-321-09: identity.recover's guards. While a job holds the service or a
// restore runs, the step fails with the sentence and runs nothing; Busy
// reports the same.
func TestRestart_Guards(t *testing.T) {
	for name, c := range map[string]struct{ held, restoring bool }{"held": {true, false}, "restoring": {false, true}} {
		run := &runRec{}
		r := newRestarter(t, run, c.held, c.restoring)
		if err := step(r); err == nil || err.Error() != BusySentence {
			t.Errorf("%s: %v", name, err)
		}
		if len(run.calls) != 0 {
			t.Errorf("%s: ran %q", name, run.calls)
		}
		if reason, busy := r.Busy(context.Background()); !busy || reason != BusySentence {
			t.Errorf("%s: Busy = %q %v", name, reason, busy)
		}
	}
	if _, busy := newRestarter(t, &runRec{}, false, false).Busy(context.Background()); busy {
		t.Error("busy with no guard holding")
	}
}

func TestNew_RefusesIncompleteDeps(t *testing.T) {
	good := func() Deps {
		return Deps{Run: (&runRec{}).run, Held: func(context.Context) bool { return false }, Restoring: func() (string, bool) { return "", false },
			DBUnit: "a", Unit: "b", Log: slog.New(slog.DiscardHandler), StepTimeout: time.Minute}
	}
	for name, edit := range map[string]func(*Deps){
		"Run": func(d *Deps) { d.Run = nil }, "Held": func(d *Deps) { d.Held = nil }, "Restoring": func(d *Deps) { d.Restoring = nil },
		"Unit": func(d *Deps) { d.Unit = "" }, "Log": func(d *Deps) { d.Log = nil }, "StepTimeout": func(d *Deps) { d.StepTimeout = 0 },
	} {
		d := good()
		edit(&d)
		if _, err := New(d); err == nil {
			t.Errorf("New with no %s succeeded", name)
		}
	}
}
