package unitrecover

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identitystate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/sysunit"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// pair is the identity pair's units and the space, as the fakes report them,
// and the systemctl calls the restart made.
type pair struct {
	mu      sync.Mutex
	units   identitystate.Units
	free    uint64
	held    bool
	restore bool
	calls   []string
	failRun error
}

func (p *pair) set(fn func(*pair)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fn(p)
}

func (p *pair) run(_ context.Context, name string, args ...string) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, name+" "+strings.Join(args, " "))
	return nil, p.failRun
}

// identityRecoverer is a Recoverer with the identity wiring's parameters:
// identitystate.PairState over the fake units, and sysunit.RestartUnits over
// the fake runner.
func identityRecoverer(t *testing.T, p *pair) (*Recoverer, *logkittest.Recorder) {
	t.Helper()
	log, rec := logkittest.New()
	r, err := New(Deps{
		Kind: "identity.recover", Service: "sign-in service", Component: "identity",
		Dir: testDir,
		Free: func(string) (uint64, error) {
			p.mu.Lock()
			defer p.mu.Unlock()
			return p.free, nil
		},
		FullBelow: fullAt,
		Unit:      "keycloak.service",
		UnitState: identitystate.PairStateOf(func(context.Context) (identitystate.Units, error) {
			p.mu.Lock()
			defer p.mu.Unlock()
			return p.units, nil
		}),
		Held: func(context.Context) bool {
			p.mu.Lock()
			defer p.mu.Unlock()
			return p.held
		},
		Restoring: func() (string, bool) {
			p.mu.Lock()
			defer p.mu.Unlock()
			return "job-restore", p.restore
		},
		Restart: func(ctx context.Context) error {
			return sysunit.RestartUnits(ctx, p.run, []string{"keycloak-db.service", "keycloak.service"}, "keycloak.service")
		},
		Log:         log,
		StepTimeout: 15 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r, rec
}

func units(kc, db string) identitystate.Units {
	return identitystate.Units{KC: identitystate.Unit{ActiveState: kc}, DB: identitystate.Unit{ActiveState: db}}
}

func step(t *testing.T, r *Recoverer) (json.RawMessage, []stepLine, error) {
	t.Helper()
	var lines []stepLine
	sc := &jobs.StepCtx{Ctx: t.Context(), JobID: "job-id", Log: func(level, msg string) { lines = append(lines, stepLine{level, msg}) }}
	out, err := r.Workflow().Steps[0].Do(sc)
	return out, lines, err
}

// TC-979-21: unitrecover for the identity pair through PairState, including
// Keycloak left inactive after its database recovers (F-979-02).
func TestIdentityPair(t *testing.T) {
	const wantReset = "systemctl reset-failed keycloak-db.service keycloak.service"
	const wantRestart = "systemctl restart keycloak.service"

	// arm puts r in the armed state through a full reading with the pair in
	// state (kc, db).
	arm := func(t *testing.T, p *pair, r *Recoverer, kc, db string) {
		t.Helper()
		p.set(func(p *pair) { p.free, p.units = 0, units(kc, db) })
		if due, _ := r.Due(t.Context()); due || !r.isArmed() {
			t.Fatalf("full with kc %s, db %s: due %t, armed %t; want armed, not due", kc, db, due, r.isArmed())
		}
	}

	t.Run("A: room returns with the database failed", func(t *testing.T) {
		p := &pair{}
		r, rec := identityRecoverer(t, p)
		arm(t, p, r, "inactive", "failed")
		if n := len(rec.Matching(slog.LevelInfo, "sign-in service failed while the data partition was full")); n != 1 {
			t.Fatalf("%d armed records", n)
		}
		if e, _ := logkittest.Attr(rec.Records()[0], "event"); e != "identity.recover_armed" {
			t.Fatalf("event = %q", e)
		}
		p.set(func(p *pair) { p.free = fullAt })
		if due, _ := r.Due(t.Context()); !due {
			t.Fatal("not due with room")
		}
		if due, _ := r.Due(t.Context()); due {
			t.Fatal("due twice")
		}
		out, _, err := step(t, r)
		if err != nil || string(out) != `{"restarted":true}` {
			t.Fatalf("step: %s, %v", out, err)
		}
		if strings.Join(p.calls, "|") != wantReset+"|"+wantRestart {
			t.Fatalf("calls = %q", p.calls)
		}
		if n := len(rec.Matching(slog.LevelInfo, "sign-in service restarting")); n != 1 {
			t.Fatalf("%d restart records", n)
		}
	})

	t.Run("B: the database active, Keycloak inactive", func(t *testing.T) {
		p := &pair{}
		r, _ := identityRecoverer(t, p)
		arm(t, p, r, "inactive", "activating")
		p.set(func(p *pair) { p.free, p.units = fullAt, units("inactive", "active") })
		due1, _ := r.Due(t.Context())
		due2, _ := r.Due(t.Context())
		if !due1 || due2 {
			t.Fatalf("due %t then %t, want once", due1, due2)
		}
		if _, _, err := step(t, r); err != nil {
			t.Fatal(err)
		}
		if strings.Join(p.calls, "|") != wantReset+"|"+wantRestart {
			t.Fatalf("calls = %q, want exactly one pair restart", p.calls)
		}
	})

	t.Run("C: both active disarms", func(t *testing.T) {
		p := &pair{}
		r, rec := identityRecoverer(t, p)
		arm(t, p, r, "inactive", "failed")
		p.set(func(p *pair) { p.free, p.units = fullAt, units("active", "active") })
		if due, _ := r.Due(t.Context()); due || r.isArmed() {
			t.Fatal("both active: due or still armed")
		}
		if n := len(rec.Matching(slog.LevelInfo, "sign-in service is no longer failed")); n != 1 {
			t.Fatalf("%d disarmed records", n)
		}
		if e, _ := logkittest.Attr(rec.Matching(slog.LevelInfo, "no longer failed")[0], "event"); e != "identity.recover_disarmed" {
			t.Fatalf("event = %q", e)
		}
		if len(p.calls) != 0 {
			t.Fatalf("calls = %q", p.calls)
		}
	})

	t.Run("D: the database activating under an active Keycloak", func(t *testing.T) {
		p := &pair{}
		r, _ := identityRecoverer(t, p)
		arm(t, p, r, "active", "activating")
		p.set(func(p *pair) { p.free = fullAt })
		if due, _ := r.Due(t.Context()); due || !r.isArmed() {
			t.Fatal("activating: due, or disarmed")
		}
	})

	t.Run("held or restoring is skipped with the reason", func(t *testing.T) {
		p := &pair{}
		r, _ := identityRecoverer(t, p)
		arm(t, p, r, "inactive", "failed")
		p.set(func(p *pair) { p.free, p.held = fullAt, true })
		if due, reason := r.Due(t.Context()); due || reason != "a job holds the sign-in service" {
			t.Fatalf("held: %t %q", due, reason)
		}
		out, _, err := step(t, r)
		if err != nil || !strings.Contains(string(out), "a job holds the sign-in service") {
			t.Fatalf("held step: %s %v", out, err)
		}
		p.set(func(p *pair) { p.held, p.restore = false, true })
		if due, reason := r.Due(t.Context()); due || reason != "a restore is in progress" {
			t.Fatalf("restoring: %t %q", due, reason)
		}
		if len(p.calls) != 0 {
			t.Fatalf("calls = %q", p.calls)
		}
	})

	t.Run("a failed restart", func(t *testing.T) {
		p := &pair{failRun: errors.New("unit not found")}
		r, rec := identityRecoverer(t, p)
		p.set(func(p *pair) { p.free, p.units = fullAt, units("failed", "failed") })
		_, _, err := step(t, r)
		if err == nil || err.Error() != "The sign-in service could not be restarted after the data partition was freed, so it is still down." {
			t.Fatalf("err = %v", err)
		}
		e := rec.Matching(slog.LevelError, "systemctl restart of the sign-in service unit failed")
		if len(e) != 1 {
			t.Fatalf("%d ERRORs", len(e))
		}
		if ev, _ := logkittest.Attr(e[0], "event"); ev != "identity.recover_restart_failed" {
			t.Fatalf("event = %q", ev)
		}
		if c, _ := logkittest.Attr(e[0], "component"); c != "identity" {
			t.Fatalf("component = %q", c)
		}
	})

	if w := func() jobs.Workflow { r, _ := identityRecoverer(t, &pair{}); return r.Workflow() }(); w.Kind != "identity.recover" {
		t.Fatalf("workflow kind = %q", w.Kind)
	}
}
