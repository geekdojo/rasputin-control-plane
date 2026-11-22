package identitystate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/looptls"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// denied, refused, protocol, timedOut and the TLS errors are the shapes the
// production client returns.
var (
	errDenied   = &idclient.Error{Op: "health", Kind: idclient.ErrDenied, Err: errors.New("client certificate refused")}
	errProtocol = &idclient.Error{Op: "health", Status: 404, Kind: idclient.ErrProtocol, Err: errors.New("unexpected status")}
	errRefused  = &idclient.Error{Op: "health", Kind: idclient.ErrUnreachable, Err: syscall.ECONNREFUSED}
	errTimedOut = &idclient.Error{Op: "health", Kind: idclient.ErrUnreachable, Err: context.DeadlineExceeded}
	errVerify   = &idclient.Error{Op: "health", Kind: idclient.ErrUnreachable,
		Err: fmt.Errorf("server certificate not trusted: %w", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}})}
	errLeaf = &idclient.Error{Op: "health", Kind: idclient.ErrUnreachable, Err: &looptls.LeafError{Err: errors.New("no leaf")}}
	err503  = &idclient.Error{Op: "health", Status: 503, Kind: idclient.ErrUnreachable}
)

// TC-979-05: each of the eleven facts, injected alone, gives its state; once
// it is removed, the reading is Ready. Now never advances and nothing waits.
func TestState_EachFactRaisesAndClears(t *testing.T) {
	cases := []struct {
		want   State
		inject func(t *testing.T, x *fixture)
		remove func(t *testing.T, x *fixture)
	}{
		{Starting, func(_ *testing.T, x *fixture) { x.w.set(func(w *world) { w.units.KC = kcStartPost }) },
			func(_ *testing.T, x *fixture) { x.w.set(func(w *world) { w.units.KC = kcActive }) }},
		{Upgrading, func(_ *testing.T, x *fixture) {
			x.w.set(func(w *world) { w.units.KC, w.marker = kcStartPost, "26.9.0" })
		}, func(_ *testing.T, x *fixture) { x.w.set(func(w *world) { w.units.KC = kcActive }) }},
		{Paused, func(_ *testing.T, x *fixture) {
			x.w.set(func(w *world) { w.healthErr, w.jobRunning["backup-1"] = errRefused, true })
			x.m.Quiesce("backup-1")
		}, func(_ *testing.T, x *fixture) {
			x.w.set(func(w *world) { w.healthErr, w.jobRunning["backup-1"] = nil, false })
		}},
		{DatabaseDown, func(_ *testing.T, x *fixture) {
			x.w.set(func(w *world) { w.units.DB = Unit{ActiveState: "inactive", SubState: "dead"} })
		}, func(_ *testing.T, x *fixture) { x.w.set(func(w *world) { w.units.DB = dbActive }) }},
		{Held, func(t *testing.T, x *fixture) { x.ledger.rollback(t, "refused", "Update again to bring sign-in back.") },
			func(t *testing.T, x *fixture) { x.ledger.rollback(t, "current", "") }},
		{OutOfMemory, func(t *testing.T, x *fixture) {
			x.oom(t, id(1))
			x.w.set(func(w *world) { w.units.KC = kcAutoRestart })
		}, func(_ *testing.T, x *fixture) { x.w.set(func(w *world) { w.units.KC = kcActive }) }},
		{Failed, func(_ *testing.T, x *fixture) { x.w.set(func(w *world) { w.units.KC = kcFailed }) },
			func(_ *testing.T, x *fixture) { x.w.set(func(w *world) { w.units.KC = kcActive }) }},
		{Unreachable, func(_ *testing.T, x *fixture) { x.w.set(func(w *world) { w.healthErr = errDenied }) },
			func(_ *testing.T, x *fixture) { x.w.set(func(w *world) { w.healthErr = nil }) }},
		{Blank, func(_ *testing.T, x *fixture) { x.w.set(func(w *world) { w.blank = true }) },
			func(_ *testing.T, x *fixture) { x.w.set(func(w *world) { w.blank = false }) }},
		{AppsPaused, func(_ *testing.T, x *fixture) { x.w.set(func(w *world) { w.appsPaused = true }) },
			func(_ *testing.T, x *fixture) { x.w.set(func(w *world) { w.appsPaused = false }) }},
		{HistoryBehind, func(_ *testing.T, x *fixture) { x.w.set(func(w *world) { w.historyBehind = true }) },
			func(_ *testing.T, x *fixture) { x.w.set(func(w *world) { w.historyBehind = false }) }},
	}
	if len(cases) != 11 {
		t.Fatalf("%d facts, want 11", len(cases))
	}
	for _, c := range cases {
		t.Run(string(c.want), func(t *testing.T) {
			x := newFixture(t)
			if got := x.state(t); got != Ready {
				t.Fatalf("before: %s, want ready", got)
			}
			c.inject(t, x)
			if got := x.state(t); got != c.want {
				t.Fatalf("with the fact: %s, want %s", got, c.want)
			}
			c.remove(t, x)
			if got := x.state(t); got != Ready {
				t.Fatalf("after removing the fact: %s, want ready", got)
			}
		})
	}
}

// TC-979-06: precedence when facts overlap.
func TestState_Precedence(t *testing.T) {
	cases := []struct {
		name string
		set  func(t *testing.T, x *fixture)
		want State
	}{
		{"blank beats everything", func(t *testing.T, x *fixture) {
			x.oom(t, id(1))
			x.ledger.rollback(t, "refused", "Update again.")
			x.w.set(func(w *world) {
				w.blank, w.units.KC, w.units.DB = true, kcFailed, Unit{ActiveState: "failed", SubState: "failed"}
				w.jobRunning["j"], w.healthErr = true, errDenied
			})
			x.m.Quiesce("j")
		}, Blank},
		{"paused beats database-down", func(_ *testing.T, x *fixture) {
			// A backup stopped the database, and Keycloak with it (Requires=).
			x.w.set(func(w *world) {
				w.units.KC, w.units.DB, w.jobRunning["backup"] = kcInactive, Unit{ActiveState: "inactive"}, true
			})
			x.m.Quiesce("backup")
		}, Paused},
		{"held beats database-down", func(t *testing.T, x *fixture) {
			x.ledger.rollback(t, "refused", "Update again.")
			x.w.set(func(w *world) { w.units.DB = Unit{ActiveState: "failed", SubState: "failed"} })
		}, Held},
		{"out-of-memory beats failed", func(t *testing.T, x *fixture) {
			x.oom(t, id(1))
			x.w.set(func(w *world) { w.units.KC = kcFailed })
		}, OutOfMemory},
		{"database-down beats failed", func(_ *testing.T, x *fixture) {
			x.w.set(func(w *world) { w.units.KC, w.units.DB = kcFailed, Unit{ActiveState: "inactive"} })
		}, DatabaseDown},
		{"unreachable beats starting", func(_ *testing.T, x *fixture) {
			x.w.set(func(w *world) { w.healthErr = errProtocol })
		}, Unreachable},
		{"upgrading beats starting", func(_ *testing.T, x *fixture) {
			x.w.set(func(w *world) { w.units.KC, w.marker = kcStart, "26.9.0" })
		}, Upgrading},
		{"starting beats apps-paused", func(_ *testing.T, x *fixture) {
			x.w.set(func(w *world) { w.units.KC, w.appsPaused = kcStartPost, true })
		}, Starting},
		{"apps-paused beats history-behind", func(_ *testing.T, x *fixture) {
			x.w.set(func(w *world) { w.appsPaused, w.historyBehind = true, true })
		}, AppsPaused},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := newFixture(t)
			c.set(t, x)
			if got := x.state(t); got != c.want {
				t.Fatalf("state = %s, want %s", got, c.want)
			}
		})
	}
}

// TC-979-07: database-down only while the database is not running (F-979-04).
func TestState_DatabaseDownOnlyWhenNotRunning(t *testing.T) {
	cases := []struct {
		db     Unit
		marker string
		want   State
	}{
		{Unit{ActiveState: "activating", SubState: "start-pre"}, "26.8.2", Starting},
		{Unit{ActiveState: "activating", SubState: "start"}, "26.8.2", Starting},
		{Unit{ActiveState: "activating", SubState: "start-pre"}, "26.9.0", Upgrading},
		{Unit{ActiveState: "activating", SubState: "start"}, "26.9.0", Upgrading},
		{Unit{ActiveState: "activating", SubState: "auto-restart"}, "26.8.2", DatabaseDown},
		{Unit{ActiveState: "inactive", SubState: "dead"}, "26.8.2", DatabaseDown},
		{Unit{ActiveState: "failed", SubState: "failed"}, "26.8.2", DatabaseDown},
	}
	for _, c := range cases {
		t.Run(c.db.ActiveState+"/"+c.db.SubState+"/"+c.marker, func(t *testing.T) {
			x := newFixture(t)
			// Keycloak waits on its database (After=), in its own start.
			x.w.set(func(w *world) { w.units.KC, w.units.DB, w.marker = kcStartPre, c.db, c.marker })
			if got := x.state(t); got != c.want {
				t.Fatalf("state = %s, want %s", got, c.want)
			}
		})
	}
}

// TC-979-08: out-of-memory belongs to the invocation `last` names (F-979-01);
// a run that ended otherwise reads failed (F-979-07).
func TestState_OutOfMemoryIsTheLastRunsOnly(t *testing.T) {
	cases := []struct {
		name string
		set  func(t *testing.T, x *fixture)
		kc   Unit
		err  error
		want State
	}{
		{"(a) start", func(t *testing.T, x *fixture) { x.oom(t, id(1)) }, kcStart, nil, OutOfMemory},
		{"(a) start-post", func(t *testing.T, x *fixture) { x.oom(t, id(1)) }, kcStartPost, nil, OutOfMemory},
		{"(a) auto-restart", func(t *testing.T, x *fixture) { x.oom(t, id(1)) }, kcAutoRestart, nil, OutOfMemory},
		{"(a) failed", func(t *testing.T, x *fixture) { x.oom(t, id(1)) }, kcFailed, nil, OutOfMemory},
		{"(b) an older exit 3, last success", func(t *testing.T, x *fixture) {
			x.record(t, id(1), "exit-code", "exited", "3", fixedNow)
			x.record(t, id(2), "success", "exited", "143", fixedNow)
			x.last(t, id(2))
		}, kcStartPost, nil, Starting},
		{"(c) no last", func(*testing.T, *fixture) {}, kcStartPost, nil, Starting},
		{"(d) oom-kill", func(t *testing.T, x *fixture) {
			x.record(t, id(1), "oom-kill", "killed", "KILL", fixedNow)
			x.last(t, id(1))
		}, kcAutoRestart, nil, OutOfMemory},
		{"(e) active, refused", func(t *testing.T, x *fixture) { x.oom(t, id(1)) }, kcActive, errRefused, Starting},
		{"(f) active, ready", func(t *testing.T, x *fixture) { x.oom(t, id(1)) }, kcActive, nil, Ready},
		{"(g) exit status 1", func(t *testing.T, x *fixture) {
			x.record(t, id(1), "exit-code", "exited", "1", fixedNow)
			x.last(t, id(1))
		}, kcAutoRestart, nil, Failed},
		{"(g) signal", func(t *testing.T, x *fixture) {
			x.record(t, id(1), "signal", "killed", "SEGV", fixedNow)
			x.last(t, id(1))
		}, kcAutoRestart, nil, Failed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := newFixture(t)
			c.set(t, x)
			x.w.set(func(w *world) { w.units.KC, w.healthErr = c.kc, c.err })
			if got := x.state(t); got != c.want {
				t.Fatalf("state = %s, want %s", got, c.want)
			}
		})
	}
}

// TC-979-09: with Keycloak active, the health answer's kind decides
// unreachable or starting, in exactly one call; in every other unit state no
// health call is made, and /health/started is never asked.
func TestState_HealthClassification(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want State
	}{
		{"client certificate refused", errDenied, Unreachable},
		{"protocol", errProtocol, Unreachable},
		{"server certificate not verified", errVerify, Unreachable},
		{"leaf error", errLeaf, Unreachable},
		{"connection refused", errRefused, Starting},
		{"out of its bound", errTimedOut, Starting},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := newFixture(t)
			x.w.set(func(w *world) { w.healthErr = c.err })
			if got := x.state(t); got != c.want {
				t.Fatalf("state = %s, want %s", got, c.want)
			}
			if x.w.healthCalls != 1 {
				t.Fatalf("%d health calls, want 1", x.w.healthCalls)
			}
		})
	}
	for _, kc := range []Unit{kcStartPre, kcStart, kcStartPost, kcAutoRestart, kcInactive, kcFailed} {
		t.Run("no call while "+kc.ActiveState+"/"+kc.SubState, func(t *testing.T) {
			x := newFixture(t)
			x.w.set(func(w *world) { w.units.KC = kc })
			x.state(t)
			if x.w.healthCalls != 0 {
				t.Fatalf("%d health calls, want 0", x.w.healthCalls)
			}
		})
	}
	// The Monitor's only call is Health, and idclient's Health requests
	// /health/ready and nothing else (TC-979-20, TestHealth), so no reading
	// asks /health/started.
}

// TC-979-13: held from the version gate and from the start hold.
func TestState_Held(t *testing.T) {
	t.Run("(a) the gate refused", func(t *testing.T) {
		x := newFixture(t)
		x.ledger.rollback(t, "refused", "Update again, or reflash a release at least as new and restore.")
		x.w.set(func(w *world) { w.units.KC, w.units.DB = kcInactive, Unit{ActiveState: "failed"} })
		a := x.m.Alerts(t.Context(), fixedNow)
		if len(a) != 1 || a[0].ID != "identity:held" || a[0].Detail != "Update again, or reflash a release at least as new and restore." {
			t.Fatalf("alerts = %+v, want identity:held with the reason", a)
		}
	})
	t.Run("(b) a newer current job", func(t *testing.T) {
		x := newFixture(t)
		x.ledger.rollback(t, "refused", "Update again.")
		x.ledger.rollback(t, "current", "")
		if got := x.state(t); got == Held {
			t.Fatal("held after a newer current outcome")
		}
	})
	t.Run("(c) the start hold, Keycloak failed", func(t *testing.T) {
		x := newFixture(t)
		x.w.set(func(w *world) {
			w.units.KC = kcFailed
			w.startHold = StartHold{Refused: true, Reason: "Sign-in failed to start three times in a row: its configuration was refused."}
		})
		a := x.m.Alerts(t.Context(), fixedNow)
		if len(a) != 1 || a[0].ID != "identity:held" || a[0].Detail != "Sign-in failed to start three times in a row: its configuration was refused." {
			t.Fatalf("alerts = %+v, want identity:held with the record's cause", a)
		}
	})
	t.Run("(d) the start hold, Keycloak active", func(t *testing.T) {
		x := newFixture(t)
		x.w.set(func(w *world) { w.startHold = StartHold{Refused: true, Reason: "Old."} })
		if got := x.state(t); got == Held {
			t.Fatal("held while Keycloak is active")
		}
	})
}

// TC-979-14: upgrading from the version marker (F-979-08), and the ready
// version stored only when it changed.
func TestState_Upgrading(t *testing.T) {
	for _, c := range []struct {
		name              string
		marker, stored    string
		markerErr, getErr error
		want              State
		wantWarn          bool
	}{
		{"marker differs", "26.9.0", "26.8.2", nil, nil, Upgrading, false},
		{"marker equal", "26.8.2", "26.8.2", nil, nil, Starting, false},
		{"no stored version", "26.9.0", "", nil, nil, Starting, false},
		{"marker unreadable", "", "26.8.2", errors.New("no marker"), nil, Starting, true},
		{"settings unreadable", "26.9.0", "", nil, errors.New("db locked"), Starting, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := newFixture(t)
			x.w.set(func(w *world) {
				w.units.KC, w.marker, w.stored, w.markerErr, w.getErr = kcStartPost, c.marker, c.stored, c.markerErr, c.getErr
			})
			for range 2 {
				if got := x.state(t); got != c.want {
					t.Fatalf("state = %s, want %s", got, c.want)
				}
			}
			warns := len(x.rec.Matching(slog.LevelWarn, "identity version marker or ready version unreadable"))
			if c.wantWarn && warns != 1 || !c.wantWarn && warns != 0 {
				t.Fatalf("%d WARNs over two readings, want one per outage (%t)", warns, c.wantWarn)
			}
		})
	}
	t.Run("ready stores the marker once", func(t *testing.T) {
		x := newFixture(t)
		x.w.set(func(w *world) { w.marker, w.stored = "26.9.0", "26.8.2" })
		if got := x.state(t); got != Ready {
			t.Fatalf("state = %s", got)
		}
		if x.w.stored != "26.9.0" || x.w.setCalls != 1 {
			t.Fatalf("stored %q after %d writes, want 26.9.0 after 1", x.w.stored, x.w.setCalls)
		}
		x.state(t)
		if x.w.setCalls != 1 {
			t.Fatalf("%d writes after a second ready reading with the marker unchanged, want 1", x.w.setCalls)
		}
	})
}

// TC-979-16: unreadable facts fail closed; a cancelled reading records
// nothing.
func TestState_FailClosed(t *testing.T) {
	for _, c := range []struct {
		name string
		set  func(w *world)
		want State
	}{
		{"blank errors", func(w *world) { w.blankErr = errors.New("unread") }, Blank},
		{"apps-paused errors", func(w *world) { w.appsPausedErr = errors.New("unread") }, AppsPaused},
		{"history-behind errors", func(w *world) { w.historyBehindErr = errors.New("unread") }, HistoryBehind},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := newFixture(t)
			x.w.set(c.set)
			if got := x.state(t); got != c.want {
				t.Fatalf("state = %s, want %s", got, c.want)
			}
			x.state(t)
			if n := len(x.rec.Matching(slog.LevelWarn, "identity fact unreadable")); n != 1 {
				t.Fatalf("%d WARNs over two readings, want 1", n)
			}
		})
	}
	t.Run("a hold's status unreadable is held", func(t *testing.T) {
		x := newFixture(t)
		x.w.set(func(w *world) { w.runningErr = errors.New("db locked") })
		x.m.Quiesce("j")
		if !x.m.Held(t.Context()) {
			t.Fatal("Held = false with the hold's job status unreadable")
		}
	})
	t.Run("the exits directory unreadable", func(t *testing.T) {
		x := newFixture(t)
		x.oom(t, id(1))
		x.w.set(func(w *world) { w.units.KC = kcAutoRestart })
		x.m.d.Exits = func(context.Context) (ExitDir, error) { return ExitDir{}, errors.New("permission denied") }
		for range 2 {
			if got := x.state(t); got != Starting {
				t.Fatalf("state = %s, want starting: no out-of-memory or failed from unread records", got)
			}
		}
		if n := len(x.rec.Matching(slog.LevelWarn, "identity exit records unreadable")); n != 1 {
			t.Fatalf("%d WARNs over two readings, want 1", n)
		}
		if err := x.m.Ready(t.Context()); err == nil {
			t.Fatal("Ready is nil with no ready answer")
		}
		x.w.set(func(w *world) { w.units.KC = kcActive })
		if err := x.m.Ready(t.Context()); err != nil {
			t.Fatalf("Ready = %v with health ready", err)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		x := newFixture(t)
		x.oom(t, id(1))
		x.record(t, id(2), "exit-code", "exited", "3", fixedNow)
		x.w.set(func(w *world) { w.units.KC, w.marker = kcAutoRestart, "26.9.0" })
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := x.m.Ready(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("Ready = %v, want the ctx error", err)
		}
		if x.ledger.records != 0 || x.w.removes != 0 || x.w.setCalls != 0 || len(x.rec.Records()) != 0 {
			t.Fatalf("cancelled reading: %d jobs, %d removes, %d settings writes, %d log records; want none",
				x.ledger.records, x.w.removes, x.w.setCalls, len(x.rec.Records()))
		}
	})
}

// TC-979-17: Ready's refusal carries identity_not_ready and the state's
// sentence; every title, detail and error is a vendor-neutral sentence.
func TestState_NotReadySentences(t *testing.T) {
	all := []State{Starting, Upgrading, Paused, DatabaseDown, Held, OutOfMemory, Failed, Unreachable, Blank, AppsPaused, HistoryBehind,
		FeaturesMismatch, FeaturesUnchecked}
	vendors := []string{"Keycloak", "PostgreSQL", "Postgres", "Java", "JVM"}
	sentence := func(t *testing.T, what, s string) {
		t.Helper()
		if s == "" || s[0] < 'A' || s[0] > 'Z' || !strings.HasSuffix(s, ".") {
			t.Errorf("%s %q is not a sentence", what, s)
		}
		for _, v := range vendors {
			if strings.Contains(s, v) {
				t.Errorf("%s %q names %s", what, s, v)
			}
		}
	}
	for _, st := range all {
		err := error(&NotReadyError{State: st})
		var nr *NotReadyError
		if !st.Blocks() {
			continue
		}
		if !errors.As(err, &nr) || nr.Code() != "identity_not_ready" || !errors.Is(err, ErrNotReady) {
			t.Errorf("%s: %v is not a coded NotReadyError", st, err)
		}
		if want := st.sentence() + " Error code: identity_not_ready."; err.Error() != want {
			t.Errorf("%s: Error() = %q, want %q", st, err.Error(), want)
		}
		sentence(t, string(st)+" error", err.Error())
	}
	for _, st := range all {
		a := alertFor(reading{state: st})
		sentence(t, string(st)+" title", a.Title)
		sentence(t, string(st)+" detail", a.Detail)
	}
	sentence(t, "exit job error", exitJobError)

	// Ready is nil exactly for Ready, apps-paused and history-behind.
	for _, c := range []struct {
		set     func(w *world)
		wantNil bool
	}{
		{func(*world) {}, true},
		{func(w *world) { w.appsPaused = true }, true},
		{func(w *world) { w.historyBehind = true }, true},
		{func(w *world) { w.units.KC = kcStartPost }, false},
		{func(w *world) { w.units.KC = kcFailed }, false},
	} {
		x := newFixture(t)
		x.w.set(c.set)
		err := x.m.Ready(t.Context())
		var nr *NotReadyError
		if c.wantNil != (err == nil) || (!c.wantNil && (!errors.As(err, &nr) || nr.Code() != Code)) {
			t.Errorf("Ready = %v, want nil=%t", err, c.wantNil)
		}
	}
}

// TC-979-18: alerts carry identity:<state>, the severity, Source security
// and Since from the first sight; transitions log once.
func TestState_AlertsAndTransitions(t *testing.T) {
	x := newFixture(t)
	now := fixedNow
	x.m.d.Now = func() time.Time { return now }
	x.w.set(func(w *world) { w.units.KC = kcStartPost })
	a1 := x.m.Alerts(t.Context(), now)
	now = now.Add(time.Minute)
	a2 := x.m.Alerts(t.Context(), now)
	if len(a1) != 1 || len(a2) != 1 || a1[0].ID != "identity:starting" || a1[0].Severity != proto.AlertWarn ||
		a1[0].Source != proto.AlertSourceSecurity || !a2[0].Since.Equal(fixedNow) {
		t.Fatalf("starting alerts = %+v, %+v; want identity:starting, warn, security, Since kept", a1, a2)
	}
	now = now.Add(time.Minute)
	x.w.set(func(w *world) { w.units.KC, w.units.DB = kcInactive, Unit{ActiveState: "inactive", SubState: "dead"} })
	a3 := x.m.Alerts(t.Context(), now)
	if len(a3) != 1 || a3[0].ID != "identity:database-down" || a3[0].Severity != proto.AlertCrit || !a3[0].Since.Equal(now) {
		t.Fatalf("database-down alerts = %+v; want crit, Since reset", a3)
	}
	x.w.set(func(w *world) { w.units.KC, w.units.DB = kcActive, dbActive })
	if a := x.m.Alerts(t.Context(), now); len(a) != 0 {
		t.Fatalf("ready alerts = %+v, want none", a)
	}
	warns := x.rec.Matching(slog.LevelWarn, "identity service not ready")
	if len(warns) != 2 {
		t.Fatalf("%d not-ready WARNs, want one per new state (2)", len(warns))
	}
	for _, w := range warns {
		for _, k := range []string{"state", "kc_state", "kc_substate", "db_state", "component"} {
			if _, ok := logkittest.Attr(w, k); !ok {
				t.Errorf("WARN has no %s", k)
			}
		}
	}
	if v, _ := logkittest.Attr(warns[0], "kc_substate"); v != "start-post" {
		t.Errorf("kc_substate = %q", v)
	}
	if n := len(x.rec.Matching(slog.LevelInfo, "identity service ready")); n != 1 {
		t.Fatalf("%d ready INFOs, want 1", n)
	}
	for _, r := range x.rec.Records() {
		if c, _ := logkittest.Attr(r, "component"); c != "identity" {
			t.Errorf("record %q carries component=%q", r.Message, c)
		}
	}
	if text := x.rec.Text(); strings.Contains(text, "token") || strings.Contains(text, "body") {
		t.Errorf("a record carries a body or a token: %s", text)
	}
}

// TC-979-19: paused while a running job holds the quiesce; release logs and
// clears it; a hold whose job no longer runs does not count.
func TestState_PausedAndHeld(t *testing.T) {
	x := newFixture(t)
	x.w.set(func(w *world) { w.healthErr, w.jobRunning["backup-7"] = errRefused, true })
	release := x.m.Quiesce("backup-7")
	if got := x.state(t); got != Paused || !x.m.Held(t.Context()) {
		t.Fatalf("state %s, Held %t; want paused and held", got, x.m.Held(t.Context()))
	}
	if n := len(x.rec.Matching(slog.LevelInfo, "identity service quiesced")); n != 1 {
		t.Fatalf("%d quiesced INFOs", n)
	}
	release()
	release()
	if n := len(x.rec.Matching(slog.LevelInfo, "identity service quiesce released")); n != 1 {
		t.Fatalf("%d released INFOs, want 1", n)
	}
	if got := x.state(t); got != Starting || x.m.Held(t.Context()) {
		t.Fatalf("after release: %s, Held %t; want starting, not held", got, x.m.Held(t.Context()))
	}
	x.m.Quiesce("backup-8") // its job is not running
	if got := x.state(t); got != Starting || x.m.Held(t.Context()) {
		t.Fatalf("a hold of a finished job: %s, Held %t", got, x.m.Held(t.Context()))
	}
}

// TC-979-24: the start count is #973's alone. Across three invocations, each
// through start-pre, start, start-post and active, no reading opens, stats or
// removes the count file; every activating reading is starting (upgrading
// when the marker differs) with no health call, and the first active reading
// makes one call and reads ready.
func TestState_NeverTouchesTheStartCount(t *testing.T) {
	const countPath = "var/lib/rasputin/identity/start-failures"
	fsys := &countingFS{files: fstest.MapFS{
		countPath:                          {Data: []byte("2\n")},
		"run/rasputin-identity-exits/last": {Data: []byte(id(9) + "\n")},
	}}
	var removed []string
	x := newFixture(t)
	x.m.d.Exits = ExitRecords(fsys, "/run/rasputin-identity-exits")
	x.m.d.RemoveExit = RemoveExitRecord(func(name string) error { removed = append(removed, name); return nil }, "/run/rasputin-identity-exits")
	x.m.d.StartHold = StartHoldRecord(fsys, "/run/rasputin-identity-start-hold/outcome")
	x.m.d.Marker = MarkerFile(fsys, "/var/lib/rasputin/identity/keycloak-version")
	fsys.files["var/lib/rasputin/identity/keycloak-version"] = &fstest.MapFile{Data: []byte("26.8.2\n")}
	for inv := range 3 {
		for _, sub := range []string{"start-pre", "start", "start-post"} {
			x.w.set(func(w *world) {
				w.units.KC = Unit{ActiveState: "activating", SubState: sub, InvocationID: id(300 + inv)}
				w.marker, w.stored = "26.8.2", "26.8.2"
			})
			calls := x.w.healthCalls
			if got := x.state(t); got != Starting || x.w.healthCalls != calls {
				t.Fatalf("invocation %d %s: %s with %d health calls; want starting, none", inv, sub, got, x.w.healthCalls-calls)
			}
		}
		x.w.set(func(w *world) {
			w.units.KC = Unit{ActiveState: "active", SubState: "running", InvocationID: id(300 + inv)}
		})
		calls := x.w.healthCalls
		if got := x.state(t); got != Ready || x.w.healthCalls != calls+1 {
			t.Fatalf("invocation %d active: %s with %d health calls; want ready, one", inv, got, x.w.healthCalls-calls)
		}
	}
	fsys.mu.Lock()
	fsys.files["var/lib/rasputin/identity/keycloak-version"] = &fstest.MapFile{Data: []byte("26.9.0\n")}
	fsys.mu.Unlock()
	x.w.set(func(w *world) { w.units.KC = kcStartPost })
	if got := x.state(t); got != Upgrading {
		t.Fatalf("activating with the marker changed: %s, want upgrading", got)
	}
	for _, name := range fsys.opened() {
		if strings.Contains(name, "start-failures") {
			t.Fatalf("a reading opened the count file: %s", name)
		}
	}
	for _, name := range removed {
		if strings.Contains(name, "start-failures") {
			t.Fatalf("a reading removed the count file: %s", name)
		}
	}
	if string(fsys.files[countPath].Data) != "2\n" {
		t.Fatal("the count file changed")
	}
}

// countingFS is an fs.FS that records every name opened. It implements only
// Open, so ReadDir, ReadFile and Stat all go through it.
type countingFS struct {
	mu    sync.Mutex
	files fstest.MapFS
	names []string
}

func (c *countingFS) Open(name string) (fs.File, error) {
	c.mu.Lock()
	c.names = append(c.names, name)
	c.mu.Unlock()
	return c.files.Open(name)
}

func (c *countingFS) opened() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.names...)
}

// TC-979-15 (the Monitor's half): the outcome records are read once per new
// database run that is active or failed, and not again for the same run or
// while it is activating.
func TestState_OutcomesOncePerDatabaseRun(t *testing.T) {
	x := newFixture(t)
	steps := []struct {
		db    Unit
		calls int
	}{
		{dbActive, 1},
		{dbActive, 1},
		{Unit{ActiveState: "activating", SubState: "start-pre", InvocationID: id(201)}, 1},
		{Unit{ActiveState: "failed", SubState: "failed", InvocationID: id(201)}, 2},
		{Unit{ActiveState: "failed", SubState: "failed", InvocationID: id(201)}, 2},
		{Unit{ActiveState: "active", SubState: "running", InvocationID: id(202)}, 3},
	}
	for i, s := range steps {
		x.w.set(func(w *world) { w.units.DB = s.db })
		x.state(t)
		if x.w.readRecordsCalls != s.calls {
			t.Fatalf("step %d (%s %s): %d reads, want %d", i, s.db.ActiveState, s.db.InvocationID, x.w.readRecordsCalls, s.calls)
		}
	}
}

// New refuses each missing collaborator by name and does no I/O.
func TestNew_Refuses(t *testing.T) {
	x := newFixture(t)
	log, _ := logkittest.New()
	for name, mut := range map[string]func(*Deps){
		"Units": func(d *Deps) { d.Units = nil }, "Exits": func(d *Deps) { d.Exits = nil },
		"RemoveExit": func(d *Deps) { d.RemoveExit = nil }, "Health": func(d *Deps) { d.Health = nil },
		"Ledger": func(d *Deps) { d.Ledger = nil }, "ReadRecords": func(d *Deps) { d.ReadRecords = nil },
		"StartHold": func(d *Deps) { d.StartHold = nil }, "Marker": func(d *Deps) { d.Marker = nil },
		"Settings": func(d *Deps) { d.Settings = nil }, "JobRunning": func(d *Deps) { d.JobRunning = nil },
		"Blank": func(d *Deps) { d.Blank = nil }, "AppsPaused": func(d *Deps) { d.AppsPaused = nil },
		"HistoryBehind": func(d *Deps) { d.HistoryBehind = nil }, "Now": func(d *Deps) { d.Now = nil },
		"Features": func(d *Deps) { d.Features = nil },
		"Log":      func(d *Deps) { d.Log = nil },
	} {
		d := x.deps(log, x.ledger)
		mut(&d)
		if _, err := New(d); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("New without %s = %v", name, err)
		}
	}
	if x.w.unitsCalls != 0 || x.w.healthCalls != 0 {
		t.Fatal("New did I/O")
	}
}

// Units that cannot be read: health is asked as though Keycloak were active,
// one WARN per outage, and the database's state is not guessed.
func TestState_UnitsUnreadable(t *testing.T) {
	x := newFixture(t)
	x.w.set(func(w *world) { w.unitsErr = errors.New("no bus") })
	for range 2 {
		if got := x.state(t); got != Ready {
			t.Fatalf("state = %s, want ready from health", got)
		}
	}
	x.w.set(func(w *world) { w.health, w.healthErr = healthDown, err503 })
	if got := x.state(t); got != DatabaseDown {
		t.Fatalf("state = %s, want database-down from the 503", got)
	}
	if n := len(x.rec.Matching(slog.LevelWarn, "identity units unreadable")); n != 1 {
		t.Fatalf("%d WARNs, want 1", n)
	}
	if x.w.readRecordsCalls != 0 {
		t.Fatal("outcome records read without the database's run")
	}
}

// TC-981-08: features-mismatch and features-unchecked arise only on an
// otherwise ready service, before apps-paused; both block and are critical,
// with Appendix F's sentences and identity:<state> alert IDs. The
// service-only readiness reads both as ready and refuses every other
// blocking state.
func TestState_Features(t *testing.T) {
	const (
		mismatchSentence  = "Sign-in is closed: the sign-in service is not running with the features this release built it with. Update or reinstall this release."
		uncheckedSentence = "Sign-in is closed because the control plane cannot check which features its sign-in service is running with."
	)
	for _, c := range []struct {
		name     string
		set      func(w *world)
		want     State
		sentence string
	}{
		{"mismatch", func(w *world) { w.featuresMismatch = true }, FeaturesMismatch, mismatchSentence},
		{"unchecked", func(w *world) { w.featuresErr = errors.New("serverinfo unreadable") }, FeaturesUnchecked, uncheckedSentence},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := newFixture(t)
			x.w.set(c.set)
			// Before apps-paused.
			x.w.set(func(w *world) { w.appsPaused = true })
			if got := x.state(t); got != c.want {
				t.Fatalf("state = %s, want %s", got, c.want)
			}
			if !c.want.Blocks() || !c.want.critical() || c.want.sentence() != c.sentence {
				t.Errorf("%s: Blocks %t, critical %t, sentence %q", c.want, c.want.Blocks(), c.want.critical(), c.want.sentence())
			}
			err := x.m.Ready(t.Context())
			var nr *NotReadyError
			if !errors.As(err, &nr) || nr.State != c.want {
				t.Errorf("Ready = %v, want NotReadyError{%s}", err, c.want)
			}
			a := x.m.Alerts(t.Context(), fixedNow)
			if len(a) != 1 || a[0].ID != "identity:"+string(c.want) || a[0].Severity != proto.AlertCrit || a[0].Title != c.sentence {
				t.Errorf("alerts = %+v", a)
			}
			if err := x.m.ServiceOnly().Ready(t.Context()); err != nil {
				t.Errorf("ServiceOnly().Ready = %v, want nil", err)
			}
			if got := x.w.featuresCalls; len(got) == 0 || got[0] != kcActive.InvocationID {
				t.Errorf("Features called with %v, want Keycloak's invocation %s", got, kcActive.InvocationID)
			}
			// Only when otherwise ready: a starting service reads starting
			// and asks nothing.
			x.w.set(func(w *world) { w.units.KC = kcStartPost; w.featuresCalls = nil })
			if got := x.state(t); got != Starting {
				t.Errorf("starting service: state = %s, want starting", got)
			}
			if len(x.w.featuresCalls) != 0 {
				t.Errorf("Features asked while starting: %v", x.w.featuresCalls)
			}
			err = x.m.ServiceOnly().Ready(t.Context())
			if !errors.As(err, &nr) || nr.State != Starting {
				t.Errorf("ServiceOnly().Ready while starting = %v, want NotReadyError{starting}", err)
			}
		})
	}
	// A match is ready, through both readinesses.
	x := newFixture(t)
	if got := x.state(t); got != Ready {
		t.Fatalf("matching features: state = %s, want ready", got)
	}
	if err := x.m.ServiceOnly().Ready(t.Context()); err != nil {
		t.Errorf("ServiceOnly().Ready = %v", err)
	}
	// Every other blocking state still refuses through the service-only
	// readiness.
	x.w.set(func(w *world) { w.units.KC = kcFailed })
	var nr *NotReadyError
	if err := x.m.ServiceOnly().Ready(t.Context()); !errors.As(err, &nr) || nr.State != Failed {
		t.Errorf("ServiceOnly().Ready on a failed unit = %v, want NotReadyError{failed}", err)
	}
}
