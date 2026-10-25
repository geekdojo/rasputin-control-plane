package storestate

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-760-01: every Health answer maps through secretstore.InactiveReason to
// one state, failing closed to Unreachable for anything it cannot name, and
// the transition record carries the classifier's kind.
func TestMonitor_HealthMapping(t *testing.T) {
	for _, tc := range []struct {
		name string
		h    secretstore.Health
		err  error
		want State
		kind string
	}{
		{"200 unsealed", readyHealth, nil, Ready, ""},
		{"nil error, Sealed true", secretstore.Health{Initialized: true, Sealed: true}, nil, Sealed, "sealed"},
		{"nil error, Initialized false", secretstore.Health{}, nil, Uninitialised, "uninitialised"},
		{"ErrSealed", secretstore.Health{}, healthErr(secretstore.ErrSealed), Sealed, "sealed"},
		{"ErrUninitialised (501)", secretstore.Health{}, healthErr(secretstore.ErrUninitialised), Uninitialised, "uninitialised"},
		{"ErrUnreachable", secretstore.Health{}, healthErr(secretstore.ErrUnreachable), Unreachable, "unreachable"},
		{"ErrDenied", secretstore.Health{}, healthErr(secretstore.ErrDenied), Unreachable, "error"},
		{"ErrProtocol", secretstore.Health{}, healthErr(secretstore.ErrProtocol), Unreachable, "error"},
		{"ErrDisabled", secretstore.Health{}, healthErr(secretstore.ErrDisabled), Unreachable, "disabled"},
		{"unclassified", secretstore.Health{}, errUnclassified, Unreachable, "error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, tc.h, tc.err)
			if got := f.state(t); got != tc.want {
				t.Fatalf("State = %q, want %q", got, tc.want)
			}
			warns := f.rec.Matching(slog.LevelWarn, "secret store not ready")
			if tc.want == Ready {
				if len(warns) != 0 {
					t.Fatalf("a ready store logged %d not-ready records", len(warns))
				}
				return
			}
			if len(warns) != 1 {
				t.Fatalf("%d not-ready records, want 1", len(warns))
			}
			if got, _ := logkittest.Attr(warns[0], "kind"); got != tc.kind {
				t.Errorf("kind = %q, want %q", got, tc.kind)
			}
			if got, _ := logkittest.Attr(warns[0], "state"); got != string(tc.want) {
				t.Errorf("state = %q, want %q", got, tc.want)
			}
		})
	}
}

// TC-760-02: a reading whose ctx was cancelled returns an error and records
// nothing: the remembered state and its Since are unchanged, and no
// transition is logged.
func TestMonitor_CancelledReadingRecordsNothing(t *testing.T) {
	f := newFixture(t, readyHealth, nil)
	t1 := f.clock.now()
	f.state(t)
	n := len(f.rec.Records())

	f.store.set(secretstore.Health{}, healthErr(secretstore.ErrSealed))
	f.clock.advance(time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.m.State(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("State(cancelled) = %v, want context.Canceled", err)
	}
	if got := len(f.rec.Records()); got != n {
		t.Fatalf("a cancelled reading logged %d record(s)", got-n)
	}

	f.store.set(readyHealth, nil)
	f.clock.advance(time.Minute)
	st, since, err := f.m.read(context.Background())
	if err != nil || st != Ready || !since.Equal(t1) {
		t.Fatalf("follow-up reading = %q since %v (%v), want ready since %v", st, since, err, t1)
	}
	if got := len(f.rec.Records()); got != n {
		t.Fatalf("the follow-up reading logged a transition the cancelled one should not have made")
	}
}

// TC-760-03: Since is the first observation of a state, and each transition
// is logged once at its level, with the store's text only in attributes.
func TestMonitor_SinceAndTransitionLogging(t *testing.T) {
	sealedErr := &secretstore.Error{Op: "health", Status: 503, Kind: secretstore.ErrSealed, StoreMessages: []string{"STORE-TEXT"}}
	f := newFixture(t, secretstore.Health{}, sealedErr)
	t1 := f.clock.now()
	for i := range 3 {
		alerts := f.m.Alerts(context.Background(), f.clock.now())
		if len(alerts) != 1 || !alerts[0].Since.Equal(t1) {
			t.Fatalf("sealed reading %d: alerts %+v, want one with Since %v", i+1, alerts, t1)
		}
		f.clock.advance(time.Minute)
	}
	f.store.set(readyHealth, nil)
	if got := f.state(t); got != Ready {
		t.Fatalf("State = %q, want ready", got)
	}
	f.clock.advance(time.Minute)
	t5 := f.clock.now()
	f.store.set(secretstore.Health{}, healthErr(secretstore.ErrUnreachable))
	alerts := f.m.Alerts(context.Background(), t5)
	if len(alerts) != 1 || alerts[0].ID != "secret-store:unreachable" || !alerts[0].Since.Equal(t5) {
		t.Fatalf("unreachable alerts %+v, want one since %v", alerts, t5)
	}

	warns := f.rec.Matching(slog.LevelWarn, "secret store not ready")
	if len(warns) != 2 {
		t.Fatalf("%d not-ready records, want 2 (sealed, then unreachable)", len(warns))
	}
	for i, want := range []struct{ state, kind string }{{"sealed", "sealed"}, {"unreachable", "unreachable"}} {
		for key, v := range map[string]string{"component": "secretstore", "state": want.state, "kind": want.kind} {
			if got, _ := logkittest.Attr(warns[i], key); got != v {
				t.Errorf("record %d %s = %q, want %q", i, key, got, v)
			}
		}
	}
	if msgs, _ := logkittest.Attr(warns[0], "store_messages"); !strings.Contains(msgs, "STORE-TEXT") {
		t.Errorf("the sealed record lacks the store's messages: %q", msgs)
	}
	infos := f.rec.Matching(slog.LevelInfo, "secret store ready")
	if len(infos) != 1 {
		t.Fatalf("%d ready records, want 1", len(infos))
	}
	if v, _ := logkittest.Attr(infos[0], "version"); v != "2.7.1" {
		t.Errorf("ready record version = %q, want 2.7.1", v)
	}
	for _, r := range f.rec.Records() {
		if strings.Contains(r.Message, "STORE-TEXT") {
			t.Errorf("the store's text reached a message: %q", r.Message)
		}
	}
	for _, a := range alerts {
		if strings.Contains(a.Title+a.Detail, "STORE-TEXT") {
			t.Errorf("the store's text reached an alert: %+v", a)
		}
	}
}

// TC-760-04: New refuses each nil dependency, returning a nil Monitor.
func TestNew_RefusesNil(t *testing.T) {
	full := func() Deps {
		return Deps{Store: newFakeStore(readyHealth, nil), Now: time.Now, Log: slog.New(slog.DiscardHandler),
			JobRunning: func(context.Context, string) (bool, error) { return false, nil },
			Blank:      func(context.Context) (bool, error) { return false, nil }}
	}
	for field, clear := range map[string]func(*Deps){
		"Store":      func(d *Deps) { d.Store = nil },
		"Now":        func(d *Deps) { d.Now = nil },
		"Log":        func(d *Deps) { d.Log = nil },
		"JobRunning": func(d *Deps) { d.JobRunning = nil },
		// F-765-07: the blank verdict is required, never an optional seam.
		"Blank": func(d *Deps) { d.Blank = nil },
	} {
		d := full()
		clear(&d)
		m, err := New(d)
		if err == nil || m != nil || !strings.Contains(err.Error(), field) {
			t.Errorf("New without %s = (%v, %v), want a nil Monitor and an error naming it", field, m, err)
		}
	}
	if m, err := New(full()); err != nil || m == nil {
		t.Fatalf("New(full) = (%v, %v)", m, err)
	}
}

// TC-760-13: one alert per state, with its id and severity, the security
// source, Since at the first observation, and vendor-neutral sentences.
func TestMonitor_AlertPerState(t *testing.T) {
	for _, tc := range []struct {
		name     string
		setup    func(f *fixture)
		id       string
		severity proto.AlertSeverity
	}{
		{"ready", func(*fixture) {}, "", ""},
		{"sealed", func(f *fixture) { f.store.set(secretstore.Health{}, healthErr(secretstore.ErrSealed)) },
			"secret-store:sealed", proto.AlertCrit},
		{"uninitialised", func(f *fixture) { f.store.set(secretstore.Health{}, healthErr(secretstore.ErrUninitialised)) },
			"secret-store:uninitialised", proto.AlertCrit},
		{"unreachable", func(f *fixture) { f.store.set(secretstore.Health{}, healthErr(secretstore.ErrUnreachable)) },
			"secret-store:unreachable", proto.AlertCrit},
		{"audit-blocked", func(f *fixture) { f.m.ObserveAudited(context.Background(), clientTimeout("read")) },
			"secret-store:audit-blocked", proto.AlertCrit},
		{"quiesced", func(f *fixture) {
			f.store.set(secretstore.Health{}, healthErr(secretstore.ErrUnreachable))
			f.running["job-q"] = true
			f.m.Quiesce("job-q", QuiesceBackup)
		}, "secret-store:quiesced", proto.AlertWarn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, readyHealth, nil)
			first := f.clock.now()
			tc.setup(f)
			for range 2 {
				alerts := f.m.Alerts(context.Background(), f.clock.now())
				if tc.id == "" {
					if len(alerts) != 0 {
						t.Fatalf("a ready store raised %+v", alerts)
					}
					continue
				}
				if len(alerts) != 1 {
					t.Fatalf("alerts %+v, want exactly %s", alerts, tc.id)
				}
				a := alerts[0]
				if a.ID != tc.id || a.Severity != tc.severity || a.Source != proto.AlertSourceSecurity || !a.Since.Equal(first) {
					t.Fatalf("alert %+v, want %s %s security since %v", a, tc.id, tc.severity, first)
				}
				assertSentence(t, "title", a.Title)
				assertSentence(t, "detail", a.Detail)
				assertNoVendor(t, "alert", a.Title+" "+a.Detail)
				if tc.id == "secret-store:unreachable" && !strings.Contains(a.Detail, "configuration was refused") {
					t.Errorf("the unreachable detail does not name a refused configuration: %q", a.Detail)
				}
				f.clock.advance(time.Minute)
			}
		})
	}
}

// TC-760-15: the quiesce hook logs its start and release with the job's id,
// turns a not-ready store into Quiesced while the job runs, and releases
// idempotently. A ready store with a hold reads Ready.
func TestMonitor_Quiesce(t *testing.T) {
	f := newFixture(t, secretstore.Health{}, healthErr(secretstore.ErrUnreachable))
	f.running["job-1"] = true
	release := f.m.Quiesce("job-1", QuiesceBackup)

	q := f.rec.Matching(slog.LevelInfo, "secret store quiesced for a backup")
	if len(q) != 1 {
		t.Fatalf("%d quiesce records, want 1", len(q))
	}
	for key, want := range map[string]string{"event": "secretstore.quiesced", "job_id": "job-1"} {
		if got, _ := logkittest.Attr(q[0], key); got != want {
			t.Errorf("quiesce record %s = %q, want %q", key, got, want)
		}
	}
	if got := f.state(t); got != Quiesced {
		t.Fatalf("State = %q, want quiesced", got)
	}
	if a := f.m.Alerts(context.Background(), f.clock.now()); len(a) != 1 || a[0].ID != "secret-store:quiesced" || a[0].Severity != proto.AlertWarn {
		t.Fatalf("alerts %+v, want only the quiesced warn", a)
	}

	release()
	r := f.rec.Matching(slog.LevelInfo, "secret store quiesce released")
	if len(r) != 1 {
		t.Fatalf("%d release records, want 1", len(r))
	}
	for key, want := range map[string]string{"event": "secretstore.quiesce_released", "job_id": "job-1"} {
		if got, _ := logkittest.Attr(r[0], key); got != want {
			t.Errorf("release record %s = %q, want %q", key, got, want)
		}
	}
	if got := f.state(t); got != Unreachable {
		t.Fatalf("State after release = %q, want unreachable", got)
	}
	if a := f.m.Alerts(context.Background(), f.clock.now()); len(a) != 1 || a[0].ID != "secret-store:unreachable" || a[0].Severity != proto.AlertCrit {
		t.Fatalf("alerts after release %+v, want the unreachable crit", a)
	}
	n := len(f.rec.Records())
	release()
	if got := len(f.rec.Records()); got != n {
		t.Errorf("a second release logged %d record(s)", got-n)
	}

	ready := newFixture(t, readyHealth, nil)
	ready.running["job-2"] = true
	ready.m.Quiesce("job-2", QuiesceBackup)
	if got := ready.state(t); got != Ready {
		t.Fatalf("a ready store with a hold reads %q, want ready", got)
	}
}

// TC-760-16: a hold whose job is not running, or whose status cannot be
// read, is ignored with a WARN naming the job and the reason, so the real
// state and its alert show.
func TestMonitor_StaleHoldIgnored(t *testing.T) {
	for _, tc := range []struct {
		name   string
		runErr error
		errSub string
	}{
		{"not running", nil, "not running"},
		{"status unreadable", errors.New("ledger closed"), "ledger closed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, secretstore.Health{}, healthErr(secretstore.ErrUnreachable))
			f.runErr = tc.runErr
			f.m.Quiesce("job-stale", QuiesceBackup)
			if got := f.state(t); got != Unreachable {
				t.Fatalf("State = %q, want unreachable", got)
			}
			if a := f.m.Alerts(context.Background(), f.clock.now()); len(a) != 1 || a[0].ID != "secret-store:unreachable" {
				t.Fatalf("alerts %+v, want the unreachable crit", a)
			}
			w := f.rec.Matching(slog.LevelWarn, "secret store quiesce hold ignored")
			if len(w) != 1 {
				t.Fatalf("%d hold-ignored records over two readings, want 1", len(w))
			}
			if got, _ := logkittest.Attr(w[0], "job_id"); got != "job-stale" {
				t.Errorf("job_id = %q", got)
			}
			if got, _ := logkittest.Attr(w[0], "err"); !strings.Contains(got, tc.errSub) {
				t.Errorf("err = %q, want it to contain %q", got, tc.errSub)
			}
		})
	}
}

// TC-760-17: audit-blocked is raised only when an audited call times out on
// the client's own bound while sys/health, read during that observation,
// answers 200 unsealed; Since is stamped then. The same timeout while health
// answers sealed or fails raises nothing, even if health is 200 afterwards.
func TestObserveAudited_RaisesOnlyOnGuard4(t *testing.T) {
	t.Run("200 at the moment", func(t *testing.T) {
		f := newFixture(t, readyHealth, nil)
		var order []string
		f.store.order = &order
		kv := &kvStore{fakeStore: f.store, err: clientTimeout("read"), order: &order}
		obs, err := NewObservedStore(kv, f.m)
		if err != nil {
			t.Fatal(err)
		}
		raisedAt := f.clock.advance(time.Minute)
		_, _ = obs.Read(context.Background(), tokenOf("t"), pathOf(t), 0)
		order = append(order, "returned")
		if got := strings.Join(order, ","); got != "read,health,returned" {
			t.Fatalf("call order %s, want read,health,returned: health must be read during the observation", got)
		}
		f.clock.advance(time.Minute)
		st, since, err := f.m.read(context.Background())
		if err != nil || st != AuditBlocked || !since.Equal(raisedAt) {
			t.Fatalf("State = %q since %v (%v), want audit-blocked since %v", st, since, err, raisedAt)
		}
	})
	for name, health := range map[string]error{
		"sealed at the moment": healthErr(secretstore.ErrSealed),
		"health fails":         healthErr(secretstore.ErrUnreachable),
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, secretstore.Health{}, health)
			f.m.ObserveAudited(context.Background(), clientTimeout("read"))
			f.store.set(readyHealth, nil)
			if got := f.state(t); got != Ready {
				t.Fatalf("State = %q, want ready: a later 200 is not the guard-4 fact", got)
			}
		})
	}
}

// TC-760-18: a call that failed because the caller cancelled, or because the
// caller's own shorter deadline passed, raises nothing and asks no health.
func TestObserveAudited_CallerEndRaisesNothing(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancel2 := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel2()
	for name, tc := range map[string]struct {
		ctx context.Context
		err error
	}{
		"caller cancelled": {cancelled, &secretstore.Error{Op: "read", Kind: secretstore.ErrUnreachable, Err: context.Canceled}},
		"caller deadline":  {expired, clientTimeout("read")},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, readyHealth, nil)
			f.m.ObserveAudited(tc.ctx, tc.err)
			if n := f.store.count(); n != 0 {
				t.Fatalf("the observation asked health %d time(s), want 0", n)
			}
			if got := f.state(t); got != Ready {
				t.Fatalf("State = %q, want ready", got)
			}
		})
	}
}

// TC-760-19: an answered audited call clears audit-blocked with no restart,
// and so does a not-ready reading: after a sealed reading, the next 200 is
// ready, not audit-blocked.
func TestObserveAudited_Clears(t *testing.T) {
	for name, err := range map[string]error{
		"nil":          nil,
		"not found":    &secretstore.Error{Op: "read", Kind: secretstore.ErrNotFound},
		"cas mismatch": &secretstore.Error{Op: "write", Kind: secretstore.ErrCASMismatch},
		"denied":       &secretstore.Error{Op: "read", Kind: secretstore.ErrDenied},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, readyHealth, nil)
			f.m.ObserveAudited(context.Background(), clientTimeout("read"))
			if got := f.state(t); got != AuditBlocked {
				t.Fatalf("State = %q, want audit-blocked", got)
			}
			f.m.ObserveAudited(context.Background(), err)
			if got := f.state(t); got != Ready {
				t.Fatalf("State after an answered call = %q, want ready", got)
			}
			if c := f.rec.Matching(slog.LevelInfo, "accepting audit records again"); len(c) != 1 {
				t.Errorf("%d cleared records, want 1", len(c))
			}
		})
	}
	t.Run("a not-ready reading", func(t *testing.T) {
		f := newFixture(t, readyHealth, nil)
		f.m.ObserveAudited(context.Background(), clientTimeout("read"))
		f.store.set(secretstore.Health{}, healthErr(secretstore.ErrSealed))
		if got := f.state(t); got != Sealed {
			t.Fatalf("State = %q, want sealed", got)
		}
		f.store.set(readyHealth, nil)
		if got := f.state(t); got != Ready {
			t.Fatalf("State after sealed then 200 = %q, want ready", got)
		}
	})
	t.Run("another error changes nothing", func(t *testing.T) {
		f := newFixture(t, readyHealth, nil)
		f.m.ObserveAudited(context.Background(), clientTimeout("read"))
		f.m.ObserveAudited(context.Background(), &secretstore.Error{Op: "read", Kind: secretstore.ErrProtocol})
		if got := f.state(t); got != AuditBlocked {
			t.Fatalf("State = %q, want audit-blocked still", got)
		}
	})
}

// A reading whose ctx ends returns no alert: nobody is waiting for the list.
func TestMonitor_AlertsOnEndedCtx(t *testing.T) {
	f := newFixture(t, secretstore.Health{}, healthErr(secretstore.ErrSealed))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if a := f.m.Alerts(ctx, f.clock.now()); a != nil {
		t.Fatalf("Alerts on an ended ctx = %+v, want none", a)
	}
}

// TC-830-11: a quiesce for a backup and one for a seal-key rotation raise the
// same warn alert ID, each with copy naming its own job and not the other.
func TestMonitor_QuiesceReasonCopy(t *testing.T) {
	for _, tc := range []struct {
		reason       QuiesceReason
		says, notSay string
		logMsg       string
		// field is the record's reason field, which log queries filter on:
		// one value per reason.
		field string
	}{
		{QuiesceBackup, "backup", "seal-key", "secret store quiesced for a backup", "backup"},
		{QuiesceSealRotation, "seal-key rotation", "backup", "secret store quiesced for a seal-key rotation", "seal-rotation"},
	} {
		t.Run(tc.reason.String(), func(t *testing.T) {
			f := newFixture(t, secretstore.Health{}, healthErr(secretstore.ErrUnreachable))
			f.running["job"] = true
			release := f.m.Quiesce("job", tc.reason)
			defer release()
			a := f.m.Alerts(context.Background(), f.clock.now())
			if len(a) != 1 || a[0].ID != "secret-store:quiesced" || a[0].Severity != proto.AlertWarn {
				t.Fatalf("alerts = %+v", a)
			}
			copy := a[0].Title + " " + a[0].Detail
			if !strings.Contains(copy, tc.says) || strings.Contains(copy, tc.notSay) {
				t.Errorf("copy %q: want %q and not %q", copy, tc.says, tc.notSay)
			}
			recs := f.rec.Matching(slog.LevelInfo, tc.logMsg)
			if len(recs) != 1 {
				t.Fatalf("no %q record", tc.logMsg)
			}
			if got, _ := logkittest.Attr(recs[0], "reason"); got != tc.field {
				t.Errorf("reason field = %q, want %q", got, tc.field)
			}
		})
	}
}

// TC-874-13: Held fails closed. A running hold is held, no hold is not, a hold
// whose job is confirmed not running is not held with one WARN, and a hold
// whose job status cannot be read is held, with a WARN naming the job and the
// error (F-874-01).
func TestMonitor_Held(t *testing.T) {
	for _, tc := range []struct {
		name    string
		hold    bool
		running bool
		runErr  error
		want    bool
		warnErr string
	}{
		{name: "running hold", hold: true, running: true, want: true},
		{name: "no hold", want: false},
		{name: "not running", hold: true, want: false, warnErr: "not running"},
		{name: "status unreadable", hold: true, runErr: errors.New("ledger closed"), want: true, warnErr: "ledger closed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, secretstore.Health{}, healthErr(secretstore.ErrUnreachable))
			f.running["job-h"] = tc.running
			f.runErr = tc.runErr
			if tc.hold {
				f.m.Quiesce("job-h", QuiesceSealRotation)
			}
			for range 2 {
				if got := f.m.Held(context.Background()); got != tc.want {
					t.Fatalf("Held = %v, want %v", got, tc.want)
				}
			}
			w := f.rec.Matching(slog.LevelWarn, "secret store quiesce hold ignored")
			if tc.warnErr == "" {
				if len(w) != 0 {
					t.Errorf("%d WARN records, want 0", len(w))
				}
				return
			}
			if len(w) != 1 {
				t.Fatalf("%d WARN records over two calls, want 1", len(w))
			}
			if got, _ := logkittest.Attr(w[0], "job_id"); got != "job-h" {
				t.Errorf("job_id = %q", got)
			}
			if got, _ := logkittest.Attr(w[0], "err"); !strings.Contains(got, tc.warnErr) {
				t.Errorf("err = %q, want it to contain %q", got, tc.warnErr)
			}
		})
	}
}
