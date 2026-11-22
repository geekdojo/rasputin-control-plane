package converge

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/migrations"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// fakeReady is the identity service's readiness.
type fakeReady struct{ err error }

func (f *fakeReady) Ready(context.Context) error { return f.err }

// fakeLedger holds jobs by kind, newest last.
type fakeLedger struct {
	mu   sync.Mutex
	jobs map[string][]string
	err  error
}

func (l *fakeLedger) ListJobsByKind(_ context.Context, kind string, limit int) ([]*jobs.Job, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return nil, l.err
	}
	ids := l.jobs[kind]
	if len(ids) == 0 || limit < 1 {
		return nil, nil
	}
	return []*jobs.Job{{ID: ids[len(ids)-1], Kind: kind}}, nil
}

func (l *fakeLedger) add(kind string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.jobs == nil {
		l.jobs = map[string][]string{}
	}
	l.jobs[kind] = append(l.jobs[kind], fmt.Sprintf("%s-%d", kind, len(l.jobs[kind])+1))
}

// fakeLagging is the migrations record.
type fakeLagging struct {
	applied, want int
	err           error
}

func (f *fakeLagging) Lagging(context.Context) (int, int, error) { return f.applied, f.want, f.err }

func newTrigger(t *testing.T, kind string, ready *fakeReady, l *fakeLedger, cond Cond, level slog.Level) (*Trigger, *logkittest.Recorder) {
	t.Helper()
	log, rec := logkittest.New()
	tr, err := NewTrigger(TriggerDeps{Kind: kind, Ready: ready, Ledger: l, Cond: cond, CondErrLevel: level, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	return tr, rec
}

// dueEither reads the trigger twice and reports whether either reading was
// due.
func dueEither(t *testing.T, tr *Trigger) bool {
	t.Helper()
	first := due(t, tr)
	return due(t, tr) || first
}

func due(t *testing.T, tr *Trigger) bool {
	t.Helper()
	d, _ := tr.Due(t.Context())
	return d
}

// TC-981-12: the shared latch: not ready is not due; a cond error or an
// unreadable ledger is not due with one WARN per outage; the first ready
// reading with cond is due, logging INFO with the reason, until a job of its
// kind exists; a not-ready to ready transition re-arms it.
func TestTrigger_Latch(t *testing.T) {
	ready, l := &fakeReady{err: errors.New("starting")}, &fakeLedger{}
	var condErr error
	cond := func(context.Context) (bool, string, string, error) { return condErr == nil, "the reason", "", condErr }
	tr, rec := newTrigger(t, "k", ready, l, cond, slog.LevelWarn)

	if dueEither(t, tr) {
		t.Fatal("due while not ready")
	}
	if n := len(rec.AtLevel(slog.LevelWarn)); n != 1 {
		t.Errorf("%d not-ready WARNs over one outage, want 1", n)
	}
	ready.err = nil
	if d, reason := tr.Due(t.Context()); !d || reason != "the reason" {
		t.Fatalf("first ready reading = %v %q, want due", d, reason)
	}
	infos := rec.Matching(slog.LevelInfo, "due")
	if len(infos) != 1 {
		t.Fatalf("records:\n%s\nwant one INFO", rec.Text())
	}
	if r, _ := logkittest.Attr(infos[0], "reason"); r != "the reason" {
		t.Errorf("INFO reason = %q", r)
	}
	if !due(t, tr) {
		t.Error("not due again before any job exists (a failed submit leaves no row)")
	}
	l.add("k")
	if due(t, tr) {
		t.Error("due after its job was created")
	}
	ready.err = errors.New("restarting")
	_ = due(t, tr)
	ready.err = nil
	if !due(t, tr) {
		t.Error("not re-armed by a not-ready to ready transition")
	}
	l.add("k")

	// A cond that cannot be read: not due, one WARN per outage.
	before := len(rec.AtLevel(slog.LevelWarn))
	condErr = errors.New("db")
	if dueEither(t, tr) {
		t.Error("due with the cond unreadable")
	}
	condErr = nil
	_ = due(t, tr)
	condErr = errors.New("db again")
	_ = due(t, tr)
	if n := len(rec.AtLevel(slog.LevelWarn)) - before; n != 2 {
		t.Errorf("%d cond WARNs over two outages, want 2", n)
	}
	condErr = nil

	// An unreadable ledger: not due, one WARN per outage.
	ready.err = errors.New("x")
	_ = due(t, tr)
	ready.err = nil
	before = len(rec.AtLevel(slog.LevelWarn))
	l.err = errors.New("ledger")
	if dueEither(t, tr) {
		t.Error("due with the ledger unreadable")
	}
	if n := len(rec.AtLevel(slog.LevelWarn)) - before; n != 1 {
		t.Errorf("%d ledger WARNs, want 1", n)
	}
	l.err = nil
	if !due(t, tr) {
		t.Error("not due once the ledger reads again")
	}
}

// TC-981-12: converge's trigger is not due while the realm lags its
// migrations or the record cannot be read, is due once per readiness
// episode, and re-arms on a new desired hash that differs from the stored
// one.
func TestTrigger_Converge(t *testing.T) {
	r := newRig(t)
	lag := &fakeLagging{applied: 0, want: 1}
	ready, l := &fakeReady{}, &fakeLedger{}
	tr, _ := newTrigger(t, ConvergeKind, ready, l, ConvergeCond(r.c, lag), slog.LevelWarn)
	if due(t, tr) {
		t.Error("due while the realm lags its migrations")
	}
	lag.err = errors.New("unreadable")
	if due(t, tr) {
		t.Error("due while the migration record is unreadable")
	}
	lag.applied, lag.err = 1, nil
	if !due(t, tr) {
		t.Fatal("not due on the readiness episode")
	}
	l.add(ConvergeKind)
	r.storeHash() // the job reached the desired state
	if due(t, tr) {
		t.Error("due again within the episode")
	}
	r.inputs.InstallName = "Renamed Home"
	if !due(t, tr) {
		t.Error("not re-armed by a new differing desired hash")
	}
	l.add(ConvergeKind) // that run failed: the hash is not stored
	if due(t, tr) {
		t.Error("re-armed by the same differing hash after its run")
	}
}

// TC-981-12: migrate's trigger is due only while the realm lags; arm's while
// no realm id is recorded or the armed marker is absent.
func TestTrigger_MigrateAndArm(t *testing.T) {
	lag := &fakeLagging{applied: 2, want: 2}
	ready, l := &fakeReady{}, &fakeLedger{}
	mig, _ := newTrigger(t, MigrateKind, ready, l, MigrateCond(lag), slog.LevelError)
	if due(t, mig) {
		t.Error("migrate due with nothing to apply")
	}
	lag.applied = 1
	if !due(t, mig) {
		t.Error("migrate not due while the realm lags")
	}
	lag.err = errors.New("newer than this release")
	if due(t, mig) {
		t.Error("migrate due on an unusable record")
	}

	a := newArmRig(t)
	arm, _ := newTrigger(t, ArmKind, ready, l, ArmCond(a.a), slog.LevelWarn)
	if !due(t, arm) {
		t.Error("arm not due with no realm id")
	}
	l.add(ArmKind)
	a.settings.m[RealmIDKey], a.exists = "realm-uuid-1", true
	ready.err = errors.New("restart")
	_ = due(t, arm)
	ready.err = nil
	if due(t, arm) {
		t.Error("arm due with the id recorded and the marker present")
	}
	a.exists = false
	if !due(t, arm) {
		t.Error("arm not due with the marker absent")
	}
}

// TC-981-19: the upgrade from the previous release: no realm id, no converge
// hash, no armed marker, a realm with no rasputin.migrations and All empty,
// the service ready. Arm and converge are due and migrate is not; converge's
// first run repairs fields, logs INFO with the field list and raises no
// drift alert.
func TestUpgradeFromThePreviousRelease(t *testing.T) {
	r := newRig(t)
	// The realm the previous release imported: the baseline as is.
	r.kc.realm = map[string]any{
		"id": "realm-uuid-1", "realm": testRealm, "eventsEnabled": true, "eventsListeners": []any{},
		"adminEventsEnabled": false, "adminEventsDetailsEnabled": false, "smtpServer": map[string]any{},
		"attributes":                 map[string]any{"CreateDefaultClientScopes": "true"},
		"webAuthnPolicyRpEntityName": "keycloak", "webAuthnPolicyRpId": "",
		"webAuthnPolicyPasswordlessRpEntityName": "keycloak", "webAuthnPolicyPasswordlessRpId": "",
	}
	log, _ := logkittest.New()
	runner, err := migrations.New(migrations.Deps{Admin: r.kc, Realm: testRealm, Lock: r.lock, All: migrations.All, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	a := newArmRig(t)
	a.kc = r.kc
	ready, l := &fakeReady{}, &fakeLedger{}
	conv, _ := newTrigger(t, ConvergeKind, ready, l, ConvergeCond(r.c, runner), slog.LevelWarn)
	mig, _ := newTrigger(t, MigrateKind, ready, l, MigrateCond(runner), slog.LevelError)
	arm, _ := newTrigger(t, ArmKind, ready, l, ArmCond(a.a), slog.LevelWarn)
	if !due(t, arm) || !due(t, conv) || due(t, mig) {
		t.Fatalf("arm, converge, migrate due = %v, %v, %v; want true, true, false", due(t, arm), due(t, conv), due(t, mig))
	}
	fields, err := r.c.Run(t.Context())
	if err != nil || len(fields) == 0 {
		t.Fatalf("first converge = %v, %v; want repairs", fields, err)
	}
	infos := r.rec.Matching(slog.LevelInfo, "set to Rasputin's")
	if len(infos) != 1 || len(r.rec.AtLevel(slog.LevelWarn)) != 0 {
		t.Fatalf("records:\n%s\nwant one INFO and no WARN", r.rec.Text())
	}
	if f, _ := logkittest.Attr(infos[0], "fields"); f == "" {
		t.Error("the INFO carries no field list")
	}
	if alerts := r.c.Alerts(t.Context(), testNow); len(alerts) != 0 {
		t.Errorf("alerts = %+v, want no drift alert", alerts)
	}
}
