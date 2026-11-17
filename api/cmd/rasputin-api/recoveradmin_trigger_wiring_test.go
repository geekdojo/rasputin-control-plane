package main

import (
	"context"
	"log/slog"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/recoveradmin"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// countedIdentity is the session's login and Admin API, counting calls.
type countedIdentity struct{ n atomic.Int64 }

func (c *countedIdentity) ClientCredentials(context.Context, string, string, *secret.Value) (secret.Value, error) {
	c.n.Add(1)
	return secret.New([]byte("tok")), nil
}

func (c *countedIdentity) Admin(context.Context, secret.Value, string, string, any, any) (idclient.Response, error) {
	c.n.Add(1)
	return idclient.Response{Status: 200}, nil
}

// TC-1127-13: under keycloak the trigger's entry is identity.recover_admin on
// the identity check's cadence; it is not due, and probes nothing, until the
// restored alert's holder is set (F-1127-04), and then it reads the fact.
// Under off and mock there is no entry and no trigger.
func TestIdentityAdminTrigger_Wiring(t *testing.T) {
	c := &identityCounts{}
	st, err := identityStateWiring(identityDeps(t, identityModeKeycloak, c))
	if err != nil {
		t.Fatal(err)
	}
	ident := &countedIdentity{}
	sess, err := idclient.NewSession(idclient.SessionConfig{Login: ident, Admin: ident, Realm: identityRealm,
		ClientID: identityAdminClient, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	holder := &atomic.Pointer[restoredFunc]{}
	entry, trig, err := identityAdminTrigger(identityModeKeycloak, st.monitor, sess, openJobStore(t), holder, slog.New(slog.DiscardHandler))
	if err != nil || entry == nil || trig == nil {
		t.Fatalf("identityAdminTrigger = %v, %v, %v", entry, trig, err)
	}
	if entry.Kind != recoveradmin.Kind || entry.Interval != storeAuditCheckEvery || entry.Due == nil || entry.InitialDelay != 0 {
		t.Fatalf("entry = %+v", entry)
	}
	if c.total() != 0 || ident.n.Load() != 0 {
		t.Fatalf("building made %d state and %d identity calls", c.total(), ident.n.Load())
	}
	if due, reason := entry.Due(t.Context()); due || reason != "" {
		t.Errorf("holder unset: Due = %v %q, want false", due, reason)
	}
	if c.total() != 0 || ident.n.Load() != 0 {
		t.Errorf("holder unset: Due made %d state and %d identity calls, want none", c.total(), ident.n.Load())
	}
	f := restoredFunc(func(context.Context, string) error { return nil })
	holder.Store(&f)
	if due, _ := entry.Due(t.Context()); due {
		t.Error("due with the identity service not ready")
	}
	if c.total() == 0 {
		t.Error("holder set: Due did not read the identity state")
	}
	if got := entriesOf(entry); len(got) != 1 || got[0].Kind != recoveradmin.Kind {
		t.Errorf("entriesOf = %+v", got)
	}

	for _, mode := range []string{identityModeOff, identityModeMock} {
		e, tr, err := identityAdminTrigger(mode, nil, nil, nil, nil, nil)
		if e != nil || tr != nil || err != nil || entriesOf(e) != nil {
			t.Errorf("%s: %v, %v, %v; want none", mode, e, tr, err)
		}
	}
	if _, _, err := identityAdminTrigger(identityModeKeycloak, st.monitor, nil, openJobStore(t), holder, slog.New(slog.DiscardHandler)); err == nil {
		t.Error("a nil session under keycloak was accepted")
	}
}

// TC-1127-11 (the holder half): a job that succeeds before the holder is set
// writes one ERROR naming the job and nothing panics; once it is set, the
// alert is raised for the job.
func TestIdentityAdminRestored_Holder(t *testing.T) {
	ca := ensureIdentityCA(t, t.TempDir(), tlscatest.Deps())
	srv := newIdentityServer(t, ca)
	log, rec := logkittest.New()
	holder := &atomic.Pointer[restoredFunc]{}
	w, err := wireIdentity(t.Context(), log, "keycloak", srv.URL, srv.URL, ca, t.TempDir(), (&scriptedRun{}).run, noRunEnv, holder)
	if err != nil || w.recoverer == nil {
		t.Fatalf("wireIdentity: %v", err)
	}
	wf := w.recoverer.Workflow()
	wf.OnTerminal(t.Context(), "J1", true, "")
	errs := rec.Matching(slog.LevelError, "The admin client restored alert was not raised.")
	if len(errs) != 1 || len(rec.Records()) != 1 {
		t.Fatalf("records:\n%s\nwant one ERROR", rec.Text())
	}
	if a := attrsOf(errs[0]); a["job_id"] != "J1" || a["err"] != errRestoredUnwired.Error() {
		t.Errorf("ERROR attrs = %v", a)
	}
	var raised []string
	f := restoredFunc(func(_ context.Context, id string) error { raised = append(raised, id); return nil })
	holder.Store(&f)
	wf.OnTerminal(t.Context(), "J2", true, "")
	if !slices.Equal(raised, []string{"J2"}) || len(rec.Records()) != 1 {
		t.Errorf("raised %v, records:\n%s", raised, rec.Text())
	}
	if _, err := wireIdentity(t.Context(), log, "keycloak", srv.URL, srv.URL, ca, t.TempDir(), (&scriptedRun{}).run, noRunEnv, nil); err == nil {
		t.Error("a nil holder under keycloak was accepted")
	}
}

// fixedAlerts records the identity alerts source.
type fixedAlerts struct {
	fn func(context.Context, time.Time) []proto.Alert
}

func (f *fixedAlerts) SetIdentityAlerts(fn func(context.Context, time.Time) []proto.Alert) { f.fn = fn }

// The identity alerts source is the monitor's alerts followed by the
// trigger's (F-1127-08): with the service unreachable, one identity: state
// alert and no still-refused alert, since nothing was refused.
func TestIdentityState_WireAlertsWithTrigger(t *testing.T) {
	st, err := identityStateWiring(identityDeps(t, identityModeKeycloak, &identityCounts{}))
	if err != nil {
		t.Fatal(err)
	}
	ident := &countedIdentity{}
	sess, _ := idclient.NewSession(idclient.SessionConfig{Login: ident, Admin: ident, Realm: identityRealm,
		ClientID: identityAdminClient, Log: slog.New(slog.DiscardHandler)})
	_, trig, err := identityAdminTrigger(identityModeKeycloak, st.monitor, sess, openJobStore(t), &atomic.Pointer[restoredFunc]{}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	hook := &fixedAlerts{}
	st.wireAlerts(hook, trig)
	if hook.fn == nil {
		t.Fatal("no identity alerts source")
	}
	got := hook.fn(t.Context(), time.Now())
	if len(got) != 1 || got[0].ID == recoveradmin.AdminRefusedAlertID {
		t.Errorf("alerts = %+v, want the monitor's one", got)
	}
}
