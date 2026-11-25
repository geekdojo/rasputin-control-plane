package accounts

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/markers"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// grantRig is the grant over recording fakes: every call it makes, in
// order, in one log, and a failure for any of them by name.
type grantRig struct {
	log   *callLog
	fail  map[string]error
	des   map[string]Designation
	facts authz.AccountFacts
	// network is the grants the account holds when the grant reads them.
	network []string
	// admins is the enabled administrators' count (C25).
	admins int
	g      *Granter
	rec    *logkittest.Recorder
}

func (r *grantRig) call(name string) error {
	r.log.add(name)
	return r.fail[name]
}

type gDes struct{ r *grantRig }

func (d gDes) Get(_ context.Context, sub string) (Designation, bool, error) {
	if err := d.r.fail["Get"]; err != nil {
		return Designation{}, false, err
	}
	x, ok := d.r.des[sub]
	return x, ok, nil
}

func (d gDes) Clear(_ context.Context, sub string) error {
	if err := d.r.call("Clear"); err != nil {
		return err
	}
	delete(d.r.des, sub)
	return nil
}

func (d gDes) Wait(_ context.Context, sub string) error {
	if err := d.r.call("Wait"); err != nil {
		return err
	}
	x := d.r.des[sub]
	x.Reason = ReasonWaiting
	d.r.des[sub] = x
	return nil
}

func (d gDes) WaitMoved(_ context.Context, except string) error {
	if err := d.r.call("WaitMoved"); err != nil {
		return err
	}
	for sub, x := range d.r.des {
		if sub != except && x.Reason == ReasonMoved {
			x.Reason = ReasonWaiting
			d.r.des[sub] = x
		}
	}
	return nil
}

type gAdmins struct{ r *grantRig }

func (a gAdmins) EnabledAdmins(context.Context) (int, error) {
	return a.r.admins, a.r.call("EnabledAdmins")
}

type gFacts struct{ r *grantRig }

func (f gFacts) Facts(context.Context, string) (authz.AccountFacts, error) {
	return f.r.facts, f.r.fail["Facts"]
}

type gMarkers struct{ r *grantRig }

func (m gMarkers) BeforePrivilege(context.Context, string) error { return m.r.call("BeforePrivilege") }

type gSessions struct{ r *grantRig }

func (s gSessions) EndAll(context.Context, string) error { return s.r.call("EndAll") }
func (s gSessions) EndOffline(context.Context, string) (int, error) {
	return 0, s.r.call("EndOffline")
}

type gRoles struct{ r *grantRig }

func (g gRoles) AddConsoleRole(_ context.Context, _, role string) error {
	return g.r.call("AddConsoleRole:" + role)
}

type gAccess struct{ r *grantRig }

func (a gAccess) Grant(_ context.Context, _ string, level AppLevel) error {
	return a.r.call("Access.Grant:" + string(level))
}

type gUsers struct{ r *grantRig }

func (u gUsers) Read(context.Context, string) (Person, error) {
	return Person{Network: u.r.network}, u.r.fail["Read"]
}
func (u gUsers) SetNetwork(_ context.Context, _ string, grants []string) error {
	return u.r.call("SetNetwork:" + strings.Join(grants, ","))
}
func (u gUsers) ConfirmEmail(context.Context, string) error { return u.r.call("ConfirmEmail") }

type gConsole struct{ r *grantRig }

func (c gConsole) EndBySub(context.Context, string) (int64, error) { return 0, c.r.call("EndBySub") }

const grantSub = "designee"

var complete = authz.AccountFacts{Sub: grantSub, Enabled: true, HoldsSecondStep: true, HoldsRecoveryCodes: true}

func newGrantRig(t *testing.T) *grantRig {
	t.Helper()
	log, rec := logkittest.New()
	r := &grantRig{log: &callLog{}, fail: map[string]error{}, rec: rec, facts: complete,
		des: map[string]Designation{grantSub: {Sub: grantSub, ConsoleRole: "admin", AppRole: AppAdmin, Reason: ReasonFirstAdmin}}}
	g, err := NewGranter(GranterDeps{Designations: gDes{r}, Facts: gFacts{r}, Markers: gMarkers{r}, Sessions: gSessions{r},
		Roles: gRoles{r}, Users: gUsers{r}, Access: gAccess{r}, Console: gConsole{r}, Admins: gAdmins{r}, Lock: &sync.Mutex{}, Log: log, StepTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	r.g = g
	return r
}

// run runs the workflow's steps in order as the runner does, by createdBy,
// stopping at the first failure. It returns each step's outcome and the
// error that stopped it.
func (r *grantRig) run(t *testing.T, createdBy string) (map[string]string, error) {
	t.Helper()
	spec, _ := json.Marshal(GrantSpec{AccountID: grantSub})
	prior := map[string]json.RawMessage{}
	out := map[string]string{}
	for _, st := range r.g.Workflow().Steps {
		b, err := st.Do(&jobs.StepCtx{Ctx: t.Context(), JobID: "j1", Spec: spec, PriorResults: prior, CreatedBy: createdBy})
		if err != nil {
			return out, err
		}
		prior[st.Name] = b
		out[st.Name] = outcomeOf(b)
	}
	return out, nil
}

// TC-990-21: the grant's steps.
func TestGranter_TC990_21(t *testing.T) {
	t.Run("complete: the calls in order", func(t *testing.T) {
		r := newGrantRig(t)
		out, err := r.run(t, "accounts.designation")
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"BeforePrivilege", "EndAll", "EndOffline", "AddConsoleRole:admin", "ConfirmEmail", "Access.Grant:admin", "EndBySub", "Clear"}
		if got := r.log.all(); !slices.Equal(got, want) {
			t.Errorf("calls %v, want %v", got, want)
		}
		if out[StepCheck] != outcomeComplete || out[StepGrantRole] != outcomeGranted || out[StepFinish] != outcomeFinished {
			t.Errorf("outcomes %v", out)
		}
		if _, ok := r.des[grantSub]; ok {
			t.Error("the designation was not cleared")
		}
	})
	t.Run("the same for any CreatedBy", func(t *testing.T) {
		for _, by := range []string{"", "someone-else", "admin-sub"} {
			r := newGrantRig(t)
			out, err := r.run(t, by)
			if err != nil || out[StepFinish] != outcomeFinished || len(r.log.all()) != 8 {
				t.Errorf("CreatedBy %q: %v %v %v", by, out, err, r.log.all())
			}
		}
	})
	t.Run("incomplete facts: waiting, nothing written", func(t *testing.T) {
		for name, f := range map[string]authz.AccountFacts{
			"codes only":       {Sub: grantSub, HoldsRecoveryCodes: true},
			"second step only": {Sub: grantSub, HoldsSecondStep: true},
			"action pending":   {Sub: grantSub, HoldsSecondStep: true, HoldsRecoveryCodes: true, RequiredActionPending: true},
		} {
			r := newGrantRig(t)
			r.facts = f
			out, err := r.run(t, "")
			if err != nil || out[StepCheck] != outcomeWaiting || out[StepGrantRole] != outcomeNotNeeded || out[StepFinish] != outcomeNotNeeded {
				t.Errorf("%s: %v %v", name, out, err)
			}
			if len(r.log.all()) != 0 {
				t.Errorf("%s: calls %v", name, r.log.all())
			}
			if _, ok := r.des[grantSub]; !ok {
				t.Errorf("%s: the designation went", name)
			}
		}
	})
	t.Run("no second step at BeforePrivilege: waiting, no role", func(t *testing.T) {
		r := newGrantRig(t)
		r.fail["BeforePrivilege"] = markers.ErrNoSecondStep
		out, err := r.run(t, "")
		if err != nil || out[StepGrantRole] != outcomeWaiting || out[StepFinish] != outcomeNotNeeded {
			t.Errorf("%v %v", out, err)
		}
		if got := r.log.all(); !slices.Equal(got, []string{"BeforePrivilege"}) {
			t.Errorf("calls %v", got)
		}
	})
	t.Run("not designated: nothing written", func(t *testing.T) {
		r := newGrantRig(t)
		r.des = map[string]Designation{}
		out, err := r.run(t, "")
		if err != nil || out[StepCheck] != outcomeNotDesignated || out[StepGrantRole] != outcomeNotNeeded || len(r.log.all()) != 0 {
			t.Errorf("%v %v %v", out, err, r.log.all())
		}
	})
	t.Run("a failure at each step stops the job, keeps the designation, and is one WARN with no account id", func(t *testing.T) {
		ie := &idclient.Error{Op: "admin", Path: "/admin/realms/rasputin/users/" + grantSub, Status: 503, Kind: idclient.ErrUnreachable}
		for _, at := range []string{"Facts", "Get", "BeforePrivilege", "EndAll", "EndOffline", "AddConsoleRole:admin", "ConfirmEmail", "Access.Grant:admin", "EndBySub", "Clear"} {
			r := newGrantRig(t)
			r.fail[at] = ie
			_, err := r.run(t, "")
			var se *StepError
			if !errors.As(err, &se) || se.Sentence == "" {
				t.Errorf("%s: err %v, want a step error with a sentence", at, err)
				continue
			}
			if at != "Clear" {
				if _, ok := r.des[grantSub]; !ok {
					t.Errorf("%s: the designation went", at)
				}
			}
			var warn []slog.Record
			for _, rec := range r.rec.Records() {
				if ev, _ := logkittest.Attr(rec, "event"); ev == "accounts.grant.failed" && rec.Level == slog.LevelWarn {
					warn = append(warn, rec)
				}
			}
			if len(warn) != 1 {
				t.Errorf("%s: %d failure records", at, len(warn))
				continue
			}
			if st, _ := logkittest.Attr(warn[0], "status"); st != "503" {
				t.Errorf("%s: status %q", at, st)
			}
			if k, _ := logkittest.Attr(warn[0], "kind"); k == "" {
				t.Errorf("%s: no kind", at)
			}
			if step, _ := logkittest.Attr(warn[0], "step"); step == "" {
				t.Errorf("%s: no step", at)
			}
			if strings.Contains(r.rec.Text(), grantSub) {
				t.Errorf("%s: the account id is in the log:\n%s", at, r.rec.Text())
			}
		}
	})
	t.Run("a spec with no account fails", func(t *testing.T) {
		r := newGrantRig(t)
		st := r.g.Workflow().Steps[0]
		if _, err := st.Do(&jobs.StepCtx{Ctx: t.Context(), Spec: json.RawMessage(`{}`)}); err == nil {
			t.Error("accepted")
		}
	})
	if wf := newGrantRig(t).g.Workflow(); wf.Kind != GrantKind || !wf.System {
		t.Errorf("the workflow %s, System %v", wf.Kind, wf.System)
	}
	if _, err := NewGranter(GranterDeps{}); err == nil {
		t.Error("NewGranter with nothing succeeded")
	}
}

// fakeSubmitter records the System jobs submitted.
type fakeSubmitter struct {
	mu    sync.Mutex
	specs []GrantSpec
	err   error
}

func (s *fakeSubmitter) Submit(_ context.Context, kind string, spec any, by string) (*jobs.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if kind != GrantKind || by != grantSubmitter {
		return nil, errors.New("wrong kind or submitter")
	}
	if s.err != nil {
		return nil, s.err
	}
	s.specs = append(s.specs, spec.(GrantSpec))
	return &jobs.Job{ID: "j"}, nil
}

func (s *fakeSubmitter) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.specs)
}

// TC-990-22: the kind is system-only; the observer submits only for a
// designated account with complete facts; a read or submit error submits
// nothing and is one WARN with no account id; a grant that failed is
// submitted again at the next sign-in (B101).
func TestObserver_TC990_22(t *testing.T) {
	kinds, err := authz.NewKindPolicy(noApps{})
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(GrantSpec{AccountID: grantSub})
	admin := authz.Person(authz.Subject{Sub: "admin-sub", Roles: []string{"admin"}})
	if err := kinds.Authorize(t.Context(), GrantKind, spec, admin); err == nil {
		t.Error("an administrator may submit accounts.grant_designated_role")
	}
	if !authz.SystemOnly(GrantKind) {
		t.Error("the kind is not system-only")
	}

	r := newGrantRig(t)
	sub := &fakeSubmitter{}
	log, rec := logkittest.New()
	o, err := NewObserver(ObserverDeps{Designations: gDes{r}, Facts: gFacts{r}, Runner: sub, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	o.SignedIn(ctx, grantSub)
	if sub.count() != 1 || sub.specs[0].AccountID != grantSub {
		t.Fatalf("complete: submitted %v", sub.specs)
	}
	// B101: the grant failed and the designation is still there, so the
	// next sign-in submits again.
	o.SignedIn(ctx, grantSub)
	if sub.count() != 2 {
		t.Errorf("the next sign-in submitted %d in all, want 2", sub.count())
	}
	o.SignedIn(ctx, "")
	o.SignedIn(ctx, "not-designated")
	r.facts = authz.AccountFacts{Sub: grantSub, HoldsRecoveryCodes: true}
	o.SignedIn(ctx, grantSub)
	if sub.count() != 2 {
		t.Errorf("an empty sub, no designation or incomplete facts submitted (%d)", sub.count())
	}
	if len(rec.Records()) != 0 {
		t.Errorf("records:\n%s", rec.Text())
	}

	warns := func() int {
		n := 0
		for _, x := range rec.Records() {
			if ev, _ := logkittest.Attr(x, "event"); ev == "accounts.designation.check_failed" && x.Level == slog.LevelWarn {
				n++
			}
		}
		return n
	}
	r.facts = complete
	cases := []func(){
		func() { r.fail["Get"] = errors.New("unreadable") },
		func() { r.des[grantSub] = Designation{Sub: grantSub, ConsoleRole: "owner", Reason: ReasonPrivileged} },
		func() { r.fail["Facts"] = &idclient.Error{Status: 503, Kind: idclient.ErrUnreachable} },
		func() { sub.err = errors.New("refused") },
	}
	for i, set := range cases {
		r.fail = map[string]error{}
		r.des = map[string]Designation{grantSub: {Sub: grantSub, ConsoleRole: "admin", AppRole: AppAdmin, Reason: ReasonFirstAdmin}}
		sub.err = nil
		set()
		before, w := sub.count(), warns()
		o.SignedIn(ctx, grantSub)
		if sub.count() != before && i != 3 {
			t.Errorf("case %d submitted", i)
		}
		if warns() != w+1 {
			t.Errorf("case %d: no WARN", i)
		}
	}
	if strings.Contains(rec.Text(), grantSub) {
		t.Errorf("the account id is in the log:\n%s", rec.Text())
	}
	if _, err := NewObserver(ObserverDeps{}); err == nil {
		t.Error("NewObserver with nothing succeeded")
	}
}
