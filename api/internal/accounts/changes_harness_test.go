package accounts

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/markers"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/removednames"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The account changes of Identity 4.12 (geekdojo/geekdojo-brain#994) over
// #991's harness: the real Users, guard, revoker, access grant, markers
// writer and designations over the fake Admin API and real SQLite, on a
// runner the kind table decides.

// completeCreds are a password, an authenticator app and recovery codes.
var completeCreds = []string{"password", "otp", "recovery-authn-codes"}

type recMarkers struct {
	inner *markers.Writer
	log   *callLog
}

func (m recMarkers) BeforePrivilege(ctx context.Context, sub string) error {
	m.log.add("before-privilege")
	return m.inner.BeforePrivilege(ctx, sub)
}

func (m recMarkers) AfterRemoval(ctx context.Context, sub string) error {
	m.log.add("after-removal")
	return m.inner.AfterRemoval(ctx, sub)
}

type recDes struct {
	inner *Designations
	log   *callLog
}

func (d recDes) Designate(ctx context.Context, x Designation) error {
	d.log.add("designate")
	return d.inner.Designate(ctx, x)
}

func (d recDes) Choose(ctx context.Context, sub string, level Level, value string) error {
	d.log.add("choose:" + string(level) + "=" + value)
	return d.inner.Choose(ctx, sub, level, value)
}

func (d recDes) Withdraw(ctx context.Context, sub string, level Level) error {
	d.log.add("withdraw:" + string(level))
	return d.inner.Withdraw(ctx, sub, level)
}

func (d recDes) Clear(ctx context.Context, sub string) error {
	d.log.add("clear")
	return d.inner.Clear(ctx, sub)
}

// removedCheck is the removed-name list, or a read that fails.
type removedCheck struct {
	inner *removednames.Store
	err   error
}

func (r *removedCheck) Removed(ctx context.Context, name, email string) (bool, error) {
	if r.err != nil {
		return false, r.err
	}
	return r.inner.Removed(ctx, name, email)
}

// factsCheck is RoleAccounts, or a read that fails.
type factsCheck struct {
	inner RoleAccounts
	err   error
}

func (f *factsCheck) Facts(ctx context.Context, sub string) (authz.AccountFacts, error) {
	if f.err != nil {
		return authz.AccountFacts{}, f.err
	}
	return f.inner.Facts(ctx, sub)
}

type changeHarness struct {
	*harness
	held     *Held
	fresh    *Fresh
	changes  *Changes
	requests *Requests
	granter  *Granter
	runner   *jobs.Runner
	removedC *removedCheck
	factsC   *factsCheck
	clog     *logkittest.Recorder
	// mw is the one marker writer, the drain's sink in main.
	mw *markers.Writer
}

func newChangeHarness(t *testing.T) *changeHarness {
	t.Helper()
	h := newHarness(t)
	h.world()
	slogger, rec := logkittest.New()
	c := &changeHarness{harness: h, held: NewHeld(), fresh: NewFresh(), clog: rec,
		removedC: &removedCheck{inner: h.removed}, factsC: &factsCheck{inner: h.ra}}
	mw, err := markers.New(markers.Deps{Admin: h.kc, Realm: realm, Lock: h.lock, Log: slogger,
		DoorOf: func(string) (flows.Door, bool) { return "", false }})
	if err != nil {
		t.Fatal(err)
	}
	c.mw = mw
	kp, err := authz.NewKindPolicy(noApps{})
	if err != nil {
		t.Fatal(err)
	}
	if c.runner, err = jobs.NewAuthorizedRunner(h.jobs, h.nc, kp); err != nil {
		t.Fatal(err)
	}
	if c.changes, err = NewChanges(ChangesDeps{Guard: recGuard{inner: h.guard, log: h.log}, Users: h.users, Access: h.access,
		Sessions: h.sessions, Markers: recMarkers{inner: mw, log: h.log}, Designations: recDes{inner: h.designations, log: h.log},
		Facts: h.ra, Revoker: h.rev, Removed: c.removedC, Held: c.held, Fresh: c.fresh, Lock: h.lock, Log: slogger,
		StepTimeout: time.Minute}); err != nil {
		t.Fatal(err)
	}
	for _, wf := range c.changes.Workflows() {
		c.runner.Register(wf)
	}
	gw, err := c.changes.GrantWaitingWorkflow(h.designations)
	if err != nil {
		t.Fatal(err)
	}
	c.runner.Register(gw)
	if c.granter, err = NewGranter(GranterDeps{Designations: h.designations, Facts: h.ra, Markers: recMarkers{inner: mw, log: h.log},
		Sessions: h.sessions, Roles: h.users, Users: h.users, Access: h.access, Console: h.console, Admins: h.ra, Lock: h.lock, Log: slogger,
		StepTimeout: time.Minute}); err != nil {
		t.Fatal(err)
	}
	c.runner.Register(c.granter.Workflow())
	if c.requests, err = NewRequests(RequestsDeps{Authorizer: kp, Runner: c.runner, Held: c.held, Facts: c.factsC, Log: slogger}); err != nil {
		t.Fatal(err)
	}
	return c
}

// who is a signed-in person as a job's submitter.
func who(sub string, roles ...string) authz.Submitter {
	return auth.Principal{Sub: sub, Roles: roles}.Submitter()
}

var adminSubmitter = who(adminA, "admin")

// run submits kind with spec for by, marked fresh when fresh and holding
// value when it is not empty, and waits for it.
func (c *changeHarness) run(t *testing.T, by authz.Submitter, kind string, spec any, fresh bool, value string) result {
	t.Helper()
	j, err := c.runner.SubmitFor(t.Context(), by, kind, spec, func(id string) error {
		if fresh {
			c.fresh.Mark(id)
		}
		if value != "" {
			c.held.Put(id, secret.New([]byte(value)))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("submit %s: %v", kind, err)
	}
	c.runner.Wait()
	return c.result(t, j.ID)
}

// operatorSpec runs POST /api/jobs' path: a person's raw spec.
func (c *changeHarness) operatorSpec(t *testing.T, by authz.Submitter, kind, raw string) result {
	t.Helper()
	j, err := c.runner.SubmitOperatorSpec(t.Context(), kind, json.RawMessage(raw), by)
	if err != nil {
		t.Fatalf("submit %s: %v", kind, err)
	}
	c.runner.Wait()
	return c.result(t, j.ID)
}

// out is a step's recorded outcome, decoded.
func (r result) out(name string) map[string]any {
	s := r.step(name)
	if s == nil {
		return nil
	}
	var m map[string]any
	_ = json.Unmarshal(s.Result, &m)
	return m
}

// names are the steps that ran, in order.
func (r result) names() []string {
	var out []string
	for _, s := range r.steps {
		out = append(out, s.Name)
	}
	return out
}

// writes are the identity writes, in order.
func (h *harness) writes() []string {
	return h.log.only("add-console", "remove-console", "set-attr", "remove-attr", "set-rasputin", "set-email", "set-name",
		"enable", "disable", "delete-user", "delete-credential", "rename-credential", "unlock", "add-offline", "remove-offline")
}

// index is where entry first appears in calls, -1 when it doesn't.
func index(calls []string, prefix string) int {
	return slices.IndexFunc(calls, func(c string) bool { return strings.HasPrefix(c, prefix) })
}

// waitFor waits for cond, a fact, and fails the test if it doesn't come
// true within a bound far outside normal.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s never came true", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// designation is sub's designation, or the zero one.
func (h *harness) designation(t *testing.T, sub string) (Designation, bool) {
	t.Helper()
	x, ok, err := h.designations.Get(t.Context(), sub)
	if err != nil {
		t.Fatal(err)
	}
	return x, ok
}

// complete makes sub's setup complete: a second step, codes, no action.
func (h *harness) complete(sub string) {
	h.kc.mu.Lock()
	defer h.kc.mu.Unlock()
	u := h.kc.users[sub]
	u.creds, u.credIDs = slices.Clone(completeCreds), []string{"id-password", "id-otp", "id-codes"}
	u.rep["requiredActions"] = []any{}
}

// consoleOf is sub's console roles in the fake.
func (h *harness) consoleOf(sub string) []string {
	h.kc.mu.Lock()
	defer h.kc.mu.Unlock()
	return slices.Clone(h.kc.users[sub].console)
}

// attr is one of sub's attributes, joined by commas.
func (h *harness) attr(sub, name string) string {
	h.kc.mu.Lock()
	defer h.kc.mu.Unlock()
	return attrOf(h.kc.users[sub].rep["attributes"], name)
}

// grant runs accounts.grant_designated_role for sub.
func (c *changeHarness) grant(t *testing.T, sub string) result {
	t.Helper()
	j, err := c.runner.Submit(t.Context(), GrantKind, GrantSpec{AccountID: sub}, grantSubmitter)
	if err != nil {
		t.Fatal(err)
	}
	c.runner.Wait()
	return c.result(t, j.ID)
}
