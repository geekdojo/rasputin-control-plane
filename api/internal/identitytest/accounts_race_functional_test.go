package identitytest

// The grant race against the real identity service
// (geekdojo/geekdojo-brain#994): two designated-role grants for one account
// (one per qualifying sign-in event) run at once. Before the fix each wrote
// the second-step markers outside the accounts lock, the identity service
// stored each marker twice, and it refused every later write of the
// account with a 400 (main run 45685353621, TC-994-41).

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/markers"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// contendedLock is the rig's one accounts lock, recording whether a caller
// ever had to wait for it.
type contendedLock struct {
	inner   *sync.Mutex
	waiting atomic.Int32
	waited  atomic.Bool
}

func (l *contendedLock) Lock() {
	if l.inner.TryLock() {
		return
	}
	l.waiting.Add(1)
	l.waited.Store(true)
	l.inner.Lock()
	l.waiting.Add(-1)
}

func (l *contendedLock) Unlock() { l.inner.Unlock() }

// raceGate, once armed with an account, holds the marker writer's first
// read of that account's credentials (BeforePrivilege's first call) until
// another caller waits for the accounts lock, or the call's context ends.
type raceGate struct {
	lock *contendedLock
	mu   sync.Mutex
	path string
	// opened is whether the hold ended because a caller waited for the lock.
	opened atomic.Bool
}

func (g *raceGate) arm(id string) {
	g.mu.Lock()
	g.path = "/admin/realms/" + baselineRealm + "/users/" + id + "/credentials"
	g.mu.Unlock()
}

func (g *raceGate) hold(ctx context.Context, method, path string) {
	g.mu.Lock()
	armed := method == http.MethodGet && path == g.path
	if armed {
		g.path = ""
	}
	g.mu.Unlock()
	for armed && ctx.Err() == nil {
		if g.lock.waiting.Load() > 0 {
			g.opened.Store(true)
			return
		}
		time.Sleep(time.Millisecond)
	}
}

// gatedAdmin is the marker writer's Admin API session, through the gate.
type gatedAdmin struct {
	inner markers.Admin
	gate  *raceGate
}

func (a gatedAdmin) Admin(ctx context.Context, method, path string, in, out any) (idclient.Response, error) {
	a.gate.hold(ctx, method, path)
	return a.inner.Admin(ctx, method, path, in, out)
}

// grantRace: a complete account designated app admin gets two grants at
// once. The first holds the accounts lock from its markers' read until the
// second waits for it, so the two overlap. Both succeed; the account ends
// app admin with each marker stored once and the designation cleared, and
// a later write of the account is accepted.
func (r *accountsRig) grantRace(t *testing.T) {
	const name = "acct-race"
	id, pw := r.user(t, name)
	r.enrol(t, id, name, pw, true)
	r.runner.Wait()
	if err := r.designations.Designate(t.Context(), accounts.Designation{Sub: id, AppRole: accounts.AppAdmin,
		Reason: accounts.ReasonPrivileged}); err != nil {
		t.Fatal(err)
	}
	r.race.arm(id)
	var ids []string
	for range 2 {
		j, err := r.runner.Submit(t.Context(), accounts.GrantKind, accounts.GrantSpec{AccountID: id}, "accounts.designation")
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, j.ID)
	}
	r.runner.Wait()
	if !r.race.opened.Load() {
		t.Error("the second grant never waited for the accounts lock while the first wrote the markers")
	}
	for _, jid := range ids {
		if j := r.job(t, jid); j.Status != jobs.StatusSucceeded {
			t.Errorf("grant %s %q", j.Status, j.Error)
		}
	}
	status, rep := r.userRep(t, id)
	if status != http.StatusOK {
		t.Fatalf("read the account: %d", status)
	}
	attrs, _ := rep["attributes"].(map[string]any)
	for _, m := range []string{flows.MarkerSecondStepHome, flows.MarkerSecondStepApp, flows.MarkerSecondStepAny} {
		if vs, _ := attrs[m].([]any); len(vs) != 1 || vs[0] != "true" {
			t.Errorf("%s holds %v, want exactly one value true", m, attrs[m])
		}
	}
	if vs, _ := attrs[accounts.AttrAppRole].([]any); len(vs) != 1 || vs[0] != string(accounts.AppAdmin) {
		t.Errorf("app access %v, want exactly admin", attrs[accounts.AttrAppRole])
	}
	if _, ok, _ := r.designations.Get(t.Context(), id); ok {
		t.Error("the designation was not cleared")
	}
	if err := r.users.SetDisplayName(t.Context(), id, "Racer"); err != nil {
		t.Errorf("a later write of the account: %v", err)
	}
}
