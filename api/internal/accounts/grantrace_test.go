package accounts

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/events"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// The grant race (geekdojo/geekdojo-brain#994): two account writes that
// read and write one account at once. The identity service is the row
// model (fakeKC.rows), under which two overlapping writes of a marker store
// it twice and every later write of the account is refused.

// raceSub is the account the race cases write.
const raceSub = "racer"

// secondSteps are the three markers a privileged grant sets.
var secondSteps = []string{flows.MarkerSecondStepHome, flows.MarkerSecondStepApp, flows.MarkerSecondStepAny}

// overlap holds the first user PUT on raceSub, after its rows are loaded,
// until another writer of the account either waits for the accounts lock
// (the writes are serialised) or loads its own rows for a PUT (the writes
// overlap, as they did before the fix). It records which came true.
type overlap struct {
	puts      atomic.Int32
	contended atomic.Bool
	second    atomic.Bool
}

func (o *overlap) observe(lock *countingLock) func(method, rel string) {
	return func(method, rel string) {
		if method != http.MethodPut || rel != "/users/"+raceSub || o.puts.Add(1) != 1 {
			return
		}
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			switch {
			case lock.waiting.Load() > 0:
				o.contended.Store(true)
				return
			case o.puts.Load() > 1:
				o.second.Store(true)
				return
			}
			time.Sleep(time.Millisecond)
		}
	}
}

// raceHarness is the change harness over the row model with raceSub
// complete (an authenticator app and codes), holding no marker and no app
// access, and designated app admin.
func raceHarness(t *testing.T) (*changeHarness, *overlap) {
	t.Helper()
	h := newChangeHarness(t)
	h.kc.add(person{sub: raceSub, name: raceSub, email: "racer@example.invalid", enabled: true, creds: completeCreds, actions: []any{}})
	h.kc.mu.Lock()
	h.kc.users[raceSub].rep["attributes"] = map[string]any{}
	h.kc.rows = true
	h.kc.mu.Unlock()
	if err := h.designations.Designate(t.Context(), Designation{Sub: raceSub, AppRole: AppAdmin, Reason: ReasonPrivileged}); err != nil {
		t.Fatal(err)
	}
	o := &overlap{}
	h.kc.mu.Lock()
	h.kc.observe = o.observe(h.lock)
	h.kc.mu.Unlock()
	return h, o
}

func (c *changeHarness) submitGrant(t *testing.T) string {
	t.Helper()
	j, err := c.runner.Submit(t.Context(), GrantKind, GrantSpec{AccountID: raceSub}, grantSubmitter)
	if err != nil {
		t.Fatal(err)
	}
	return j.ID
}

// healthy fails the test unless raceSub ended app admin with each marker
// stored once, no write was refused, and the designation is cleared.
func (c *changeHarness) healthy(t *testing.T) {
	t.Helper()
	for _, m := range secondSteps {
		if got := c.attr(raceSub, m); got != "true" {
			t.Errorf("%s holds %q, want one value true", m, got)
		}
	}
	if got := c.attr(raceSub, AttrAppRole); got != string(AppAdmin) {
		t.Errorf("app access %q, want admin", got)
	}
	c.kc.mu.Lock()
	rejected := c.kc.rejected
	c.kc.mu.Unlock()
	if rejected != 0 {
		t.Errorf("%d account writes were refused", rejected)
	}
	if _, ok := c.designation(t, raceSub); ok {
		t.Error("the designation was not cleared")
	}
}

// TestGrantRace_TwoGrants: two designated-role grants for one account, one
// per qualifying sign-in event, run at once. The second waits for the
// accounts lock while the first writes the markers, so no marker is stored
// twice, both succeed and the account ends app admin.
func TestGrantRace_TwoGrants(t *testing.T) {
	h, o := raceHarness(t)
	ids := []string{h.submitGrant(t), h.submitGrant(t)}
	h.runner.Wait()
	if !o.contended.Load() || o.second.Load() {
		t.Errorf("the second grant did not wait for the lock: contended %v, overlapping PUT %v", o.contended.Load(), o.second.Load())
	}
	for _, id := range ids {
		if r := h.result(t, id); r.job.Status != jobs.StatusSucceeded {
			t.Errorf("grant %s %q", r.job.Status, r.job.Error)
		}
	}
	h.healthy(t)
}

// TestGrantRace_GrantAndDrainWriter: the drain's marker writer handles a
// stored authenticator app while the grant runs. It takes the accounts
// lock, so neither write reads the account the other is writing: no
// marker is stored twice and the drain never writes back the app access
// it read before the grant.
func TestGrantRace_GrantAndDrainWriter(t *testing.T) {
	h, o := raceHarness(t)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.mw.UserEvent(t.Context(), events.UserEvent{Type: "UPDATE_TOTP", UserID: raceSub, CredentialType: "otp"})
	}()
	id := h.submitGrant(t)
	h.runner.Wait()
	wg.Wait()
	if !o.contended.Load() || o.second.Load() {
		t.Errorf("the writers did not take turns at the lock: contended %v, overlapping PUT %v", o.contended.Load(), o.second.Load())
	}
	if r := h.result(t, id); r.job.Status != jobs.StatusSucceeded {
		t.Errorf("grant %s %q", r.job.Status, r.job.Error)
	}
	h.healthy(t)
}

// TestGrantRace_DoubledAccountRepaired: an account the race already
// reached (each marker and its app access stored twice) is repaired by its
// next write, through Users and through the marker writer, instead of
// being refused for good. A multi-valued attribute keeps every value.
func TestGrantRace_DoubledAccountRepaired(t *testing.T) {
	doubled := func(h *changeHarness) {
		h.kc.mu.Lock()
		defer h.kc.mu.Unlock()
		h.kc.observe = nil // one writer: nothing to overlap
		attrs := map[string]any{AttrAppRole: []any{"user", "user"}, AttrNetwork: []any{"join", "gear-read"}}
		for _, m := range secondSteps {
			attrs[m] = []any{"true", "true"}
		}
		h.kc.users[raceSub].rep["attributes"] = attrs
	}
	check := func(t *testing.T, h *changeHarness, role string) {
		t.Helper()
		for _, m := range secondSteps {
			if got := h.attr(raceSub, m); got != "true" {
				t.Errorf("%s holds %q, want one value", m, got)
			}
		}
		if got := h.attr(raceSub, AttrAppRole); got != role {
			t.Errorf("app access %q, want %q", got, role)
		}
		if got := h.attr(raceSub, AttrNetwork); got != "join,gear-read" {
			t.Errorf("network %q, want both grants kept", got)
		}
	}
	t.Run("a refused write is the defect", func(t *testing.T) {
		h, _ := raceHarness(t)
		doubled(h)
		// The row model refuses the doubled values as the identity service
		// does: what Users would send without the collapse.
		h.kc.mu.Lock()
		rep := cloneAttrs(h.kc.users[raceSub].rep["attributes"])
		h.kc.mu.Unlock()
		_, err := h.kc.Admin(t.Context(), http.MethodPut, "/admin/realms/"+realm+"/users/"+raceSub, map[string]any{"attributes": rep}, nil)
		var ie *idclient.Error
		if !errors.As(err, &ie) || ie.Status != http.StatusBadRequest {
			t.Fatalf("the row model accepted doubled values: %v", err)
		}
	})
	t.Run("Users.write", func(t *testing.T) {
		h, _ := raceHarness(t)
		doubled(h)
		if err := h.users.SetAppRole(t.Context(), raceSub, AppAdmin); err != nil {
			t.Fatalf("SetAppRole on a doubled account: %v", err)
		}
		check(t, h, "admin")
		if err := h.users.SetEnabled(t.Context(), raceSub, false); err != nil {
			t.Errorf("a later write: %v", err)
		}
	})
	t.Run("the marker writer, with every marker already set", func(t *testing.T) {
		h, _ := raceHarness(t)
		doubled(h)
		if err := h.mw.BeforePrivilege(context.WithoutCancel(t.Context()), raceSub); err != nil {
			t.Fatalf("BeforePrivilege on a doubled account: %v", err)
		}
		check(t, h, "user")
		if err := h.users.SetAppRole(t.Context(), raceSub, AppAdmin); err != nil {
			t.Errorf("a later write: %v", err)
		}
	})
}
