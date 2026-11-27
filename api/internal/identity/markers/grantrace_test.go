package markers

import (
	"context"
	"slices"
	"sync"
	"testing"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/events"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
)

// The grant race (geekdojo/geekdojo-brain#994): the marker writer's own
// part. The accounts end-to-end cases (accounts.TestGrantRace_*) run it
// against the identity service's row model.

// lockLog records the lock's turns and the Admin API calls in one order.
type lockLog struct {
	mu    sync.Mutex
	inner sync.Mutex
	calls []string
}

func (l *lockLog) add(c string) { l.mu.Lock(); l.calls = append(l.calls, c); l.mu.Unlock() }
func (l *lockLog) Lock()        { l.inner.Lock(); l.add("lock") }
func (l *lockLog) Unlock()      { l.add("unlock"); l.inner.Unlock() }

type loggedAdmin struct {
	inner *fakeAdmin
	log   *lockLog
}

func (a loggedAdmin) Admin(ctx context.Context, method, path string, in, out any) (idclient.Response, error) {
	a.log.add(method)
	return a.inner.Admin(ctx, method, path, in, out)
}

// TestGrantRace_UserEventHoldsTheLock: the drain's write reads and writes
// the account under the accounts lock; BeforePrivilege and AfterRemoval,
// whose callers hold it, never take it (it is not re-entrant).
func TestGrantRace_UserEventHoldsTheLock(t *testing.T) {
	f := &fakeAdmin{user: newUser(), creds: []string{"password", "otp"}}
	l := &lockLog{}
	w, _ := newWriter(t, f)
	w.d.Admin, w.d.Lock = loggedAdmin{inner: f, log: l}, l
	w.UserEvent(t.Context(), events.UserEvent{Type: "UPDATE_TOTP", UserID: userID, CredentialType: "otp"})
	got := slices.Clone(l.calls)
	if len(got) < 4 || got[0] != "lock" || got[len(got)-1] != "unlock" || !slices.Contains(got, "PUT") ||
		slices.Contains(got[1:len(got)-1], "lock") {
		t.Errorf("UserEvent: %v, want its reads and its write between one lock and unlock", got)
	}
	l.calls = nil
	f.user = newUser()
	if err := w.BeforePrivilege(t.Context(), userID); err != nil {
		t.Fatal(err)
	}
	if err := w.AfterRemoval(t.Context(), userID); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(l.calls, "lock") {
		t.Errorf("BeforePrivilege or AfterRemoval took the lock: %v", l.calls)
	}
}

// TestGrantRace_CollapseSingleValued: an admin-only single-valued attribute
// stored twice keeps its first value; a multi-valued one, an attribute that
// is not admin-only, and one stored once are untouched.
func TestGrantRace_CollapseSingleValued(t *testing.T) {
	attrs := map[string]any{
		flows.MarkerSecondStepAny: []any{"true", "true"}, flows.AttrConfirmedEmail: []any{"a@x.invalid", "b@x.invalid"},
		"rasputin_app_role": []any{"admin", "user"}, "rasputin_network": []any{"join", "gear-read"},
		flows.MarkerSecondStepHome: []any{"true"}, "pet": []any{"cat", "dog"},
	}
	if !CollapseSingleValued(attrs) {
		t.Error("reported no change")
	}
	want := map[string][]string{
		flows.MarkerSecondStepAny: {"true"}, flows.AttrConfirmedEmail: {"a@x.invalid"}, "rasputin_app_role": {"admin"},
		"rasputin_network": {"join", "gear-read"}, flows.MarkerSecondStepHome: {"true"}, "pet": {"cat", "dog"},
	}
	for name, vs := range want {
		if got := values(attrs, name); !slices.Equal(got, vs) {
			t.Errorf("%s: %v, want %v", name, got, vs)
		}
	}
	if CollapseSingleValued(attrs) {
		t.Error("a second pass reported a change")
	}
}

// TestGrantRace_WriteRepairsDoubledMarkers: an account whose markers are
// all set but stored twice is written back with one value each, though no
// marker changed; a healthy account with them set is not written.
func TestGrantRace_WriteRepairsDoubledMarkers(t *testing.T) {
	f := &fakeAdmin{user: newUser(), creds: []string{"otp"}}
	attrs := f.user["attributes"].(map[string]any)
	for _, m := range []string{flows.MarkerSecondStepHome, flows.MarkerSecondStepApp, flows.MarkerSecondStepAny} {
		attrs[m] = []any{"true", "true"}
	}
	w, _ := newWriter(t, f)
	if err := w.BeforePrivilege(t.Context(), userID); err != nil {
		t.Fatal(err)
	}
	if len(f.puts) != 1 {
		t.Fatalf("%d writes, want one repairing write", len(f.puts))
	}
	sent := f.puts[0]["attributes"].(map[string]any)
	for _, m := range []string{flows.MarkerSecondStepHome, flows.MarkerSecondStepApp, flows.MarkerSecondStepAny} {
		if got := values(sent, m); !slices.Equal(got, []string{"true"}) {
			t.Errorf("%s sent as %v", m, got)
		}
	}
	if got := values(sent, "pet"); !slices.Equal(got, []string{"cat"}) {
		t.Errorf("another attribute sent as %v", got)
	}
	if err := w.BeforePrivilege(t.Context(), userID); err != nil || len(f.puts) != 1 {
		t.Errorf("a healthy account was written again: %v, %d writes", err, len(f.puts))
	}
}
