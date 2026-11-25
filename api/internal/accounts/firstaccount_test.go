package accounts

import (
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/removednames"
)

// harnessUsers is a fake Admin API and Users over it, with no runner.
func harnessUsers(t *testing.T) (*fakeKC, *Users) {
	t.Helper()
	kc := &fakeKC{users: map[string]*kcUser{}, log: &callLog{}}
	u, err := NewUsers(UsersDeps{Admin: kc, Realm: realm, ConsoleClient: consoleClient})
	if err != nil {
		t.Fatal(err)
	}
	return kc, u
}

// usersList is the users listings the fake was asked for.
func (k *fakeKC) usersList() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []string
	for _, g := range k.gets {
		if strings.HasPrefix(g, "/users?") {
			out = append(out, g)
		}
	}
	return out
}

// TC-990-10: the lowest createdTimestamp wins, a tie goes to the lower id,
// zero persons is an error, a full page is an error, and the listing
// carries first, max and briefRepresentation and no filter parameter.
func TestFirstAccount_TC990_10(t *testing.T) {
	kc, users := harnessUsers(t)
	first, err := NewFirstAccount(users)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Earliest(t.Context()); err == nil {
		t.Error("a realm with no person named one")
	}
	kc.add(person{sub: "c-later", name: "c", email: "c@x.invalid", enabled: true, created: 300})
	kc.add(person{sub: "b-tie", name: "b", email: "b@x.invalid", enabled: true, created: 100})
	kc.add(person{sub: "a-tie", name: "a", email: "a@x.invalid", enabled: false, created: 100})
	got, err := first.Earliest(t.Context())
	if err != nil || got != "a-tie" {
		t.Errorf("Earliest = %q, %v; want the lower id of the tie", got, err)
	}
	for _, q := range kc.usersList() {
		v, err := url.ParseQuery(strings.TrimPrefix(q, "/users?"))
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"first", "max", "briefRepresentation"} {
			if !v.Has(k) {
				t.Errorf("the listing %q carries no %s", q, k)
			}
		}
		for _, k := range []string{"enabled", "q", "email", "username", "exact", "search"} {
			if v.Has(k) {
				t.Errorf("the listing %q filters on %s", q, k)
			}
		}
	}
	for i := range peoplePage {
		kc.add(person{sub: "filler-" + strconv.Itoa(i), name: "f", email: "f@x.invalid", created: 500})
	}
	if _, err := first.Earliest(t.Context()); err == nil {
		t.Error("a full page named a person")
	}
	if _, err := NewFirstAccount(nil); err == nil {
		t.Error("NewFirstAccount(nil) succeeded")
	}
}

// People refuses an account with no id.
func TestPeople_TC990_10_NoID(t *testing.T) {
	kc, users := harnessUsers(t)
	kc.add(person{sub: "a", name: "a", email: "a@x.invalid", enabled: true})
	kc.noID = true
	if _, err := users.People(t.Context()); err == nil {
		t.Error("an account with no id was listed")
	}
}

// TC-990-12: who waits. A disabled person, a holder of each console role,
// an app-access holder and a designated person don't; 19 waiting is not
// full and 20 is; any read error is an error.
func TestWaiting_TC990_12(t *testing.T) {
	kc, users := harnessUsers(t)
	des, _ := openDesignations(t)
	w, err := NewWaiting(users, des)
	if err != nil {
		t.Fatal(err)
	}
	kc.add(person{sub: "disabled", name: "d", email: "d@x.invalid", enabled: false})
	kc.add(person{sub: "admin", name: "ad", email: "ad@x.invalid", enabled: true, directAdmin: true})
	kc.add(person{sub: "operator", name: "op", email: "op@x.invalid", enabled: true, roles: []string{"operator"}})
	kc.add(person{sub: "viewer", name: "vi", email: "vi@x.invalid", enabled: true, roles: []string{"viewer"}})
	kc.add(person{sub: "app", name: "ap", email: "ap@x.invalid", enabled: true, appRole: "user"})
	kc.add(person{sub: "designated", name: "de", email: "de@x.invalid", enabled: true})
	if err := des.Designate(t.Context(), Designation{Sub: "designated", ConsoleRole: "admin", Reason: ReasonPrivileged}); err != nil {
		t.Fatal(err)
	}
	if n, err := w.Count(t.Context()); n != 0 || err != nil {
		t.Errorf("Count = %d, %v; want none waiting", n, err)
	}
	for i := range 19 {
		kc.add(person{sub: "wait-" + strconv.Itoa(i), name: "w", email: "w" + strconv.Itoa(i) + "@x.invalid", enabled: true})
	}
	if full, err := w.Full(t.Context()); full || err != nil {
		t.Errorf("19 waiting: Full = %v, %v", full, err)
	}
	kc.add(person{sub: "wait-19", name: "w", email: "w19@x.invalid", enabled: true})
	if n, _ := w.Count(t.Context()); n != WaitingCap {
		t.Errorf("Count = %d, want %d", n, WaitingCap)
	}
	if full, err := w.Full(t.Context()); !full || err != nil {
		t.Errorf("20 waiting: Full = %v, %v", full, err)
	}
	for _, path := range []string{"/users", "/clients/" + consoleUUID + "/roles/viewer/users"} {
		kc.fail = func(_, p string) error {
			if strings.HasPrefix(p, path) {
				return errors.New("down")
			}
			return nil
		}
		if _, err := w.Full(t.Context()); err == nil {
			t.Errorf("a failed %s read was not an error", path)
		}
	}
	kc.fail = nil
	if _, err := des.db.Exec(`DROP TABLE designations`); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Full(t.Context()); err == nil {
		t.Error("an unreadable designations table was not an error")
	}
	if _, err := NewWaiting(nil, des); err == nil {
		t.Error("NewWaiting(nil) succeeded")
	}
}

// TC-990-12 (R77's empty row): no persons and an empty designation list
// is a count of 0, not full.
func TestWaiting_TC990_12_Empty(t *testing.T) {
	_, users := harnessUsers(t)
	des, _ := openDesignations(t)
	w, _ := NewWaiting(users, des)
	if n, err := w.Count(t.Context()); n != 0 || err != nil {
		t.Errorf("Count = %d, %v", n, err)
	}
	if full, err := w.Full(t.Context()); full || err != nil {
		t.Errorf("Full = %v, %v", full, err)
	}
}

// TC-990-34: the email is normalized the one way (removednames.Normal) and
// compared over the People listing; no request carries it (F-990-09). An
// empty result is false, one hit is true whatever the case or padding, and
// an Admin API error is an error.
func TestEmailInUse_TC990_34(t *testing.T) {
	kc, users := harnessUsers(t)
	in, err := users.EmailInUse(t.Context(), " A+b@X.org ")
	if err != nil || in {
		t.Errorf("no account: %v %v", in, err)
	}
	got := kc.usersList()
	if len(got) != 1 || !strings.HasPrefix(got[0], "/users?briefRepresentation=false&first=0&max=") {
		t.Errorf("the lookup %v, want the People listing", got)
	}
	for _, g := range got {
		if strings.Contains(strings.ToLower(g), "x.org") || strings.Contains(g, "email") {
			t.Errorf("a request carries the email: %s", g)
		}
	}
	if removednames.Normal(" A+b@X.org ") != "a+b@x.org" {
		t.Error("removednames.Normal is not the form compared")
	}
	kc.add(person{sub: "a", name: "a", email: "A+b@x.org", enabled: true})
	if in, err := users.EmailInUse(t.Context(), "a+B@x.org "); err != nil || !in {
		t.Errorf("an account holds it: %v %v", in, err)
	}
	if in, err := users.EmailInUse(t.Context(), "b@x.org"); err != nil || in {
		t.Errorf("another address: %v %v", in, err)
	}
	if in, err := users.EmailInUse(t.Context(), "  "); err != nil || in {
		t.Errorf("an empty email: %v %v", in, err)
	}
	kc.fail = func(string, string) error { return errors.New("down") }
	if _, err := users.EmailInUse(t.Context(), "a+b@x.org"); err == nil {
		t.Error("an Admin API error was not an error")
	}
}

// TC-990-35: the designation facts. otp, webauthn and
// webauthn-passwordless are a second step; recovery-authn-codes is
// recovery codes; a pending required action is pending; a credential read
// error is an error.
func TestFacts_TC990_35(t *testing.T) {
	kc, users := harnessUsers(t)
	ra, _ := NewRoleAccounts(users)
	for _, c := range []struct {
		creds   []string
		actions []any
		second  bool
		codes   bool
		pending bool
	}{
		{[]string{"password"}, []any{}, false, false, false},
		{[]string{"password", "otp"}, []any{}, true, false, false},
		{[]string{"webauthn"}, []any{}, true, false, false},
		{[]string{"webauthn-passwordless", "recovery-authn-codes"}, []any{}, true, true, false},
		{[]string{"recovery-authn-codes"}, []any{"CONFIGURE_TOTP"}, false, true, true},
	} {
		kc.users = map[string]*kcUser{}
		kc.add(person{sub: "s", name: "n", email: "e@x.invalid", enabled: true, creds: c.creds, actions: c.actions})
		f, err := ra.Facts(t.Context(), "s")
		if err != nil {
			t.Fatal(err)
		}
		if f.HoldsSecondStep != c.second || f.HoldsRecoveryCodes != c.codes || f.RequiredActionPending != c.pending || f.Username != "n" {
			t.Errorf("%v %v: facts %+v", c.creds, c.actions, f)
		}
	}
	kc.fail = func(_, p string) error {
		if strings.HasSuffix(p, "/credentials") {
			return errors.New("down")
		}
		return nil
	}
	if _, err := ra.Facts(t.Context(), "s"); err == nil {
		t.Error("a credential read error was not an error")
	}
}

// AddConsoleRole gives a known console role only, by its representation.
func TestAddConsoleRole(t *testing.T) {
	kc, users := harnessUsers(t)
	kc.add(person{sub: "s", name: "n", email: "e@x.invalid", enabled: true})
	if err := users.AddConsoleRole(t.Context(), "s", "owner"); err == nil {
		t.Error("an unknown role was given")
	}
	if err := users.AddConsoleRole(t.Context(), "", "admin"); err == nil {
		t.Error("no account was accepted")
	}
	if err := users.AddConsoleRole(t.Context(), "s", "admin"); err != nil {
		t.Fatal(err)
	}
	if got := kc.log.all(); !slices.Equal(got, []string{"add-console:admin"}) {
		t.Errorf("calls %v", got)
	}
	if _, err := users.Credentials(t.Context(), ""); err == nil {
		t.Error("Credentials with no account succeeded")
	}
}
