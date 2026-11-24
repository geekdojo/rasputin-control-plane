package identitytest

// C23 against the real identity service and the real sign-in rules
// (geekdojo/geekdojo-brain#991, Identity 4.9; TC-991-31, TS-18): a
// privileged grant ends the person's identity sessions first, so a session
// made with a password alone can't carry the new role. It runs in
// TestSignInRules_AgainstPinnedKeycloak, whose rig has the rules converged.

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/removednames"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/sessions"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// tc991privileged is TC-991-31: a household account signs in at the app
// door with its password alone, and that session resumes; it then saves
// recovery codes and an authenticator app (a designation needs both, C29).
// After Access.Grant(admin) the next app sign-in does not resume the earlier
// session: it asks for the password, then for the second step, and issues
// no code without it.
func (r *rulesRig) tc991privileged(t *testing.T) {
	log, _ := logkittest.New()
	store, err := removednames.OpenStore(t.Context(), filepath.Join(t.TempDir(), "rasputin.db"), testMAC(t), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	users, err := accounts.NewUsers(accounts.UsersDeps{Admin: r.session, Realm: baselineRealm, ConsoleClient: baselineConsole})
	if err != nil {
		t.Fatal(err)
	}
	access, err := accounts.NewAccess(accounts.AccessDeps{Users: users, Sessions: sessions.Ender{Admin: r.session},
		Facts: store.Facts(), Lock: &sync.Mutex{}})
	if err != nil {
		t.Fatal(err)
	}

	a := r.account(t, "tc991-31-household", map[string][]string{"rasputin_app_role": {"user"}})
	g := r.fresh(t)
	g.signIn(r.appClient(rulesAppClients), a.name, a.pw).code(t)
	if identityOf(g.jar, r.sites.Table.App.Host) == "" {
		t.Fatal("the password sign-in left no app-door session")
	}
	resumed := g.follow(r.appClient(rulesAppClients))
	resumed.code(t) // the precondition: the session resumes with no page

	r.enrol(t, a, true, true)
	if err := access.Grant(t.Context(), a.id, accounts.AppAdmin); err != nil {
		t.Fatal(err)
	}
	r.settle(t)

	page := g.follow(r.appClient(rulesAppClients))
	if page.loc != nil && page.loc.Query().Get("code") != "" {
		t.Fatal("after the grant the earlier password-only session resumed with a code")
	}
	if page.pageID() != "login-login" {
		t.Fatalf("after the grant the app door showed %q, want the sign-in page", page.pageID())
	}
	step := r.post(t, g, page, "kc-form-login", map[string]string{"username": a.name, "password": string(a.pw.Reveal())})
	if step.loc != nil && step.loc.Query().Get("code") != "" {
		t.Fatal("the password alone got a code after the grant")
	}
	if !isSecondStep(step.pageID()) {
		t.Errorf("the password led to %q, want a second step", step.pageID())
	}
}
