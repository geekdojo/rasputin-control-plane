package identitytest

// identity.revoke against the real identity service
// (geekdojo/geekdojo-brain#991, Identity 4.9; TC-991-25 to TC-991-30, TS-23):
// the console rig (the repo's realm baseline in the pinned Keycloak in door
// mode, both doors, the console's sign-in and its back-channel route, which
// is the loopback relying party here) with the accounts as main wires them:
// sessions.Ender, Users, RoleAccounts and the real authz.RoleGuard over the
// rig's Admin API session, the removed-name list and the moved rows in the
// rig's rasputin.db, and the job on the real jobs.Runner.
//
// The console signs a person out once when offline_access is added or
// removed (RoleChangeSink on the realm role-mapping event): that is expected
// (F-991-07), and no case here counts it as a fault.
//
// It starts an Env of its own, closed with proof in its cleanup. It skips
// without RASPUTIN_IDENTITY_HOME or RASPUTIN_IDENTITY_THEME and fails instead
// under RASPUTIN_IDENTITY_FUNCTIONAL=required, as CI's backend job sets it.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/credmac"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/removednames"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/sessions"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
)

// noRemovedNames is a removed-name list holding no name, for the door rigs
// whose cases are not about it.
type noRemovedNames struct{}

func (noRemovedNames) Removed(context.Context, string, string) (bool, error) { return false, nil }

// testMAC is a fingerprint key over fixed test bytes.
func testMAC(t *testing.T) *credmac.Key {
	t.Helper()
	k, err := credmac.New(secret.New(bytes.Repeat([]byte{0x5a}, credmac.MinKeyLen)))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// revokeSteps are identity.revoke's steps, in order.
var revokeSteps = []string{accounts.StepAuthorize, accounts.StepOnlineSessions, accounts.StepOfflineSessions,
	accounts.StepChange, accounts.StepConsoleSessions, accounts.StepMovedRows, accounts.StepDevices,
	accounts.StepApps, accounts.StepNetwork}

type revokeRig struct {
	*consoleRig
	rev     *accounts.Revoker
	access  *accounts.Access
	runner  *jobs.Runner
	ledger  *jobs.Store
	removed *removednames.Store
	moved   *auth.Store
	revRec  *logkittest.Recorder
	// adminID is an enabled administrator's account id: the actor of every
	// disable and delete an endpoint would have submitted.
	adminID string
	ipMu    sync.Mutex
	ip      byte
}

func newRevokeRig(t *testing.T, env *Env) *revokeRig {
	t.Helper()
	r := &revokeRig{consoleRig: newConsoleRig(t, env)}
	ctx := t.Context()
	var err error
	if r.moved, err = auth.OpenStore(ctx, r.dbPath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.moved.Close() })
	log, rec := logkittest.New()
	r.revRec = rec
	if r.removed, err = removednames.OpenStore(ctx, r.dbPath, testMAC(t), log); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.removed.Close() })
	users, err := accounts.NewUsers(accounts.UsersDeps{Admin: r.session, Realm: baselineRealm, ConsoleClient: baselineConsole})
	if err != nil {
		t.Fatal(err)
	}
	ra, err := accounts.NewRoleAccounts(users)
	if err != nil {
		t.Fatal(err)
	}
	lock := &sync.Mutex{}
	guard, err := authz.NewRoleGuard(ra, lock)
	if err != nil {
		t.Fatal(err)
	}
	ender := sessions.Ender{Admin: r.session}
	if r.rev, err = accounts.NewRevoker(accounts.RevokerDeps{
		Sessions: ender, Users: users, Guard: guard, Lock: lock, Console: r.sessions, Moved: r.moved,
		Removed: r.removed, Facts: r.removed.Facts(),
		Devices: accounts.NoHook{What: "devices"}, Apps: accounts.NoHook{What: "apps"}, Network: accounts.NoHook{What: "network"},
		Log: log, StepTimeout: 2 * time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	if r.access, err = accounts.NewAccess(accounts.AccessDeps{Users: users, Sessions: ender, Facts: r.removed.Facts(), Lock: lock}); err != nil {
		t.Fatal(err)
	}
	if r.ledger, err = jobs.OpenStore(ctx, r.dbPath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.ledger.Close() })
	srv := natsserver.RunRandClientPortServer()
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	r.runner = jobs.NewRunner(r.ledger, nc)
	r.runner.Register(r.rev.Workflow())

	// The test app may ask for an offline session.
	api := r.admin(t)
	_, out := api.must(http.StatusOK, http.MethodGet, "/client-scopes", nil)
	var scopes []struct{ ID, Name string }
	if err := json.Unmarshal(out, &scopes); err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(scopes, func(s struct{ ID, Name string }) bool { return s.Name == "offline_access" })
	if i < 0 {
		t.Fatal("the realm has no offline_access client scope")
	}
	app, _ := api.clientRep(doorTestApp)
	api.must(http.StatusNoContent, http.MethodPut, "/clients/"+app+"/optional-client-scopes/"+scopes[i].ID, nil)
	r.adminID, _ = r.fixture(t, "revoke-admin", "admin")
	return r
}

// fresh is a Go door client from a loopback address of its own.
func (r *revokeRig) fresh(t *testing.T) *goClient {
	t.Helper()
	r.ipMu.Lock()
	r.ip++
	n := r.ip
	r.ipMu.Unlock()
	return r.client(t, netip.AddrFrom4([4]byte{127, 0, 9, n}).String())
}

// appTokens signs name in at the app door for the test app, with
// offline_access when offline, and returns the refresh token and the client
// that holds the session.
func (r *revokeRig) appTokens(t *testing.T, name string, pw secret.Value, offline bool) (string, *goClient) {
	t.Helper()
	scope := "openid"
	if offline {
		scope = "openid offline_access"
	}
	g := r.fresh(t)
	r.settle(t)
	a := g.signIn(r.appAuth(doorTestApp, map[string]string{"scope": scope}), name, pw)
	tok := g.exchange(t, r.appURL("/realms/rasputin/protocol/openid-connect/token"), url.Values{
		"code": {a.code(t)}, "client_id": {doorTestApp}, "redirect_uri": {callbackOn(AppSiteHost)}}, nil)
	if tok.RefreshToken == "" {
		t.Fatal("the exchange returned no refresh token")
	}
	return tok.RefreshToken, g
}

// refresh is a refresh at the app door's token endpoint: its status.
func (r *revokeRig) refresh(t *testing.T, g *goClient, rt string) int {
	t.Helper()
	return g.send(http.MethodPost, r.appURL("/realms/rasputin/protocol/openid-connect/token"), url.Values{
		"grant_type": {"refresh_token"}, "client_id": {doorTestApp}, "refresh_token": {rt}}, nil).status
}

// revoke runs one identity.revoke and returns its job and steps.
func (r *revokeRig) revoke(t *testing.T, sub string, kind accounts.RevokeKind, by string) (*jobs.Job, []*jobs.JobStep) {
	t.Helper()
	j, err := r.runner.Submit(t.Context(), accounts.Kind, accounts.Spec{AccountID: sub, Kind: kind}, by)
	if err != nil {
		t.Fatal(err)
	}
	r.runner.Wait()
	job, err := r.ledger.GetJob(t.Context(), j.ID)
	if err != nil {
		t.Fatal(err)
	}
	steps, err := r.ledger.ListSteps(t.Context(), j.ID)
	if err != nil {
		t.Fatal(err)
	}
	return job, steps
}

// revokeOK runs one identity.revoke and fails the test unless it
// succeeded with every step, in order.
func (r *revokeRig) revokeOK(t *testing.T, sub string, kind accounts.RevokeKind, by string) {
	t.Helper()
	job, steps := r.revoke(t, sub, kind, by)
	if job.Status != jobs.StatusSucceeded {
		t.Fatalf("job %s: %s", job.Status, job.Error)
	}
	var names []string
	for _, s := range steps {
		names = append(names, s.Name)
		if s.Status != jobs.StepSucceeded {
			t.Errorf("step %s: %s", s.Name, s.Status)
		}
	}
	if !slices.Equal(names, revokeSteps) {
		t.Errorf("the steps ran %v, want %v", names, revokeSteps)
	}
}

// userRep is the account's representation and the Admin API's status.
func (r *revokeRig) userRep(t *testing.T, id string) (int, map[string]any) {
	t.Helper()
	status, _, out := r.admin(t).do(http.MethodGet, "/users/"+id, nil)
	var rep map[string]any
	_ = json.Unmarshal(out, &rep)
	return status, rep
}

// logoutSubs are the subjects of the logout tokens the console's
// back-channel route received from index from on.
func (r *revokeRig) logoutSubs(t *testing.T, from int) []string {
	t.Helper()
	r.mu.Lock()
	toks := slices.Clone(r.logoutTokens[from:])
	r.mu.Unlock()
	var subs []string
	for _, tok := range toks {
		parts := strings.Split(tok, ".")
		if len(parts) != 3 {
			t.Fatalf("a logout token is not a JWT")
		}
		b, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		var c struct {
			Sub    string         `json:"sub"`
			Events map[string]any `json:"events"`
		}
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatal(err)
		}
		if c.Events["http://schemas.openid.net/event/backchannel-logout"] == nil {
			t.Errorf("a logout token lacks the back-channel event")
		}
		subs = append(subs, c.Sub)
	}
	return subs
}

func (r *revokeRig) logoutCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.logoutTokens)
}

func TestRevoke_AgainstPinnedKeycloak(t *testing.T) {
	p := NewPackage(func() (Config, error) {
		c, err := ConfigFromEnv()
		c.DoorMode = true
		return c, err
	})
	if !p.RequireTheme(t) {
		return
	}
	env := p.Env(t)
	if env == nil {
		return
	}
	t.Cleanup(func() {
		if err := env.Close(context.Background()); err != nil {
			t.Errorf("identitytest: teardown proof failed: %v", err)
		}
	})
	importBaseline(t, env)
	r := newRevokeRig(t, env)
	t.Run("TC-991-25 TS-23 C10 both directions", func(t *testing.T) { r.tc25(t) })
	t.Run("TC-991-26 TS-23 sign out everywhere", func(t *testing.T) { r.tcEverywhere(t, "revoke-signout", accounts.SignOut) })
	t.Run("TC-991-27 TS-23 disable", func(t *testing.T) { r.tcEverywhere(t, "revoke-disable", accounts.Disable) })
	t.Run("TC-991-28 TS-23 delete, the list and the release", func(t *testing.T) { r.tc28(t) })
	t.Run("TC-991-29 a subsystem can't disable anyone", func(t *testing.T) { r.tc29(t) })
	t.Run("TC-991-30 TS-23 C15 a moved person's old rows", func(t *testing.T) { r.tc30(t) })
}

// TC-991-25: an account given access with Access.Grant(user) holds an
// offline session whose refresh works; after remove_access it holds neither
// offline_access nor rasputin_app_role, and the refresh is refused.
func (r *revokeRig) tc25(t *testing.T) {
	const name = "revoke-c10"
	id, pw := r.fixture(t, name, "viewer")
	if err := r.access.Grant(t.Context(), id, accounts.AppUser); err != nil {
		t.Fatal(err)
	}
	r.settle(t)
	rt, g := r.appTokens(t, name, pw, true)
	if got := r.refresh(t, g, rt); got != http.StatusOK {
		t.Fatalf("the offline refresh before: %d", got)
	}
	r.revokeOK(t, id, accounts.RemoveAccess, r.adminID)
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "/users/"+id+"/role-mappings/realm", nil)
	if bytes.Contains(out, []byte(`"offline_access"`)) {
		t.Error("the account still holds offline_access")
	}
	if _, rep := r.userRep(t, id); strings.Contains(fmt.Sprint(rep["attributes"]), accounts.AttrAppRole) {
		t.Errorf("the account still carries %s", accounts.AttrAppRole)
	}
	if got := r.refresh(t, g, rt); got == http.StatusOK {
		t.Error("the offline refresh after remove_access succeeded")
	}
}

// TC-991-26 and TC-991-27: an account signed in to the console (whose
// back-channel route is the loopback relying party) and holding an online
// and an offline refresh token; sign_out, or disable by an administrator,
// makes the identity service post a logout token for the account, refuses
// both refreshes, and runs the steps in order. Disabling sends no logout
// token of its own; the job's logout does. A disabled account reads
// enabled=false.
func (r *revokeRig) tcEverywhere(t *testing.T, name string, kind accounts.RevokeKind) {
	id, pw := r.fixture(t, name, "viewer")
	if err := r.access.Grant(t.Context(), id, accounts.AppUser); err != nil {
		t.Fatal(err)
	}
	r.settle(t)
	console := r.signInGo(t, "127.0.8."+map[accounts.RevokeKind]string{accounts.SignOut: "1", accounts.Disable: "2"}[kind], name, pw)
	online, g := r.appTokens(t, name, pw, false)
	offline, _ := r.appTokens(t, name, pw, true)
	for what, rt := range map[string]string{"online": online, "offline": offline} {
		if got := r.refresh(t, g, rt); got != http.StatusOK {
			t.Fatalf("the %s refresh before: %d", what, got)
		}
	}
	before := r.logoutCount()
	r.revokeOK(t, id, kind, r.adminID)
	if subs := r.logoutSubs(t, before); !slices.Contains(subs, id) {
		t.Errorf("logout tokens for %v, want one for the account", subs)
	}
	for what, rt := range map[string]string{"online": online, "offline": offline} {
		if got := r.refresh(t, g, rt); got == http.StatusOK {
			t.Errorf("the %s refresh after %s succeeded", what, kind)
		}
	}
	if got := gated(t, console); got != http.StatusUnauthorized {
		t.Errorf("the console session after %s: %d, want 401", kind, got)
	}
	if kind == accounts.Disable {
		if _, rep := r.userRep(t, id); rep["enabled"] != false {
			t.Errorf("enabled = %v after disable", rep["enabled"])
		}
	}
}

// TC-991-28: deleting a held-access account posts its logout token, the
// account reads 404, and its name and email are on the list; deleting a
// never-accessed account leaves both free, and the Admin API creates an
// account with them again.
func (r *revokeRig) tc28(t *testing.T) {
	const held, never = "revoke-held", "revoke-never"
	id, pw := r.fixture(t, held, "viewer")
	if err := r.access.Grant(t.Context(), id, accounts.AppUser); err != nil {
		t.Fatal(err)
	}
	r.settle(t)
	r.signInGo(t, "127.0.8.3", held, pw)
	before := r.logoutCount()
	r.revokeOK(t, id, accounts.Delete, r.adminID)
	if subs := r.logoutSubs(t, before); !slices.Contains(subs, id) {
		t.Errorf("logout tokens for %v, want one for the account", subs)
	}
	if status, _ := r.userRep(t, id); status != http.StatusNotFound {
		t.Errorf("the deleted account reads %d", status)
	}
	if got, err := r.removed.Removed(t.Context(), held, held+"@door.invalid"); err != nil || !got {
		t.Errorf("Removed(the held account) = %v, %v", got, err)
	}

	nid, _ := r.fixture(t, never, "viewer")
	r.revokeOK(t, nid, accounts.Delete, r.adminID)
	for _, c := range [][2]string{{never, ""}, {"", never + "@door.invalid"}} {
		if got, err := r.removed.Removed(t.Context(), c[0], c[1]); err != nil || got {
			t.Errorf("Removed(%q, %q) = %v, %v", c[0], c[1], got, err)
		}
	}
	r.admin(t).must(http.StatusCreated, http.MethodPost, "/users", map[string]any{
		"username": never, "enabled": true, "email": never + "@door.invalid", "emailVerified": true, "firstName": "Door", "lastName": "User",
	})
}

// TC-991-29: a disable whose createdBy is a subsystem fails with
// not_permitted; the account stays enabled and its refresh still works.
func (r *revokeRig) tc29(t *testing.T) {
	const name = "revoke-subsystem"
	id, pw := r.fixture(t, name, "viewer")
	if err := r.access.Grant(t.Context(), id, accounts.AppUser); err != nil {
		t.Fatal(err)
	}
	r.settle(t)
	rt, g := r.appTokens(t, name, pw, false)
	job, _ := r.revoke(t, id, accounts.Disable, "scheduler")
	if job.Status != jobs.StatusFailed || job.Error != "Only an administrator can change roles." {
		t.Errorf("job %s %q", job.Status, job.Error)
	}
	code := ""
	for _, rec := range r.revRec.Records() {
		if c, ok := logkittest.Attr(rec, "code"); ok {
			code = c
		}
	}
	if code != "not_permitted" {
		t.Errorf("the refusal's code %q", code)
	}
	if _, rep := r.userRep(t, id); rep["enabled"] != true {
		t.Errorf("enabled = %v", rep["enabled"])
	}
	if got := r.refresh(t, g, rt); got != http.StatusOK {
		t.Errorf("the refresh after the refusal: %d", got)
	}
}

// movedRows is the handle's users row rendered, and its credentials and
// sessions counts.
func (r *revokeRig) movedRows(t *testing.T, handle []byte) (string, int, int) {
	t.Helper()
	db := r.db(t)
	defer func() { _ = db.Close() }()
	var id, name, display []byte
	var created int64
	var last sql.NullInt64
	if err := db.QueryRowContext(t.Context(), `SELECT id, name, display_name, created_at, last_login_at FROM users WHERE id = ?`, handle).
		Scan(&id, &name, &display, &created, &last); err != nil {
		t.Fatal(err)
	}
	var creds, sess int
	_ = db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM credentials WHERE user_id = ?`, handle).Scan(&creds)
	_ = db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sessions WHERE user_id = ?`, handle).Scan(&sess)
	return fmt.Sprintf("%x|%x|%x|%d|%v", id, name, display, created, last), creds, sess
}

// TC-991-30: a moved account, imported by partialImport under
// MovedAccountID(handle) over a fixture's pre-update rows: disable, and
// separately delete, remove that handle's credentials and sessions rows and
// leave its users row byte-equal.
func (r *revokeRig) tc30(t *testing.T) {
	for i, kind := range []accounts.RevokeKind{accounts.Disable, accounts.Delete} {
		handle := bytes.Repeat([]byte{byte(0x30 + i)}, 16)
		name := fmt.Sprintf("revoke-moved-%d", i)
		id := auth.MovedAccountID(handle)
		now := time.Now()
		if err := r.moved.CreateUser(t.Context(), &auth.User{ID: handle, Name: name, DisplayName: "Moved", CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
		if err := r.moved.CreateCredential(t.Context(), &auth.Credential{ID: append([]byte("cred-"), handle...), UserID: handle,
			PublicKey: []byte{1}, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
		if err := r.moved.CreateSession(t.Context(), &auth.Session{Token: "moved-" + name, UserID: handle, CreatedAt: now,
			ExpiresAt: now.Add(time.Hour), LastActiveAt: now}); err != nil {
			t.Fatal(err)
		}
		r.admin(t).must(http.StatusOK, http.MethodPost, "/partialImport", map[string]any{
			"ifResourceExists": "SKIP",
			"users": []map[string]any{{"id": id, "username": name, "enabled": true, "email": name + "@door.invalid",
				"emailVerified": true, "firstName": "Moved", "lastName": "User"}},
		})
		users, creds, sess := r.movedRows(t, handle)
		if creds != 1 || sess != 1 {
			t.Fatalf("the fixture holds %d credentials and %d sessions", creds, sess)
		}
		r.revokeOK(t, id, kind, r.adminID)
		after, creds, sess := r.movedRows(t, handle)
		if creds != 0 || sess != 0 {
			t.Errorf("%s: %d credentials and %d sessions left", kind, creds, sess)
		}
		if after != users {
			t.Errorf("%s: the users row changed:\n%s\n%s", kind, users, after)
		}
	}
}
