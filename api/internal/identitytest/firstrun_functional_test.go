package identitytest

// First run, open sign-up and the first administrator against the real
// identity service (geekdojo/geekdojo-brain#990, Identity 4.8; TC-990-01,
// -03, -04, -05, -11, -13, -19, -20, -24 and -29): the console rig's home
// door and console sign-in, with the claim's real collaborators (the auth
// store's first-run predicate, accounts.FirstAccount, accounts.Observer and
// accounts.grant_designated_role on the real job runner) and registration's
// real waiting count, in-use email check and removed-name list. CI connects
// from loopback, so the network facts are injected at the policy's Network
// interface: loopback 127.0.0.0/24 is the home network, unless a case names
// the peer as a node or tailnet address. The real NetworkSource is the unit
// tests' and the bench's (TC-990-15, TC-990-30).
//
// It starts an Env of its own, closed with proof in its cleanup. It skips
// without RASPUTIN_IDENTITY_HOME or RASPUTIN_IDENTITY_THEME and fails instead
// under RASPUTIN_IDENTITY_FUNCTIONAL=required, as CI's backend job sets it.

import (
	"context"
	"encoding/json"
	"html"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door/policy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/markers"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/removednames"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/sessions"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The sentences a sign-up meets.
const (
	firstRunSourceSentence = "Create your account from a device on your home network."
	firstRunFullSentence   = "Too many people are waiting for access. Ask an administrator."
	firstRunEmailSentence  = "Use a different email, or ask an administrator."
)

// switchNetwork is registration's network facts, replaceable per case.
type switchNetwork struct {
	mu sync.Mutex
	f  policy.NetworkFacts
}

func (n *switchNetwork) set(f policy.NetworkFacts) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.f = f
}

func (n *switchNetwork) Facts(context.Context) (policy.NetworkFacts, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.f, nil
}

// homeFacts is loopback as the home network, with the door rig's tailnet.
func homeFacts() policy.NetworkFacts {
	return policy.NetworkFacts{HomeSubnets: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/24")}, Tailnet: []netip.Prefix{doorTailnet}}
}

// firstRunRig is the console rig with the claim and registration wired as
// main wires them.
type firstRunRig struct {
	*consoleRig
	store   *auth.Store
	users   *accounts.Users
	waiting *accounts.Waiting
	removed *removednames.Store
	runner  *jobs.Runner
	ledger  *jobs.Store
	net     *switchNetwork
	otp     *totpCodes
	ip      atomic.Uint32
	rec     *logkittest.Recorder
}

func newFirstRunRig(t *testing.T, env *Env) *firstRunRig {
	t.Helper()
	r := &firstRunRig{consoleRig: newConsoleRig(t, env), net: &switchNetwork{f: homeFacts()}, otp: &totpCodes{used: map[string]bool{}}}
	r.ip.Store(1)
	ctx := t.Context()
	var err error
	if r.store, err = auth.OpenStore(ctx, r.dbPath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.store.Close() })
	log, rec := logkittest.New()
	r.rec = rec
	if r.removed, err = removednames.OpenStore(ctx, r.dbPath, testMAC(t), log); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.removed.Close() })
	if r.users, err = accounts.NewUsers(accounts.UsersDeps{Admin: r.session, Realm: baselineRealm, ConsoleClient: baselineConsole}); err != nil {
		t.Fatal(err)
	}
	ra, err := accounts.NewRoleAccounts(r.users)
	if err != nil {
		t.Fatal(err)
	}
	first, err := accounts.NewFirstAccount(r.users)
	if err != nil {
		t.Fatal(err)
	}
	if r.waiting, err = accounts.NewWaiting(r.users, r.designations); err != nil {
		t.Fatal(err)
	}
	lock := &sync.Mutex{}
	ender := sessions.Ender{Admin: r.session}
	access, err := accounts.NewAccess(accounts.AccessDeps{Users: r.users, Sessions: ender, Facts: r.removed.Facts(), Lock: lock})
	if err != nil {
		t.Fatal(err)
	}
	table := r.sites.Table
	mw, err := markers.New(markers.Deps{Admin: r.session, Realm: baselineRealm, Log: log, DoorOf: func(c string) (flows.Door, bool) {
		switch {
		case slices.Contains(table.Home.Clients, c):
			return flows.DoorHome, true
		case slices.Contains(table.App.Clients, c):
			return flows.DoorApp, true
		}
		return "", false
	}})
	if err != nil {
		t.Fatal(err)
	}
	granter, err := accounts.NewGranter(accounts.GranterDeps{Designations: r.designations, Facts: ra, Markers: mw, Sessions: ender,
		Roles: r.users, Access: access, Console: r.sessions, Lock: lock, Log: log, StepTimeout: 2 * time.Minute})
	if err != nil {
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
	r.runner.Register(granter.Workflow())
	observer, err := accounts.NewObserver(accounts.ObserverDeps{Designations: r.designations, Facts: ra, Runner: r.runner, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	r.claim.set(r.store.FirstRun, first, observer)
	r.reg.mu.Lock()
	r.reg.network, r.reg.waiting, r.reg.emails, r.reg.removed = r.net, r.waiting, r.users, r.removed
	r.reg.mu.Unlock()
	r.converge(t)
	return r
}

// converge runs converge on the rig's inputs, first run included.
func (r *firstRunRig) converge(t *testing.T) {
	t.Helper()
	if _, err := r.conv.Run(t.Context()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	r.settle(t)
}

// next is a Go client from a fresh loopback address on the home network
// (127.0.0.2 to 127.0.0.63, below the door rig's tailnet range).
func (r *firstRunRig) next(t *testing.T) (*goClient, string) {
	t.Helper()
	n := r.ip.Add(1)
	if n > 63 {
		t.Fatal("the rig ran out of home-network loopback addresses")
	}
	ip := "127.0.0." + strconv.Itoa(int(n))
	return r.client(t, ip), ip
}

// signupURL is the console's CREATE ACCOUNT link.
func signupURL() string { return "https://" + ConsoleHost + "/api/auth/signup" }

// person is a sign-up's account.
type person struct {
	name, email string
	pw          secret.Value
	g           *goClient
}

func (r *firstRunRig) newPerson(t *testing.T, name string) person {
	t.Helper()
	pw, err := randomSecret(r.env.h.cfg.Rand)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pw.Destroy)
	g, _ := r.next(t)
	return person{name: name, email: name + "@firstrun.invalid", pw: pw, g: g}
}

// openForm starts the sign-up and returns the registration page.
func (r *firstRunRig) openForm(t *testing.T, p person) doorAnswer {
	t.Helper()
	a := p.g.follow(signupURL())
	if a.pageID() != "login-register" {
		t.Fatalf("%s: the sign-up opened %q (%d) %q", p.name, a.pageID(), a.status, a.sentence())
	}
	return a
}

// register posts the registration form for p, with its own email unless
// email is set, and returns the answer, followed.
func (r *firstRunRig) register(t *testing.T, p person, form doorAnswer, email string) doorAnswer {
	t.Helper()
	if email == "" {
		email = p.email
	}
	r.settle(t)
	return p.g.submit(form, "kc-register-form", map[string]string{
		"username": p.name, "email": email, "firstName": "First", "lastName": "Run",
		"password": string(p.pw.Reveal()), "password-confirm": string(p.pw.Reveal()),
	})
}

// saveCodes answers the recovery-codes page.
func (r *firstRunRig) saveCodes(t *testing.T, p person, a doorAnswer) doorAnswer {
	t.Helper()
	if a.pageID() != "login-login-recovery-authn-code-config" {
		t.Fatalf("%s: want the recovery-codes page, got %q (%d) %q", p.name, a.pageID(), a.status, errorText(a))
	}
	r.settle(t)
	return p.g.submit(a, "kc-recovery-codes-settings-form", nil)
}

// atConsole asserts the answer is the console's launcher after a callback
// that minted a session.
func (r *firstRunRig) atConsole(t *testing.T, p person, a doorAnswer) {
	t.Helper()
	if a.pageID() != consoleLoginPage {
		t.Fatalf("%s: ended on %q (%d) %q, want the console after the callback", p.name, a.pageID(), a.status, errorText(a))
	}
	r.settle(t)
}

// me is p's /api/auth/me.
func (r *firstRunRig) me(t *testing.T, p person) map[string]any {
	t.Helper()
	a := p.g.send(http.MethodGet, "https://"+ConsoleHost+"/api/auth/me", nil, nil)
	if a.status != http.StatusOK {
		t.Fatalf("%s: /api/auth/me answered %d", p.name, a.status)
	}
	var m map[string]any
	if err := json.Unmarshal(a.body, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// idOf is the account id of the sign-in name.
func (r *firstRunRig) idOf(t *testing.T, name string) string {
	t.Helper()
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "/users?exact=true&username="+url.QueryEscape(name), nil)
	var users []map[string]any
	if err := json.Unmarshal(out, &users); err != nil || len(users) != 1 {
		t.Fatalf("%s: %d accounts (%v)", name, len(users), err)
	}
	return users[0]["id"].(string)
}

// exists reports whether an account has the sign-in name.
func (r *firstRunRig) exists(t *testing.T, name string) bool {
	t.Helper()
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "/users?exact=true&username="+url.QueryEscape(name), nil)
	var users []map[string]any
	_ = json.Unmarshal(out, &users)
	return len(users) > 0
}

// claims are the first_admin rows' subjects.
func (r *firstRunRig) claims(t *testing.T) []string {
	t.Helper()
	db := r.db(t)
	defer func() { _ = db.Close() }()
	rows, err := db.QueryContext(t.Context(), `SELECT sub FROM first_admin`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func (r *firstRunRig) designated(t *testing.T) []accounts.Designation {
	t.Helper()
	ds, err := r.designations.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return ds
}

// recoveryDefault is the realm's recovery-codes defaultAction.
func (r *firstRunRig) recoveryDefault(t *testing.T) bool {
	t.Helper()
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "/authentication/required-actions/"+flows.ActionRecoveryCodes, nil)
	var a struct {
		DefaultAction bool `json:"defaultAction"`
	}
	if err := json.Unmarshal(out, &a); err != nil {
		t.Fatal(err)
	}
	return a.DefaultAction
}

// ---- the test ----------------------------------------------------------------

func TestFirstRun_AgainstPinnedKeycloak(t *testing.T) {
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
	r := newFirstRunRig(t, env)

	var a, b person
	t.Run("TC-990-29 a sign-up from a node or tailnet address is refused at the door", func(t *testing.T) { r.tc29(t) })
	t.Run("TC-990-04 TS-31 a pre-update operator: not first run, and a sign-up claims nothing", func(t *testing.T) { r.tc04(t) })
	t.Run("TC-990-01 IA-F1 TS-19 the account created first is the one designee", func(t *testing.T) { a, b = r.tc01(t) })
	t.Run("TC-990-05 IA-F5 a role-less account holds self only; app and mesh sign-ins refused", func(t *testing.T) { r.tc05(t, b) })
	t.Run("TC-990-03 C29 F-987-08 the designation is granted only with a second step", func(t *testing.T) { r.tc03(t, a) })
	t.Run("TC-990-24 the recovery codes are a default action during first run only", func(t *testing.T) { r.tc24(t) })
	t.Run("TC-990-11 T250 T251 T252", func(t *testing.T) { r.tc11(t, a) })
	t.Run("TC-990-19 F-991-12 a removed and an in-use email get the same answer", func(t *testing.T) { r.tc19(t, a) })
	t.Run("TC-990-20 #1145 a listed password is refused at sign-up", func(t *testing.T) { r.tc20(t) })
	t.Run("TC-990-13 the 21st waiting account is refused", func(t *testing.T) { r.tc13(t) })
}

// TC-990-29: with the client's loopback peer named as a node address, then
// as a tailnet address, the sign-up is the door's 403 with the sentence and
// the back link, and the identity service serves no registration page.
func (r *firstRunRig) tc29(t *testing.T) {
	defer r.net.set(homeFacts())
	for what, facts := range map[string]func(peer netip.Addr) policy.NetworkFacts{
		"a node address": func(peer netip.Addr) policy.NetworkFacts {
			f := homeFacts()
			f.Nodes = []netip.Addr{peer}
			return f
		},
		"a tailnet address": func(peer netip.Addr) policy.NetworkFacts {
			f := homeFacts()
			f.Tailnet = append(f.Tailnet, netip.PrefixFrom(peer, 32))
			return f
		},
	} {
		g, ip := r.next(t)
		r.net.set(facts(netip.MustParseAddr(ip)))
		got := g.follow(signupURL())
		if got.status != http.StatusForbidden || !shows(got, firstRunSourceSentence) || got.pageID() == "login-register" {
			t.Errorf("%s: %d page %q, want the door's 403 with %q", what, got.status, got.pageID(), firstRunSourceSentence)
		}
		if !strings.Contains(string(got.body), "https://"+ConsoleHost+"/login") {
			t.Errorf("%s: the refusal has no link back to the sign-in", what)
		}
	}
}

// TC-990-04: with a pre-update users row and no claim, status says not
// first run, and an ordinary sign-up and its callback write no claim and
// no designation. The row and the account are removed after, so the cases
// below start in first run.
func (r *firstRunRig) tc04(t *testing.T) {
	if err := r.store.CreateUser(t.Context(), &auth.User{ID: []byte("0123456789abcdef"), Name: "op", DisplayName: "Op", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	r.converge(t)
	g, _ := r.next(t)
	st := g.send(http.MethodGet, "https://"+ConsoleHost+"/api/auth/status", nil, nil)
	if !strings.Contains(string(st.body), `"firstRun":false`) {
		t.Errorf("status with a pre-update operator: %s", st.body)
	}
	pp := r.newPerson(t, "tc990-04")
	got := r.register(t, pp, r.openForm(t, pp), "")
	r.atConsole(t, pp, got) // no recovery-codes page outside first run
	if c := r.claims(t); len(c) != 0 {
		t.Errorf("a sign-up with a pre-update operator claimed %v", c)
	}
	if d := r.designated(t); len(d) != 0 {
		t.Errorf("a sign-up with a pre-update operator designated %v", d)
	}
	db := r.db(t)
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(t.Context(), `DELETE FROM users`); err != nil {
		t.Fatal(err)
	}
	r.admin(t).must(http.StatusNoContent, http.MethodDelete, "/users/"+r.idOf(t, pp.name), nil)
	r.converge(t)
	if first, err := r.store.FirstRun(t.Context()); err != nil || !first {
		t.Fatalf("first run after the cleanup: %v %v", first, err)
	}
}

// TC-990-01: A registers first and stops at "Save your recovery codes"; B
// registers and saves its codes, so B's callback runs first; then A
// finishes. One first_admin row names A, one designation (admin, admin,
// first_admin) is A's, and both sessions hold no role.
func (r *firstRunRig) tc01(t *testing.T) (person, person) {
	if !r.recoveryDefault(t) {
		t.Error("during first run the recovery codes are not a default action")
	}
	a := r.newPerson(t, "tc990-01-a")
	b := r.newPerson(t, "tc990-01-b")
	aCodes := r.register(t, a, r.openForm(t, a), "")
	if aCodes.pageID() != "login-login-recovery-authn-code-config" {
		t.Fatalf("A's sign-up ended on %q, want the recovery-codes page", aCodes.pageID())
	}
	bCodes := r.register(t, b, r.openForm(t, b), "")
	r.atConsole(t, b, r.saveCodes(t, b, bCodes))
	r.atConsole(t, a, r.saveCodes(t, a, aCodes))

	aID := r.idOf(t, a.name)
	if c := r.claims(t); !slices.Equal(c, []string{aID}) {
		t.Errorf("first_admin rows %v, want only A (%s), created first though it finished second", c, aID)
	}
	d := r.designated(t)
	if len(d) != 1 || d[0].Sub != aID || d[0].ConsoleRole != string(authz.Admin) || d[0].AppRole != accounts.AppAdmin || d[0].Reason != accounts.ReasonFirstAdmin {
		t.Errorf("designations %+v, want A's admin/admin first_admin", d)
	}
	for _, x := range []person{a, b} {
		m := r.me(t, x)
		if caps := stringList(m["capabilities"]); !slices.Equal(caps, []string{string(authz.Self)}) {
			t.Errorf("%s: capabilities %v, want self only", x.name, caps)
		}
	}
	if n := len(r.apiRec.Matching(slog.LevelInfo, "First run is over")); n != 1 {
		t.Errorf("%d firstrun.claimed records, want 1", n)
	}
	return a, b
}

// TC-990-05: B holds self only; its app sign-in and its private-network
// sign-in are refused with the app-access sentence.
func (r *firstRunRig) tc05(t *testing.T, b person) {
	if b.g == nil {
		t.Fatal("TC-990-01 did not run")
	}
	g, _ := r.next(t)
	refused(t, "the app sign-in", g.signIn(r.appAuth(doorTestApp, nil), b.name, b.pw), flows.SentenceNoAppAccess)
	g2, _ := r.next(t)
	refused(t, "the private-network sign-in", g2.signIn(r.homeAuth(baselineMesh, nil), b.name, b.pw), flows.SentenceNoAppAccess)
}

// grantJobs are the grant's jobs in the ledger, oldest first.
func (r *firstRunRig) grantJobs(t *testing.T) []*jobs.Job {
	t.Helper()
	js, err := r.ledger.ListJobs(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	var out []*jobs.Job
	for _, j := range js {
		if j.Kind == accounts.GrantKind {
			out = append(out, j)
		}
	}
	slices.SortFunc(out, func(x, y *jobs.Job) int { return x.CreatedAt.Compare(y.CreatedAt) })
	return out
}

// outcomes are a job's step outcomes, by step.
func (r *firstRunRig) outcomes(t *testing.T, id string) map[string]string {
	t.Helper()
	steps, err := r.ledger.ListSteps(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, s := range steps {
		var o struct {
			Outcome string `json:"outcome"`
		}
		_ = json.Unmarshal(s.Result, &o)
		out[s.Name] = o.Outcome
	}
	return out
}

// enrolTOTP answers the authenticator-app setup page.
func (r *firstRunRig) enrolTOTP(t *testing.T, g *goClient, a doorAnswer) (doorAnswer, string) {
	t.Helper()
	if a.pageID() != "login-login-config-totp" {
		t.Fatalf("want the authenticator-app setup page, got %q (%d) %q", a.pageID(), a.status, errorText(a))
	}
	m := regexp.MustCompile(`<img id="kc-totp-secret-qr-code" src="([^"]*)"`).FindSubmatch(a.body)
	if m == nil {
		t.Fatal("the setup page shows no QR code")
	}
	text, err := decodeQR(html.UnescapeString(string(m[1])))
	if err != nil {
		t.Fatalf("decode the QR code: %v", err)
	}
	u, err := url.Parse(text)
	if err != nil || u.Scheme != "otpauth" {
		t.Fatal("the QR code holds no otpauth URI")
	}
	secretB32 := u.Query().Get("secret")
	r.settle(t)
	return g.submit(a, "kc-totp-settings-form", map[string]string{"totp": r.otp.next(t, secretB32), "userLabel": "First run phone"}), secretB32
}

// consoleSignin is the console's SIGN IN, followed to the door's login page.
func consoleSignin() string { return "https://" + ConsoleHost + "/api/auth/signin" }

// TC-990-03: with recovery codes alone, A's sign-in submits no grant and a
// grant run records waiting, with no role and the designation kept. Once A
// enrols an authenticator app at a sign-in, its callback submits the grant,
// which runs check, grant and finish: A holds console admin, app admin and
// the second-step markers, its console sessions are gone and its
// designation is cleared. Then a password alone gets no code, and a
// password and an authenticator code mint a session with the administrator
// capabilities.
func (r *firstRunRig) tc03(t *testing.T, a person) {
	if a.g == nil {
		t.Fatal("TC-990-01 did not run")
	}
	aID := r.idOf(t, a.name)
	api := r.admin(t)

	// Codes only: the sign-in submits nothing; a grant run waits.
	g, _ := r.next(t)
	r.atConsole(t, a, g.signIn(consoleSignin(), a.name, a.pw))
	r.runner.Wait()
	if js := r.grantJobs(t); len(js) != 0 {
		t.Fatalf("a sign-in with recovery codes alone submitted %d grants", len(js))
	}
	j, err := r.runner.Submit(t.Context(), accounts.GrantKind, accounts.GrantSpec{AccountID: aID}, "tc990-03")
	if err != nil {
		t.Fatal(err)
	}
	r.runner.Wait()
	if o := r.outcomes(t, j.ID); o[accounts.StepCheck] != "waiting" || o[accounts.StepGrantRole] != "not_needed" {
		t.Errorf("a grant with codes alone: %v", o)
	}
	roles, err := r.users.ConsoleRoles(t.Context(), aID)
	if err != nil {
		t.Fatal(err)
	}
	pr, err := r.users.Read(t.Context(), aID)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(roles, string(authz.Admin)) || pr.AppRole != "" || len(r.designated(t)) != 1 {
		t.Errorf("with codes alone: roles %v, app %q, designations %v", roles, pr.AppRole, r.designated(t))
	}

	// The authenticator app at the next sign-in.
	_, out := api.must(http.StatusOK, http.MethodGet, "/users/"+aID, nil)
	var rep map[string]any
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatal(err)
	}
	rep["requiredActions"] = []string{flows.ActionConfigureTOTP}
	api.must(http.StatusNoContent, http.MethodPut, "/users/"+aID, rep)
	g2, _ := r.next(t)
	page := g2.signIn(consoleSignin(), a.name, a.pw)
	done, secretB32 := r.enrolTOTP(t, g2, page)
	r.atConsole(t, a, done)
	r.runner.Wait()
	js := r.grantJobs(t)
	if len(js) != 2 {
		t.Fatalf("%d grants, want the one the completing sign-in submitted besides the test's", len(js))
	}
	if o := r.outcomes(t, js[1].ID); o[accounts.StepCheck] != "complete" || o[accounts.StepGrantRole] != "granted" || o[accounts.StepFinish] != "finished" {
		t.Errorf("the grant: %v (job %s %s)", o, js[1].Status, js[1].Error)
	}
	if roles, _ := r.users.ConsoleRoles(t.Context(), aID); !slices.Contains(roles, string(authz.Admin)) {
		t.Errorf("after the grant: console roles %v", roles)
	}
	_, out = api.must(http.StatusOK, http.MethodGet, "/users/"+aID, nil)
	var after struct {
		Attributes map[string][]string `json:"attributes"`
	}
	_ = json.Unmarshal(out, &after)
	for _, k := range []string{accounts.AttrAppRole, flows.MarkerSecondStepHome, flows.MarkerSecondStepApp, flows.MarkerSecondStepAny} {
		if len(after.Attributes[k]) == 0 {
			t.Errorf("after the grant: no %s", k)
		}
	}
	if v := after.Attributes[accounts.AttrAppRole]; len(v) == 0 || v[0] != "admin" {
		t.Errorf("app access %v, want admin", v)
	}
	if n := r.sessionsOf(t, aID); n != 0 {
		t.Errorf("%d console sessions of A after the grant, want none", n)
	}
	_, out = api.must(http.StatusOK, http.MethodGet, "/users/"+aID+"/sessions", nil)
	var idSessions []map[string]any
	if err := json.Unmarshal(out, &idSessions); err != nil || len(idSessions) != 0 {
		t.Errorf("A's identity sessions after the grant: %d (%v), want none (C23)", len(idSessions), err)
	}
	if len(r.designated(t)) != 0 {
		t.Errorf("the designation was not cleared: %v", r.designated(t))
	}

	// A password alone gets no code; a password and the app's code do.
	g3, _ := r.next(t)
	second := g3.signIn(consoleSignin(), a.name, a.pw)
	if !isSecondStep(second.pageID()) {
		t.Fatalf("an administrator's password alone reached %q, want a second step", second.pageID())
	}
	if second.loc != nil && second.loc.Query().Get("code") != "" {
		t.Fatal("a password alone got a code")
	}
	if second.pageID() != "login-login-otp" {
		second = r.otpInstead(t, g3, second)
	}
	r.settle(t)
	r.atConsole(t, a, g3.submit(second, "kc-otp-login-form", map[string]string{"otp": r.otp.next(t, secretB32)}))
	resp := g3.send(http.MethodGet, "https://"+ConsoleHost+"/api/auth/me", nil, nil)
	var m map[string]any
	_ = json.Unmarshal(resp.body, &m)
	if caps := stringList(m["capabilities"]); !slices.Contains(caps, string(authz.IAM)) {
		t.Errorf("the administrator's capabilities %v", caps)
	}
}

// otpInstead picks the authenticator app from a second-step page that
// offered another method first.
func (r *firstRunRig) otpInstead(t *testing.T, g *goClient, a doorAnswer) doorAnswer {
	t.Helper()
	sel := g.submit(a, "kc-select-try-another-way-form", nil)
	if sel.pageID() != "login-select-authenticator" {
		t.Fatalf("try another way opened %q", sel.pageID())
	}
	_, action := g.form(sel, "kc-select-credential-form")
	for _, m := range regexp.MustCompile(`(?s)<button[^>]*name="authenticationExecution"[^>]*value="([^"]+)"[^>]*>(.*?)</button>`).FindAllSubmatch(sel.body, -1) {
		if strings.Contains(strings.ToLower(string(m[2])), "authenticator") {
			b := g.send(http.MethodPost, action, url.Values{"authenticationExecution": {string(m[1])}}, nil)
			return g.follow(b.at.ResolveReference(b.loc).String())
		}
	}
	t.Fatal("the chooser offers no authenticator app")
	return a
}

// sessionsOf counts sub's console sessions.
func (r *firstRunRig) sessionsOf(t *testing.T, sub string) int {
	t.Helper()
	db := r.db(t)
	defer func() { _ = db.Close() }()
	var n int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM console_sessions WHERE sub = ?`, sub).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TC-990-24: after the claim and converge's next run, the recovery codes
// are no default action, and a new account's sign-up ends at the callback
// with no recovery-codes page.
func (r *firstRunRig) tc24(t *testing.T) {
	r.converge(t)
	if r.recoveryDefault(t) {
		t.Error("after the claim the recovery codes are still a default action")
	}
	p := r.newPerson(t, "tc990-24")
	r.atConsole(t, p, r.register(t, p, r.openForm(t, p), ""))
}

// TC-990-11: T250, the unfiltered listing's createdTimestamp and no service
// account; T251, prompt=create's registration page ending as a code at the
// console's callback (TC-990-01's); T252, the exact email lookup ignoring
// case.
func (r *firstRunRig) tc11(t *testing.T, a person) {
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "/users?first=0&max=1000&briefRepresentation=false", nil)
	var list []map[string]any
	if err := json.Unmarshal(out, &list); err != nil || len(list) == 0 {
		t.Fatalf("the listing: %d, %v", len(list), err)
	}
	for _, u := range list {
		if _, ok := u["createdTimestamp"].(float64); !ok {
			t.Errorf("%v carries no createdTimestamp", u["username"])
		}
		if name, _ := u["username"].(string); strings.HasPrefix(name, "service-account-") {
			t.Errorf("the listing holds %s", name)
		}
	}
	r.mu.Lock()
	codes := 0
	for _, q := range r.callbackQueries {
		if q.Get("code") != "" {
			codes++
		}
	}
	r.mu.Unlock()
	if codes == 0 {
		t.Error("no sign-up reached the console's callback with a code")
	}
	in, err := r.users.EmailInUse(t.Context(), strings.ToUpper(a.email))
	if err != nil || !in {
		t.Errorf("the upper-case email: %v, %v", in, err)
	}
	_, out = r.admin(t).must(http.StatusOK, http.MethodGet, "/users?exact=true&email="+url.QueryEscape(strings.ToUpper(a.email)), nil)
	if err := json.Unmarshal(out, &list); err != nil || len(list) != 1 {
		t.Errorf("the exact upper-case lookup found %d", len(list))
	}
}

// correlationRE is a door page's reference line.
var correlationRE = regexp.MustCompile(`Reference: [^<]*`)

// TC-990-19: a removed account's email and an existing account's email,
// each posted at registration through the real door, get responses
// byte-identical but for the correlation id; the theme's own taken-email
// sentence is the same.
func (r *firstRunRig) tc19(t *testing.T, a person) {
	if err := r.removed.Record(t.Context(), "tc990-19-removed", "removed@firstrun.invalid"); err != nil {
		t.Fatal(err)
	}
	x, y := r.newPerson(t, "tc990-19-x"), r.newPerson(t, "tc990-19-y")
	fx, fy := r.openForm(t, x), r.openForm(t, y)
	gone := r.register(t, x, fx, "removed@firstrun.invalid")
	taken := r.register(t, y, fy, a.email)
	for what, got := range map[string]doorAnswer{"removed": gone, "in use": taken} {
		if got.status != http.StatusForbidden || !shows(got, firstRunEmailSentence) {
			t.Errorf("%s: %d %q", what, got.status, got.pageID())
		}
	}
	if strip := func(b []byte) string { return correlationRE.ReplaceAllString(string(b), "") }; strip(gone.body) != strip(taken.body) || gone.status != taken.status {
		t.Errorf("the two answers differ:\n%s\n----\n%s", gone.body, taken.body)
	}
	if r.exists(t, x.name) || r.exists(t, y.name) {
		t.Error("a refused registration created an account")
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "ui", "identity-theme", "src", "login", "messages", "messages_en.properties"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "\nemailExistsMessage="+firstRunEmailSentence+"\n") {
		t.Error("the theme's emailExistsMessage is not the door's sentence")
	}
}

// TC-990-20: a sign-up with a password from the staged deny list is refused
// with its sentence and creates no account; with one off the list, the
// account is created.
func (r *firstRunRig) tc20(t *testing.T) {
	listed, _ := listedEntries(t, r.env.kcHome)
	defer listed.Destroy()
	p := r.newPerson(t, "tc990-20-listed")
	p.pw = secret.New(listed.Reveal())
	got := r.register(t, p, r.openForm(t, p), "")
	if !shows(got, denylistSentence) || r.exists(t, p.name) {
		t.Errorf("a listed password: page %q (%d), account created %v", got.pageID(), got.status, r.exists(t, p.name))
	}
	q := r.newPerson(t, "tc990-20-unlisted")
	r.atConsole(t, q, r.register(t, q, r.openForm(t, q), ""))
	if !r.exists(t, q.name) {
		t.Error("an unlisted password created no account")
	}
}

// TC-990-13: with 20 enabled role-less accounts waiting, a 21st person's
// sign-up and its form post are each the door's 403 with the cap's
// sentence and the back link, logged at INFO as registration_full, and the
// realm still holds 20 waiting.
func (r *firstRunRig) tc13(t *testing.T) {
	n, err := r.waiting.Count(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	add := func(i int) {
		r.admin(t).must(http.StatusCreated, http.MethodPost, "/users", map[string]any{
			"username": "tc990-13-w" + strconv.Itoa(i), "enabled": true, "email": "w" + strconv.Itoa(i) + "@firstrun.invalid", "firstName": "W",
		})
	}
	for i := n; i < accounts.WaitingCap-1; i++ {
		add(i)
	}
	late := r.newPerson(t, "tc990-13-late")
	form := r.openForm(t, late) // opened at 19 waiting
	add(accounts.WaitingCap - 1)
	if c, _ := r.waiting.Count(t.Context()); c != accounts.WaitingCap {
		t.Fatalf("%d waiting, want %d", c, accounts.WaitingCap)
	}
	posted := r.register(t, late, form, "")
	fresh, _ := r.next(t)
	opened := fresh.follow(signupURL())
	for what, got := range map[string]doorAnswer{"the post": posted, "the sign-up": opened} {
		if got.status != http.StatusForbidden || !shows(got, firstRunFullSentence) || !strings.Contains(string(got.body), "https://"+ConsoleHost+"/login") {
			t.Errorf("%s: %d page %q", what, got.status, got.pageID())
		}
	}
	if c, _ := r.waiting.Count(t.Context()); c != accounts.WaitingCap || r.exists(t, late.name) {
		t.Errorf("after the refusals: %d waiting, the 21st exists %v", c, r.exists(t, late.name))
	}
	full := 0
	for _, rec := range r.apiRec.Records() {
		if v, _ := logkittest.Attr(rec, "refused"); v == "registration_full" && rec.Level == slog.LevelInfo {
			full++
		}
	}
	if full < 2 {
		t.Errorf("%d INFO registration_full records, want 2", full)
	}
}
