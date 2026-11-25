package identitytest

// Identity 5.1's move of the pre-update operators against the real
// identity service (geekdojo/geekdojo-brain#1004; TC-1004-01, -02, -04,
// -05, -06, -07, -08, -20 and -22): the first-run rig's home door, console
// sign-in, designated-role grant and observer, with identity.move as main
// wires it over the auth store's old tables and the realm, on a runner the
// kind table decides with the move's state. A fixture rasputin.db is built
// here by auth.Store with five pre-update operators, each with a passkey
// row (a soft P-256 authenticator's COSE key, its private key kept by the
// fixture) and a session row. A synthetic password set through the Admin
// API stands in for Identity 5.2's bridge.
//
// It starts an Env of its own, closed with proof in its cleanup. It skips
// without RASPUTIN_IDENTITY_HOME or RASPUTIN_IDENTITY_THEME and fails instead
// under RASPUTIN_IDENTITY_FUNCTIONAL=required, as CI's backend job sets it.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/breakglass"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/move"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// oldOp is one pre-update operator of the fixture.
type oldOp struct {
	handle []byte
	name   string
	want   string // the mapped sign-in name
	key    *ecdsa.PrivateKey
}

// alwaysReady is the identity service's readiness in the rig: the Env is
// ready before any case runs.
type alwaysReady struct{}

func (alwaysReady) Ready(context.Context) error { return nil }

type moveRig struct {
	*firstRunRig
	moveStore  *move.Store
	state      *move.State
	moveRunner *jobs.Runner
	moveLog    *logkittest.Recorder
	ops        []oldOp
	// door is the door account that took "bryce" before the move.
	door      string
	removedID string // the moved person accounts.delete removed (TC-1004-06)
	ids       map[string]string
	created   map[string]int64
}

func newMoveRig(t *testing.T, env *Env) *moveRig {
	t.Helper()
	r := &moveRig{firstRunRig: newFirstRunRig(t, env)}
	ctx := t.Context()
	var err error
	if r.moveStore, err = move.OpenStore(ctx, r.dbPath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.moveStore.Close() })
	log, rec := logkittest.New()
	r.moveLog = rec
	if r.state, err = move.NewState(r.store, r.moveStore, r.users, r.removed); err != nil {
		t.Fatal(err)
	}
	mover, err := move.New(move.Deps{Admin: r.session, OldUsers: r.store, Persons: r.users, Designations: r.designations,
		Facts: r.removed.Facts(), Removed: r.removed, Ready: alwaysReady{}, Records: r.moveStore, Lock: &sync.Mutex{},
		Realm: baselineRealm, Now: time.Now, Log: log, StepTimeout: 2 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	kp, err := authz.NewKindPolicy(resetApps{}, authz.WithMoveState(r.state))
	if err != nil {
		t.Fatal(err)
	}
	srv := natsserver.RunRandClientPortServer()
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	if r.moveRunner, err = jobs.NewAuthorizedRunner(r.ledger, nc, kp); err != nil {
		t.Fatal(err)
	}
	r.moveRunner.Register(mover.Workflow())
	return r
}

// coseP256 is key's public half as a COSE_Key (RFC 9053: kty EC2, alg
// ES256, crv P-256, x, y), as a WebAuthn authenticator registers it.
func coseP256(key *ecdsa.PrivateKey) []byte {
	pub, _ := key.PublicKey.ECDH()
	raw := pub.Bytes() // 0x04 || x || y
	out := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}
	out = append(out, raw[1:33]...)
	out = append(out, 0x22, 0x58, 0x20)
	return append(out, raw[33:65]...)
}

// seed writes the five pre-update operators with a passkey row and a
// session row each, Bryce older than bryce, and converges out of first run.
func (r *moveRig) seed(t *testing.T) {
	t.Helper()
	ctx := t.Context()
	base := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	for i, o := range []struct{ name, want string }{
		{"Bryce", "bryce-2"}, {"bryce", "bryce-3"}, {"b", "b-1"}, {"9lives", "u9lives"}, {"carol", "carol"},
	} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		h := make([]byte, 16)
		if _, err := rand.Read(h); err != nil {
			t.Fatal(err)
		}
		at := base.Add(time.Duration(i) * time.Minute)
		if err := r.store.CreateUser(ctx, &auth.User{ID: h, Name: o.name, DisplayName: "Old " + o.name, CreatedAt: at}); err != nil {
			t.Fatal(err)
		}
		if err := r.store.CreateCredential(ctx, &auth.Credential{ID: append([]byte("pk-"), h...), UserID: h, PublicKey: coseP256(key),
			AttestationType: "none", CreatedAt: at}); err != nil {
			t.Fatal(err)
		}
		if err := r.store.CreateSession(ctx, &auth.Session{Token: fmt.Sprintf("old-session-%x", h), UserID: h, CreatedAt: at,
			ExpiresAt: at.Add(24 * time.Hour), LastActiveAt: at}); err != nil {
			t.Fatal(err)
		}
		r.ops = append(r.ops, oldOp{handle: h, name: o.name, want: o.want, key: key})
	}
	r.converge(t)
}

func (r *moveRig) status(t *testing.T, stage string) {
	t.Helper()
	g, _ := r.next(t)
	st := g.send(http.MethodGet, "https://"+ConsoleHost+"/api/auth/status", nil, nil)
	if !strings.Contains(string(st.body), `"firstRun":false`) {
		t.Errorf("%s: status %s, want not first run", stage, st.body)
	}
	if c := r.claims(t); len(c) != 0 {
		t.Errorf("%s: first_admin rows %v", stage, c)
	}
}

// dump is the old tables, ordered, as text.
func (r *moveRig) dump(t *testing.T) map[string]string {
	t.Helper()
	db := r.db(t)
	defer func() { _ = db.Close() }()
	out := map[string]string{}
	for _, table := range []string{"users", "credentials", "sessions"} {
		rows, err := db.QueryContext(t.Context(), "SELECT * FROM "+table+" ORDER BY 1")
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		var b strings.Builder
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(&b, "%#v\n", vals)
		}
		_ = rows.Close()
		out[table] = b.String()
	}
	return out
}

// runMove submits the system move as the scheduler does and returns its
// job and step outcomes.
func (r *moveRig) runMove(t *testing.T) (*jobs.Job, map[string]json.RawMessage) {
	t.Helper()
	j, err := r.moveRunner.SubmitRawSpec(t.Context(), move.Kind, json.RawMessage(`{}`), "scheduler")
	if err != nil {
		t.Fatal(err)
	}
	r.moveRunner.Wait()
	return r.moveJob(t, j.ID)
}

func (r *moveRig) moveJob(t *testing.T, id string) (*jobs.Job, map[string]json.RawMessage) {
	t.Helper()
	job, err := r.ledger.GetJob(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	steps, err := r.ledger.ListSteps(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]json.RawMessage{}
	for _, s := range steps {
		out[s.Name] = s.Result
	}
	return job, out
}

func outcome(raw json.RawMessage) string {
	var o struct {
		Outcome string `json:"outcome"`
	}
	_ = json.Unmarshal(raw, &o)
	return o.Outcome
}

// realm is every person's username and createdTimestamp by id.
func (r *moveRig) realm(t *testing.T) (map[string]string, map[string]int64) {
	t.Helper()
	people, err := r.users.People(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	names, created := map[string]string{}, map[string]int64{}
	for _, p := range people {
		names[p.ID], created[p.ID] = p.Username, p.Created
	}
	return names, created
}

// rep is the account's representation.
func (r *moveRig) rep(t *testing.T, id string) map[string]any {
	t.Helper()
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "/users/"+id, nil)
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func (r *moveRig) realmRoles(t *testing.T, id string) []string {
	t.Helper()
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "/users/"+id+"/role-mappings/realm", nil)
	var roles []struct{ Name string }
	_ = json.Unmarshal(out, &roles)
	var names []string
	for _, x := range roles {
		names = append(names, x.Name)
	}
	return names
}

func (r *moveRig) credTypes(t *testing.T, id string) []string {
	t.Helper()
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "/users/"+id+"/credentials", nil)
	var creds []struct{ Type string }
	_ = json.Unmarshal(out, &creds)
	var types []string
	for _, c := range creds {
		types = append(types, c.Type)
	}
	return types
}

func (r *moveRig) consoleRoles(t *testing.T, id string) []string {
	t.Helper()
	roles, err := r.users.ConsoleRoles(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	return roles
}

func (r *moveRig) designation(t *testing.T, id string) (accounts.Designation, bool) {
	t.Helper()
	x, ok, err := r.designations.Get(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	return x, ok
}

// assertMoved checks a moved account as the move leaves it.
func (r *moveRig) assertMoved(t *testing.T, o oldOp) {
	t.Helper()
	id := auth.MovedAccountID(o.handle)
	rep := r.rep(t, id)
	attrs, _ := rep["attributes"].(map[string]any)
	app, _ := attrs[accounts.AttrAppRole].([]any)
	actions, _ := rep["requiredActions"].([]any)
	if rep["username"] != o.want || rep["enabled"] != true || len(app) != 1 || app[0] != "user" {
		t.Errorf("%s: username %v enabled %v app %v", o.name, rep["username"], rep["enabled"], app)
	}
	if !slices.Contains(actions, any(flows.ActionRecoveryCodes)) {
		t.Errorf("%s: required actions %v", o.name, actions)
	}
	if e, ok := rep["email"]; ok && e != "" {
		t.Errorf("%s: email %v, want none", o.name, e)
	}
	if !slices.Contains(r.realmRoles(t, id), "offline_access") {
		t.Errorf("%s: realm roles %v, want offline_access", o.name, r.realmRoles(t, id))
	}
	if c := r.credTypes(t, id); len(c) != 0 {
		t.Errorf("%s: credentials %v, want none", o.name, c)
	}
	if c := r.consoleRoles(t, id); len(c) != 0 {
		t.Errorf("%s: console roles %v, want none", o.name, c)
	}
	if x, ok := r.designation(t, id); !ok || x.ConsoleRole != "admin" || x.AppRole != accounts.AppAdmin || x.Reason != accounts.ReasonMoved {
		t.Errorf("%s: designation %+v %v, want admin/admin moved", o.name, x, ok)
	}
}

// setPassword is the synthetic password that stands in for 5.2's bridge.
func (r *moveRig) setPassword(t *testing.T, id string) secret.Value {
	t.Helper()
	pw, err := randomSecret(r.env.h.cfg.Rand)
	if err != nil {
		t.Fatal(err)
	}
	r.top.Cleanup(pw.Destroy)
	r.admin(t).must(http.StatusNoContent, http.MethodPut, "/users/"+id+"/reset-password",
		map[string]any{"type": "password", "value": string(pw.Reveal()), "temporary": false})
	return pw
}

// drive answers the sign-in's pages until the console: the profile page
// (the email the person sets first), the recovery codes (atCodes runs on
// the page, before they are saved) and the authenticator app.
func (r *moveRig) drive(t *testing.T, p person, a doorAnswer, atCodes func()) {
	t.Helper()
	for range 6 {
		switch a.pageID() {
		case "login-login-update-profile":
			r.settle(t)
			a = p.g.submit(a, "kc-update-profile-form", map[string]string{"firstName": "Moved", "email": p.email})
		case "login-login-recovery-authn-code-config":
			if atCodes != nil {
				atCodes()
			}
			a = r.saveCodes(t, p, a)
		case "login-login-config-totp":
			a, _ = r.enrolTOTP(t, p.g, a)
		case consoleLoginPage:
			r.atConsole(t, p, a)
			return
		default:
			t.Fatalf("%s: the sign-in reached %q (%d) %q", p.name, a.pageID(), a.status, errorText(a))
		}
	}
	t.Fatalf("%s: the sign-in did not reach the console", p.name)
}

// requireTOTP sets the authenticator app as the account's required action.
func (r *moveRig) requireTOTP(t *testing.T, id string) {
	t.Helper()
	rep := r.rep(t, id)
	rep["requiredActions"] = []string{flows.ActionConfigureTOTP}
	r.admin(t).must(http.StatusNoContent, http.MethodPut, "/users/"+id, rep)
}

// complete signs the moved operator in with a password, saves recovery
// codes, then enrols an authenticator app at the next sign-in, checking
// the console roles after each.
func (r *moveRig) complete(t *testing.T, o oldOp) (string, []string) {
	t.Helper()
	id := auth.MovedAccountID(o.handle)
	pw := r.setPassword(t, id)
	g, _ := r.next(t)
	p := person{name: o.want, email: o.want + "@move.invalid", pw: pw, g: g}
	r.drive(t, p, g.signIn(consoleSignin(), o.want, pw), func() {
		if c := r.consoleRoles(t, id); len(c) != 0 {
			t.Errorf("%s: after a password-only sign-in, console roles %v", o.want, c)
		}
	})
	r.runner.Wait()
	afterCodes := r.consoleRoles(t, id)
	r.requireTOTP(t, id)
	g2, _ := r.next(t)
	p.g = g2
	r.drive(t, p, g2.signIn(consoleSignin(), o.want, pw), nil)
	r.runner.Wait()
	return id, afterCodes
}

// ---- the test ----------------------------------------------------------------

func TestMove_AgainstPinnedKeycloak(t *testing.T) {
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
	r := newMoveRig(t, env)

	t.Run("TC-1004-22 K-PARTIALIMPORT at the pinned Keycloak", func(t *testing.T) { r.tc22(t) })
	var before map[string]string
	t.Run("TC-1004-01 TC-1004-08 the fixture and a door account that took bryce", func(t *testing.T) { before = r.tcFixture(t) })
	t.Run("TC-1004-04 TC-1004-06 TC-1004-08 the move", func(t *testing.T) { r.tcMove(t, before) })
	t.Run("TC-1004-02 a re-run creates no second account", func(t *testing.T) { r.tc02(t, before) })
	t.Run("TC-1004-04 C29 the first to finish becomes administrator", func(t *testing.T) { r.tc04(t) })
	t.Run("TC-1004-05 C25 the second to finish waits", func(t *testing.T) { r.tc05(t) })
	t.Run("TC-1004-06 C15 deleting a moved person", func(t *testing.T) { r.tc06(t) })
	var token string
	t.Run("TC-1004-20 the repair re-run's refusals", func(t *testing.T) { token = r.tc20(t) })
	t.Run("TC-1004-07 the repair re-run leaves the removed person out", func(t *testing.T) { r.tc07(t, token) })
}

// TC-1004-22: partialImport with SKIP adds a new user under its own id with
// its attributes, required action and realm role and no credential or
// email, and skips a user whose id exists, leaving it unchanged.
func (r *moveRig) tc22(t *testing.T) {
	api := r.admin(t)
	id := auth.MovedAccountID([]byte("k-partialimport-probe"))
	user := map[string]any{"id": id, "username": "kpi-probe", "enabled": true, "firstName": "Probe",
		"attributes": map[string][]string{accounts.AttrAppRole: {"user"}}, "requiredActions": []string{flows.ActionRecoveryCodes},
		"realmRoles": []string{"offline_access"}}
	var res struct{ Added, Skipped, Overwritten int }
	_, out := api.must(http.StatusOK, http.MethodPost, "/partialImport", map[string]any{"ifResourceExists": "SKIP", "users": []any{user}})
	if err := json.Unmarshal(out, &res); err != nil || res.Added != 1 || res.Skipped != 0 {
		t.Fatalf("the first import: %+v %v (%s)", res, err, out)
	}
	rep := r.rep(t, id)
	attrs, _ := rep["attributes"].(map[string]any)
	if rep["username"] != "kpi-probe" || rep["enabled"] != true || fmt.Sprint(attrs[accounts.AttrAppRole]) != "[user]" ||
		fmt.Sprint(rep["requiredActions"]) != "["+flows.ActionRecoveryCodes+"]" {
		t.Errorf("ADDED: %v", rep)
	}
	if e, ok := rep["email"]; ok && e != "" {
		t.Errorf("ADDED with email %v", e)
	}
	if !slices.Contains(r.realmRoles(t, id), "offline_access") || len(r.credTypes(t, id)) != 0 {
		t.Errorf("ADDED: realm roles %v, credentials %v", r.realmRoles(t, id), r.credTypes(t, id))
	}
	user["firstName"], user["username"] = "Changed", "kpi-changed"
	_, out = api.must(http.StatusOK, http.MethodPost, "/partialImport", map[string]any{"ifResourceExists": "SKIP", "users": []any{user}})
	if err := json.Unmarshal(out, &res); err != nil || res.Skipped != 1 || res.Added != 0 {
		t.Errorf("the second import: %+v %v (%s)", res, err, out)
	}
	if again := r.rep(t, id); again["firstName"] != "Probe" || again["username"] != "kpi-probe" || again["createdTimestamp"] != rep["createdTimestamp"] {
		t.Errorf("SKIPPED changed the user: %v", again)
	}
	api.must(http.StatusNoContent, http.MethodDelete, "/users/"+id, nil)
}

// tcFixture seeds the old operators, signs a door account up as bryce
// before the move (TC-1004-08), and checks first run is closed with the
// door account claiming nothing (TC-1004-01). It returns the old tables'
// dump taken after the api opened the fixture.
func (r *moveRig) tcFixture(t *testing.T) map[string]string {
	r.seed(t)
	r.status(t, "before the move")
	if p, err := r.state.Pending(t.Context()); err != nil || !p {
		t.Fatalf("Pending before the move: %v %v", p, err)
	}
	door := r.newPerson(t, "bryce")
	r.atConsole(t, door, r.register(t, door, r.openForm(t, door), ""))
	r.door = r.idOf(t, "bryce")
	if _, ok := r.designation(t, r.door); ok || len(r.consoleRoles(t, r.door)) != 0 {
		t.Errorf("the door account was designated or given a role")
	}
	return r.dump(t)
}

// tcMove: the move succeeds; every old operator is imported under its
// moved id and mapped name, designated, app user, no credential, no email
// (TC-1004-04); the door account is untouched and the old Bryce and bryce
// are bryce-2 and bryce-3, in the job's result and the rows (TC-1004-08);
// the old tables are byte-equal (TC-1004-06); first run stays closed.
func (r *moveRig) tcMove(t *testing.T, before map[string]string) {
	job, res := r.runMove(t)
	if job.Status != jobs.StatusSucceeded {
		t.Fatalf("the move: %s %q", job.Status, job.Error)
	}
	for _, o := range r.ops {
		r.assertMoved(t, o)
	}
	if rep := r.rep(t, r.door); rep["username"] != "bryce" {
		t.Errorf("the door account is %v", rep["username"])
	}
	if _, ok := r.designation(t, r.door); ok || len(r.consoleRoles(t, r.door)) != 0 {
		t.Error("the move designated the door account or gave it a role")
	}
	var result struct {
		Accounts []move.Moved `json:"accounts"`
	}
	if err := json.Unmarshal(res[move.StepImport], &result); err != nil || len(result.Accounts) != len(r.ops) {
		t.Fatalf("the import's result %s (%v)", res[move.StepImport], err)
	}
	rows, err := r.moveStore.Rows(t.Context())
	if err != nil || len(rows) != len(r.ops) {
		t.Fatalf("%d move rows (%v)", len(rows), err)
	}
	for _, o := range r.ops {
		id := auth.MovedAccountID(o.handle)
		if !slices.Contains(result.Accounts, move.Moved{AccountID: id, From: o.name, To: o.want}) {
			t.Errorf("the result lacks %s -> %s", o.name, o.want)
		}
		i := slices.IndexFunc(rows, func(x move.Row) bool { return x.AccountID == id })
		if i < 0 || rows[i].OldName != o.name || rows[i].NewName != o.want || string(rows[i].Handle) != string(o.handle) {
			t.Errorf("the row for %s: %+v", o.name, rows)
		}
	}
	if after := r.dump(t); !mapsEqual(after, before) {
		t.Errorf("the move changed the old tables")
	}
	r.ids, r.created = r.realm(t)
	r.status(t, "after the move")
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// TC-1004-02: a second system move is not_needed and imports nothing.
// With the rows deleted (a crash before record), the move runs again: the
// same accounts under the same ids and names, createdTimestamp unchanged,
// and the rows written once more. The old tables stay byte-equal.
func (r *moveRig) tc02(t *testing.T, before map[string]string) {
	job, res := r.runMove(t)
	if job.Status != jobs.StatusSucceeded || outcome(res[move.StepCheck]) != "not_needed" || outcome(res[move.StepImport]) != "not_needed" {
		t.Errorf("the second move: %s, check %q import %q", job.Status, outcome(res[move.StepCheck]), outcome(res[move.StepImport]))
	}
	names, created := r.realm(t)
	if !mapsEqual(names, r.ids) || fmt.Sprint(created) != fmt.Sprint(r.created) {
		t.Errorf("a not_needed move changed the realm")
	}
	db := r.db(t)
	if _, err := db.ExecContext(t.Context(), `DELETE FROM identity_move`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	job, _ = r.runMove(t)
	if job.Status != jobs.StatusSucceeded {
		t.Fatalf("the move after a crash before record: %s %q", job.Status, job.Error)
	}
	names, created = r.realm(t)
	if !mapsEqual(names, r.ids) || fmt.Sprint(created) != fmt.Sprint(r.created) {
		t.Errorf("SKIP changed an account: %v (was %v)", names, r.ids)
	}
	if rows, _ := r.moveStore.Rows(t.Context()); len(rows) != len(r.ops) {
		t.Errorf("%d rows after the re-run, want %d", len(rows), len(r.ops))
	}
	if after := r.dump(t); !mapsEqual(after, before) {
		t.Errorf("a re-run changed the old tables")
	}
}

// TC-1004-04: the old Bryce (bryce-2), the first to finish, holds no
// console role after a password-only sign-in or after saving recovery
// codes; once an authenticator app is enrolled it holds console admin and
// app admin and its designation is gone. First run stays closed.
func (r *moveRig) tc04(t *testing.T) {
	id, afterCodes := r.complete(t, r.ops[0])
	if len(afterCodes) != 0 {
		t.Errorf("after recovery codes only, console roles %v", afterCodes)
	}
	if !slices.Contains(r.consoleRoles(t, id), string(authz.Admin)) {
		t.Errorf("console roles %v, want admin", r.consoleRoles(t, id))
	}
	pr, err := r.users.Read(t.Context(), id)
	if err != nil || pr.AppRole != accounts.AppAdmin {
		t.Errorf("app access %q (%v), want admin", pr.AppRole, err)
	}
	if x, ok := r.designation(t, id); ok {
		t.Errorf("the designation outlived the grant: %+v", x)
	}
	r.status(t, "after a moved account was granted")
}

// TC-1004-05 (CI): the second to finish (b-1) holds no console role, its
// designation is waiting and the waiting count counts it, its completing
// sign-in submits no grant and a later grant gives nothing.
func (r *moveRig) tc05(t *testing.T) {
	o := r.ops[2]
	id := auth.MovedAccountID(o.handle)
	if x, _ := r.designation(t, id); x.Reason != accounts.ReasonWaiting {
		t.Fatalf("after the first administrator, %s is %q, want waiting", o.want, x.Reason)
	}
	_, _ = r.complete(t, o)
	if c := r.consoleRoles(t, id); len(c) != 0 {
		t.Errorf("the second to finish holds %v", c)
	}
	for _, j := range r.grantJobs(t) {
		if strings.Contains(string(j.Spec), id) {
			t.Errorf("a grant was submitted for a waiting account: %s", j.ID)
		}
	}
	j, err := r.runner.Submit(t.Context(), accounts.GrantKind, accounts.GrantSpec{AccountID: id}, "tc1004-05")
	if err != nil {
		t.Fatal(err)
	}
	r.runner.Wait()
	if out := r.outcomes(t, j.ID); out[accounts.StepCheck] != "waiting_for_admin" || len(r.consoleRoles(t, id)) != 0 {
		t.Errorf("a later grant: %v, console %v", out, r.consoleRoles(t, id))
	}
	// Waiting: the four moved accounts left, and the door account when it
	// holds no app access.
	want := len(r.ops) - 1
	if dp, err := r.users.Read(t.Context(), r.door); err == nil && dp.AppRole == "" {
		want++
	}
	if n, err := r.waiting.Count(t.Context()); err != nil || n != want {
		t.Errorf("the waiting count %d (%v), want %d", n, err, want)
	}
}

// TC-1004-06 (C15): accounts.delete of a moved person removes only that
// person's credentials and sessions rows; its users row is byte-equal.
func (r *moveRig) tc06(t *testing.T) {
	rv := revokeOn(t, r.consoleRig)
	o := r.ops[4]
	id := auth.MovedAccountID(o.handle)
	before := r.dump(t)
	users, creds, sess := rv.movedRows(t, o.handle)
	if creds != 1 || sess != 1 {
		t.Fatalf("the fixture holds %d credentials and %d sessions for %s", creds, sess, o.name)
	}
	rv.revokeOK(t, id, accounts.Delete, rv.adminID)
	after, creds, sess := rv.movedRows(t, o.handle)
	if creds != 0 || sess != 0 || after != users {
		t.Errorf("after the delete: %d credentials, %d sessions, users row changed %v", creds, sess, after != users)
	}
	now := r.dump(t)
	if now["users"] != before["users"] {
		t.Error("the delete changed the users table")
	}
	for _, other := range r.ops[:4] {
		if _, c, s := rv.movedRows(t, other.handle); c != 1 || s != 1 {
			t.Errorf("%s lost rows: %d credentials, %d sessions", other.name, c, s)
		}
	}
	r.removedID = id
}

// c9 deletes every person in the realm, service accounts kept, so C9's
// state holds.
func (r *moveRig) c9(t *testing.T) {
	t.Helper()
	people, err := r.users.People(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range people {
		r.admin(t).must(http.StatusNoContent, http.MethodDelete, "/users/"+p.ID, nil)
	}
}

// TC-1004-20: in C9's state, a stale token is refused before any job row
// exists, and with a person in the realm a repair submission is refused
// the same way. It returns the current token.
func (r *moveRig) tc20(t *testing.T) string {
	r.c9(t)
	st, err := r.state.Repair(t.Context())
	if err != nil || !st.Holds || st.Accounts != len(r.ops)-1 {
		t.Fatalf("C9: %+v %v, want holding with %d", st, err, len(r.ops)-1)
	}
	count := func() int {
		js, err := r.ledger.ListJobsByKind(t.Context(), move.Kind, 1000)
		if err != nil {
			t.Fatal(err)
		}
		return len(js)
	}
	n := count()
	repair := breakglass.Session{}.Submitter()
	_, err = r.moveRunner.SubmitFor(t.Context(), repair, move.Kind, move.Spec{Repair: true, StateToken: "stale"}, nil)
	var kr *authz.KindRefusal
	if !errors.As(err, &kr) || kr.Code != authz.CodeStateChanged {
		t.Errorf("a stale token: %v, want state_changed", err)
	}
	loc, _ := r.admin(t).must(http.StatusCreated, http.MethodPost, "/users", map[string]any{"username": "c9-person", "enabled": true})
	_, err = r.moveRunner.SubmitFor(t.Context(), repair, move.Kind, move.Spec{Repair: true, StateToken: st.Token}, nil)
	if !errors.As(err, &kr) || kr.Code != authz.CodeMoveState {
		t.Errorf("a person in the realm: %v, want move_state", err)
	}
	r.admin(t).must(http.StatusNoContent, http.MethodDelete, loc, nil)
	if got := count(); got != n {
		t.Errorf("the refusals left %d move jobs, want %d", got, n)
	}
	return st.Token
}

// TC-1004-07: a repair session's re-run in C9's state with the current
// token succeeds: every pre-update operator but the removed one is back
// under the same id and mapped name, designated moved, app user, no
// credential. First run stays closed.
func (r *moveRig) tc07(t *testing.T, token string) {
	j, err := r.moveRunner.SubmitFor(t.Context(), breakglass.Session{}.Submitter(), move.Kind, move.Spec{Repair: true, StateToken: token}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.moveRunner.Wait()
	job, _ := r.moveJob(t, j.ID)
	if job.Status != jobs.StatusSucceeded || job.CreatedBy != "break-glass" {
		t.Fatalf("the repair re-run: %s %q by %q", job.Status, job.Error, job.CreatedBy)
	}
	names, _ := r.realm(t)
	want := map[string]string{}
	for _, o := range r.ops {
		if id := auth.MovedAccountID(o.handle); id != r.removedID {
			want[id] = o.want
		}
	}
	if !mapsEqual(names, want) {
		t.Errorf("the realm after the re-run %v, want %v", names, want)
	}
	for _, o := range r.ops {
		if auth.MovedAccountID(o.handle) != r.removedID {
			r.assertMoved(t, o)
		}
	}
	r.status(t, "after the repair re-run")
}
