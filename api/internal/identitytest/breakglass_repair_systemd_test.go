package identitytest

// CI TC-321-54 to TC-321-62 (geekdojo/geekdojo-brain#321, PR 2): a
// break-glass repair session's two account powers on the console stack
// (console_systemd_test.go), against the real api, Keycloak and systemd.
//
//   - C1: with the administrator's second steps and recovery codes removed
//     through the Admin API, so it can no longer sign in, a repair session
//     resets its sign-in once, the alert is raised, and the account gets
//     its admin role back after it sets up again (C29).
//   - C9: old operators seeded in rasputin.db before the api starts are
//     imported by the api's own identity.move. While the realm holds
//     accounts the repair re-run is refused; once every realm user is gone
//     the lost-accounts alert shows, the repair session confirms the count
//     and brings them back, and the state closes again.
//
// It needs what the console stack needs, plus util-linux's script. Without
// them it skips, and under RASPUTIN_IDENTITY_SYSTEMD_FUNCTIONAL=required it
// fails (TC-321-62).

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitytest/signin"
	"github.com/geekdojo/rasputin-control-plane/api/internal/proctest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// repairOps are the seeded pre-update operators' names.
var repairOps = []string{"ciopone", "cioptwo", "ciopthree"}

// repairAdminName is the C1 fixture administrator.
const repairAdminName = "repair-admin-fixture"

// repairs is the test's state over the stack.
type repairs struct {
	*breakGlass
	origin string
	// handles are the seeded operators' handles, by name.
	handles map[string][]byte
	// fixture is the C1 administrator; its session after C29 is the
	// console administrator's kept session for C9.
	fixture *adminFixture
	dbh     *sql.DB
}

func TestIdentitySystemd_BreakGlassRepairs(t *testing.T) {
	if _, err := exec.LookPath("script"); err != nil {
		functest.SkipOrFail(t, systemdSwitchEnv, "the break-glass repairs test needs util-linux's script: %v", err)
		return
	}
	rp := &repairs{origin: "https://" + consoleCID + ".local", handles: map[string][]byte{}}
	s, ctx, admin := startConsoleStack(t, consoleStackOpts{allAddrs: true, clockSynced: true, seedDB: rp.seed})
	if s == nil {
		return
	}
	if s.port != "443" {
		t.Fatalf("the break-glass repairs test needs the api on :443, not %s", s.port)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(filepath.Dir(repairSocket)); err != nil {
			t.Errorf("remove %s: %v", filepath.Dir(repairSocket), err)
		}
	})
	rp.breakGlass = &breakGlass{t: t, s: s, ctx: ctx, admin: admin, local: s.client(nil)}
	s.awaitFiles(ctx, "the api serves the repair-code socket", repairSocket)

	rp.awaitSystemMove()
	rp.firstRunFalse("after the seed")
	rp.tc54Reset()
	rp.tc55OnceAndState()
	rp.tc56RoleBack()
	removed := rp.tc57Refused()
	rp.tc58AlertAndConfirm()
	rp.tc59BroughtBack(removed)
	rp.tc60OtherSessions()
}

// seed writes the pre-update operators into rasputin.db (seedDB).
func (rp *repairs) seed(t *testing.T, dbPath string) {
	st, err := auth.OpenStore(t.Context(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	for _, name := range repairOps {
		h := make([]byte, 16)
		if _, err := rand.Read(h); err != nil {
			t.Fatal(err)
		}
		rp.handles[name] = h
		if err := st.CreateUser(t.Context(), &auth.User{ID: h, Name: name, DisplayName: name, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
}

// opID is a seeded operator's account id in the realm.
func (rp *repairs) opID(name string) string { return auth.MovedAccountID(rp.handles[name]) }

// realm is the Admin API's path for the realm.
func realmPath(rest string) string { return "/admin/realms/" + baselineRealm + rest }

// get reads path from the Admin API into out.
func (rp *repairs) get(path string, out any) {
	rp.t.Helper()
	if _, err := rp.admin.Admin(rp.ctx, http.MethodGet, realmPath(path), nil, out); err != nil {
		rp.t.Fatalf("GET %s: %v", path, err)
	}
}

// jobStatus waits until the job id has an outcome and returns its status
// and submitter.
func (rp *repairs) jobStatus(id string) (status, by string) {
	rp.t.Helper()
	err := proctest.Await(rp.ctx, nil, func(ctx context.Context) (bool, string, error) {
		if err := rp.s.apiAlive(); err != nil {
			return false, "", &proctest.Final{Err: err}
		}
		if err := rp.rdb().QueryRowContext(ctx, `SELECT status, created_by FROM jobs WHERE id = ?`, id).Scan(&status, &by); err != nil {
			return false, err.Error(), nil
		}
		return status == "succeeded" || status == "failed", "status " + status, nil
	}, func(last string) { rp.s.cfg.Logger.Info("repairs: waiting for a job", "job", id, "last", last) })
	if err != nil {
		rp.t.Fatal(errNamed("job "+id+" has an outcome", err))
	}
	return status, by
}

// awaitSystemMove waits on the fact that the api's own identity.move has
// imported the seeded operators.
func (rp *repairs) awaitSystemMove() {
	t := rp.t
	var id string
	err := proctest.Await(rp.ctx, nil, func(ctx context.Context) (bool, string, error) {
		if err := rp.s.apiAlive(); err != nil {
			return false, "", &proctest.Final{Err: err}
		}
		var status string
		err := rp.rdb().QueryRowContext(ctx, `SELECT id, status FROM jobs WHERE kind = 'identity.move' ORDER BY created_at DESC LIMIT 1`).Scan(&id, &status)
		switch {
		case err != nil:
			return false, "no identity.move job: " + err.Error(), nil
		case status == "failed":
			return false, "", &proctest.Final{Err: fmt.Errorf("the system identity.move failed")}
		}
		return status == "succeeded", "identity.move is " + status, nil
	}, func(last string) { rp.s.cfg.Logger.Info("repairs: waiting for the system move", "last", last) })
	if err != nil {
		t.Fatal(errNamed("the api's identity.move imported the seeded operators", err))
	}
	for _, name := range repairOps {
		var u struct {
			Username string `json:"username"`
		}
		rp.get("/users/"+rp.opID(name), &u)
		if u.Username != name {
			t.Fatalf("the moved %s holds the name %q", name, u.Username)
		}
	}
}

// firstRunFalse asserts GET /api/auth/status reports firstRun false
// (TC-321-61).
func (rp *repairs) firstRunFalse(when string) {
	rp.t.Helper()
	status, b, _ := rp.call(rp.local, http.MethodGet, rp.origin+"/api/auth/status", "", nil)
	var st struct {
		FirstRun *bool `json:"firstRun"`
	}
	if status != http.StatusOK || json.Unmarshal(b, &st) != nil || st.FirstRun == nil || *st.FirstRun {
		rp.t.Errorf("TC-321-61 %s: status %d %s, want firstRun false", when, status, b)
	}
}

// open redeems a fresh code at the console's origin.
func (rp *repairs) open() *http.Cookie {
	rp.t.Helper()
	status, code, c := rp.redeem(rp.local, rp.origin, rp.code())
	if status != http.StatusOK || c == nil {
		rp.t.Fatalf("redeem: %d %s", status, code)
	}
	return c
}

// post posts body to path with cookie, and returns the status and the
// decoded body.
func (rp *repairs) post(path, body string, c *http.Cookie) (int, map[string]any) {
	rp.t.Helper()
	var cs []*http.Cookie
	if c != nil {
		cs = append(cs, c)
	}
	status, b, _ := rp.call(rp.local, http.MethodPost, rp.origin+path, body, nil, cs...)
	out := map[string]any{}
	_ = json.Unmarshal(b, &out)
	return status, out
}

// state is the repair state for c.
func (rp *repairs) state(c *http.Cookie) map[string]any {
	rp.t.Helper()
	status, b, _ := rp.call(rp.local, http.MethodGet, rp.origin+"/api/repair/state", "", nil, c)
	out := map[string]any{}
	if status != http.StatusOK || json.Unmarshal(b, &out) != nil {
		rp.t.Fatalf("repair state: %d %s", status, b)
	}
	return out
}

// action is the state's action id, or nil.
func action(st map[string]any, id string) map[string]any {
	as, _ := st["actions"].([]any)
	for _, a := range as {
		m, _ := a.(map[string]any)
		if m["id"] == id {
			return m
		}
	}
	return nil
}

// consoleClientID is the console client's internal id.
func (rp *repairs) consoleClientID() string {
	var cs []struct {
		ID string `json:"id"`
	}
	rp.get("/clients?clientId="+baselineConsole, &cs)
	if len(cs) != 1 {
		rp.t.Fatalf("%d console clients", len(cs))
	}
	return cs[0].ID
}

// tc54Reset is TC-321-54: the fixture administrator can no longer sign in;
// a repair session lists it, confirms it by name, and resets it.
func (rp *repairs) tc54Reset() {
	t := rp.t
	// The fixture holds app admin, so TC-321-55 proves the reset lowers it
	// to user (F-321-38).
	rp.fixture = rp.adminFixture(repairAdminName, true)
	a := rp.fixture
	var creds []struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	}
	rp.get("/users/"+a.id+"/credentials", &creds)
	for _, c := range creds {
		if c.Type == "password" {
			continue
		}
		if _, err := rp.admin.Admin(rp.ctx, http.MethodDelete, realmPath("/users/"+a.id+"/credentials/"+c.ID), nil, nil); err != nil {
			t.Fatalf("delete the fixture's %s: %v", c.Type, err)
		}
	}
	// With no Steps, any page after the password is an error: the sign-in
	// must not be offered a way to set up a second step on its own.
	plain := signin.Console{Origin: rp.origin, Transport: admitted{next: rp.local.Transport, log: rp.s.cfg.Logger}, Logger: rp.s.cfg.Logger}
	if _, pages, err := signin.ConsoleSignIn(rp.ctx, plain, a.name, a.pw); err == nil {
		t.Fatalf("TC-321-54: the fixture's sign-in reached the console without a second step (pages %v)", pages)
	}

	sess := rp.open()
	reset := action(rp.state(sess), "reset")
	targets, _ := reset["targets"].([]any)
	if !slices.ContainsFunc(targets, func(x any) bool { m, _ := x.(map[string]any); return m["id"] == a.id && m["name"] == a.name }) {
		t.Fatalf("TC-321-54: the reset targets %v don't list the fixture", reset)
	}
	status, body := rp.post("/api/repair/reset", `{"accountId":"`+a.id+`"}`, sess)
	msg, _ := body["error"].(string)
	token, _ := body["stateToken"].(string)
	if status != http.StatusConflict || body["code"] != "repair_confirm" || !strings.Contains(msg, a.name) || token == "" {
		t.Fatalf("TC-321-54: no token: %d %v, want 409 naming %s", status, body, a.name)
	}
	temp, err := randomSecret(rp.s.cfg.Rand)
	if err != nil {
		t.Fatal(err)
	}
	a.pw.Destroy()
	a.pw = temp
	req, _ := json.Marshal(map[string]string{"accountId": a.id, "stateToken": token, "password": string(temp.Reveal())})
	status, body = rp.post("/api/repair/reset", string(req), sess)
	id, _ := body["id"].(string)
	if status != http.StatusAccepted || id == "" {
		t.Fatalf("TC-321-54: confirmed: %d %v", status, body)
	}
	var kind string
	if err := rp.rdb().QueryRowContext(rp.ctx, `SELECT kind FROM jobs WHERE id = ?`, id).Scan(&kind); err != nil || kind != "accounts.repair_reset" {
		t.Errorf("TC-321-54: the job's kind %q (%v)", kind, err)
	}
	if st, by := rp.jobStatus(id); st != "succeeded" || by != "break-glass" {
		t.Fatalf("TC-321-54: accounts.repair_reset %s by %s", st, by)
	}
	status, body = rp.post("/api/repair/reset", string(req), sess)
	if status != http.StatusForbidden || body["code"] != "repair_reset_used" {
		t.Errorf("TC-321-55: a second reset: %d %v, want 403 repair_reset_used", status, body)
	}
}

// tc55OnceAndState is TC-321-55: the alert row and the account's state.
func (rp *repairs) tc55OnceAndState() {
	t := rp.t
	a := rp.fixture
	if n := rp.count(`SELECT COUNT(*) FROM persisted_alerts WHERE labels LIKE ? AND title = ?`,
		`%"alertname":"BreakGlassSignInReset"%`, "A break-glass repair reset an administrator's sign-in."); n != 1 {
		t.Errorf("TC-321-55: %d reset alert rows, want 1", n)
	}
	var roles []map[string]any
	rp.get("/users/"+a.id+"/role-mappings/clients/"+rp.consoleClientID(), &roles)
	if len(roles) != 0 {
		t.Errorf("TC-321-55: console roles %v, want none", roles)
	}
	var u struct {
		Attributes      map[string][]string `json:"attributes"`
		RequiredActions []string            `json:"requiredActions"`
	}
	rp.get("/users/"+a.id, &u)
	if v := u.Attributes["rasputin_app_role"]; len(v) != 1 || v[0] != "user" {
		t.Errorf("TC-321-55: app access %v, want user", v)
	}
	for _, want := range []string{flows.ActionRecoveryCodes, flows.ActionUpdatePassword} {
		if !slices.Contains(u.RequiredActions, want) {
			t.Errorf("TC-321-55: required actions %v lack %s", u.RequiredActions, want)
		}
	}
	var creds []struct {
		Type string `json:"type"`
	}
	rp.get("/users/"+a.id+"/credentials", &creds)
	for _, c := range creds {
		if slices.Contains([]string{"otp", "webauthn", "webauthn-passwordless", "recovery-authn-codes"}, c.Type) {
			t.Errorf("TC-321-55: the fixture still holds %s", c.Type)
		}
	}
	var reason string
	if err := rp.rdb().QueryRowContext(rp.ctx, `SELECT reason FROM designations WHERE sub = ?`, a.id).Scan(&reason); err != nil || reason != "repair" {
		t.Errorf("TC-321-55: designation reason %q (%v), want repair", reason, err)
	}
	if n := rp.count(`SELECT COUNT(*) FROM console_sessions WHERE sub = ?`, a.id); n != 0 {
		t.Errorf("TC-321-55: %d console sessions of the fixture left", n)
	}
}

// tc56RoleBack is TC-321-56: the fixture chooses an authenticator app (the
// action added here stands in for its choice), signs in with the temporary
// password, sets a new one, enrols the app and saves codes, and then holds
// admin again with its designation gone.
func (rp *repairs) tc56RoleBack() {
	t := rp.t
	a := rp.fixture
	userPath := realmPath("/users/" + a.id)
	var rep map[string]any
	if _, err := rp.admin.Admin(rp.ctx, http.MethodGet, userPath, nil, &rep); err != nil {
		t.Fatal(err)
	}
	ras, _ := rep["requiredActions"].([]any)
	rep["requiredActions"] = append(ras, flows.ActionConfigureTOTP)
	if _, err := rp.admin.Admin(rp.ctx, http.MethodPut, userPath, rep, nil); err != nil {
		t.Fatalf("add the authenticator-app action: %v", err)
	}
	next, err := randomSecret(rp.s.cfg.Rand)
	if err != nil {
		t.Fatal(err)
	}
	a.next, a.secret = next, ""
	// The setup sign-in may end at the console or be refused there; the
	// grant that follows decides the role.
	_ = rp.signInAs(a)
	if a.secret == "" {
		t.Fatal("TC-321-56: the sign-in showed no authenticator app setup")
	}
	a.pw.Destroy()
	a.pw, a.next = next, secret.Value{}
	err = proctest.Await(rp.ctx, nil, func(ctx context.Context) (bool, string, error) {
		var roles []struct {
			Name string `json:"name"`
		}
		if _, err := rp.admin.Admin(ctx, http.MethodGet, realmPath("/users/"+a.id+"/role-mappings/clients/"+rp.consoleClientID()), nil, &roles); err != nil {
			return false, err.Error(), nil
		}
		held := slices.ContainsFunc(roles, func(r struct {
			Name string `json:"name"`
		}) bool {
			return r.Name == "admin"
		})
		var n int
		if err := rp.rdb().QueryRowContext(ctx, `SELECT COUNT(*) FROM designations WHERE sub = ?`, a.id).Scan(&n); err != nil {
			return false, err.Error(), nil
		}
		return held && n == 0, fmt.Sprintf("admin held %v, designation rows %d", held, n), nil
	}, func(last string) { rp.s.cfg.Logger.Info("repairs: waiting for the role to come back", "last", last) })
	if err != nil {
		t.Fatal(errNamed("TC-321-56: the fixture holds admin again and its designation is gone", err))
	}
	rp.s.awaitGrantDrained(rp.ctx, rp.admin, a.id)
	if err := rp.signInAs(a); err != nil {
		t.Fatalf("TC-321-56: the fixture's sign-in after the role came back: %v", err)
	}
}

// tc57Refused is TC-321-57: the console administrator removes one moved
// operator; while the realm holds accounts, the repair re-run is refused,
// not listed, and no alert shows. It returns the removed operator's name.
func (rp *repairs) tc57Refused() string {
	t := rp.t
	removed := repairOps[0]
	status, body := rp.post("/api/accounts/jobs", `{"kind":"accounts.delete","spec":{"accountId":"`+rp.opID(removed)+`"}}`, rp.fixture.session)
	id, _ := body["job"].(string)
	if status != http.StatusAccepted || id == "" {
		t.Fatalf("TC-321-57: accounts.delete: %d %v", status, body)
	}
	if st, _ := rp.jobStatus(id); st != "succeeded" {
		t.Fatalf("TC-321-57: accounts.delete %s", st)
	}
	rp.firstRunFalse("after the removal")
	sess := rp.open()
	status, body = rp.post("/api/repair/move", `{}`, sess)
	if status != http.StatusForbidden || body["code"] != "job_move_state" {
		t.Errorf("TC-321-57: the re-run while the realm holds accounts: %d %v, want 403 job_move_state", status, body)
	}
	if action(rp.state(sess), "move") != nil {
		t.Error("TC-321-57: the state lists the move while the realm holds accounts")
	}
	if rp.blankAlert() {
		t.Error("TC-321-57: identity:blank shows while the realm holds accounts")
	}
	if n := rp.count(`SELECT COUNT(*) FROM jobs WHERE kind = 'identity.move' AND created_by = 'break-glass'`); n != 0 {
		t.Errorf("TC-321-57: %d identity.move jobs by break-glass", n)
	}
	return removed
}

// blankAlert reports whether GET /api/alerts, read with the console
// administrator's kept session, lists identity:blank.
func (rp *repairs) blankAlert() bool {
	rp.t.Helper()
	status, b, _ := rp.call(rp.local, http.MethodGet, rp.origin+"/api/alerts", "", nil, rp.fixture.session)
	if status != http.StatusOK {
		rp.t.Fatalf("GET /api/alerts with the kept session: %d %s", status, b)
	}
	var list []struct {
		ID       string `json:"id"`
		Severity string `json:"severity"`
		Title    string `json:"title"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		rp.t.Fatalf("GET /api/alerts: %v: %s", err, b)
	}
	return slices.ContainsFunc(list, func(a struct {
		ID       string `json:"id"`
		Severity string `json:"severity"`
		Title    string `json:"title"`
	}) bool {
		return a.ID == "identity:blank" && strings.HasPrefix(a.Title, "Sign-in has lost its accounts")
	})
}

// tc58AlertAndConfirm is TC-321-58: every realm user is deleted; the alert
// shows, the state lists the move, and the re-run confirms the count and
// succeeds.
func (rp *repairs) tc58AlertAndConfirm() {
	t := rp.t
	var users []struct {
		ID string `json:"id"`
	}
	rp.get("/users?briefRepresentation=true&first=0&max=1000", &users)
	for _, u := range users {
		if _, err := rp.admin.Admin(rp.ctx, http.MethodDelete, realmPath("/users/"+u.ID), nil, nil); err != nil {
			t.Fatalf("delete a realm user: %v", err)
		}
	}
	rp.firstRunFalse("after the wipe")
	if !rp.blankAlert() {
		t.Error("TC-321-58: no identity:blank alert after the wipe")
	}
	sess := rp.open()
	if action(rp.state(sess), "move") == nil {
		t.Error("TC-321-58: the state doesn't list the move")
	}
	status, body := rp.post("/api/repair/move", `{}`, sess)
	token, _ := body["stateToken"].(string)
	if n, _ := body["accounts"].(float64); status != http.StatusConflict || int(n) != len(repairOps)-1 || token == "" {
		t.Fatalf("TC-321-58: no token: %d %v, want 409 with accounts %d", status, body, len(repairOps)-1)
	}
	if status, body = rp.post("/api/repair/move", `{"stateToken":"stale"}`, sess); status != http.StatusConflict || body["stateToken"] != token {
		t.Errorf("TC-321-58: a stale token: %d %v, want 409 with the current token", status, body)
	}
	rp.firstRunFalse("after the 409")
	status, body = rp.post("/api/repair/move", `{"stateToken":"`+token+`"}`, sess)
	id, _ := body["id"].(string)
	if status != http.StatusAccepted || id == "" {
		t.Fatalf("TC-321-58: confirmed: %d %v", status, body)
	}
	if st, by := rp.jobStatus(id); st != "succeeded" || by != "break-glass" {
		t.Fatalf("TC-321-58: identity.move %s by %s", st, by)
	}
	rp.firstRunFalse("after the move")
}

// tc59BroughtBack is TC-321-59: what came back, and the state closing.
func (rp *repairs) tc59BroughtBack(removed string) {
	t := rp.t
	for _, name := range repairOps {
		var u struct {
			Username   string              `json:"username"`
			Attributes map[string][]string `json:"attributes"`
		}
		_, err := rp.admin.Admin(rp.ctx, http.MethodGet, realmPath("/users/"+rp.opID(name)), nil, &u)
		if name == removed {
			if err == nil {
				t.Errorf("TC-321-59: the removed %s came back", name)
			}
			continue
		}
		if err != nil || u.Username != name {
			t.Errorf("TC-321-59: %s: %+v %v", name, u, err)
			continue
		}
		if v := u.Attributes["rasputin_app_role"]; len(v) != 1 || v[0] != "user" {
			t.Errorf("TC-321-59: %s app access %v", name, v)
		}
		var creds []map[string]any
		rp.get("/users/"+rp.opID(name)+"/credentials", &creds)
		if len(creds) != 0 {
			t.Errorf("TC-321-59: %s holds %d credentials", name, len(creds))
		}
		var reason string
		if err := rp.rdb().QueryRowContext(rp.ctx, `SELECT reason FROM designations WHERE sub = ?`, rp.opID(name)).Scan(&reason); err != nil || reason != "moved" {
			t.Errorf("TC-321-59: %s designation %q (%v)", name, reason, err)
		}
	}
	if rp.blankAlert() {
		t.Error("TC-321-59: identity:blank still shows")
	}
	sess := rp.open()
	if action(rp.state(sess), "move") != nil {
		t.Error("TC-321-59: the state still lists the move")
	}
	status, body := rp.post("/api/repair/move", `{"stateToken":"any"}`, sess)
	if status != http.StatusForbidden || body["code"] != "job_move_state" {
		t.Errorf("TC-321-59: a second re-run: %d %v, want 403 job_move_state", status, body)
	}
}

// tc60OtherSessions is TC-321-60: only the live repair session reaches the
// re-run.
func (rp *repairs) tc60OtherSessions() {
	t := rp.t
	before := rp.count(`SELECT COUNT(*) FROM jobs`)
	if status, _ := rp.post("/api/repair/move", `{}`, rp.fixture.session); status != http.StatusUnauthorized {
		t.Errorf("TC-321-60: a console session on /api/repair/move: %d, want 401", status)
	}
	status, body := rp.post("/api/jobs", `{"kind":"identity.move","spec":{"repair":true,"stateToken":"x"}}`, rp.fixture.session)
	if status != http.StatusForbidden || body["code"] != "job_system_only" {
		t.Errorf("TC-321-60: POST /api/jobs identity.move by a console session: %d %v, want 403 job_system_only", status, body)
	}
	old := rp.open()
	rp.open() // a newer redemption
	if status, _ := rp.post("/api/repair/move", `{}`, old); status != http.StatusUnauthorized {
		t.Errorf("TC-321-60: a replaced repair session: %d, want 401", status)
	}
	if after := rp.count(`SELECT COUNT(*) FROM jobs`); after != before {
		t.Errorf("TC-321-60: the jobs table went from %d rows to %d", before, after)
	}
}

// rdb is one read-only handle on rasputin.db for the whole run, so the
// polls below don't each open one.
func (rp *repairs) rdb() *sql.DB {
	if rp.dbh == nil {
		rp.dbh = rp.db()
	}
	return rp.dbh
}
