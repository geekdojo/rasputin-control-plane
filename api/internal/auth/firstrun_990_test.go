package auth

import (
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"testing"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// The first-run predicate and its claim (geekdojo/geekdojo-brain#990).

func (f *authFixture) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := f.store.db.ExecContext(f.ctx, q, args...); err != nil {
		t.Fatal(err)
	}
}

func (f *authFixture) claimed(t *testing.T) []string {
	t.Helper()
	rows, err := f.store.db.QueryContext(f.ctx, `SELECT sub FROM first_admin`)
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

func (f *authFixture) designated(t *testing.T) int { return f.countRows(t, "test_designations") }

// TC-990-02: C03's predicate, both clauses in one statement: empty tables
// are first run; a first_admin row, a users row or both are not; either
// table unreadable is (false, err), never first run.
func TestStoreFirstRun_TC990_02_Table(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T, f *authFixture)
		want    bool
		wantErr bool
	}{
		{"(a) empty", func(*testing.T, *authFixture) {}, true, false},
		{"(b) a first_admin row", func(t *testing.T, f *authFixture) {
			f.exec(t, `INSERT INTO first_admin (id, sub, claimed_at) VALUES (1, 'a', 0)`)
		}, false, false},
		{"(c) a users row", func(t *testing.T, f *authFixture) { f.mintUser(t, "op") }, false, false},
		{"(d) both", func(t *testing.T, f *authFixture) {
			f.exec(t, `INSERT INTO first_admin (id, sub, claimed_at) VALUES (1, 'a', 0)`)
			f.mintUser(t, "op")
		}, false, false},
		{"(e) first_admin dropped", func(t *testing.T, f *authFixture) { f.exec(t, `DROP TABLE first_admin`) }, false, true},
		{"(f) users dropped", func(t *testing.T, f *authFixture) { f.exec(t, `DROP TABLE users`) }, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newAuthFixture(t)
			c.setup(t, f)
			got, err := f.store.FirstRun(f.ctx)
			if got != c.want || (err != nil) != c.wantErr {
				t.Errorf("FirstRun = %v, %v; want %v, error %v", got, err, c.want, c.wantErr)
			}
			if svc, err := f.svc.FirstRun(f.ctx); svc != got || (err != nil) != c.wantErr {
				t.Errorf("Service.FirstRun = %v, %v; want the store's", svc, err)
			}
			if !c.wantErr {
				return
			}
			// The status route answers 500 and reports no firstRun.
			w := get(f.handler(), "/api/auth/status")
			if w.Code != http.StatusInternalServerError {
				t.Errorf("status answered %d on an unreadable table", w.Code)
			}
		})
	}
}

// TC-990-02: a first-run read error at the callback is not first run: a
// plain session is minted, nothing is claimed, and one WARN
// firstrun.unreadable is written.
func TestComplete_TC990_02_FirstRunUnreadable(t *testing.T) {
	r := newSigninRig(t)
	r.first.set(true, errTest)
	w := r.signIn(t, nil)
	if sessionFrom(w) == nil || w.Header().Get("Location") != "/login" {
		t.Fatalf("no session minted: %d %s", w.Code, w.Header().Get("Location"))
	}
	if len(r.f.claimed(t)) != 0 || r.f.designated(t) != 0 || r.claimer.calls != 0 {
		t.Errorf("claimed %v, designated %d, Earliest called %d times", r.f.claimed(t), r.f.designated(t), r.claimer.calls)
	}
	if recs := r.events("firstrun.unreadable"); len(recs) != 1 || recs[0].Level != slog.LevelWarn {
		t.Errorf("firstrun.unreadable records: %v", recs)
	}
}

// TC-990-31: a database the previous release made has no first_admin
// table; opening the store creates it, and the predicate then reads the
// users table as before.
func TestOpenStore_TC990_31_Upgrade(t *testing.T) {
	for _, withUser := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "rasputin.db")
		prev, err := OpenStore(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := prev.db.Exec(`DROP TABLE first_admin`); err != nil {
			t.Fatal(err)
		}
		if withUser {
			if _, err := prev.db.Exec(`INSERT INTO users (id, name, display_name, created_at) VALUES (x'00', 'op', 'Op', 0)`); err != nil {
				t.Fatal(err)
			}
		}
		if err := prev.Close(); err != nil {
			t.Fatal(err)
		}
		st, err := OpenStore(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		var n int
		if err := st.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'first_admin'`).Scan(&n); err != nil || n != 1 {
			t.Errorf("first_admin after the upgrade: %d tables, %v", n, err)
		}
		first, err := st.FirstRun(t.Context())
		if err != nil || first == withUser {
			t.Errorf("with a users row %v: FirstRun = %v, %v", withUser, first, err)
		}
		_ = st.Close()
	}
}

// TC-990-07: first run held when the callback read it, then the users
// table can't be read inside the claim's transaction: nothing commits (no
// claim, no designation, no session), and the callback answers 500 with
// ERROR signin.store_failed.
func TestCreateWithClaim_TC990_07_UsersUnreadableAbortsAll(t *testing.T) {
	r := newSigninRig(t)
	r.first.set(true, nil)
	r.f.exec(t, `DROP TABLE users`)
	w := r.signIn(t, nil)
	if w.Code != http.StatusInternalServerError || sessionFrom(w) != nil {
		t.Errorf("callback answered %d with session %v, want 500 and none", w.Code, sessionFrom(w))
	}
	if len(r.f.claimed(t)) != 0 || r.f.designated(t) != 0 || r.f.countRows(t, "console_sessions") != 0 {
		t.Errorf("claim %v, designations %d, sessions %d: want none", r.f.claimed(t), r.f.designated(t), r.f.countRows(t, "console_sessions"))
	}
	if recs := r.events("signin.store_failed"); len(recs) != 1 || recs[0].Level != slog.LevelError {
		t.Errorf("signin.store_failed records: %v", recs)
	}
	// A designation that fails rolls the claim and the session back too.
	r2 := newSigninRig(t)
	r2.first.set(true, nil)
	r2.f.des.err = errTest
	if w := r2.signIn(t, nil); w.Code != http.StatusInternalServerError {
		t.Errorf("a failed designation answered %d", w.Code)
	}
	if len(r2.f.claimed(t)) != 0 || r2.f.countRows(t, "console_sessions") != 0 {
		t.Error("a failed designation left a claim or a session")
	}
}

// TC-990-09: Complete's claim rules, with fakes.
func TestComplete_TC990_09_ClaimRules(t *testing.T) {
	t.Run("(a) first run: the claim names Earliest's person, not the caller; (d) INFO firstrun.claimed", func(t *testing.T) {
		r := newSigninRig(t)
		r.first.set(true, nil)
		w := r.signIn(t, nil)
		if sessionFrom(w) == nil {
			t.Fatalf("no session: %d", w.Code)
		}
		if got := r.f.claimed(t); !slices.Equal(got, []string{"sub-earliest"}) {
			t.Errorf("first_admin %v, want Earliest's person, not %s", got, rigSub)
		}
		if r.f.designated(t) != 1 {
			t.Errorf("%d designations, want 1", r.f.designated(t))
		}
		recs := r.events("firstrun.claimed")
		if len(recs) != 1 || recs[0].Level != slog.LevelInfo {
			t.Fatalf("firstrun.claimed records %v", recs)
		}
		if sub, _ := logkittest.Attr(recs[0], "sub"); sub != "sub-earliest" {
			t.Errorf("firstrun.claimed sub %q", sub)
		}
		// The next callback finds first run over in the table itself.
		if w := r.signIn(t, nil); sessionFrom(w) == nil || len(r.f.claimed(t)) != 1 || len(r.events("firstrun.claimed")) != 1 {
			t.Error("a second callback claimed again")
		}
	})
	t.Run("(b) not first run: no claim, Earliest not asked", func(t *testing.T) {
		r := newSigninRig(t)
		if w := r.signIn(t, nil); sessionFrom(w) == nil {
			t.Fatal("no session")
		}
		if len(r.f.claimed(t)) != 0 || r.claimer.calls != 0 || len(r.events("firstrun.claimed")) != 0 {
			t.Errorf("claimed %v, Earliest called %d", r.f.claimed(t), r.claimer.calls)
		}
	})
	t.Run("(c) an Earliest error mints the session with no claim; WARN with status and kind, no person data", func(t *testing.T) {
		r := newSigninRig(t)
		r.first.set(true, nil)
		r.claimer.err = &idclient.Error{Op: "admin", Path: "/admin/realms/rasputin/users", Status: 503, Kind: idclient.ErrUnreachable}
		w := r.signIn(t, func(c map[string]any) { delete(c, "rasputin_roles") })
		if sessionFrom(w) == nil {
			t.Fatal("no session")
		}
		if len(r.f.claimed(t)) != 0 || r.f.designated(t) != 0 {
			t.Error("an Earliest error claimed")
		}
		recs := r.events("firstrun.claim_aborted")
		if len(recs) != 1 || recs[0].Level != slog.LevelWarn {
			t.Fatalf("firstrun.claim_aborted records %v", recs)
		}
		if st, _ := logkittest.Attr(recs[0], "status"); st != "503" {
			t.Errorf("status attr %q", st)
		}
		if k, _ := logkittest.Attr(recs[0], "kind"); k != "unreachable" {
			t.Errorf("kind attr %q", k)
		}
		for _, k := range []string{"sub", "err", "path"} {
			if v, ok := logkittest.Attr(recs[0], k); ok {
				t.Errorf("the record carries %s=%q", k, v)
			}
		}
		p := r.resolve(t, sessionFrom(w))
		if len(p.Roles) != 0 {
			t.Errorf("the session holds %v", p.Roles)
		}
	})
	t.Run("(e) the Observer is told once on the session path and once on the action path", func(t *testing.T) {
		r := newSigninRig(t)
		r.signIn(t, nil)
		if got := r.observer.seen(); !slices.Equal(got, []string{rigSub}) {
			t.Fatalf("session path: observer saw %v", got)
		}
		pending := r.prepare(t, rigSub, "test-action", nil)
		req := httptestRequest(rigConsole, "/settings/act")
		req.AddCookie(pending)
		req = req.WithContext(WithPrincipal(req.Context(), Principal{Sub: rigSub, Name: "alice"}))
		sw := recorder()
		r.si.StartAction(sw, req, "test-action")
		loc, _ := url.Parse(sw.Header().Get("Location"))
		b := begun{q: loc.Query(), loc: loc}
		for _, c := range sw.Result().Cookies() {
			if c.Name == pendingCookieName {
				b.pending = c
			}
		}
		r.ex.set(r.is.sign(t, r.idClaims(b)), nil)
		r.callback(r.callbackQuery(b, "c2"), b.pending)
		if r.action.count() != 1 {
			t.Fatalf("the action ran %d times", r.action.count())
		}
		if got := r.observer.seen(); !slices.Equal(got, []string{rigSub, rigSub}) {
			t.Errorf("after the action: observer saw %v", got)
		}
	})
}

// resolve is the Principal a session cookie names.
func (r *signinRig) resolve(t *testing.T, c *http.Cookie) Principal {
	t.Helper()
	p, ok, err := r.f.sessions.Resolve(r.f.ctx, secretOf(c))
	if err != nil || !ok {
		t.Fatalf("resolve: %v %v", ok, err)
	}
	return p
}

// TC-990-26: GET /api/auth/signup sends the browser to the home door with
// prompt=create, the console's client, PKCE and a new pending cookie; with
// no sign-in, to the launcher's unavailable sentence.
func TestSignup_TC990_26(t *testing.T) {
	r := newSigninRig(t)
	b := r.beginAt(t, "/api/auth/signup")
	if !slices.Equal(b.q["prompt"], []string{"create"}) || b.q.Get("client_id") != "rasputin-console" ||
		b.q.Get("code_challenge_method") != "S256" || b.q.Get("code_challenge") == "" ||
		b.loc.Scheme+"://"+b.loc.Host+b.loc.Path != r.door.Issuer+"/protocol/openid-connect/auth" {
		t.Errorf("signup Location %s", b.loc)
	}
	if b.pending == nil || b.pending.Value == "" {
		t.Error("no pending cookie")
	}
	// The sign-up's return is an ordinary sign-in at the callback.
	r.ex.set(r.is.sign(t, r.idClaims(b)), nil)
	if w := r.callback(r.callbackQuery(b, "c"), b.pending); sessionFrom(w) == nil {
		t.Errorf("the sign-up's callback minted no session: %d", w.Code)
	}
	if b := r.begin(t); !slices.Equal(b.q["prompt"], []string{"login"}) {
		t.Errorf("sign-in prompt %v", b.q["prompt"])
	}

	f := newAuthFixture(t)
	if loc := get(f.handler(), "/api/auth/signup").Header().Get("Location"); loc != "/login?signin=unavailable" {
		t.Errorf("no sign-in: signup -> %q", loc)
	}
}

// TC-990-06: register/begin, step-up and finish are gone: 404 each.
func TestRegisterRoutes_TC990_06_Gone(t *testing.T) {
	f := newAuthFixture(t)
	for _, p := range []string{"/api/auth/register/begin", "/api/auth/register/step-up", "/api/auth/register/finish"} {
		if w := post(f.handler(), p, `{"name":"alice"}`); w.Code != http.StatusNotFound {
			t.Errorf("POST %s: %d, want 404", p, w.Code)
		}
	}
}

// NewSignIn refuses a missing first-run collaborator.
func TestNewSignIn_TC990_09_RefusesMissingClaimDeps(t *testing.T) {
	r := newSigninRig(t)
	for name, mut := range map[string]func(*SignInDeps){
		"FirstRun": func(d *SignInDeps) { d.FirstRun = nil },
		"Claimer":  func(d *SignInDeps) { d.Claimer = nil },
		"Observer": func(d *SignInDeps) { d.Observer = nil },
	} {
		d := r.si.d
		mut(&d)
		if _, err := NewSignIn(d); err == nil {
			t.Errorf("NewSignIn with no %s succeeded", name)
		}
	}
}

// CreateWithClaim refuses a claim with no subject and a session with none.
func TestCreateWithClaim_RefusesEmpty(t *testing.T) {
	f := newAuthFixture(t)
	if _, _, err := f.sessions.CreateWithClaim(f.ctx, Principal{Sub: "a", Session: SessionRef{SID: "s"}}, &Claim{}); err == nil {
		t.Error("an empty claim was accepted")
	}
	if _, _, err := f.sessions.CreateWithClaim(f.ctx, Principal{}, nil); err == nil {
		t.Error("a session with no subject was accepted")
	}
}
