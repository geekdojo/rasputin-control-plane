package auth

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth/idtoken"
	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// fakeResetExchanger answers ExchangeAccessToken with token, or err.
type fakeResetExchanger struct {
	mu    sync.Mutex
	token string
	err   error
	calls int
	last  idclient.CodeExchange
	code  string
}

func (x *fakeResetExchanger) ExchangeAccessToken(_ context.Context, c idclient.CodeExchange) (secret.Value, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.calls++
	x.last, x.code = c, string(c.Code.Reveal())
	if x.err != nil {
		return secret.Value{}, x.err
	}
	return secret.New([]byte(x.token)), nil
}

// fakeIdentity records EndAll and EndOffline.
type fakeIdentity struct {
	mu                sync.Mutex
	all, offline      []string
	allErr, offlineEr error
}

func (f *fakeIdentity) EndAll(_ context.Context, sub string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.all = append(f.all, sub)
	return f.allErr
}

func (f *fakeIdentity) EndOffline(_ context.Context, sub string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.offline = append(f.offline, sub)
	return 1, f.offlineEr
}

// failingConsole is a console ender that fails.
type failingConsole struct{}

func (failingConsole) EndBySub(context.Context, string) (int64, error) { return 0, errTest }

// resetRig is one door's ResetDone over a real verifier on the test
// issuer, the auth fixture's console sessions and fakes.
type resetRig struct {
	f      *authFixture
	door   doors.Door
	client string
	is     *testIssuer
	ex     *fakeResetExchanger
	id     *fakeIdentity
	rd     *ResetDone
	log    *logkittest.Recorder
}

func newResetRig(t *testing.T, app bool, console ConsoleEnder) *resetRig {
	t.Helper()
	f := newAuthFixture(t)
	table, err := doors.New(rigCID)
	if err != nil {
		t.Fatal(err)
	}
	r := &resetRig{f: f, door: table.Home, client: "rasputin-reset-home", is: newTestIssuer(t), ex: &fakeResetExchanger{}, id: &fakeIdentity{}}
	name := "home"
	if app {
		r.door, r.client, name = table.App, "rasputin-reset-app", "app"
	}
	v, err := idtoken.New(t.Context(), r.door.Issuer, r.client, r.is.keyClient(), f.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	if console == nil {
		console = f.sessions
	}
	log, rec := logkittest.New()
	r.log = rec
	r.rd, err = NewResetDone(ResetDoneDeps{Door: r.door, DoorName: name, ClientID: r.client, RedirectURI: "https://" + r.door.Host + ResetDonePath,
		Realm: "rasputin", Exchanger: r.ex, Verifier: v, Identity: r.id, Console: console, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// access is a valid access token's claims for the rig's client.
func (r *resetRig) access(edit func(map[string]any)) map[string]any {
	now := r.f.clock.Now()
	c := map[string]any{"iss": r.door.Issuer, "sub": rigSub, "aud": "account", "azp": r.client, "typ": "Bearer",
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()}
	if edit != nil {
		edit(c)
	}
	return c
}

func (r *resetRig) query() url.Values {
	return url.Values{"code": {"reset-code-1"}, "iss": {r.door.Issuer}, "session_state": {"ss"}}
}

func (r *resetRig) events(ev string) []slog.Record {
	var out []slog.Record
	for _, rec := range r.log.Records() {
		if got, _ := logkittest.Attr(rec, "event"); got == ev {
			out = append(out, rec)
		}
	}
	return out
}

// noSecrets fails when a fixture value reaches the log (TC-992-11).
func (r *resetRig) noSecrets(t *testing.T, extra ...string) {
	t.Helper()
	text := r.log.Text()
	for _, s := range append([]string{"reset-code-1", "session_state", "ss=", r.ex.token}, extra...) {
		if s != "" && strings.Contains(text, s) {
			t.Errorf("the log holds %q", s)
		}
	}
}

func cookieless(t *testing.T, w http.ResponseWriter) {
	t.Helper()
	if rw, ok := w.(interface{ Header() http.Header }); ok && rw.Header().Get("Set-Cookie") != "" {
		t.Errorf("Set-Cookie %q, want none", rw.Header().Get("Set-Cookie"))
	}
}

// TC-992-07 and TC-992-11: every refusal, at each door, is reset-failed
// with one WARN reset.refused carrying its reason and door; no session ends
// and no cookie is set; nothing secret is logged.
func TestResetDone_TC992_07_Refusals(t *testing.T) {
	for _, app := range []bool{false, true} {
		cases := []struct {
			name, reason string
			q            func(r *resetRig) url.Values
			claims       func(map[string]any)
			exErr        error
		}{
			{name: "error parameter", reason: "door_error", q: func(r *resetRig) url.Values { q := r.query(); q.Set("error", "access_denied"); return q }},
			{name: "no iss", reason: "iss", q: func(r *resetRig) url.Values { q := r.query(); q.Del("iss"); return q }},
			{name: "two iss", reason: "iss", q: func(r *resetRig) url.Values { q := r.query(); q.Add("iss", r.door.Issuer); return q }},
			{name: "wrong iss", reason: "iss", q: func(r *resetRig) url.Values { q := r.query(); q.Set("iss", "https://elsewhere"); return q }},
			{name: "no code", reason: "code", q: func(r *resetRig) url.Values { q := r.query(); q.Del("code"); return q }},
			{name: "two codes", reason: "code", q: func(r *resetRig) url.Values { q := r.query(); q.Add("code", "x"); return q }},
			{name: "empty code", reason: "code", q: func(r *resetRig) url.Values { q := r.query(); q.Set("code", ""); return q }},
			{name: "exchange refused", reason: "exchange", exErr: invalidGrant()},
			{name: "foreign iss", reason: "token", claims: func(c map[string]any) { c["iss"] = "https://elsewhere" }},
			{name: "console azp", reason: "token", claims: func(c map[string]any) { c["azp"] = "rasputin-console" }},
			{name: "empty sub", reason: "token", claims: func(c map[string]any) { c["sub"] = "" }},
			{name: "an ID token", reason: "token", claims: func(c map[string]any) { c["typ"] = "ID" }},
		}
		for _, tc := range cases {
			t.Run(map[bool]string{false: "home ", true: "app "}[app]+tc.name, func(t *testing.T) {
				r := newResetRig(t, app, nil)
				r.ex.token, r.ex.err = r.is.sign(t, r.access(tc.claims)), tc.exErr
				q := r.query()
				if tc.q != nil {
					q = tc.q(r)
				}
				outcome, sentence := r.rd.Finish(t.Context(), q)
				if outcome != ResetOutcomeFailed || sentence != resetSentences[ResetOutcomeFailed] {
					t.Errorf("Finish = %s %q", outcome, sentence)
				}
				recs := r.events("reset.refused")
				if len(recs) != 1 || recs[0].Level != slog.LevelWarn {
					t.Fatalf("log %s", r.log.Text())
				}
				reason, _ := logkittest.Attr(recs[0], "reason")
				door, _ := logkittest.Attr(recs[0], "door")
				if reason != tc.reason || door != map[bool]string{false: "home", true: "app"}[app] {
					t.Errorf("reason %s door %s, want %s", reason, door, tc.reason)
				}
				if len(r.id.all)+len(r.id.offline) != 0 {
					t.Error("a session ender ran on a refusal")
				}
				r.noSecrets(t)
			})
		}
	}
	t.Run("home answers 303 to the launcher with no cookie", func(t *testing.T) {
		r := newResetRig(t, false, nil)
		w := serve(r.rd, rigConsole, ResetDonePath+"?error=x")
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login?signin=reset-failed" {
			t.Errorf("answer %d %s", w.Code, w.Header().Get("Location"))
		}
		cookieless(t, w)
	})
}

// TC-992-08: an exchange the identity service did not answer, or keys it
// did not serve, are reset-failed with ERROR reset.exchange_failed and kind.
func TestResetDone_TC992_08_DependencyDown(t *testing.T) {
	r := newResetRig(t, false, nil)
	r.ex.err = unreachable()
	if out, _ := r.rd.Finish(t.Context(), r.query()); out != ResetOutcomeFailed {
		t.Errorf("unreachable exchange: %s", out)
	}
	r2 := newResetRig(t, true, nil)
	r2.ex.token = r2.is.sign(t, r2.access(nil))
	r2.is.down.Store(true)
	if out, _ := r2.rd.Finish(t.Context(), r2.query()); out != ResetOutcomeFailed {
		t.Errorf("keys down: %s", out)
	}
	for rig, want := range map[*resetRig]string{r: "unreachable", r2: "keys"} {
		recs := rig.events("reset.exchange_failed")
		if len(recs) != 1 || recs[0].Level != slog.LevelError {
			t.Fatalf("log %s", rig.log.Text())
		}
		if k, _ := logkittest.Attr(recs[0], "kind"); k != want {
			t.Errorf("kind %s, want %s", k, want)
		}
		rig.noSecrets(t)
	}
}

// TC-992-09: a valid return ends the verified person's identity sessions,
// online then offline, and their console sessions, once each; the home door
// answers 303 /login?signin=reset-done with no cookie, the app door's sentence
// is the done one; no console row remains; INFO reset.done carries sub and
// door. The exchange carries no verifier, the reset client and its redirect.
func TestResetDone_TC992_09_Success(t *testing.T) {
	r := newResetRig(t, false, nil)
	consoleCookie(t, r.f, Principal{Sub: rigSub, Name: "alice"})
	r.ex.token = r.is.sign(t, r.access(nil))
	w := serve(r.rd, rigConsole, ResetDonePath+"?"+r.query().Encode())
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login?signin=reset-done" {
		t.Errorf("answer %d %s", w.Code, w.Header().Get("Location"))
	}
	cookieless(t, w)
	if len(r.id.all) != 1 || r.id.all[0] != rigSub || len(r.id.offline) != 1 || r.id.offline[0] != rigSub {
		t.Errorf("EndAll %v EndOffline %v", r.id.all, r.id.offline)
	}
	if n := r.f.countRows(t, "console_sessions"); n != 0 {
		t.Errorf("%d console sessions remain", n)
	}
	x := r.ex.last
	if !x.NoVerifier || x.Verifier.Len() != 0 || x.ClientID != "rasputin-reset-home" || x.RedirectURI != "https://"+r.door.Host+ResetDonePath || x.Forward == nil {
		t.Errorf("exchange %+v", x)
	}
	recs := r.events("reset.done")
	if len(recs) != 1 || recs[0].Level != slog.LevelInfo {
		t.Fatalf("log %s", r.log.Text())
	}
	if sub, _ := logkittest.Attr(recs[0], "sub"); sub != rigSub {
		t.Errorf("sub %s", sub)
	}
	r.noSecrets(t)

	app := newResetRig(t, true, nil)
	app.ex.token = app.is.sign(t, app.access(nil))
	out, sentence := app.rd.Finish(t.Context(), app.query())
	if out != ResetOutcomeDone || sentence != "Your password is changed. Sign in with it and your second step." {
		t.Errorf("app door: %s %q", out, sentence)
	}
	if d, _ := logkittest.Attr(app.events("reset.done")[0], "door"); d != "app" {
		t.Errorf("door %s", d)
	}
}

// TC-992-10: an identity end or the console end failing is
// reset-incomplete, with ERROR reset.sessions_not_ended carrying sub, door
// and err; the remaining ends still run.
func TestResetDone_TC992_10_EndFailure(t *testing.T) {
	const incomplete = "Your password is changed, but Rasputin couldn't end your other sign-ins. Ask an administrator to sign you out everywhere."
	for name, setup := range map[string]func(r *resetRig){
		"online":  func(r *resetRig) { r.id.allErr = errTest },
		"offline": func(r *resetRig) { r.id.offlineEr = errTest },
	} {
		t.Run(name, func(t *testing.T) {
			r := newResetRig(t, false, nil)
			setup(r)
			r.ex.token = r.is.sign(t, r.access(nil))
			out, sentence := r.rd.Finish(t.Context(), r.query())
			if out != ResetOutcomeIncomplete || sentence != incomplete {
				t.Errorf("Finish = %s %q", out, sentence)
			}
			if len(r.id.all) != 1 || len(r.id.offline) != 1 {
				t.Errorf("EndAll %d EndOffline %d, want each once", len(r.id.all), len(r.id.offline))
			}
			checkNotEnded(t, r)
		})
	}
	t.Run("console", func(t *testing.T) {
		r := newResetRig(t, true, failingConsole{})
		r.ex.token = r.is.sign(t, r.access(nil))
		if out, _ := r.rd.Finish(t.Context(), r.query()); out != ResetOutcomeIncomplete {
			t.Errorf("Finish = %s", out)
		}
		checkNotEnded(t, r)
	})
}

func checkNotEnded(t *testing.T, r *resetRig) {
	t.Helper()
	recs := r.events("reset.sessions_not_ended")
	if len(recs) != 1 || recs[0].Level != slog.LevelError {
		t.Fatalf("log %s", r.log.Text())
	}
	for _, k := range []string{"sub", "door", "err", "step"} {
		if v, ok := logkittest.Attr(recs[0], k); !ok || v == "" {
			t.Errorf("reset.sessions_not_ended has no %s", k)
		}
	}
	if len(r.events("reset.done")) != 0 {
		t.Error("reset.done logged on an incomplete reset")
	}
	r.noSecrets(t)
}

// TC-992-12: each door's reset start names its own reset client and the
// escaped reset-done URL.
func TestResetStartURL_TC992_12(t *testing.T) {
	table, _ := doors.New(rigCID)
	for _, c := range []struct {
		door            doors.Door
		client, return_ string
	}{
		{table.Home, "rasputin-reset-home", "https://ci.local/api/auth/reset-done"},
		{table.App, "rasputin-reset-app", "https://" + table.App.Host + "/api/auth/reset-done"},
	} {
		got := ResetStartURL(c.door, c.client, c.return_)
		want := c.door.Issuer + "/login-actions/reset-credentials?client_id=" + c.client + "&redirect_uri=" + url.QueryEscape(c.return_)
		if got != want {
			t.Errorf("ResetStartURL = %s, want %s", got, want)
		}
		u, _ := url.Parse(got)
		if u.Query().Get("client_id") == "" || u.Query().Get("redirect_uri") == "" {
			t.Errorf("%s misses a parameter", got)
		}
	}
}

// The home route answers reset-failed until a ResetDone is installed, and
// runs it once installed; NewResetDone refuses a missing collaborator.
func TestService_ResetDoneRoute(t *testing.T) {
	r := newSigninRig(t)
	w := r.get(ResetDonePath+"?code=c", rigConsole)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login?signin=reset-failed" {
		t.Errorf("uninstalled: %d %s", w.Code, w.Header().Get("Location"))
	}
	rr := newResetRig(t, false, nil)
	r.f.svc.SetResetDone(rr.rd)
	rr.ex.token = rr.is.sign(t, rr.access(nil))
	w = r.get(ResetDonePath+"?"+rr.query().Encode(), rigConsole)
	if w.Header().Get("Location") != "/login?signin=reset-done" {
		t.Errorf("installed: %d %s", w.Code, w.Header().Get("Location"))
	}
	if _, err := NewResetDone(ResetDoneDeps{}); err == nil {
		t.Error("NewResetDone accepted nothing")
	}
	d := rr.rd.d
	d.Console = nil
	if _, err := NewResetDone(d); err == nil {
		t.Error("NewResetDone accepted a nil console")
	}
	d = rr.rd.d
	d.RedirectURI = ""
	if _, err := NewResetDone(d); err == nil {
		t.Error("NewResetDone accepted no redirect URI")
	}
}
