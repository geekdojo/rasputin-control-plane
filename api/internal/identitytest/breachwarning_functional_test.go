package identitytest

// The breached-password warning against the real identity service
// (geekdojo/geekdojo-brain#1145, PR 2; TC-1145-38 to TC-1145-40): the
// sign-in rules rig's doors ask a real breachcheck.Checker, pointed at a
// local TLS stand-in for the range API that lists one synthetic phrase, and
// the cases drive the door's warning page, its own link and its own Keep
// form, through the pinned Keycloak. CI never calls the live range API.
//
// They run as subtests of TestSignInRules_AgainstPinnedKeycloak, which
// skips without the identity service and fails instead under
// RASPUTIN_IDENTITY_FUNCTIONAL=required.

import (
	"context"
	"encoding/json"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/breachcheck"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The one phrase the range stub lists: 15 characters or more, and on no
// deny list. Its SHA-1 is precomputed, so no test here hashes anything.
const (
	breachPhrase     = "ochre-lantern-quiver-1145"
	breachPhraseHash = "E23E7E4700629B976470C1E539258FCBBDD3092E"
	breachPrefix     = "E23E7"
	breachSuffix     = "E4700629B976470C1E539258FCBBDD3092E"
)

// neverListed is the breach check for the rigs whose cases are not about
// it: it lists nothing.
type neverListed struct{}

func (neverListed) Listed(context.Context, secret.Value) (bool, error) { return false, nil }

// rangeRequest is one request the range stub received.
type rangeRequest struct {
	method, path, query, padding string
}

// rangeStub is the local TLS stand-in for the range API: the phrase's
// suffix with a count above 0 under its prefix, padding (count 0) under
// every prefix.
type rangeStub struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []rangeRequest
}

func newRangeStub(t *testing.T) *rangeStub {
	t.Helper()
	s := &rangeStub{}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.reqs = append(s.reqs, rangeRequest{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Add-Padding")})
		s.mu.Unlock()
		body := "0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0\r\n"
		if strings.EqualFold(strings.TrimPrefix(r.URL.Path, "/range/"), breachPrefix) {
			body += breachSuffix + ":42\r\n"
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

// checker is a real breachcheck.Checker against the stub.
func (s *rangeStub) checker(t *testing.T) *breachcheck.Checker {
	t.Helper()
	base, err := url.Parse(s.srv.URL + "/range")
	if err != nil {
		t.Fatal(err)
	}
	c, err := breachcheck.New(breachcheck.Config{Client: s.srv.Client(), Base: base, CallTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (s *rangeStub) since(n int) []rangeRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]rangeRequest(nil), s.reqs[n:]...)
}

func (s *rangeStub) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.reqs)
}

// isWarning reports whether the answer is the door's warning page.
func isWarning(a doorAnswer) bool { return a.pageID() == "rasputin-door-warning" }

var chooseRE = regexp.MustCompile(`id="rasputin-choose-another" href="([^"]*)"`)

// chooseAnother follows the warning page's choose-another link exactly as
// rendered.
func chooseAnother(t *testing.T, g *goClient, warn doorAnswer) doorAnswer {
	t.Helper()
	m := chooseRE.FindSubmatch(warn.body)
	if m == nil {
		t.Fatalf("the warning page has no choose-another link")
	}
	u, err := warn.at.Parse(html.UnescapeString(string(m[1])))
	if err != nil {
		t.Fatal(err)
	}
	return g.follow(u.String())
}

// keep submits the warning page's own Keep form as rendered: its action
// and its hidden inputs, nothing the test builds.
func (r *rulesRig) keep(t *testing.T, g *goClient, warn doorAnswer) doorAnswer {
	t.Helper()
	return r.post(t, g, warn, "rasputin-keep-form", nil)
}

// usersNamed is the Admin API's exact lookup of name.
func (r *rulesRig) usersNamed(t *testing.T, name string) []map[string]any {
	t.Helper()
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "/users?exact=true&username="+name, nil)
	var users []map[string]any
	if err := json.Unmarshal(out, &users); err != nil {
		t.Fatal(err)
	}
	return users
}

// temporaryAccount is an account whose password an administrator set as
// temporary, and that password.
func (r *rulesRig) temporaryAccount(t *testing.T, name string) (account, secret.Value) {
	t.Helper()
	a := r.account(t, name, nil)
	temp, err := randomSecret(r.env.h.cfg.Rand)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(temp.Destroy)
	r.admin(t).must(http.StatusNoContent, http.MethodPut, "/users/"+a.id+"/reset-password",
		map[string]any{"type": "password", "value": string(temp.Reveal()), "temporary": true})
	return a, temp
}

// postPhrase posts the listed phrase on the UPDATE_PASSWORD page.
func (r *rulesRig) postPhrase(t *testing.T, g *goClient, page doorAnswer) doorAnswer {
	t.Helper()
	if page.pageID() != "login-login-update-password" {
		t.Fatalf("want the password change, got %q (%q)", page.pageID(), errorText(page))
	}
	return r.post(t, g, page, "kc-passwd-update-form", map[string]string{"password-new": breachPhrase, "password-confirm": breachPhrase})
}

// TC-1145-38: account creation at the home door with the listed phrase
// gets the warning and creates nothing, and only a prefix leaves; the link
// re-renders the form; the Keep form, as rendered, creates the account,
// which stores no keep marker.
func (r *rulesRig) tc1145breachRegistration(t *testing.T) {
	register := func(g *goClient, name string) doorAnswer {
		a := g.follow(r.homeAuth(baselineConsole, map[string]string{"prompt": "create"}))
		if a.pageID() != "login-register" {
			t.Fatalf("prompt=create opened %q", a.pageID())
		}
		return r.post(t, g, a, "kc-register-form", map[string]string{
			"username": name, "email": name + "@rules.invalid", "firstName": "Breached",
			"password": breachPhrase, "password-confirm": breachPhrase,
		})
	}
	mark := r.breach.count()
	g := r.client(t, "127.0.0.47")
	warn := register(g, "tc1145-38-choose")
	if !isWarning(warn) {
		t.Fatalf("the listed phrase answered %q (%d), want the warning page", warn.pageID(), warn.status)
	}
	if n := len(r.usersNamed(t, "tc1145-38-choose")); n != 0 {
		t.Errorf("the warning created %d accounts", n)
	}
	reqs := r.breach.since(mark)
	if len(reqs) == 0 {
		t.Error("the range stub saw no request")
	}
	prefixPath := regexp.MustCompile(`^/range/[0-9A-F]{5}$`)
	for _, q := range reqs {
		if q.method != http.MethodGet || !prefixPath.MatchString(q.path) || q.query != "" || q.padding != "true" {
			t.Errorf("the range stub saw %s %s?%s (Add-Padding %q), want GET /range/<5 hex> with padding", q.method, q.path, q.query, q.padding)
		}
		if strings.Contains(strings.ToUpper(q.path+q.query), breachSuffix) {
			t.Error("a range request holds the suffix")
		}
	}
	if again := chooseAnother(t, g, warn); again.pageID() != "login-register" {
		t.Errorf("choose-another answered %q (%d), want login-register", again.pageID(), again.status)
	}

	k := r.client(t, "127.0.0.48")
	warn = register(k, "tc1145-38-keep")
	if !isWarning(warn) {
		t.Fatalf("the listed phrase answered %q, want the warning page", warn.pageID())
	}
	r.keep(t, k, warn).code(t)
	users := r.usersNamed(t, "tc1145-38-keep")
	if len(users) != 1 {
		t.Fatalf("Keep created %d accounts, want 1", len(users))
	}
	if attrs, _ := users[0]["attributes"].(map[string]any); attrs["rasputin-keep-password"] != nil {
		t.Error("the account stores the keep marker as an attribute")
	}
}

// TC-1145-39: at UPDATE_PASSWORD after an administrator's temporary
// password, at each door, the listed phrase gets the warning and changes
// nothing; the link re-renders the change, where another password is
// accepted; in another account, Keep as rendered sets the phrase, which
// then signs in with no warning, and the temporary one no longer does.
func (r *rulesRig) tc1145breachUpdate(t *testing.T) {
	for _, d := range r.bothDoors() {
		door := strings.Fields(d.name)[0]
		a, temp := r.temporaryAccount(t, "tc1145-39-"+door)
		g := r.fresh(t)
		warn := r.postPhrase(t, g, g.signIn(d.auth(), a.name, temp))
		if !isWarning(warn) {
			t.Fatalf("%s: the listed phrase answered %q (%d), want the warning page", d.name, warn.pageID(), warn.status)
		}
		if p := r.fresh(t).signIn(d.auth(), a.name, temp); p.pageID() != "login-login-update-password" {
			t.Errorf("%s: after the warning the temporary password reached %q, want the password change still owed", d.name, p.pageID())
		}
		again := chooseAnother(t, g, warn)
		if again.pageID() != "login-login-update-password" {
			t.Fatalf("%s: choose-another answered %q (%d), want login-login-update-password", d.name, again.pageID(), again.status)
		}
		next, err := randomSecret(r.env.h.cfg.Rand)
		if err != nil {
			t.Fatal(err)
		}
		r.post(t, g, again, "kc-passwd-update-form", map[string]string{
			"password-new": string(next.Reveal()), "password-confirm": string(next.Reveal())}).code(t)
		r.fresh(t).signIn(d.auth(), a.name, next).code(t)
		next.Destroy()

		b, temp2 := r.temporaryAccount(t, "tc1145-39-keep-"+door)
		k := r.fresh(t)
		warn = r.postPhrase(t, k, k.signIn(d.auth(), b.name, temp2))
		if !isWarning(warn) {
			t.Fatalf("%s: the listed phrase answered %q, want the warning page", d.name, warn.pageID())
		}
		r.keep(t, k, warn).code(t)
		phrase := secret.New([]byte(breachPhrase))
		r.fresh(t).signIn(d.auth(), b.name, phrase).code(t)
		phrase.Destroy()
		if p := r.fresh(t).signIn(d.auth(), b.name, temp2); p.loc != nil && p.loc.Query().Get("code") != "" {
			t.Errorf("%s: the temporary password still signs in after Keep", d.name)
		}
	}
}

// TC-1145-40: with the range stub closed, the listed phrase at
// UPDATE_PASSWORD at the home door is set with no warning (EX-1), one WARN
// names the connect class, and no log holds the phrase, its hash, its
// suffix or (in the door's records) its prefix.
func (r *rulesRig) tc1145breachOffline(t *testing.T) {
	r.breach.srv.Close()
	mark := len(r.rec.Records())
	a, temp := r.temporaryAccount(t, "tc1145-40-offline")
	home := r.bothDoors()[0]
	g := r.fresh(t)
	got := r.postPhrase(t, g, g.signIn(home.auth(), a.name, temp))
	if isWarning(got) {
		t.Fatal("offline, the door showed the warning")
	}
	got.code(t)
	phrase := secret.New([]byte(breachPhrase))
	defer phrase.Destroy()
	r.fresh(t).signIn(home.auth(), a.name, phrase).code(t)
	var warns []slog.Record
	for _, rec := range r.rec.Records()[mark:] {
		if v, _ := logkittest.Attr(rec, "breach_check"); v == "unavailable" {
			warns = append(warns, rec)
		}
	}
	if len(warns) != 1 {
		t.Fatalf("%d records name breach_check=unavailable, want 1:\n%s", len(warns), r.rec.Text())
	}
	if class, _ := logkittest.Attr(warns[0], "breach_error_class"); warns[0].Level != slog.LevelWarn || class != "connect" {
		t.Errorf("the record is %s with class %q, want WARN with connect", warns[0].Level, class)
	}
	text := r.rec.Text()
	for _, s := range []string{breachPhrase, breachPhraseHash, strings.ToLower(breachPhraseHash), breachSuffix, strings.ToLower(breachSuffix)} {
		if strings.Contains(text, s) {
			t.Errorf("the run's log holds %q", s)
		}
	}
	// The prefix is 5 hex characters, which a hash elsewhere in the log can
	// hold by chance, so it is searched in the door's own records.
	for _, rec := range r.rec.Records() {
		if c, _ := logkittest.Attr(rec, "component"); c != "signin-door" {
			continue
		}
		rec.Attrs(func(at slog.Attr) bool {
			if v := strings.ToUpper(at.Value.String()); strings.Contains(v, breachPrefix) {
				t.Errorf("the door's record field %s holds the prefix", at.Key)
			}
			return true
		})
	}
}
