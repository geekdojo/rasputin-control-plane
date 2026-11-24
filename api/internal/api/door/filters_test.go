package door

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door/policy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/adminguard"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

func basic(user, pass string) http.Header {
	return http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(user)+":"+pass))}}
}

func (f *fixture) want400(k Kind, r req, what string) {
	f.t.Helper()
	before := f.up.count()
	w := f.do(k, r)
	f.wantRefused(w, http.StatusBadRequest, before, what)
	if s := sentenceIn(f.t, w.Body.String()); !isSentence(s) {
		f.t.Errorf("%s: the refusal %q is not a sentence", what, s)
	}
}

func (f *fixture) wantPass(k Kind, r req, what string) {
	f.t.Helper()
	before := f.up.count()
	w := f.do(k, r)
	f.wantForwarded(w, before, what)
}

// TC-985-06: the client rule per route kind (F-985-04).
func TestDoor_ClientBinding(t *testing.T) {
	f := newFixture(t)
	auth := oidc("auth")
	token := oidc("token")
	for _, k := range []Kind{Home, App} {
		f.want400(k, req{target: auth + "?" + authQuery("", map[string]string{"client_id": ""})}, k.String()+" auth with no client_id")
		f.want400(k, req{target: auth + "?" + authQuery(doorClient(k), nil) + "&client_id=" + doorClient(k)}, k.String()+" client_id twice in the query")
		f.want400(k, req{method: http.MethodPost, target: auth + "?" + authQuery(doorClient(k), nil),
			form: url.Values{"client_id": {doorClient(k)}}}, k.String()+" client_id in query and form")
		f.want400(k, req{method: http.MethodPost, target: token,
			form: url.Values{"client_id": {doorClient(k)}, "grant_type": {"authorization_code"}}, header: basic("someone-else", "s")},
			k.String()+" Basic and form naming different clients")
		f.wantPass(k, req{method: http.MethodPost, target: token,
			form: url.Values{"grant_type": {"authorization_code"}, "code": {"c"}}, header: basic(doorClient(k), "secret")},
			k.String()+" a client_secret_basic token call with no form client_id")
		f.want400(k, req{method: http.MethodPost, target: token,
			form: url.Values{"grant_type": {"authorization_code"}, "client_assertion": {"x.y.z"}}},
			k.String()+" a token call that names no client")
		for _, p := range []string{realmPrefix + ".well-known/openid-configuration", oidc("certs"), oidc("userinfo")} {
			f.wantPass(k, req{target: p, header: http.Header{"Authorization": {"Bearer t"}}}, k.String()+" "+p+" with no client")
		}
		f.wantPass(k, req{target: oidc("logout")}, k.String()+" logout with no client")
		f.want400(k, req{target: oidc("logout") + "?client_id=" + otherDoorClient(k)}, k.String()+" logout naming the other door's client")
	}
	f.want400(App, req{target: auth + "?" + authQuery("rasputin-mesh", nil)}, "rasputin-mesh at the app door")
	f.want400(Home, req{target: auth + "?" + authQuery("rasputin-account", nil)}, "rasputin-account at the home door")
	f.want400(Home, req{target: auth + "?" + authQuery("immich", nil)}, "an app client at the home door")
	f.wantPass(App, req{target: auth + "?" + authQuery("immich", nil)}, "an app client at the app door")
	f.apps.err = errors.New("unreadable")
	f.want400(App, req{target: auth + "?" + authQuery("immich", nil)}, "an app client the registry cannot read")
}

func otherDoorClient(k Kind) string {
	if k == Home {
		return "rasputin-account"
	}
	return policy.ConsoleClient
}

// TC-985-07: only the code and refresh grants reach the token endpoint.
func TestDoor_GrantTypes(t *testing.T) {
	f := newFixture(t)
	for _, k := range []Kind{Home, App} {
		for _, g := range []string{"password", "client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange",
			"urn:ietf:params:oauth:grant-type:device_code", ""} {
			form := url.Values{"client_id": {doorClient(k)}}
			if g != "" {
				form.Set("grant_type", g)
			}
			f.want400(k, req{method: http.MethodPost, target: oidc("token"), form: form}, k.String()+" grant "+g)
		}
		for _, g := range []string{"authorization_code", "refresh_token"} {
			f.wantPass(k, req{method: http.MethodPost, target: oidc("token"),
				form: url.Values{"client_id": {doorClient(k)}, "grant_type": {g}}}, k.String()+" grant "+g)
		}
	}
}

// TC-985-08: the home door's response shape and prompt.
func TestDoor_HomeShapeAndPrompt(t *testing.T) {
	f := newFixture(t)
	auth := oidc("auth") + "?"
	for name, extra := range map[string]map[string]string{
		"form_post":            {"response_mode": "form_post"},
		"fragment":             {"response_mode": "fragment"},
		"request":              {"request": "eyJ.x.y"},
		"request_uri":          {"request_uri": "urn:x"},
		"token response":       {"response_type": "code id_token"},
		"no prompt":            {"prompt": ""},
		"prompt none":          {"prompt": "none"},
		"prompt consent":       {"prompt": "consent"},
		"prompt login consent": {"prompt": "login consent"},
	} {
		f.want400(Home, req{target: auth + authQuery(policy.ConsoleClient, extra)}, "home "+name)
	}
	for _, c := range []string{"rasputin-mesh", policy.ResetHomeClient} {
		f.want400(Home, req{target: auth + authQuery(c, map[string]string{"prompt": "create"})}, "prompt=create for "+c)
	}
	for _, c := range []string{policy.ConsoleClient, "rasputin-mesh", policy.ResetHomeClient} {
		f.wantPass(Home, req{target: auth + authQuery(c, nil)}, "prompt=login for "+c)
	}
	f.wantPass(Home, req{target: auth + authQuery(policy.ConsoleClient, map[string]string{"prompt": "create", "response_mode": "query"})},
		"prompt=create for the console")
}

// TC-985-09: the app door's form_post and request objects, per client.
func TestDoor_AppShape(t *testing.T) {
	f := newFixture(t)
	auth := oidc("auth") + "?"
	f.want400(App, req{target: auth + authQuery("immich", map[string]string{"response_mode": "form_post"})}, "form_post, no declaring client")
	f.want400(App, req{target: auth + authQuery("rasputin-account", map[string]string{"request": "x"})}, "a request object, no declaring client")
	f.apps.m["vault"] = policy.AppClient{FormPost: true}
	f.wantPass(App, req{target: auth + authQuery("vault", map[string]string{"response_mode": "form_post"})}, "form_post for a declaring client")
	f.want400(App, req{target: auth + authQuery("immich", map[string]string{"response_mode": "form_post"})}, "form_post for another client")
	f.want400(App, req{target: auth + authQuery("vault", map[string]string{"request_uri": "urn:x"})}, "a request object for a client declaring only form_post")
	f.wantPass(App, req{target: auth + authQuery("immich", map[string]string{"prompt": ""})}, "the app door forwards prompt as sent")
}

// TC-985-10: a repeated filtered parameter is refused, in the query alone
// or split across query and form.
func TestDoor_RepeatedParameters(t *testing.T) {
	f := newFixture(t)
	for _, k := range []Kind{Home, App} {
		for _, p := range []string{"prompt", "response_mode", "response_type", "grant_type", "kc_action"} {
			base := authQuery(doorClient(k), map[string]string{p: "x"})
			f.want400(k, req{target: oidc("auth") + "?" + base + "&" + p + "=x"}, k.String()+" "+p+" twice in the query")
			f.want400(k, req{method: http.MethodPost, target: oidc("auth") + "?" + base,
				form: url.Values{p: {"x"}}}, k.String()+" "+p+" in query and form")
		}
	}
}

// TC-985-11: kc_action only when the launcher issued it for this request;
// delete_credential never.
func TestDoor_KCAction(t *testing.T) {
	f := newFixture(t)
	auth := func(action string) req {
		return req{target: oidc("auth") + "?" + authQuery(policy.ConsoleClient, map[string]string{"kc_action": action})}
	}
	f.actions.issued = false
	f.want400(Home, auth("UPDATE_PASSWORD"), "an action nobody issued")
	f.actions.issued = true
	f.wantPass(Home, auth("UPDATE_PASSWORD"), "an issued action")
	got := f.actions.got[len(f.actions.got)-1]
	if got != (policy.ActionRequest{Client: policy.ConsoleClient, Action: "UPDATE_PASSWORD", State: "st"}) {
		t.Errorf("Issued was asked %+v, want the client, action and state", got)
	}
	f.want400(Home, auth("delete_credential"), "delete_credential")
	f.want400(Home, auth("delete_credential:abc-123"), "delete_credential:<id>")
	f.want400(Home, auth("DELETE_CREDENTIAL"), "DELETE_CREDENTIAL")
	f.actions.err = errors.New("unreadable")
	f.want400(Home, auth("UPDATE_PASSWORD"), "an action whose issue cannot be read")
}

// TC-985-12: a reset only for the door's own reset client.
func TestDoor_ResetPerDoor(t *testing.T) {
	f := newFixture(t)
	reset := actions("reset-credentials") + "?client_id="
	f.wantPass(Home, req{target: reset + policy.ResetHomeClient}, "home reset client at home")
	f.wantPass(App, req{target: reset + policy.ResetAppClient}, "app reset client at the app door")
	for _, c := range []string{policy.ResetAppClient, policy.ConsoleClient, "rasputin-mesh"} {
		f.want400(Home, req{target: reset + c}, c+" reset at home")
	}
	for _, c := range []string{policy.ResetHomeClient, "rasputin-account", "immich"} {
		f.want400(App, req{target: reset + c}, c+" reset at the app door")
	}
}

// TC-985-13: registration, only at home, for the console, from a home
// subnet address that is not a tailnet or node address, while not full.
func TestDoor_Registration(t *testing.T) {
	f := newFixture(t)
	reg := req{target: oidc("registrations") + "?" + authQuery(policy.ConsoleClient, map[string]string{"prompt": "create"})}
	refused := func(r req, what string) {
		t.Helper()
		before := f.up.count()
		w := f.do(Home, r)
		if w.Code < 400 || !isDoorPage(w) || f.up.count() != before {
			t.Errorf("%s: %d, door page %v, forwarded %v; want a refusal", what, w.Code, isDoorPage(w), f.up.count() != before)
			return
		}
		if !isSentence(sentenceIn(t, w.Body.String())) {
			t.Errorf("%s: %q is not a sentence", what, sentenceIn(t, w.Body.String()))
		}
		if !strings.Contains(w.Body.String(), `href="https://ci.local/login"`) {
			t.Errorf("%s: the refusal does not link back to the form", what)
		}
	}
	f.wantPass(Home, reg, "from a home subnet address")
	create := req{target: oidc("auth") + "?" + authQuery(policy.ConsoleClient, map[string]string{"prompt": "create"})}
	f.wantPass(Home, create, "an authorization request with prompt=create from a home subnet address")
	tailnetCreate := create
	tailnetCreate.remote = "100.64.1.2:5000"
	refused(tailnetCreate, "an authorization request with prompt=create from a tailnet address")
	f.want400(App, req{target: oidc("auth") + "?" + authQuery("rasputin-account", map[string]string{"prompt": "create"})}, "prompt=create at the app door")
	f.want400(App, req{target: oidc("auth") + "?" + authQuery("immich", map[string]string{"prompt": "login create"})}, "prompt=login create at the app door")
	f.wantPass(Home, req{method: http.MethodPost, target: actions("registration") + "?client_id=" + policy.ConsoleClient,
		form: url.Values{"username": {"new"}}}, "the registration form's step")
	for what, remote := range map[string]string{
		"a tailnet v4 address": "100.64.1.2:5000", "a tailnet v6 address": "[fd7a:115c:a1e0::5]:5000",
		"a node address": "192.0.2.50:5000", "an address off the home subnets": "198.51.100.1:5000",
	} {
		r := reg
		r.remote = remote
		refused(r, what)
	}
	f.waiting.full = true
	refused(reg, "while the waiting list is full")
	f.waiting.full, f.waiting.err = false, errors.New("x")
	refused(reg, "while the waiting count cannot be read")
	f.waiting.err, f.network.err = nil, errors.New("x")
	refused(reg, "while the network facts cannot be read")
	f.network.err = nil

	closed, err := policy.New(policy.Deps{Table: f.table, Readiness: f.ready, Throttle: f.th, AppClients: policy.NoAppClients{},
		Actions: policy.NoActionsIssued{}, Network: policy.RegistrationClosed{}, Waiting: policy.RegistrationClosed{}, Removed: noneRemoved{}, Now: func() time.Time { return f.now }})
	if err != nil {
		t.Fatal(err)
	}
	f.policySvc = closed
	f.home, f.app = f.build(t)
	refused(reg, "with RegistrationClosed")
	f.want400(Home, req{target: oidc("registrations") + "?" + authQuery("rasputin-mesh", map[string]string{"prompt": "create"})}, "another client")

	// The template's refusal names a refused name and links back (4.8's
	// registration refusal).
	w := httptest.NewRecorder()
	f.home.RefusalPage(w, http.StatusConflict, "This sign-in name is taken. Choose another.", "hoodoo", consoleOrigin+"/login", "c1")
	if !strings.Contains(w.Body.String(), "hoodoo") || !strings.Contains(w.Body.String(), `href="https://ci.local/login"`) {
		t.Errorf("RefusalPage does not name the name and link back: %s", w.Body.String())
	}
}

// TC-985-14: the admin-account guard runs before anything is forwarded, with
// its sentence and a WARN record.
func TestDoor_AdminGuard(t *testing.T) {
	f := newFixture(t)
	for _, k := range []Kind{Home, App} {
		for what, r := range map[string]req{
			"a query value": {target: oidc("auth") + "?" + authQuery(doorClient(k), map[string]string{"login_hint": "rasputin-admin"})},
			"a form value":  {method: http.MethodPost, target: oidc("token"), form: url.Values{"client_id": {doorClient(k)}, "grant_type": {"authorization_code"}, "username": {" Service-Account-Rasputin-Admin "}}},
			"a Basic user":  {method: http.MethodPost, target: oidc("token"), form: url.Values{"grant_type": {"authorization_code"}}, header: basic("rasputin-admin", "x")},
			"a client_id":   {target: oidc("auth") + "?" + authQuery("rasputin-admin", nil)},
		} {
			before := f.up.count()
			w := f.do(k, r)
			f.wantRefused(w, http.StatusBadRequest, before, k.String()+" "+what)
			if got, want := sentenceIn(t, w.Body.String()), adminguard.Sentence(adminguard.ErrAdminAccount); got != want {
				t.Errorf("%s %s: %q, want the guard's sentence %q", k, what, got, want)
			}
		}
		before := f.up.count()
		w := f.do(k, req{method: http.MethodPost, target: oidc("token"), body: `{"grant_type":"password"}`, ctype: "application/json"})
		f.wantRefused(w, http.StatusBadRequest, before, k.String()+" a JSON body")
		if got := sentenceIn(t, w.Body.String()); got != adminguard.Sentence(adminguard.ErrUnreadable) {
			t.Errorf("%s JSON body: %q", k, got)
		}
	}
	reasons := map[string]int{}
	for _, r := range f.rec.AtLevel(slog.LevelWarn) {
		if v, ok := logkittest.Attr(r, "refused"); ok {
			reasons[v]++
		}
	}
	if reasons["admin_account"] != 8 || reasons["unreadable"] != 2 {
		t.Errorf("WARN refusals %v, want admin_account 8 and unreadable 2", reasons)
	}
}

// TC-985-15: cross-origin protection with the one SAML bypass at the app
// door, refused with the door page; the SAML POST binding is url-encoded
// only.
func TestDoor_CrossOriginAndSAML(t *testing.T) {
	f := newFixture(t)
	cross := http.Header{"Sec-Fetch-Site": {"cross-site"}, "Origin": {"https://app.ci.internal"}}
	saml := realmPrefix + "protocol/saml"
	f.wantPass(App, req{method: http.MethodPost, target: saml, form: url.Values{"SAMLRequest": {"x"}}, header: cross}, "a cross-site SAML POST")
	f.want400(App, req{method: http.MethodPost, target: saml, body: "<xml/>", ctype: "text/xml"}, "a SAML POST that is not url-encoded")
	for _, c := range []struct {
		k      Kind
		target string
	}{
		{App, actions("authenticate") + "?client_id=rasputin-account"},
		{Home, actions("authenticate") + "?client_id=" + policy.ConsoleClient},
		{Home, oidc("token")},
		{Home, oidc("logout")},
	} {
		before := f.up.count()
		w := f.do(c.k, req{method: http.MethodPost, target: c.target, form: url.Values{"username": {"u"}}, header: cross})
		f.wantRefused(w, http.StatusForbidden, before, c.k.String()+" cross-site POST "+c.target)
		if s := sentenceIn(t, w.Body.String()); s != sentenceCrossOrigin {
			t.Errorf("%s: %q, want the cross-origin sentence", c.target, s)
		}
	}
}
