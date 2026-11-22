package adminguard

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func basic(userPass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(userPass))
}

// TC-1127-19: Check refuses every value naming the admin account, whatever
// the parameter, padding or case, and the Basic user after base64 and URL
// decoding; it fails closed on a Basic credential it cannot decode; and it
// passes everything else.
func TestCheck_RefusesEveryValueNamingTheAdminAccount(t *testing.T) {
	form := func(kv ...string) url.Values {
		v := url.Values{}
		for i := 0; i < len(kv); i += 2 {
			v.Add(kv[i], kv[i+1])
		}
		return v
	}
	for _, tc := range []struct {
		name string
		in   Input
		want error
	}{
		{"form client_id", Input{Form: form("client_id", "rasputin-admin")}, ErrAdminAccount},
		{"query client_id", Input{Query: form("client_id", "rasputin-admin")}, ErrAdminAccount},
		{"form username", Input{Form: form("username", "service-account-rasputin-admin")}, ErrAdminAccount},
		{"surrounding ASCII spaces", Input{Form: form("username", "  service-account-rasputin-admin ")}, ErrAdminAccount},
		{"leading \\x01", Input{Form: form("username", "\x01service-account-rasputin-admin")}, ErrAdminAccount},
		{"trailing U+00A0", Input{Form: form("username", "service-account-rasputin-admin ")}, ErrAdminAccount},
		{"mixed case", Input{Form: form("username", "Service-Account-RASPUTIN-Admin")}, ErrAdminAccount},
		{"second of two username values", Input{Form: form("username", "alice", "username", "service-account-rasputin-admin")}, ErrAdminAccount},
		{"query login_hint", Input{Query: form("login_hint", "service-account-rasputin-admin")}, ErrAdminAccount},
		{"a parameter Keycloak does not read", Input{Form: form("x", "rasputin-admin")}, ErrAdminAccount},
		{"Basic rasputin-admin", Input{Authorization: basic("rasputin-admin:x")}, ErrAdminAccount},
		{"Basic URL-encoded rasputin%2Dadmin", Input{Authorization: basic("rasputin%2Dadmin:x")}, ErrAdminAccount},
		{"lower-case basic scheme", Input{Authorization: "basic " + base64.StdEncoding.EncodeToString([]byte("rasputin-admin:x"))}, ErrAdminAccount},
		{"Basic service account", Input{Authorization: basic("service-account-rasputin-admin:x")}, ErrAdminAccount},

		{"Basic with a character outside base64", Input{Authorization: "Basic cmFzcHV0aW4tYWRta*W46eA=="}, ErrUnreadable},
		{"Basic user with a bad escape", Input{Authorization: basic("rasputin%zz:x")}, ErrUnreadable},

		{"alice on the console", Input{Form: form("username", "alice", "client_id", "rasputin-console")}, nil},
		{"empty", Input{}, nil},
		{"service account with a suffix", Input{Form: form("username", "service-account-rasputin-admin-x")}, nil},
		{"rasputin-administrator", Input{Form: form("username", "rasputin-administrator")}, nil},
		{"the name inside a longer string", Input{Form: form("note", "ask rasputin-admin later")}, nil},
		{"Basic rasputin-console", Input{Authorization: basic("rasputin-console:x")}, nil},
	} {
		if got := Check(tc.in); !errors.Is(got, tc.want) || (tc.want == nil && got != nil) {
			t.Errorf("%s: Check = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TC-1127-19: the two errors are distinct, the error values stay lowercase
// with no closing punctuation (ST1005, F-1127-17), and Sentence maps each to
// its person-facing sentence.
func TestSentence_MapsEachErrorToItsSentence(t *testing.T) {
	if errors.Is(ErrAdminAccount, ErrUnreadable) || errors.Is(ErrUnreadable, ErrAdminAccount) {
		t.Fatal("errors.Is does not tell the two errors apart")
	}
	if got := Sentence(ErrAdminAccount); got != "This account can't sign in here. Sign in with your own account." {
		t.Errorf("Sentence(ErrAdminAccount) = %q", got)
	}
	if got := Sentence(ErrUnreadable); got != "This sign-in request couldn't be read. Start signing in again." {
		t.Errorf("Sentence(ErrUnreadable) = %q", got)
	}
	for _, err := range []error{ErrAdminAccount, ErrUnreadable} {
		msg := err.Error()
		if first := msg[:1]; first != strings.ToLower(first) || strings.HasSuffix(msg, ".") {
			t.Errorf("%q is not a lowercase error value without closing punctuation", msg)
		}
	}
}

// TC-1127-19: ServiceAccountUsername is the baseline's service-account user
// of AdminClientID.
func TestServiceAccountUsername_MatchesTheBaseline(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "identity", "realm-baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	var b struct {
		Users []struct {
			Username               string `json:"username"`
			ServiceAccountClientID string `json:"serviceAccountClientId"`
		} `json:"users"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, u := range b.Users {
		if u.ServiceAccountClientID == AdminClientID {
			found = true
			if u.Username != ServiceAccountUsername {
				t.Errorf("the baseline's service account of %s is %q, want %q", AdminClientID, u.Username, ServiceAccountUsername)
			}
		}
	}
	if !found {
		t.Fatalf("the baseline has no service-account user for %s", AdminClientID)
	}
}

// TC-1127-20: FromRequest fails closed on what it cannot read, keeps query
// and form apart, and puts back a body that parses to exactly the original
// form values, whatever the realm in the path.
func TestFromRequest_FailsClosedAndForwardsTheBodyIntact(t *testing.T) {
	for _, realm := range []string{"rasputin", "master", "harness"} {
		base := "https://front.test/realms/" + realm + "/protocol/openid-connect/token"
		post := func(target, contentType, body string) *http.Request {
			r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
			r.Header.Set("Content-Type", contentType)
			return r
		}
		twoAuth := post(base, "application/x-www-form-urlencoded", "a=b")
		twoAuth.Header.Add("Authorization", basic("alice:x"))
		twoAuth.Header.Add("Authorization", basic("bob:y"))
		badQuery := httptest.NewRequest(http.MethodGet, base, nil)
		badQuery.URL.RawQuery = "client_id=%zz"
		for name, r := range map[string]*http.Request{
			"multipart POST":       post(base, "multipart/form-data; boundary=x", "--x\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\nalice\r\n--x--\r\n"),
			"JSON POST":            post(base, "application/json", `{"username":"alice"}`),
			"GET with a body":      httptest.NewRequest(http.MethodGet, base, strings.NewReader("username=alice")),
			"bad escape in a form": post(base, "application/x-www-form-urlencoded", "username=%zz"),
			"bad escape in query":  badQuery,
			"two Authorization":    twoAuth,
		} {
			if _, err := FromRequest(r); !errors.Is(err, ErrUnreadable) {
				t.Errorf("%s, realm %s: err = %v, want ErrUnreadable", name, realm, err)
			}
		}

		get := httptest.NewRequest(http.MethodGet, base+"?client_id=rasputin-console&state=s", nil)
		get.Header.Set("Authorization", "Bearer t")
		in, err := FromRequest(get)
		if err != nil || in.Query.Get("client_id") != "rasputin-console" || in.Query.Get("state") != "s" ||
			len(in.Form) != 0 || in.Authorization != "Bearer t" {
			t.Errorf("GET, realm %s: %+v, %v", realm, in, err)
		}

		r := post(base+"?tab_id=q", "application/x-www-form-urlencoded; charset=UTF-8", "username=alice&password=p%26w&username=bob")
		r.Header.Set("Authorization", basic("rasputin-console:x"))
		in, err = FromRequest(r)
		if err != nil {
			t.Fatalf("POST, realm %s: %v", realm, err)
		}
		wantForm := url.Values{"username": {"alice", "bob"}, "password": {"p&w"}}
		if in.Query.Encode() != "tab_id=q" || in.Form.Encode() != wantForm.Encode() || in.Authorization != basic("rasputin-console:x") {
			t.Errorf("POST, realm %s: query %v, form %v, authorization %q", realm, in.Query, in.Form, in.Authorization)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		got, err := url.ParseQuery(string(body))
		if err != nil || got.Encode() != wantForm.Encode() || r.ContentLength != int64(len(body)) {
			t.Errorf("POST, realm %s: forwarded body %q (length %d, ContentLength %d, %v), want %v",
				realm, body, len(body), r.ContentLength, err, wantForm)
		}
	}
}
