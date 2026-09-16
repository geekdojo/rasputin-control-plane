package api

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
)

const (
	testOperatorKey  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK2AcGjrl5kW bryce@laptop"
	testOperatorKey2 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB other@host"
)

func decodeOperatorKey(t *testing.T, body []byte) operatorKeyResponse {
	t.Helper()
	var resp operatorKeyResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal %s: %v", body, err)
	}
	return resp
}

func TestOperatorKey_RequireAuth(t *testing.T) {
	f := newAPIFixture(t)
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/enroll/operator-key", ""},
		{http.MethodPut, "/api/enroll/operator-key", `{"key":""}`},
	} {
		w := f.do(t, tc.method, tc.path, tc.body, nil)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without cookie: want 401, got %d", tc.method, tc.path, w.Code)
		}
	}
}

// The list endpoint is gone: a stale client must fail loudly rather than
// have its list body half-understood.
func TestOperatorKey_OldListRouteRemoved(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	for _, m := range []string{http.MethodGet, http.MethodPut} {
		w := f.do(t, m, "/api/enroll/operator-keys", `{"keys":[]}`, c)
		if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /api/enroll/operator-keys: want 404/405, got %d", m, w.Code)
		}
	}
}

func TestOperatorKey_GetUncaptured(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/enroll/operator-key", "", c)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	if resp := decodeOperatorKey(t, w.Body.Bytes()); resp != (operatorKeyResponse{}) {
		t.Errorf("want uncaptured, no key, nothing ignored; got %+v", resp)
	}
}

func TestOperatorKey_PutThenGet(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPut, "/api/enroll/operator-key", `{"key":"  `+testOperatorKey+` "}`, c)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT: want 200, got %d body=%s", w.Code, w.Body.String())
	}
	want := operatorKeyResponse{Key: testOperatorKey, Captured: true}
	if resp := decodeOperatorKey(t, w.Body.Bytes()); resp != want {
		t.Errorf("PUT response: want %+v, got %+v", want, resp)
	}
	w = f.do(t, http.MethodGet, "/api/enroll/operator-key", "", c)
	if resp := decodeOperatorKey(t, w.Body.Bytes()); resp != want {
		t.Errorf("round-trip: want %+v, got %+v", want, resp)
	}
}

// Replacing is a replace, not an add: the setting never grows a second key.
func TestOperatorKey_PutReplaces(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	for _, k := range []string{testOperatorKey, testOperatorKey2} {
		if w := f.do(t, http.MethodPut, "/api/enroll/operator-key", `{"key":"`+k+`"}`, c); w.Code != http.StatusOK {
			t.Fatalf("PUT %q: want 200, got %d body=%s", k, w.Code, w.Body.String())
		}
	}
	w := f.do(t, http.MethodGet, "/api/enroll/operator-key", "", c)
	want := operatorKeyResponse{Key: testOperatorKey2, Captured: true}
	if resp := decodeOperatorKey(t, w.Body.Bytes()); resp != want {
		t.Errorf("want %+v, got %+v", want, resp)
	}
}

func TestOperatorKey_PutInvalidKey(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	if w := f.do(t, http.MethodPut, "/api/enroll/operator-key", `{"key":"`+testOperatorKey+`"}`, c); w.Code != http.StatusOK {
		t.Fatalf("seed PUT: %d", w.Code)
	}
	w := f.do(t, http.MethodPut, "/api/enroll/operator-key", `{"key":"not-a-key"}`, c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for invalid key, got %d body=%s", w.Code, w.Body.String())
	}
	// A rejected replace leaves the saved key alone.
	w = f.do(t, http.MethodGet, "/api/enroll/operator-key", "", c)
	if resp := decodeOperatorKey(t, w.Body.Bytes()); resp.Key != testOperatorKey {
		t.Errorf("rejected PUT changed the key: %+v", resp)
	}
}

func TestOperatorKey_PutRejectsBadBodies(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	for _, body := range []string{
		`{}`,                                   // no key field
		`{"key":null}`,                         // null is not a clear
		`{"keys":["` + testOperatorKey + `"]}`, // the old list shape
		`{"key":["` + testOperatorKey + `"]}`,  // a list where a string belongs
		`not json`,
	} {
		w := f.do(t, http.MethodPut, "/api/enroll/operator-key", body, c)
		if w.Code != http.StatusBadRequest {
			t.Errorf("body %s: want 400, got %d body=%s", body, w.Code, w.Body.String())
		}
	}
}

func TestOperatorKey_PutEmptyClears(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	if w := f.do(t, http.MethodPut, "/api/enroll/operator-key", `{"key":"`+testOperatorKey+`"}`, c); w.Code != http.StatusOK {
		t.Fatalf("seed PUT: %d", w.Code)
	}
	w := f.do(t, http.MethodPut, "/api/enroll/operator-key", `{"key":""}`, c)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT empty: want 200, got %d body=%s", w.Code, w.Body.String())
	}
	w = f.do(t, http.MethodGet, "/api/enroll/operator-key", "", c)
	want := operatorKeyResponse{Key: "", Captured: true}
	if resp := decodeOperatorKey(t, w.Body.Bytes()); resp != want {
		t.Errorf("want captured with no key, got %+v", resp)
	}
}

// A value written by the list UI can hold several keys. The first is the one
// the wizard always prefilled, so it stays the key; the rest are reported as
// ignored (never silently dropped on read) and the next save removes them.
func TestOperatorKey_LegacyMultiKeyList(t *testing.T) {
	for _, tc := range []struct {
		name    string
		putBody string
		want    operatorKeyResponse
	}{
		{"replace drops the extras", `{"key":"` + testOperatorKey2 + `"}`, operatorKeyResponse{Key: testOperatorKey2, Captured: true}},
		{"re-save of the first key drops the extras", `{"key":"` + testOperatorKey + `"}`, operatorKeyResponse{Key: testOperatorKey, Captured: true}},
		{"clear drops the extras", `{"key":""}`, operatorKeyResponse{Key: "", Captured: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAPIFixture(t)
			c := f.authenticate(t)
			writeLegacyOperatorKeys(t, f, `["`+testOperatorKey+`","`+testOperatorKey2+`","ssh-ed25519 AAAAthird third@host"]`)

			w := f.do(t, http.MethodGet, "/api/enroll/operator-key", "", c)
			if w.Code != http.StatusOK {
				t.Fatalf("GET: want 200, got %d body=%s", w.Code, w.Body.String())
			}
			legacy := operatorKeyResponse{Key: testOperatorKey, Captured: true, IgnoredKeys: 2}
			if resp := decodeOperatorKey(t, w.Body.Bytes()); resp != legacy {
				t.Fatalf("legacy GET: want %+v, got %+v", legacy, resp)
			}
			// Reading never rewrites: a second GET still sees the extras.
			w = f.do(t, http.MethodGet, "/api/enroll/operator-key", "", c)
			if resp := decodeOperatorKey(t, w.Body.Bytes()); resp != legacy {
				t.Fatalf("second GET rewrote the value: %+v", resp)
			}

			if w := f.do(t, http.MethodPut, "/api/enroll/operator-key", tc.putBody, c); w.Code != http.StatusOK {
				t.Fatalf("PUT: want 200, got %d body=%s", w.Code, w.Body.String())
			}
			w = f.do(t, http.MethodGet, "/api/enroll/operator-key", "", c)
			if resp := decodeOperatorKey(t, w.Body.Bytes()); resp != tc.want {
				t.Errorf("after PUT: want %+v, got %+v", tc.want, resp)
			}
		})
	}
}

// writeLegacyOperatorKeys stores a raw setting value the way the list-era api
// did, through a second handle on the fixture's settings database.
func writeLegacyOperatorKeys(t *testing.T, f *apiFixture, raw string) {
	t.Helper()
	st, err := setup.OpenStore(f.ctx, filepath.Join(f.dir, "setup.db"))
	if err != nil {
		t.Fatalf("open setup store: %v", err)
	}
	defer func() { _ = st.Close() }()
	if err := st.Set(f.ctx, setup.KeyOperatorSSHKeys, raw); err != nil {
		t.Fatalf("write legacy value: %v", err)
	}
}
