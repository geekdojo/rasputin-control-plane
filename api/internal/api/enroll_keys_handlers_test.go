package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

const testOperatorKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK2AcGjrl5kW bryce@laptop"

func TestOperatorKeys_RequireAuth(t *testing.T) {
	f := newAPIFixture(t)
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/enroll/operator-keys", ""},
		{http.MethodPut, "/api/enroll/operator-keys", `{"keys":[]}`},
	} {
		w := f.do(t, tc.method, tc.path, tc.body, nil)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without cookie: want 401, got %d", tc.method, tc.path, w.Code)
		}
	}
}

func TestOperatorKeys_GetUncaptured(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/enroll/operator-keys", "", c)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Keys     []string `json:"keys"`
		Captured bool     `json:"captured"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Captured || len(resp.Keys) != 0 {
		t.Errorf("want uncaptured empty list, got %+v", resp)
	}
}

func TestOperatorKeys_PutThenGet(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPut, "/api/enroll/operator-keys", `{"keys":["`+testOperatorKey+`"]}`, c)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT: want 200, got %d body=%s", w.Code, w.Body.String())
	}
	w = f.do(t, http.MethodGet, "/api/enroll/operator-keys", "", c)
	var resp struct {
		Keys     []string `json:"keys"`
		Captured bool     `json:"captured"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.Captured || len(resp.Keys) != 1 || resp.Keys[0] != testOperatorKey {
		t.Errorf("round-trip: got %+v", resp)
	}
}

func TestOperatorKeys_PutInvalidKey(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPut, "/api/enroll/operator-keys", `{"keys":["not-a-key"]}`, c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for invalid key, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestOperatorKeys_PutMissingKeysField(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPut, "/api/enroll/operator-keys", `{}`, c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for missing keys field, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestOperatorKeys_PutEmptyListIsExplicitNone(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPut, "/api/enroll/operator-keys", `{"keys":[]}`, c)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT empty: want 200, got %d body=%s", w.Code, w.Body.String())
	}
	w = f.do(t, http.MethodGet, "/api/enroll/operator-keys", "", c)
	var resp struct {
		Keys     []string `json:"keys"`
		Captured bool     `json:"captured"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.Captured || len(resp.Keys) != 0 {
		t.Errorf("want captured empty list, got %+v", resp)
	}
}
