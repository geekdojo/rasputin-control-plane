package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storeswitch"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// fakeOperatorSecrets is the operator secret service the endpoints call. It
// answers Status with statuses (or statusErr) and Set with setErr, and keeps
// what Set was given.
type fakeOperatorSecrets struct {
	mu        sync.Mutex
	statuses  []apps.OperatorSecretStatus
	statusErr error
	setErr    error
	sets      int
	user      string
	appID     string
	name      string
	value     string
}

func (f *fakeOperatorSecrets) Status(context.Context, string) ([]apps.OperatorSecretStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.statuses, f.statusErr
}

func (f *fakeOperatorSecrets) Set(_ context.Context, user, appID, name string, v secret.Value) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sets++
	f.user, f.appID, f.name, f.value = user, appID, name, string(v.Reveal())
	return f.setErr
}

func (f *fakeOperatorSecrets) setCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sets
}

const opAppID = "01J9ZK3Q0M8X7Y6W5V4T3S2R3A"

const opPutPath = "/api/apps/" + opAppID + "/secrets/feed-key"

// sentenceRe is ERR-MESSAGE: a capital first, a full stop last.
var sentenceRe = regexp.MustCompile(`^[A-Z].*\.$`)

func storeErrOf(kind error) error {
	return fmt.Errorf("secrets: create apps/%s/feed-key: %w", opAppID, &secretstore.Error{Op: "write", Kind: kind})
}

// opErrorCases is every row of the PUT's errors table that a service error
// produces, shared by TC-604-10 (status and code) and TC-604-11 (no leak).
var opErrorCases = []struct {
	why    string
	err    error
	status int
	code   string
}{
	{"app absent", fmt.Errorf("%w: %s", apps.ErrAppNotFound, opAppID), http.StatusNotFound, "app_not_found"},
	{"app removed under the write", fmt.Errorf("%w: %s", secrets.ErrNoSuchApp, opAppID), http.StatusNotFound, "app_not_found"},
	{"not declared", fmt.Errorf("%w: feed-key", apps.ErrOperatorSecretNotDeclared), http.StatusNotFound, "operator_secret_not_declared"},
	{"empty value", apps.ErrOperatorSecretEmpty, http.StatusBadRequest, "secret_value_invalid"},
	{"NUL byte", fmt.Errorf("%w: apps/%s/feed-key: the value contains a NUL byte", secretstore.ErrInvalidValue, opAppID), http.StatusBadRequest, "secret_value_invalid"},
	{"RFC 3339 value", storeErrOf(secretstore.ErrInvalidValue), http.StatusBadRequest, "secret_value_invalid"},
	{"conflict", fmt.Errorf("%w: apps/%s/feed-key changed", secrets.ErrConflict, opAppID), http.StatusConflict, "secret_write_conflict"},
	{"sealed", storeErrOf(secretstore.ErrSealed), http.StatusServiceUnavailable, "secret_store_unavailable"},
	{"unreachable", storeErrOf(secretstore.ErrUnreachable), http.StatusServiceUnavailable, "secret_store_unavailable"},
	{"disabled", storeErrOf(secretstore.ErrDisabled), http.StatusServiceUnavailable, "secret_store_unavailable"},
	{"no store requested", fmt.Errorf("%w: apps/x: %w", secrets.ErrSwitch, storeswitch.ErrNoStore), http.StatusServiceUnavailable, "secret_store_unavailable"},
	{"marker failure", fmt.Errorf("%w: apps/x: %w", secrets.ErrSwitch, fmt.Errorf("database is locked")), http.StatusInternalServerError, "secret_store_switch_failed"},
	{"anything else", fmt.Errorf("something unexpected"), http.StatusInternalServerError, "operator_secret_failed"},
}

// TC-604-10: the PUT answers 204 and hands Set the body's bytes; every row of
// the errors table maps to its status and code; an invalid name, an oversized
// body and a non-JSON body are refused before Set; and every error body is a
// code, a correlation id and a sentence.
func TestOperatorSecretPut_StatusesAndCodes(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)

	t.Run("success", func(t *testing.T) {
		f.opSecrets.setErr = nil
		w := f.do(t, http.MethodPut, opPutPath, `{"value":"s3cr3t é $x"}`, c)
		if w.Code != http.StatusNoContent || w.Body.Len() != 0 {
			t.Fatalf("status %d body %q, want 204 and no body", w.Code, w.Body.String())
		}
		if f.opSecrets.value != "s3cr3t é $x" || f.opSecrets.appID != opAppID || f.opSecrets.name != "feed-key" || f.opSecrets.user != "alice" {
			t.Fatalf("Set got (%q, %q, %q) and a different value", f.opSecrets.user, f.opSecrets.appID, f.opSecrets.name)
		}
	})
	check := func(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
		t.Helper()
		if w.Code != status {
			t.Fatalf("status %d, want %d (body %s)", w.Code, status, w.Body.String())
		}
		ce := decodeCoded(t, w.Body.Bytes())
		if ce.Code != code || ce.CorrelationID == "" || !sentenceRe.MatchString(ce.Error) {
			t.Fatalf("body %+v, want code %s, a correlation id and a sentence", ce, code)
		}
	}
	for _, tc := range opErrorCases {
		t.Run(tc.why, func(t *testing.T) {
			f.opSecrets.setErr = tc.err
			check(t, f.do(t, http.MethodPut, opPutPath, `{"value":"v"}`, c), tc.status, tc.code)
		})
	}
	f.opSecrets.setErr = nil
	for _, tc := range []struct {
		why, path, body string
		status          int
		code            string
	}{
		{"invalid name (F-604-04)", "/api/apps/" + opAppID + "/secrets/Feed_Key", `{"value":"v"}`, http.StatusBadRequest, "invalid_secret_name"},
		{"over 8 KiB", opPutPath, `{"value":"` + strings.Repeat("a", 9<<10) + `"}`, http.StatusBadRequest, "invalid_request"},
		{"not JSON", opPutPath, `value=v`, http.StatusBadRequest, "invalid_request"},
		{"no value field", opPutPath, `{"other":"v"}`, http.StatusBadRequest, "invalid_request"},
		{"empty body", opPutPath, ``, http.StatusBadRequest, "invalid_request"},
		{"an ID no app can have", "/api/apps/not-a-ulid/secrets/feed-key", `{"value":"v"}`, http.StatusNotFound, "app_not_found"},
	} {
		t.Run(tc.why, func(t *testing.T) {
			before := f.opSecrets.setCalls()
			check(t, f.do(t, http.MethodPut, tc.path, tc.body, c), tc.status, tc.code)
			if f.opSecrets.setCalls() != before {
				t.Fatal("Set was called for a request refused at the boundary")
			}
		})
	}
}

// sentinelLeakNeedles is every 3-character substring of s.
func sentinelLeakNeedles(s string) []string {
	var out []string
	for i := 0; i+3 <= len(s); i++ {
		out = append(out, s[i:i+3])
	}
	return out
}

// TC-604-11 (F-604-03): no response body and no log record carries the
// sentinel or any 3-character substring of it, on the success path, every
// error path, a malformed body whose bad byte sits inside the sentinel, and a
// query-string value; the query-string request is refused without calling
// Set; and the route is logged as the pattern.
func TestOperatorSecretPut_NoValueLeaks(t *testing.T) {
	const sentinel = "Qz7Xv9Kj4W"
	f := newAPIFixture(t)
	c := f.authenticate(t)
	log, rec := logkittest.New()
	ops := &fakeOperatorSecrets{}
	srv, err := NewServer(f.jobsStore, f.runner, f.inv, inventory.NewService(f.inv, f.nc, slog.New(slog.DiscardHandler)),
		f.fw, f.fwSvc, f.appsStore, f.metricsStore, f.updStore, f.verifier, f.bundleDir, f.srv.trustDir,
		f.mesh, f.bmcSvc, f.setupSvc, f.authSvc, nil, f.srv.busTokens, f.nc,
		f.srv.bus, ops, log, func() string { return "cid-fixed" })
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	var bodies []string
	do := func(method, path, body string) *httptest.ResponseRecorder {
		var req *http.Request
		if body == "" {
			req = httptest.NewRequest(method, path, nil)
		} else {
			req = httptest.NewRequest(method, path, strings.NewReader(body))
		}
		req.AddCookie(c)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		bodies = append(bodies, w.Body.String())
		return w
	}
	good := `{"value":"` + sentinel + `"}`

	if w := do(http.MethodPut, opPutPath, good); w.Code != http.StatusNoContent || ops.value != sentinel {
		t.Fatalf("success path: status %d", w.Code)
	}
	for _, tc := range opErrorCases {
		ops.setErr = tc.err
		if w := do(http.MethodPut, opPutPath, good); w.Code != tc.status {
			t.Fatalf("%s: status %d, want %d", tc.why, w.Code, tc.status)
		}
	}
	ops.setErr = nil
	do(http.MethodPut, "/api/apps/"+opAppID+"/secrets/Feed_Key", good)
	do(http.MethodPut, opPutPath, `{"value":"`+sentinel+strings.Repeat("x", 9<<10)+`"}`)
	do(http.MethodPut, opPutPath, `{"other":"`+sentinel+`"}`)
	before := len(rec.Records())
	if w := do(http.MethodPut, opPutPath, `{"value":"Qz7Xv`+"\x01"+`9Kj4W"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed body: status %d, want 400", w.Code)
	}
	recs := rec.Records()[before:]
	if len(recs) != 1 {
		t.Fatalf("%d records for the malformed body, want 1", len(recs))
	}
	if cause, _ := logkittest.Attr(recs[0], "cause"); cause != "body_not_json" {
		t.Fatalf("the malformed body's cause is %q, want exactly body_not_json", cause)
	}
	calls := ops.setCalls()
	if w := do(http.MethodPut, opPutPath+"?value="+sentinel, ""); w.Code != http.StatusBadRequest {
		t.Fatalf("query-string value: status %d, want 400", w.Code)
	}
	if ops.setCalls() != calls {
		t.Fatal("Set was called for a value sent in the query string")
	}

	texts := append(bodies, rec.Text())
	for _, needle := range sentinelLeakNeedles(sentinel) {
		for _, s := range texts {
			if strings.Contains(s, needle) {
				t.Errorf("%q (from the sentinel) appears in %q", needle, s)
			}
		}
	}
	for _, r := range rec.Records() {
		route, _ := logkittest.Attr(r, "route")
		if route != "PUT /api/apps/{id}/secrets/{name}" {
			t.Errorf("a record logs route %q, want the pattern", route)
		}
	}
}

// TC-604-12: GET answers 200 with exactly name, label, required and set per
// entry and never a value, also while the store refuses writes.
func TestOperatorSecretList(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	f.opSecrets.statuses = []apps.OperatorSecretStatus{
		{Name: "feed-key", Label: "Feed API key", Required: true, Set: true},
		{Name: "opt-key", Label: "Optional key", Required: false, Set: false},
	}
	f.opSecrets.setErr = storeErrOf(secretstore.ErrSealed)
	w := f.do(t, http.MethodGet, "/api/apps/"+opAppID+"/secrets", "", c)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s, want 200", w.Code, w.Body.String())
	}
	var got []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || len(got) != 2 {
		t.Fatalf("body %s: %v", w.Body.String(), err)
	}
	for _, e := range got {
		keys := make([]string, 0, len(e))
		for k := range e {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if !slices.Equal(keys, []string{"label", "name", "required", "set"}) {
			t.Fatalf("entry keys %v, want exactly name, label, required, set", keys)
		}
	}
	if got[0]["set"] != true || got[1]["required"] != false {
		t.Fatalf("entries %v do not carry the service's answer", got)
	}

	f.opSecrets.statusErr = fmt.Errorf("%w: %s", apps.ErrAppNotFound, opAppID)
	if w := f.do(t, http.MethodGet, "/api/apps/"+opAppID+"/secrets", "", c); w.Code != http.StatusNotFound || decodeCoded(t, w.Body.Bytes()).Code != "app_not_found" {
		t.Fatalf("absent app: status %d body %s", w.Code, w.Body.String())
	}
	f.opSecrets.statusErr = fmt.Errorf("refs unreadable")
	if w := f.do(t, http.MethodGet, "/api/apps/"+opAppID+"/secrets", "", c); w.Code != http.StatusInternalServerError || decodeCoded(t, w.Body.Bytes()).Code != "operator_secret_failed" {
		t.Fatalf("failed list: status %d body %s", w.Code, w.Body.String())
	}
	if w := f.do(t, http.MethodGet, "/api/apps/nope/secrets", "", c); w.Code != http.StatusNotFound {
		t.Fatalf("invalid ID: status %d", w.Code)
	}
}

// TC-604-13: both routes are registered on the mux the route-enumeration auth
// test reads (TestEveryRouteRequiresSessionUnlessAllowlisted), and answer 401
// without a session.
func TestOperatorSecretRoutesRequireASession(t *testing.T) {
	f := newAPIFixture(t)
	patterns := f.srv.routes().Patterns()
	for _, p := range []string{"GET /api/apps/{id}/secrets", "PUT /api/apps/{id}/secrets/{name}"} {
		if !slices.Contains(patterns, p) {
			t.Errorf("%s is not registered", p)
		}
		if _, ok := openRoutes[p]; ok {
			t.Errorf("%s is on the open-routes allowlist", p)
		}
	}
	for _, r := range []struct{ method, path string }{
		{http.MethodGet, "/api/apps/" + opAppID + "/secrets"},
		{http.MethodPut, opPutPath},
	} {
		if w := f.do(t, r.method, r.path, `{"value":"v"}`, nil); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a session = %d, want 401", r.method, r.path, w.Code)
		}
	}
	if f.opSecrets.setCalls() != 0 {
		t.Fatal("Set was called without a session")
	}
}
