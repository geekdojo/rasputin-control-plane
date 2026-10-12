package storepolicy_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storepolicy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstoretest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// The same switch as the harness's smoke test (docs/testing-secret-store.md):
// CI's backend job sets both, so this test must run and pass there.
const (
	binEnv    = "RASPUTIN_SECRETSTORE_BIN"
	switchEnv = "RASPUTIN_SECRETSTORE_FUNCTIONAL"
)

// Test-only roles for TC-804-07: each holds half of the rotation policy, to
// show neither half alone can rotate.
const (
	sudoOnly   = "test-rotate-sudo-only"
	updateOnly = "test-rotate-update-only"
)

// probe is one request a token must be refused (geekdojo-brain#804
// TC-804-06's list).
type probe struct {
	method, path string
	body         any
}

// denied is every path the api token, and the rotation token, must get 403
// on. A method of LIST is a GET with ?list=true.
var denied = []probe{
	{http.MethodGet, "rasputin-secrets/data/other", nil},
	{http.MethodPost, "rasputin-secrets/data/other", map[string]any{"data": map[string]string{"k": "v"}}},
	{http.MethodGet, "sys/mounts", nil},
	{"LIST", "sys/policies/acl", nil},
	{http.MethodGet, "sys/policies/acl/" + storepolicy.APIPolicy, nil},
	{http.MethodPut, "sys/policies/acl/injected", map[string]string{"policy": `path "*" { capabilities = ["sudo"] }`}},
	{http.MethodPut, "sys/policies/acl/" + storepolicy.APIPolicy, map[string]string{"policy": `path "*" { capabilities = ["sudo"] }`}},
	{http.MethodGet, "sys/audit", nil},
	{http.MethodGet, "sys/auth", nil},
	{http.MethodPost, "sys/capabilities-self", map[string]any{"paths": []string{"sys/rotate/root"}}},
	{http.MethodPost, "sys/tools/hash", map[string]string{"input": "eA=="}},
	{http.MethodPost, "sys/rotate/root", nil},
	{http.MethodPost, "sys/rotate/recovery/init", nil},
	{http.MethodGet, "sys/generate-root-token/attempt", nil},
	{http.MethodGet, "sys/storage/raft/snapshot", nil},
	{"LIST", "identity/entity/id", nil},
	{http.MethodPost, "identity/entity", map[string]string{"name": "injected"}},
	{http.MethodGet, "identity/entity/id/x", nil},
	{http.MethodPost, "auth/token/create", map[string]any{}},
	{http.MethodPost, "auth/token/create", map[string]any{"policies": []string{storepolicy.SealRotatePolicy}}},
	{http.MethodPost, "auth/token/create-orphan", map[string]any{}},
	{"LIST", "auth/token/accessors", nil},
	{http.MethodPost, "auth/cert/certs/" + storepolicy.APIPolicy, map[string]any{"token_policies": []string{storepolicy.SealRotatePolicy}}},
	{http.MethodPost, "auth/cert/certs/" + storepolicy.SealRotatePolicy, map[string]any{"allowed_common_names": []string{storepolicy.APIPolicy}}},
}

// dataProbes are the api's own data and metadata paths, which the rotation
// token must be refused too.
var dataProbes = []probe{
	{http.MethodGet, "rasputin-secrets/data/apps/x", nil},
	{http.MethodPost, "rasputin-secrets/data/apps/x", map[string]any{"data": map[string]string{"k": "v"}}},
	{http.MethodGet, "rasputin-secrets/data/devices/x", nil},
	{http.MethodPost, "rasputin-secrets/data/devices/x", map[string]any{"data": map[string]string{"k": "v"}}},
	{http.MethodGet, "rasputin-secrets/metadata/apps/x", nil},
	{http.MethodDelete, "rasputin-secrets/metadata/devices/x", nil},
	{http.MethodGet, "auth/token/lookup-self", nil},
}

// TestStorePolicy_AgainstTheRealStore runs the shipped policy text in the real
// pinned store: StartWith creates the rasputin-secrets mount, the api's role
// and the rotation role from this package's files, exactly as the image's
// init.json does, plus two test-only half-rotation roles. It proves what the
// static tests cannot: what OpenBao grants and refuses with that text
// (geekdojo-brain#804; TC-804-05 to TC-804-08; register rows T34, T35, T37).
func TestStorePolicy_AgainstTheRealStore(t *testing.T) {
	bin := os.Getenv(binEnv)
	if bin == "" {
		functest.SkipOrFail(t, switchEnv, "%s is not set, so there is no secret store binary to run", binEnv)
		return
	}
	if _, err := os.Stat(bin); err != nil {
		functest.SkipOrFail(t, switchEnv, "%s=%s: no secret store binary there: %v", binEnv, bin, err)
		return
	}
	log, rec := logkittest.New()
	h, err := secretstoretest.New(secretstoretest.Config{
		BinaryPath: bin,
		TempParent: t.TempDir(),
		Logger:     slog.New(slog.NewMultiHandler(log.Handler(), slog.NewTextHandler(t.Output(), nil))),
		Now:        time.Now,
		Rand:       rand.Reader,
	})
	if err != nil {
		t.Fatal(err)
	}
	roles := []secretstoretest.Role{
		{Name: storepolicy.APIPolicy, Policy: storepolicy.APIPolicy, PolicyText: text(t, storepolicy.APIPolicy)},
		{Name: storepolicy.SealRotatePolicy, Policy: storepolicy.SealRotatePolicy, PolicyText: text(t, storepolicy.SealRotatePolicy)},
		{Name: sudoOnly, Policy: sudoOnly, PolicyText: []byte(`path "sys/rotate/root" { capabilities = ["sudo"] }` + "\n")},
		{Name: updateOnly, Policy: updateOnly, PolicyText: []byte(`path "sys/rotate/root" { capabilities = ["update"] }` + "\n")},
	}
	s, err := h.StartWith(t.Context(), secretstoretest.Bootstrap{Mount: storepolicy.Mount, Roles: roles})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(context.Background()); err != nil {
			t.Errorf("cleanup Close: %v", err)
		}
	})
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: s.ClientTLS()}}
	defer c.CloseIdleConnections()
	do := func(t *testing.T, token string, p probe) (int, []byte) {
		t.Helper()
		return call(t, c, s.URL(), token, p)
	}
	token := func(t *testing.T, role string) string {
		t.Helper()
		v, err := s.TokenFor(t.Context(), role)
		if err != nil {
			t.Fatalf("login as %s: %v", role, err)
		}
		return string(v.Reveal())
	}
	var tokens []string

	// TC-804-08 (T35): self-init left no recovery material.
	t.Run("TC-804-08 seal-status t=0 n=0", func(t *testing.T) {
		code, body := do(t, "", probe{http.MethodGet, "sys/seal-status", nil})
		var st struct {
			Initialized bool `json:"initialized"`
			Sealed      bool `json:"sealed"`
			T           int  `json:"t"`
			N           int  `json:"n"`
		}
		if code != http.StatusOK || json.Unmarshal(body, &st) != nil {
			t.Fatalf("sys/seal-status = %d", code)
		}
		if !st.Initialized || st.Sealed || st.T != 0 || st.N != 0 {
			t.Errorf("seal-status initialized=%t sealed=%t t=%d n=%d, want initialized, unsealed, t=0 n=0",
				st.Initialized, st.Sealed, st.T, st.N)
		}
	})

	api := token(t, storepolicy.APIPolicy)
	tokens = append(tokens, api)

	// TC-804-05: the api token's own paths, and lookup-self.
	t.Run("TC-804-05 api CRUD and lookup-self", func(t *testing.T) {
		for _, kind := range []string{"apps", "devices"} {
			data := storepolicy.Mount + "/data/" + kind + "/x"
			meta := storepolicy.Mount + "/metadata/" + kind + "/x"
			steps := []struct {
				p    probe
				want int
			}{
				{probe{http.MethodPost, data, map[string]any{"data": map[string]string{"k": "1"}}}, http.StatusOK},
				{probe{http.MethodGet, data, nil}, http.StatusOK},
				{probe{http.MethodPost, data, map[string]any{"data": map[string]string{"k": "2"}}}, http.StatusOK},
				{probe{http.MethodDelete, data, nil}, http.StatusNoContent},
				{probe{http.MethodGet, meta, nil}, http.StatusOK},
				{probe{http.MethodDelete, meta, nil}, http.StatusNoContent},
			}
			for _, st := range steps {
				code, _ := do(t, api, st.p)
				t.Logf("api %s %s -> %d", st.p.method, st.p.path, code)
				if code != st.want {
					t.Errorf("api %s %s = %d, want %d", st.p.method, st.p.path, code, st.want)
				}
			}
		}
		code, body := do(t, api, probe{http.MethodGet, "auth/token/lookup-self", nil})
		var ls struct {
			Data struct {
				Policies []string `json:"policies"`
			} `json:"data"`
		}
		if code != http.StatusOK || json.Unmarshal(body, &ls) != nil {
			t.Fatalf("lookup-self = %d", code)
		}
		if !slices.Equal(ls.Data.Policies, []string{storepolicy.APIPolicy}) {
			t.Errorf("lookup-self policies = %v, want exactly [%s]: no default, no root", ls.Data.Policies, storepolicy.APIPolicy)
		}
	})

	// TC-804-06: every other path is refused to the api token, and the api's
	// leaf cannot log in against the rotation role.
	t.Run("TC-804-06 api denied", func(t *testing.T) {
		for _, p := range denied {
			code, _ := do(t, api, p)
			t.Logf("api %s %s -> %d", p.method, p.path, code)
			if code != http.StatusForbidden {
				t.Errorf("api %s %s = %d, want 403", p.method, p.path, code)
			}
		}
		if v, err := s.Login(t.Context(), storepolicy.APIPolicy, storepolicy.SealRotatePolicy); err == nil {
			tokens = append(tokens, string(v.Reveal()))
			t.Error("the api's leaf logged in against the rotation role")
		} else {
			t.Logf("api leaf against %s: %v", storepolicy.SealRotatePolicy, err)
		}
	})

	// TC-804-07: the rotation token rotates and does nothing else; neither
	// half of its policy rotates alone.
	t.Run("TC-804-07 rotation minimal", func(t *testing.T) {
		rot := token(t, storepolicy.SealRotatePolicy)
		tokens = append(tokens, rot)
		for _, p := range append(slices.Clone(denied), dataProbes...) {
			if p.path == "sys/rotate/root" {
				continue
			}
			code, _ := do(t, rot, p)
			t.Logf("rotate %s %s -> %d", p.method, p.path, code)
			if code != http.StatusForbidden {
				t.Errorf("rotation token %s %s = %d, want 403", p.method, p.path, code)
			}
		}
		for _, half := range []string{sudoOnly, updateOnly} {
			tok := token(t, half)
			tokens = append(tokens, tok)
			code, _ := do(t, tok, probe{http.MethodPost, "sys/rotate/root", nil})
			t.Logf("%s POST sys/rotate/root -> %d", half, code)
			if code != http.StatusForbidden {
				t.Errorf("%s POST sys/rotate/root = %d, want 403", half, code)
			}
		}
		code, _ := do(t, rot, probe{http.MethodPost, "sys/rotate/root", nil})
		t.Logf("rotate POST sys/rotate/root -> %d", code)
		if code != http.StatusNoContent {
			t.Errorf("rotation token POST sys/rotate/root = %d, want 204", code)
		}
	})

	// No token reaches the log.
	logged := rec.Text()
	for _, tok := range tokens {
		if tok != "" && bytes.Contains([]byte(logged), []byte(tok)) {
			t.Error("a token appears in the log")
		}
	}
}

func text(t *testing.T, name string) []byte {
	t.Helper()
	b, err := storepolicy.Text(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// call makes one request and returns the status and body. Neither the token
// nor the body is ever logged.
func call(t *testing.T, c *http.Client, base, token string, p probe) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if p.body != nil {
		b, err := json.Marshal(p.body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	method, url := p.method, base+"/v1/"+p.path
	if method == "LIST" {
		method, url = http.MethodGet, url+"?list=true"
	}
	req, err := http.NewRequestWithContext(t.Context(), method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", p.method, p.path, err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("close the response body: %v", err)
		}
	}()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, b
}
