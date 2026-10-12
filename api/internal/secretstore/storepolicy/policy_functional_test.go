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
	"strings"
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
// on (listenerRefused is the one probe that answers otherwise). A method of LIST is a GET with ?list=true.
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

// listenerRefused is refused at the listener before any policy applies: the
// store's listener disables the unauthenticated generate-root endpoints
// (register row T21; TC-756-14 sees the same 405 token-less), so a token makes
// no difference and the answer is 405, not 403 (TC-804-06).
var listenerRefused = probe{http.MethodGet, "sys/generate-root/attempt", nil}

// refusedAtListener asserts listenerRefused answers 405 to token.
func refusedAtListener(t *testing.T, do func(*testing.T, string, probe) (int, []byte), who, token string) {
	t.Helper()
	code, _ := do(t, token, listenerRefused)
	t.Logf("%s %s %s -> %d", who, listenerRefused.method, listenerRefused.path, code)
	if code != http.StatusMethodNotAllowed {
		t.Errorf("%s %s %s = %d, want 405 (refused at the listener, T21)", who, listenerRefused.method, listenerRefused.path, code)
	}
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
	roles := []secretstoretest.Role{
		{Name: storepolicy.APIPolicy, Policy: storepolicy.APIPolicy, PolicyText: text(t, storepolicy.APIPolicy)},
		{Name: storepolicy.SealRotatePolicy, Policy: storepolicy.SealRotatePolicy, PolicyText: text(t, storepolicy.SealRotatePolicy)},
		{Name: sudoOnly, Policy: sudoOnly, PolicyText: []byte(`path "sys/rotate/root" { capabilities = ["sudo"] }` + "\n")},
		{Name: updateOnly, Policy: updateOnly, PolicyText: []byte(`path "sys/rotate/root" { capabilities = ["update"] }` + "\n")},
	}
	st, ok := startStore(t, secretstoretest.Bootstrap{Mount: storepolicy.Mount, Roles: roles})
	if !ok {
		return
	}
	s, do, token, rec := st.s, st.do, st.token, st.rec
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
		refusedAtListener(t, do, "api", api)
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
		refusedAtListener(t, do, "rotate", rot)
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

// realStore is a started store and the helpers a test drives it with.
type realStore struct {
	s     *secretstoretest.Store
	rec   *logkittest.Recorder
	do    func(*testing.T, string, probe) (int, []byte)
	token func(*testing.T, string) string
}

// startStore starts the real pinned store with b, or skips or fails through
// the functional switch when there is no binary; ok is false when it skipped.
// The store is closed when the test ends.
func startStore(t *testing.T, b secretstoretest.Bootstrap) (realStore, bool) {
	t.Helper()
	bin := os.Getenv(binEnv)
	if bin == "" {
		functest.SkipOrFail(t, switchEnv, "%s is not set, so there is no secret store binary to run", binEnv)
		return realStore{}, false
	}
	if _, err := os.Stat(bin); err != nil {
		functest.SkipOrFail(t, switchEnv, "%s=%s: no secret store binary there: %v", binEnv, bin, err)
		return realStore{}, false
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
	s, err := h.StartWith(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(context.Background()); err != nil {
			t.Errorf("cleanup Close: %v", err)
		}
	})
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: s.ClientTLS()}}
	t.Cleanup(c.CloseIdleConnections)
	return realStore{
		s:   s,
		rec: rec,
		do: func(t *testing.T, token string, p probe) (int, []byte) {
			t.Helper()
			return call(t, c, s.URL(), token, p)
		},
		token: func(t *testing.T, role string) string {
			t.Helper()
			v, err := s.TokenFor(t.Context(), role)
			if err != nil {
				t.Fatalf("login as %s: %v", role, err)
			}
			return string(v.Reveal())
		},
	}, true
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

// The provisioner's test-only roles (geekdojo-brain#805), each labelled:
//   - inspector reads what the provisioner must not change, so the test can
//     compare before and after without a root token;
//   - requiredRead and readControl show required_parameters is checked on a
//     read (capability row: the reason presence comes from LIST);
//   - aliasWriter writes a role with policies and no token_policies, to show
//     the store honours the alias the provisioner's policy pins.
const (
	inspector    = "test-inspector"
	requiredRead = "test-required-on-read"
	readControl  = "test-read-control"
	aliasWriter  = "test-alias-writer"
	aliasRole    = "test-alias-a"
)

var inspectorPolicy = []byte(`path "sys/policies/acl" { capabilities = ["list"] }
path "sys/policies/acl/*" { capabilities = ["read"] }
path "sys/mounts" { capabilities = ["read"] }
path "sys/mounts/*" { capabilities = ["read"] }
path "auth/cert/certs" { capabilities = ["list"] }
path "auth/cert/certs/*" { capabilities = ["read"] }
path "auth/token/accessors" { capabilities = ["list", "sudo"] }
path "auth/token/lookup-accessor" { capabilities = ["update"] }
`)

// TestProvisionerPolicy_AgainstTheRealStore runs the shipped provisioner and
// bindable policies in the real pinned store, beside the api's and the
// rotation job's, with rasputin-bindable loaded through Bootstrap.Policies and
// no role, as the image's init.json loads it (geekdojo-brain#805, TC-805-07 to
// TC-805-15; .github/third-party-capabilities.tsv rows T47 to T56).
func TestProvisionerPolicy_AgainstTheRealStore(t *testing.T) {
	role := func(name string, pol []byte) secretstoretest.Role {
		return secretstoretest.Role{Name: name, Policy: name, PolicyText: pol}
	}
	st, ok := startStore(t, secretstoretest.Bootstrap{
		Mount: storepolicy.Mount,
		Roles: []secretstoretest.Role{
			role(storepolicy.APIPolicy, text(t, storepolicy.APIPolicy)),
			role(storepolicy.SealRotatePolicy, text(t, storepolicy.SealRotatePolicy)),
			role(storepolicy.ProvisionerPolicy, text(t, storepolicy.ProvisionerPolicy)),
			role(inspector, inspectorPolicy),
			role(requiredRead, []byte(`path "auth/cert/certs/rasputin-api" {
  capabilities = ["read"]
  required_parameters = ["certificate"]
}
`)),
			role(readControl, []byte(`path "auth/cert/certs/rasputin-api" { capabilities = ["read"] }`+"\n")),
			role(aliasWriter, []byte(`path "auth/cert/certs/test-alias-*" { capabilities = ["update"] }`+"\n")),
		},
		Policies: []secretstoretest.Policy{{Name: storepolicy.BindablePolicy, Text: text(t, storepolicy.BindablePolicy)}},
	})
	if !ok {
		return
	}
	s, do, token := st.s, st.do, st.token
	caPEM := string(s.StoreCA().CertPEM)
	prov := token(t, storepolicy.ProvisionerPolicy)
	insp := token(t, inspector)
	tokens := []string{prov, insp}

	// status asserts p answers want to tok, logging both.
	status := func(t *testing.T, who, tok string, p probe, want int) []byte {
		t.Helper()
		code, body := do(t, tok, p)
		t.Logf("%s %s %s -> %d", who, p.method, p.path, code)
		if code != want {
			t.Errorf("%s %s %s = %d, want %d", who, p.method, p.path, code, want)
		}
		return body
	}
	// read is the inspector's view of path, for comparing before and after.
	read := func(t *testing.T, path string) string {
		t.Helper()
		code, body := do(t, insp, probe{http.MethodGet, path, nil})
		if code != http.StatusOK {
			t.Fatalf("inspector GET %s = %d", path, code)
		}
		var v struct {
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(body, &v); err != nil {
			t.Fatalf("inspector GET %s: %v", path, err)
		}
		return string(v.Data)
	}
	// roles is the role names a LIST by tok returns.
	roles := func(t *testing.T, tok string) []string {
		t.Helper()
		code, body := do(t, tok, probe{"LIST", "auth/cert/certs", nil})
		var v struct {
			Data struct {
				Keys []string `json:"keys"`
			} `json:"data"`
		}
		if code != http.StatusOK || json.Unmarshal(body, &v) != nil {
			t.Fatalf("LIST auth/cert/certs = %d", code)
		}
		return v.Data.Keys
	}
	// goodRole is a fully valid namespace role body for name, every value a
	// string, as the os oneshot's CLI sends it.
	goodRole := func(name string) map[string]any {
		return map[string]any{
			"certificate": caPEM, "allowed_common_names": name, "token_policies": storepolicy.BindablePolicy,
			"token_no_default_policy": "true", "token_ttl": "1h",
		}
	}
	with := func(m map[string]any, kv ...any) map[string]any {
		out := map[string]any{}
		for k, v := range m {
			out[k] = v
		}
		for i := 0; i+1 < len(kv); i += 2 {
			if kv[i+1] == nil {
				delete(out, kv[i].(string))
				continue
			}
			out[kv[i].(string)] = kv[i+1]
		}
		return out
	}
	policies := func(t *testing.T, tok string) []string {
		t.Helper()
		code, body := do(t, tok, probe{http.MethodGet, "auth/token/lookup-self", nil})
		var ls struct {
			Data struct {
				Policies []string `json:"policies"`
			} `json:"data"`
		}
		if code != http.StatusOK || json.Unmarshal(body, &ls) != nil {
			t.Fatalf("lookup-self = %d", code)
		}
		return ls.Data.Policies
	}
	fixedRoles := []string{storepolicy.APIPolicy, storepolicy.SealRotatePolicy, storepolicy.ProvisionerPolicy}
	fixedPolicies := []string{storepolicy.APIPolicy, storepolicy.SealRotatePolicy, storepolicy.ProvisionerPolicy, storepolicy.BindablePolicy}
	before := map[string]string{}
	for _, r := range fixedRoles {
		before["auth/cert/certs/"+r] = read(t, "auth/cert/certs/"+r)
	}
	for _, p := range fixedPolicies {
		before["sys/policies/acl/"+p] = read(t, "sys/policies/acl/"+p)
	}
	before["sys/mounts/"+storepolicy.Mount+"/tune"] = read(t, "sys/mounts/"+storepolicy.Mount+"/tune")
	unchanged := func(t *testing.T) {
		t.Helper()
		for path, was := range before {
			if got := read(t, path); got != was {
				t.Errorf("%s changed:\n before %s\n after  %s", path, was, got)
			}
		}
	}

	const mount, nsRole = storepolicy.Namespace + "t", storepolicy.Namespace + "t"

	// TC-805-07 (D-805-A; rows T50, T51, T54, T55, T56): the positive path, no root.
	t.Run("TC-805-07 provisioner positive path", func(t *testing.T) {
		status(t, "prov", prov, probe{http.MethodGet, "sys/mounts/" + storepolicy.Namespace + "absent", nil}, http.StatusBadRequest)
		_, body := do(t, prov, probe{http.MethodGet, "sys/mounts/" + storepolicy.Namespace + "absent", nil})
		if !bytes.Contains(body, []byte("No secret engine mount at")) {
			t.Errorf("an absent mount's read says %q, want it to say No secret engine mount at (row T51)", body)
		}
		status(t, "prov", prov, probe{http.MethodPost, "sys/mounts/" + mount, map[string]any{"type": "kv-v2"}}, http.StatusNoContent)
		body = status(t, "prov", prov, probe{http.MethodGet, "sys/mounts/" + mount, nil}, http.StatusOK)
		var mi struct {
			Data struct {
				Type    string            `json:"type"`
				Options map[string]string `json:"options"`
			} `json:"data"`
		}
		if json.Unmarshal(body, &mi) != nil || mi.Data.Type != "kv" || mi.Data.Options["version"] != "2" {
			t.Errorf("%s reads back as %s, want type kv, options.version 2 (row T50)", mount, body)
		}
		// Longest prefix: a read below the mount answers with the mount's own entry.
		body = status(t, "prov", prov, probe{http.MethodGet, "sys/mounts/" + mount + "/sub", nil}, http.StatusOK)
		var sub struct {
			Data struct {
				UUID string `json:"uuid"`
			} `json:"data"`
		}
		var top struct {
			Data struct {
				UUID string `json:"uuid"`
			} `json:"data"`
		}
		_, topBody := do(t, prov, probe{http.MethodGet, "sys/mounts/" + mount, nil})
		if json.Unmarshal(body, &sub) != nil || json.Unmarshal(topBody, &top) != nil || sub.Data.UUID == "" || sub.Data.UUID != top.Data.UUID {
			t.Errorf("sys/mounts/%s/sub reads uuid %q, want %s's own %q (row T56)", mount, sub.Data.UUID, mount, top.Data.UUID)
		}
		got := roles(t, prov)
		for _, r := range fixedRoles {
			if !slices.Contains(got, r) {
				t.Errorf("LIST auth/cert/certs = %v, want it to hold %s (row T55)", got, r)
			}
		}
		status(t, "prov", prov, probe{http.MethodPost, "auth/cert/certs/" + nsRole, goodRole(nsRole)}, http.StatusNoContent)
		if !slices.Contains(roles(t, prov), nsRole) {
			t.Errorf("LIST after the write = %v, want %s", roles(t, prov), nsRole)
		}
		v, err := s.Login(t.Context(), nsRole, nsRole)
		if err != nil {
			t.Fatalf("a leaf with CN %s logs in against its role: %v", nsRole, err)
		}
		rel := string(v.Reveal())
		tokens = append(tokens, rel)
		if got := policies(t, rel); !slices.Equal(got, []string{storepolicy.BindablePolicy}) {
			t.Errorf("the namespace role's token carries %v, want exactly [%s]", got, storepolicy.BindablePolicy)
		}
		status(t, "rel", rel, probe{http.MethodGet, mount + "/data/x", nil}, http.StatusForbidden)
		status(t, "rel", rel, probe{http.MethodPost, mount + "/data/x", map[string]any{"data": map[string]string{"k": "v"}}}, http.StatusForbidden)
		for _, p := range denied {
			status(t, "rel", rel, p, http.StatusForbidden)
		}
	})

	// TC-805-08 (AC2): no policy write, list or read.
	t.Run("TC-805-08 no policy write", func(t *testing.T) {
		body := map[string]string{"policy": `path "*" { capabilities = ["sudo"] }`}
		for _, name := range append([]string{"x"}, fixedPolicies...) {
			status(t, "prov", prov, probe{http.MethodPut, "sys/policies/acl/" + name, body}, http.StatusForbidden)
		}
		status(t, "prov", prov, probe{"LIST", "sys/policies/acl", nil}, http.StatusForbidden)
		status(t, "prov", prov, probe{http.MethodGet, "sys/policies/acl/" + storepolicy.ProvisionerPolicy, nil}, http.StatusForbidden)
		unchanged(t)
	})

	// TC-805-09 (AC2, D-805-A; rows T47, T48): a role binds only rasputin-bindable.
	t.Run("TC-805-09 bound only to rasputin-bindable", func(t *testing.T) {
		const r = storepolicy.Namespace + "t2"
		bad := []string{storepolicy.APIPolicy, storepolicy.SealRotatePolicy, storepolicy.ProvisionerPolicy, "root", "default",
			"no-such-policy", storepolicy.BindablePolicy + "," + storepolicy.SealRotatePolicy}
		for _, pol := range bad {
			status(t, "prov token_policies="+pol, prov, probe{http.MethodPost, "auth/cert/certs/" + r, with(goodRole(r), "token_policies", pol)}, http.StatusForbidden)
			status(t, "prov policies="+pol, prov, probe{http.MethodPost, "auth/cert/certs/" + r, with(goodRole(r), "policies", pol)}, http.StatusForbidden)
		}
		status(t, "prov policies only", prov, probe{http.MethodPost, "auth/cert/certs/" + r,
			with(goodRole(r), "token_policies", nil, "policies", storepolicy.BindablePolicy)}, http.StatusForbidden)
		status(t, "prov JSON list", prov, probe{http.MethodPost, "auth/cert/certs/" + r,
			with(goodRole(r), "token_policies", []string{storepolicy.BindablePolicy})}, http.StatusForbidden)
		status(t, "prov JSON bool", prov, probe{http.MethodPost, "auth/cert/certs/" + r,
			with(goodRole(r), "token_no_default_policy", true)}, http.StatusForbidden)
		if slices.Contains(roles(t, prov), r) {
			t.Errorf("%s exists after every write was refused", r)
		}
		// The alias the pin closes is real: a role written with policies and no
		// token_policies (by a test-only writer) binds that policy (row T48).
		aw := token(t, aliasWriter)
		tokens = append(tokens, aw)
		status(t, "alias-writer", aw, probe{http.MethodPost, "auth/cert/certs/" + aliasRole, map[string]any{
			"certificate": caPEM, "allowed_common_names": aliasRole, "policies": storepolicy.BindablePolicy, "token_no_default_policy": "true",
		}}, http.StatusNoContent)
		v, err := s.Login(t.Context(), aliasRole, aliasRole)
		if err != nil {
			t.Fatalf("login against the alias role: %v", err)
		}
		tok := string(v.Reveal())
		tokens = append(tokens, tok)
		if got := policies(t, tok); !slices.Equal(got, []string{storepolicy.BindablePolicy}) {
			t.Errorf("a role written with policies= carries %v, want [%s]: the alias is honoured", got, storepolicy.BindablePolicy)
		}
	})

	// TC-805-10 (AC2): no write or delete on a fixed role.
	t.Run("TC-805-10 no write on fixed roles", func(t *testing.T) {
		foreign := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
		for _, r := range fixedRoles {
			status(t, "prov", prov, probe{http.MethodPost, "auth/cert/certs/" + r, goodRole(r)}, http.StatusForbidden)
			status(t, "prov", prov, probe{http.MethodPost, "auth/cert/certs/" + r, with(goodRole(r), "certificate", foreign)}, http.StatusForbidden)
			status(t, "prov", prov, probe{http.MethodDelete, "auth/cert/certs/" + r, nil}, http.StatusForbidden)
		}
		unchanged(t)
	})

	// TC-805-11 (rows T52, T53): every role field is pinned.
	t.Run("TC-805-11 role field limits", func(t *testing.T) {
		const r = storepolicy.Namespace + "t3"
		bodies := map[string]map[string]any{}
		for _, cn := range []string{storepolicy.APIPolicy, "*", "", storepolicy.Namespace + "x," + storepolicy.APIPolicy} {
			bodies["allowed_common_names="+cn] = with(goodRole(r), "allowed_common_names", cn)
		}
		bodies["token_no_default_policy=false"] = with(goodRole(r), "token_no_default_policy", "false")
		bodies["no token_no_default_policy"] = with(goodRole(r), "token_no_default_policy", nil)
		bodies["token_ttl=2h"] = with(goodRole(r), "token_ttl", "2h")
		bodies["no token_ttl"] = with(goodRole(r), "token_ttl", nil)
		for k, v := range map[string]string{"token_period": "1h", "token_type": "service", "display_name": "x",
			"allowed_metadata_extensions": "1.2.3", "token_bound_cidrs": "127.0.0.1/32", "allowed_names": "x", "ttl": "1h"} {
			bodies["extra "+k] = with(goodRole(r), k, v)
		}
		for name, b := range bodies {
			status(t, "prov "+name, prov, probe{http.MethodPost, "auth/cert/certs/" + r, b}, http.StatusForbidden)
		}
		if slices.Contains(roles(t, prov), r) {
			t.Errorf("%s exists after every write was refused", r)
		}
	})

	// TC-805-12 (row T52): mount limits.
	t.Run("TC-805-12 mount limits", func(t *testing.T) {
		const u = storepolicy.Namespace + "u"
		for _, p := range []probe{
			{http.MethodPost, "sys/mounts/rasputin-secrets2", map[string]any{"type": "kv-v2"}},
			{http.MethodPost, "sys/mounts/" + u, map[string]any{"type": "transit"}},
			{http.MethodPost, "sys/mounts/" + u, map[string]any{"type": "kv", "options": map[string]string{"version": "2"}}},
			{http.MethodPost, "sys/mounts/" + u, map[string]any{"type": "kv-v2", "config": map[string]string{"default_lease_ttl": "1h"}}},
			{http.MethodPost, "sys/mounts/" + u, map[string]any{"type": "kv-v2", "local": "true"}},
			{http.MethodPost, "sys/mounts/" + u, map[string]any{"type": "kv-v2", "seal_wrap": "true"}},
			{http.MethodPost, "sys/mounts/" + u, map[string]any{"type": "kv-v2", "description": "x"}},
			{http.MethodPost, "sys/mounts/" + mount + "/tune", map[string]any{"audit_non_hmac_request_keys": "k"}},
			{http.MethodPost, "sys/mounts/" + storepolicy.Mount + "/tune", map[string]any{"audit_non_hmac_request_keys": "k"}},
			{http.MethodDelete, "sys/mounts/" + mount, nil},
			{http.MethodPost, "sys/remount", map[string]any{"from": mount, "to": storepolicy.Namespace + "moved"}},
		} {
			status(t, "prov", prov, p, http.StatusForbidden)
		}
		if read(t, "sys/mounts/"+mount) == "" {
			t.Errorf("%s is no longer mounted", mount)
		}
		code, _ := do(t, insp, probe{http.MethodGet, "sys/mounts/" + u, nil})
		if code != http.StatusBadRequest {
			t.Errorf("inspector GET sys/mounts/%s = %d, want 400: no mount was made", u, code)
		}
		unchanged(t)
	})

	// TC-805-13: root and admin routes, every denied and data probe.
	t.Run("TC-805-13 root and admin routes", func(t *testing.T) {
		for _, p := range append(slices.Clone(denied), append(dataProbes,
			probe{http.MethodPost, "sys/rotate/root", nil},
			probe{http.MethodPost, "sys/audit/x", map[string]any{"type": "file"}},
			probe{http.MethodPost, "sys/auth/x", map[string]any{"type": "cert"}},
		)...) {
			status(t, "prov", prov, p, http.StatusForbidden)
		}
		refusedAtListener(t, do, "prov", prov)
	})

	// TC-805-14 (AC2, F-804-02): every route to rasputin-seal-rotate.
	t.Run("TC-805-14 every route to rasputin-seal-rotate", func(t *testing.T) {
		const r = storepolicy.Namespace + "t4"
		for _, row := range []struct {
			route string
			p     probe
		}{
			{"a policy write", probe{http.MethodPut, "sys/policies/acl/" + storepolicy.SealRotatePolicy, map[string]string{"policy": `path "*" { capabilities = ["sudo"] }`}}},
			{"a write to its role", probe{http.MethodPost, "auth/cert/certs/" + storepolicy.SealRotatePolicy, goodRole(storepolicy.SealRotatePolicy)}},
			{"a namespace role naming it in token_policies", probe{http.MethodPost, "auth/cert/certs/" + r, with(goodRole(r), "token_policies", storepolicy.SealRotatePolicy)}},
			{"a namespace role naming it in policies", probe{http.MethodPost, "auth/cert/certs/" + r, with(goodRole(r), "policies", storepolicy.SealRotatePolicy)}},
			{"a namespace role with CN rasputin-seal-rotate", probe{http.MethodPost, "auth/cert/certs/" + r, with(goodRole(r), "allowed_common_names", storepolicy.SealRotatePolicy)}},
			{"token create with it", probe{http.MethodPost, "auth/token/create", map[string]any{"policies": []string{storepolicy.SealRotatePolicy}}}},
		} {
			code, _ := do(t, prov, row.p)
			t.Logf("seal-rotate route | %-46s | %s %s | %d", row.route, row.p.method, row.p.path, code)
			if code != http.StatusForbidden {
				t.Errorf("seal-rotate route %s = %d, want 403", row.route, code)
			}
		}
		rot := token(t, storepolicy.SealRotatePolicy)
		tokens = append(tokens, rot)
		// Every token in the store, by accessor: only the seal-rotate role's
		// own login carries the rotation policy.
		code, body := do(t, insp, probe{"LIST", "auth/token/accessors", nil})
		var acc struct {
			Data struct {
				Keys []string `json:"keys"`
			} `json:"data"`
		}
		if code != http.StatusOK || json.Unmarshal(body, &acc) != nil || len(acc.Data.Keys) == 0 {
			t.Fatalf("inspector LIST auth/token/accessors = %d", code)
		}
		carrying := 0
		for _, a := range acc.Data.Keys {
			code, body := do(t, insp, probe{http.MethodPost, "auth/token/lookup-accessor", map[string]string{"accessor": a}})
			var la struct {
				Data struct {
					Policies []string          `json:"policies"`
					Meta     map[string]string `json:"meta"`
				} `json:"data"`
			}
			if code != http.StatusOK || json.Unmarshal(body, &la) != nil {
				t.Fatalf("inspector lookup-accessor = %d", code)
			}
			if slices.Contains(la.Data.Policies, storepolicy.SealRotatePolicy) {
				carrying++
				if la.Data.Meta["cert_name"] != storepolicy.SealRotatePolicy {
					t.Errorf("a token carrying %s came from cert role %q", storepolicy.SealRotatePolicy, la.Data.Meta["cert_name"])
				}
			}
		}
		t.Logf("%d token(s) in the store, %d carrying %s", len(acc.Data.Keys), carrying, storepolicy.SealRotatePolicy)
		if carrying != 1 {
			t.Errorf("%d tokens carry %s, want exactly 1, the seal-rotate role's own login", carrying, storepolicy.SealRotatePolicy)
		}
	})

	// TC-805-15: the api's token cannot provision.
	t.Run("TC-805-15 api token cannot provision", func(t *testing.T) {
		api := token(t, storepolicy.APIPolicy)
		tokens = append(tokens, api)
		const x = storepolicy.Namespace + "x"
		status(t, "api", api, probe{http.MethodPost, "auth/cert/certs/" + x, goodRole(x)}, http.StatusForbidden)
		status(t, "api", api, probe{http.MethodPost, "sys/mounts/" + x, map[string]any{"type": "kv-v2"}}, http.StatusForbidden)
	})

	// Row T49: required_parameters is checked on a read, so a read of a role
	// can never come from the provisioner's role stanza: presence is LIST's.
	t.Run("required_parameters on a read", func(t *testing.T) {
		rr, rc := token(t, requiredRead), token(t, readControl)
		tokens = append(tokens, rr, rc)
		status(t, requiredRead, rr, probe{http.MethodGet, "auth/cert/certs/" + storepolicy.APIPolicy, nil}, http.StatusForbidden)
		status(t, readControl, rc, probe{http.MethodGet, "auth/cert/certs/" + storepolicy.APIPolicy, nil}, http.StatusOK)
	})

	logged := st.rec.Text()
	for _, tok := range tokens {
		if tok != "" && strings.Contains(logged, tok) {
			t.Error("a token appears in the log")
		}
	}
}
