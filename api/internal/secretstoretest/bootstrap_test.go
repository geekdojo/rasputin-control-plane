package secretstoretest

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
)

// The geekdojo-brain#804 additions: Bootstrap, StartWith, Login, TokenFor and
// ClientTLSFor. These need no bao binary. What OpenBao does with a two-role
// bootstrap is storepolicy's policy_functional_test.go.

func twoRoles() Bootstrap {
	return Bootstrap{Mount: "kv-two", Roles: []Role{
		{Name: "role-a", Policy: "pol-a", PolicyText: []byte(`path "kv-two/data/a/*" { capabilities = ["read"] }` + "\n")},
		{Name: "role-b", Policy: "pol-b", PolicyText: []byte(`path "sys/rotate/root" { capabilities = ["update", "sudo"] }` + "\n")},
	}}
}

// TC-804-04: StartWith renders a two-role Bootstrap into the config the store
// is started with: each role admits only its own CommonName, carries only its
// policy and sets token_no_default_policy; each policy comes in through a file
// source naming a file that holds its text byte for byte. The fake store
// copies its whole root (configs and policy files) out before exiting, so the
// files checked are the ones bao would have read.
func TestStartWith_RendersTwoRoles(t *testing.T) {
	out := filepath.Join(t.TempDir(), "seen")
	cfg := validConfig(t)
	// $3 is main.hcl, $5 init.json; both sit in the root.
	cfg.BinaryPath = writeFake(t, `case "$1" in
version) echo "OpenBao v2.7.1 (fake)" ;;
server) cp -R "$(dirname "$5")" "`+out+`"; echo "init.json is $5" >&2; exit 3 ;;
esac
`)
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	b := twoRoles()
	s, err := h.StartWith(t.Context(), b)
	if s != nil || err == nil || !strings.Contains(err.Error(), "exit status 3") {
		t.Fatalf("StartWith = %v, %v; want the fake's exit", s, err)
	}
	assertEmpty(t, cfg.TempParent)

	raw, err := os.ReadFile(filepath.Join(out, "init.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Initialize []map[string]struct {
			Request []map[string]initRequest `json:"request"`
		} `json:"initialize"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("init.json is not JSON: %v", err)
	}
	byPath := map[string]initRequest{}
	var order []string
	for _, block := range doc.Initialize {
		for _, stanza := range block {
			for _, named := range stanza.Request {
				for _, r := range named {
					byPath[r.Path] = r
					order = append(order, r.Path)
				}
			}
		}
	}
	want := []string{
		"sys/policies/acl/pol-a", "sys/policies/acl/pol-b", "sys/mounts/kv-two", "sys/auth/cert",
		"auth/cert/certs/role-a", "auth/cert/certs/role-b",
	}
	if !reflect.DeepEqual(order, want) {
		t.Errorf("request paths = %v, want exactly %v", order, want)
	}
	for _, r := range b.Roles {
		pol := byPath["sys/policies/acl/"+r.Policy]
		src, _ := pol.Data["policy"].(map[string]any)
		if src["eval_source"] != "file" || src["eval_type"] != "string" {
			t.Errorf("policy %s source = %v, want an eval_source file string source", r.Policy, pol.Data["policy"])
		}
		p, _ := src["path"].(string)
		// The path names a file under the store's root; read the copy.
		got, err := os.ReadFile(filepath.Join(out, "policies", filepath.Base(p)))
		if err != nil || !bytes.Equal(got, r.PolicyText) {
			t.Errorf("policy file %s = %q, %v; want the role's PolicyText byte for byte", p, got, err)
		}
		if filepath.Base(filepath.Dir(p)) != "policies" || filepath.Base(p) != r.Policy+".hcl" {
			t.Errorf("policy %s is read from %q, want <root>/policies/%s.hcl", r.Policy, p, r.Policy)
		}
		role := byPath["auth/cert/certs/"+r.Name]
		if got := role.Data["allowed_common_names"]; !reflect.DeepEqual(got, []any{r.Name}) {
			t.Errorf("role %s allowed_common_names = %v, want [%s]", r.Name, got, r.Name)
		}
		if got := role.Data["token_policies"]; !reflect.DeepEqual(got, []any{r.Policy}) {
			t.Errorf("role %s token_policies = %v, want [%s]", r.Name, got, r.Policy)
		}
		if got := role.Data["token_no_default_policy"]; got != true {
			t.Errorf("role %s token_no_default_policy = %v, want true", r.Name, got)
		}
	}
	info, err := os.Stat(filepath.Join(out, "policies", "pol-a.hcl"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("policy file mode = %v, %v; want 0600", info, err)
	}
}

// TC-804-04: each Bootstrap self-init cannot be given is refused before any
// I/O, with an error naming the input: the fake's every subcommand leaves a
// marker, and none may appear.
func TestStartWith_RefusesBadBootstrap(t *testing.T) {
	good := func() Role { return Role{Name: "r", Policy: "p", PolicyText: []byte("x")} }
	cases := []struct {
		name   string
		b      Bootstrap
		needle string
	}{
		{"empty mount", Bootstrap{Roles: []Role{good()}}, "Bootstrap.Mount is empty"},
		{"mount outside the name rule", Bootstrap{Mount: "kv/../sys", Roles: []Role{good()}}, `Bootstrap.Mount "kv/../sys" is not a name`},
		{"no roles", Bootstrap{Mount: "kv"}, "Bootstrap.Roles is empty"},
		{"empty role name", Bootstrap{Mount: "kv", Roles: []Role{{Policy: "p", PolicyText: []byte("x")}}}, "Bootstrap.Roles[0].Name is empty"},
		{"duplicate role", Bootstrap{Mount: "kv", Roles: []Role{good(), good()}}, `Bootstrap.Roles[1].Name "r" is a duplicate role`},
		{"empty policy text", Bootstrap{Mount: "kv", Roles: []Role{{Name: "r", Policy: "p"}}}, "Bootstrap.Roles[0].PolicyText is empty"},
		{"role name outside the name rule", Bootstrap{Mount: "kv", Roles: []Role{{Name: "1bad", Policy: "p", PolicyText: []byte("x")}}}, `Bootstrap.Roles[0].Name "1bad" is not a name matching ^[A-Za-z_][A-Za-z0-9_-]*$`},
		{"policy name outside the name rule", Bootstrap{Mount: "kv", Roles: []Role{{Name: "r", Policy: "a/b", PolicyText: []byte("x")}}}, `Bootstrap.Roles[0].Policy "a/b" is not a name`},
		{"empty policy name", Bootstrap{Mount: "kv", Roles: []Role{{Name: "r", PolicyText: []byte("x")}}}, `Bootstrap.Roles[0].Policy "" is not a name`},
		{"one policy, two texts", Bootstrap{Mount: "kv", Roles: []Role{good(), {Name: "s", Policy: "p", PolicyText: []byte("y")}}}, `Bootstrap.Roles[1].Policy "p" is given two different texts`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "ran")
			cfg := validConfig(t)
			cfg.BinaryPath = writeFake(t, `touch "`+marker+`"`+"\n")
			h, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			s, err := h.StartWith(t.Context(), tc.b)
			if s != nil || err == nil {
				t.Fatalf("StartWith = %v, %v; want a refusal", s, err)
			}
			if !strings.HasPrefix(err.Error(), "secretstoretest: ") || !strings.Contains(err.Error(), tc.needle) {
				t.Errorf("err = %v, want it to name %q", err, tc.needle)
			}
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the binary ran (stat %v)", err)
			}
			assertEmpty(t, cfg.TempParent)
		})
	}
	// Two roles may share a policy given the same text; it is loaded once.
	b := Bootstrap{Mount: "kv", Roles: []Role{good(), {Name: "s", Policy: "p", PolicyText: []byte("x")}}}
	if err := b.validate(); err != nil {
		t.Errorf("a shared policy with one text is refused: %v", err)
	}
	if pols := b.policies(); len(pols) != 1 || pols[0].Name != "p" {
		t.Errorf("policies() = %v, want p once", pols)
	}
}

// TC-805-39 (F-805-07): each Policies entry is loaded through its own file
// source, after the roles' policies, with no role bound to it; a Bootstrap
// without Policies renders as before (TestStartWith_RendersTwoRoles pins that
// list, and an empty Policies renders the same bytes as none).
func TestStartWith_RendersPoliciesWithNoRole(t *testing.T) {
	out := filepath.Join(t.TempDir(), "seen")
	cfg := validConfig(t)
	cfg.BinaryPath = writeFake(t, `case "$1" in
version) echo "OpenBao v2.7.1 (fake)" ;;
server) cp -R "$(dirname "$5")" "`+out+`"; exit 3 ;;
esac
`)
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	b := twoRoles()
	b.Policies = []Policy{{Name: "pol-free", Text: []byte(`path "auth/token/lookup-self" { capabilities = ["read"] }` + "\n")}}
	if s, err := h.StartWith(t.Context(), b); s != nil || err == nil || !strings.Contains(err.Error(), "exit status 3") {
		t.Fatalf("StartWith = %v, %v; want the fake's exit", s, err)
	}
	raw, err := os.ReadFile(filepath.Join(out, "init.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Initialize []map[string]struct {
			Request []map[string]initRequest `json:"request"`
		} `json:"initialize"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("init.json is not JSON: %v", err)
	}
	var order []string
	byPath := map[string]initRequest{}
	for _, block := range doc.Initialize {
		for _, stanza := range block {
			for _, named := range stanza.Request {
				for _, r := range named {
					order = append(order, r.Path)
					byPath[r.Path] = r
				}
			}
		}
	}
	want := []string{
		"sys/policies/acl/pol-a", "sys/policies/acl/pol-b", "sys/policies/acl/pol-free", "sys/mounts/kv-two", "sys/auth/cert",
		"auth/cert/certs/role-a", "auth/cert/certs/role-b",
	}
	if !reflect.DeepEqual(order, want) {
		t.Errorf("request paths = %v, want exactly %v: one more policy, no more roles", order, want)
	}
	src, _ := byPath["sys/policies/acl/pol-free"].Data["policy"].(map[string]any)
	p, _ := src["path"].(string)
	if src["eval_source"] != "file" || src["eval_type"] != "string" || filepath.Base(p) != "pol-free.hcl" {
		t.Errorf("pol-free source = %v, want an eval_source file string source at <root>/policies/pol-free.hcl", src)
	}
	got, err := os.ReadFile(filepath.Join(out, "policies", "pol-free.hcl"))
	if err != nil || !bytes.Equal(got, b.Policies[0].Text) {
		t.Errorf("pol-free.hcl = %q, %v; want the entry's Text byte for byte", got, err)
	}
	for path, r := range byPath {
		if strings.HasPrefix(path, "auth/cert/certs/") {
			if pols, _ := r.Data["token_policies"].([]any); slices.Contains(pols, any("pol-free")) {
				t.Errorf("role %s binds pol-free", path)
			}
		}
	}

	ca := []byte("ca")
	pp := func(name string) string { return "/p/" + name }
	none, err := renderInitJSON(twoRoles(), ca, pp)
	if err != nil {
		t.Fatal(err)
	}
	empty := twoRoles()
	empty.Policies = []Policy{}
	withEmpty, err := renderInitJSON(empty, ca, pp)
	if err != nil || !bytes.Equal(none, withEmpty) {
		t.Errorf("an empty Policies renders differently from none (%v)", err)
	}
}

// TC-805-39: each Policies entry self-init cannot be given is refused before
// any I/O, naming the entry; an empty Roles is still refused.
func TestStartWith_RefusesBadPolicies(t *testing.T) {
	role := Role{Name: "r", Policy: "p", PolicyText: []byte("x")}
	cases := []struct {
		name   string
		b      Bootstrap
		needle string
	}{
		{"empty name", Bootstrap{Mount: "kv", Roles: []Role{role}, Policies: []Policy{{Text: []byte("x")}}}, "Bootstrap.Policies[0].Name is empty"},
		{"empty text", Bootstrap{Mount: "kv", Roles: []Role{role}, Policies: []Policy{{Name: "q"}}}, "Bootstrap.Policies[0].Text is empty"},
		{"name outside the name rule", Bootstrap{Mount: "kv", Roles: []Role{role}, Policies: []Policy{{Name: "a/b", Text: []byte("x")}}}, `Bootstrap.Policies[0].Name "a/b" is not a name matching`},
		{"duplicate name", Bootstrap{Mount: "kv", Roles: []Role{role}, Policies: []Policy{{Name: "q", Text: []byte("x")}, {Name: "q", Text: []byte("x")}}}, `Bootstrap.Policies[1].Name "q" is a duplicate policy`},
		{"a role's policy", Bootstrap{Mount: "kv", Roles: []Role{role}, Policies: []Policy{{Name: "p", Text: []byte("x")}}}, `Bootstrap.Policies[0].Name "p" is also a role's policy`},
		{"policies but no roles", Bootstrap{Mount: "kv", Policies: []Policy{{Name: "q", Text: []byte("x")}}}, "Bootstrap.Roles is empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "ran")
			cfg := validConfig(t)
			cfg.BinaryPath = writeFake(t, `touch "`+marker+`"`+"\n")
			h, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			s, err := h.StartWith(t.Context(), tc.b)
			if s != nil || err == nil {
				t.Fatalf("StartWith = %v, %v; want a refusal", s, err)
			}
			if !strings.HasPrefix(err.Error(), "secretstoretest: ") || !strings.Contains(err.Error(), tc.needle) {
				t.Errorf("err = %v, want it to name %q", err, tc.needle)
			}
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the binary ran (stat %v)", err)
			}
			assertEmpty(t, cfg.TempParent)
		})
	}
}

// loginStore is a Store with a real store CA and no store process, and a TLS
// test server standing in for the store's login endpoint. The server trusts
// the store CA for client certificates, presents a store-CA serverAuth leaf,
// records the CommonName and role of each login, and answers through answer.
func loginStore(t *testing.T, answer func(cn, role string) (int, string)) (*Store, *[]string) {
	t.Helper()
	root := t.TempDir()
	ca, err := tlsca.Ensure(tlsca.StoreConfig(), filepath.Join(root, "ca"), "test", tlscatest.Deps())
	if err != nil {
		t.Fatal(err)
	}
	srvLeaf, err := ca.MintLeafToDisk(filepath.Join(root, "server"), tlsca.LeafSpec{
		Usage: tlsca.UsageServer, CommonName: "server", IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(srvLeaf.CertPath, srvLeaf.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM)
	var seen []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name string `json:"name"`
		}
		b, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/v1/auth/cert/login" || r.Method != http.MethodPost || json.Unmarshal(b, &body) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		cn := r.TLS.PeerCertificates[0].Subject.CommonName
		seen = append(seen, cn+"/"+body.Name)
		code, resp := answer(cn, body.Name)
		w.WriteHeader(code)
		_, _ = io.WriteString(w, resp)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: pool,
		ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &Store{root: root, url: srv.URL, ca: ca}, &seen
}

// TC-804-04: Login presents a store-CA clientAuth leaf with the asked
// CommonName against the asked role and returns the token as a secret.Value;
// TokenFor uses the role's own name as the CommonName; a refused login is an
// error naming the role, the leaf and the status, never the body; the leaf is
// minted once and reused; a CommonName outside the name rule is refused.
func TestLogin(t *testing.T) {
	s, seen := loginStore(t, func(cn, role string) (int, string) {
		if cn == role {
			return http.StatusOK, `{"auth":{"client_token":"tok-` + role + `"}}`
		}
		return http.StatusBadRequest, `{"errors":["invalid certificate tok-secret-body"]}`
	})
	tok, err := s.TokenFor(t.Context(), "rasputin-api")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(tok.Reveal()); got != "tok-rasputin-api" {
		t.Errorf("TokenFor token = %q", got)
	}
	_, err = s.Login(t.Context(), "rasputin-api", "rasputin-seal-rotate")
	if err == nil {
		t.Fatal("a refused login returned no error")
	}
	for _, want := range []string{`"rasputin-seal-rotate"`, `leaf "rasputin-api"`, "answered 400 with no token"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to carry %s", err, want)
		}
	}
	if strings.Contains(err.Error(), "tok-secret-body") {
		t.Error("the refused login's body reached the error")
	}
	if want := []string{"rasputin-api/rasputin-api", "rasputin-api/rasputin-seal-rotate"}; !reflect.DeepEqual(*seen, want) {
		t.Errorf("logins = %v, want %v", *seen, want)
	}

	// The leaf on disk: clientAuth only, the CommonName, minted once.
	leaf := s.leaves["rasputin-api"]
	before, err := os.ReadFile(leaf.CertPath)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(before)
	if blk == nil {
		t.Fatal("the leaf is not PEM")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject.CommonName != "rasputin-api" || !reflect.DeepEqual(c.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
		t.Errorf("leaf = CN %q EKU %v, want CN rasputin-api, clientAuth only", c.Subject.CommonName, c.ExtKeyUsage)
	}
	if _, err := s.ClientTLSFor("rasputin-api"); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(leaf.CertPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Errorf("a second ClientTLSFor re-minted the leaf (%v)", err)
	}

	if _, err := s.ClientTLSFor("../x"); err == nil || !strings.Contains(err.Error(), `leaf CommonName "../x" is not a name`) {
		t.Errorf("ClientTLSFor(../x) = %v, want a refusal naming it", err)
	}
	if _, err := s.Login(t.Context(), "", "r"); err == nil {
		t.Error("Login with an empty CommonName returned no error")
	}
}

// A login that never reaches the store is an error naming the role and leaf.
func TestLogin_Unreachable(t *testing.T) {
	s, _ := loginStore(t, func(string, string) (int, string) { return http.StatusOK, "" })
	s.url = "https://127.0.0.1:1"
	_, err := s.Login(t.Context(), "a", "b")
	if err == nil || !strings.Contains(err.Error(), `login as "b" with leaf "a"`) {
		t.Errorf("Login to a closed port = %v, want an error naming the role and leaf", err)
	}
	// A 200 with no token is a refusal too.
	s2, _ := loginStore(t, func(string, string) (int, string) { return http.StatusOK, `{"auth":{}}` })
	if _, err := s2.Login(t.Context(), "a", "a"); err == nil || !strings.Contains(err.Error(), "answered 200 with no token") {
		t.Errorf("Login answered 200 with no token = %v", err)
	}
}
