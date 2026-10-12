package secretstoretest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// serverPaths are the files the store's main config names. Every one lives
// under the harness's temporary root.
type serverPaths struct {
	StoreCA    string // the store CA certificate; the listener's only client trust
	ServerCert string // the listener's serverAuth leaf
	ServerKey  string
	SealKey    string // the 32-byte static seal key, mode 0600
	Storage    string // the PebbleDB directory
	AuditLog   string // the file audit device's file_path; "" renders no audit stanza
	// ExternalSeal leaves the seal stanza out: the seal comes from a third
	// -config, the fragment in the store's seal directory (Config.ExternalSeal).
	ExternalSeal bool
}

// renderServerHCL is the store's main config: S8's transport and S6's
// storage, with a static test seal.
//
//   - One TCP listener on 127.0.0.1 with TLS, a required and verified client
//     certificate, and tls_client_ca_file set to the store CA alone (S8
//     elements 1 and 5). There is no unix listener (element 3).
//   - The two disable_unauthed_* options are LISTENER options (OpenBao holds
//     them on configutil.Listener), so they sit inside the listener stanza.
//     Placed at the top level they would be ignored, and the store would only
//     look right because both default to true (geekdojo-brain#679, D679-05).
//   - PebbleDB with clustering disabled opens only the API listener
//     (D679-07).
//   - The static seal reads a file:// key at a literal path (D679-08). With
//     p.ExternalSeal the stanza is left out, and the store reads it from the
//     seal fragment, as the image's store does (geekdojo/geekdojo-brain#830).
//   - Only when p.AuditLog is set: a declarative file audit device writing
//     there, the shape #804 ships (geekdojo-brain#799). Opt-in, so every
//     other functional test runs without audit, as before.
func renderServerHCL(p serverPaths, port int) string {
	hcl := fmt.Sprintf(`api_addr           = "https://127.0.0.1:%[1]d"
disable_clustering = true

listener "tcp" {
  address                                  = "127.0.0.1:%[1]d"
  tls_cert_file                            = %[2]q
  tls_key_file                             = %[3]q
  tls_client_ca_file                       = %[4]q
  tls_require_and_verify_client_cert       = true
  disable_unauthed_rekey_endpoints         = true
  disable_unauthed_generate_root_endpoints = true
}

storage "pebbledb" {
  path = %[5]q
}
`, port, p.ServerCert, p.ServerKey, p.StoreCA, p.Storage)
	if !p.ExternalSeal {
		hcl += fmt.Sprintf(`
seal "static" {
  current_key_id = "secretstoretest"
  current_key    = %q
}
`, "file://"+p.SealKey)
	}
	if p.AuditLog != "" {
		hcl += fmt.Sprintf(`
audit "file" "file" {
  options {
    file_path = %q
  }
}
`, p.AuditLog)
	}
	return hcl
}

// initRequest is one self-init request: an API call the store makes against
// itself, once, on an empty store.
type initRequest struct {
	Operation string         `json:"operation"`
	Path      string         `json:"path"`
	Data      map[string]any `json:"data"`
}

// kvPolicy grants the harness client exactly what the smoke test does with
// the KV mount, and nothing on any other path.
const kvPolicy = `path "` + KVMount + `/*" { capabilities = ["create", "read", "update"] }` + "\n"

// Bootstrap is what the store's self-init creates: one kv-v2 mount and, for
// each Role, its policy and a cert role bound to it (geekdojo/geekdojo-brain#804).
// Start uses defaultBootstrap; StartWith takes one from the test.
type Bootstrap struct {
	// Mount is the kv-v2 mount's path.
	Mount string
	// Roles are created in order. Two roles may share a policy only with the
	// same text.
	Roles []Role
	// Policies are loaded with no role, after the roles' policies, through a
	// file source each, as the image's init.json loads rasputin-bindable
	// (geekdojo/geekdojo-brain#805). A name may not also be a Role's policy.
	Policies []Policy
}

// Policy is a policy self-init loads with no role bound to it.
type Policy struct {
	// Name is the policy's name.
	Name string
	// Text is the policy's text, read by self-init from a file the harness
	// writes, as for a Role's PolicyText.
	Text []byte
}

// Role is one cert role and the policy it grants.
type Role struct {
	// Name is the role's name and the only CommonName it admits
	// (allowed_common_names). Log in with Store.Login or Store.TokenFor.
	Name string
	// Policy is the policy's name, the role's only token policy: the role
	// sets token_no_default_policy, so its tokens carry nothing else.
	Policy string
	// PolicyText is the policy's text. Self-init reads it from a file the
	// harness writes, through an eval_source "file" source, as the image's
	// self-init does.
	PolicyText []byte
}

// nameRE is what a mount, role or policy name may be: it is placed in request
// paths and file names, so nothing else is allowed.
var nameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)

// defaultBootstrap is the store Start makes: the harness-kv mount and the
// harness-client role holding kvPolicy.
func defaultBootstrap() Bootstrap {
	return Bootstrap{Mount: KVMount, Roles: []Role{{Name: ClientRole, Policy: KVMount, PolicyText: []byte(kvPolicy)}}}
}

// policyFile is one policy self-init loads, and the text its file holds.
type policyFile struct {
	Name string
	Text []byte
}

// validate refuses a Bootstrap self-init cannot be given, naming the input.
func (b Bootstrap) validate() error {
	if b.Mount == "" {
		return errors.New("secretstoretest: Bootstrap.Mount is empty")
	}
	if !nameRE.MatchString(b.Mount) {
		return fmt.Errorf("secretstoretest: Bootstrap.Mount %q is not a name matching %s", b.Mount, nameRE)
	}
	if len(b.Roles) == 0 {
		return errors.New("secretstoretest: Bootstrap.Roles is empty")
	}
	roles := map[string]bool{}
	texts := map[string][]byte{}
	for i, r := range b.Roles {
		switch {
		case r.Name == "":
			return fmt.Errorf("secretstoretest: Bootstrap.Roles[%d].Name is empty", i)
		case !nameRE.MatchString(r.Name):
			return fmt.Errorf("secretstoretest: Bootstrap.Roles[%d].Name %q is not a name matching %s", i, r.Name, nameRE)
		case roles[r.Name]:
			return fmt.Errorf("secretstoretest: Bootstrap.Roles[%d].Name %q is a duplicate role", i, r.Name)
		case !nameRE.MatchString(r.Policy):
			return fmt.Errorf("secretstoretest: Bootstrap.Roles[%d].Policy %q is not a name matching %s", i, r.Policy, nameRE)
		case len(r.PolicyText) == 0:
			return fmt.Errorf("secretstoretest: Bootstrap.Roles[%d].PolicyText is empty", i)
		}
		if prev, ok := texts[r.Policy]; ok && !bytes.Equal(prev, r.PolicyText) {
			return fmt.Errorf("secretstoretest: Bootstrap.Roles[%d].Policy %q is given two different texts", i, r.Policy)
		}
		roles[r.Name] = true
		texts[r.Policy] = r.PolicyText
	}
	extra := map[string]bool{}
	for i, p := range b.Policies {
		switch {
		case p.Name == "":
			return fmt.Errorf("secretstoretest: Bootstrap.Policies[%d].Name is empty", i)
		case !nameRE.MatchString(p.Name):
			return fmt.Errorf("secretstoretest: Bootstrap.Policies[%d].Name %q is not a name matching %s", i, p.Name, nameRE)
		case len(p.Text) == 0:
			return fmt.Errorf("secretstoretest: Bootstrap.Policies[%d].Text is empty", i)
		case extra[p.Name]:
			return fmt.Errorf("secretstoretest: Bootstrap.Policies[%d].Name %q is a duplicate policy", i, p.Name)
		}
		if _, ok := texts[p.Name]; ok {
			return fmt.Errorf("secretstoretest: Bootstrap.Policies[%d].Name %q is also a role's policy", i, p.Name)
		}
		extra[p.Name] = true
	}
	return nil
}

// policies is each distinct policy, in the order the roles first name it,
// then each of Policies in order.
func (b Bootstrap) policies() []policyFile {
	var out []policyFile
	seen := map[string]bool{}
	for _, r := range b.Roles {
		if !seen[r.Policy] {
			seen[r.Policy] = true
			out = append(out, policyFile{Name: r.Policy, Text: r.PolicyText})
		}
	}
	for _, p := range b.Policies {
		out = append(out, policyFile(p))
	}
	return out
}

// renderInitJSON is the store's second config file: self-init `initialize`
// stanzas in the shape geekdojo-brain#680 proved (probe680 renderInit). On
// an empty store they run once and leave no root token (D680-01):
//
//   - one policy per distinct Role.Policy, then one per Policies entry, its
//     text read from the file policyPath names through an eval_source "file"
//     source, as the image's init.json does (T34);
//   - a kv-v2 mount at b.Mount;
//   - the cert auth method;
//   - per Role, a cert role trusting the store CA, admitting only the
//     CommonName Role.Name, with Role.Policy as its only token policy and
//     token_no_default_policy set (T37).
//
// The role's certificate is the store CA PEM itself, inline.
func renderInitJSON(b Bootstrap, storeCAPEM []byte, policyPath func(name string) string) ([]byte, error) {
	block := func(name string, reqs ...map[string]initRequest) map[string]any {
		return map[string]any{name: map[string]any{"request": reqs}}
	}
	var pols []map[string]initRequest
	for _, p := range b.policies() {
		pols = append(pols, map[string]initRequest{"policy-" + p.Name: {
			Operation: "update",
			Path:      "sys/policies/acl/" + p.Name,
			Data: map[string]any{"policy": map[string]any{
				"eval_source": "file", "eval_type": "string", "path": policyPath(p.Name),
			}},
		}})
	}
	auth := []map[string]initRequest{{"enable-cert": {
		Operation: "update",
		Path:      "sys/auth/cert",
		Data:      map[string]any{"type": "cert"},
	}}}
	for _, r := range b.Roles {
		auth = append(auth, map[string]initRequest{"role-" + r.Name: {
			Operation: "update",
			Path:      "auth/cert/certs/" + r.Name,
			Data: map[string]any{
				"certificate":             string(storeCAPEM),
				"allowed_common_names":    []string{r.Name},
				"token_policies":          []string{r.Policy},
				"token_no_default_policy": true,
			},
		}})
	}
	doc := map[string]any{"initialize": []any{
		block("policies", pols...),
		block("secrets", map[string]initRequest{"kv-mount": {
			Operation: "update",
			Path:      "sys/mounts/" + b.Mount,
			Data:      map[string]any{"type": "kv", "options": map[string]any{"version": "2"}},
		}}),
		block("auth", auth...),
	}}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("secretstoretest: render init config: %w", err)
	}
	return out, nil
}

// renderSealFragment is a seal fragment in the shape rasputin-seal-key.sh
// writes (#803), byte for byte, naming keyPath. The harness's ExternalSeal
// store starts on it.
func renderSealFragment(keyID, keyPath string) []byte {
	return fmt.Appendf(nil, "seal \"static\" {\n  current_key_id = %q\n  current_key    = %q\n}\n", keyID, "file://"+keyPath)
}
