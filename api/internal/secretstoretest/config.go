package secretstoretest

import (
	"encoding/json"
	"fmt"
)

// serverPaths are the files the store's main config names. Every one lives
// under the harness's temporary root.
type serverPaths struct {
	StoreCA    string // the store CA certificate; the listener's only client trust
	ServerCert string // the listener's serverAuth leaf
	ServerKey  string
	SealKey    string // the 32-byte static seal key, mode 0600
	Storage    string // the PebbleDB directory
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
//   - The static seal reads a file:// key at a literal path (D679-08).
func renderServerHCL(p serverPaths, port int) string {
	return fmt.Sprintf(`api_addr           = "https://127.0.0.1:%[1]d"
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

seal "static" {
  current_key_id = "secretstoretest"
  current_key    = %[6]q
}
`, port, p.ServerCert, p.ServerKey, p.StoreCA, p.Storage, "file://"+p.SealKey)
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

// renderInitJSON is the store's second config file: self-init `initialize`
// stanzas in the shape geekdojo-brain#680 proved (probe680 renderInit). On
// an empty store they run once and leave no root token (D680-01):
//
//   - a policy granting create/read/update on the KV mount;
//   - a kv-v2 mount;
//   - the cert auth method;
//   - a cert role trusting the store CA, for the one client CN, with that
//     policy.
//
// The role's certificate is the store CA PEM itself, inline.
func renderInitJSON(storeCAPEM []byte) ([]byte, error) {
	block := func(name string, reqs ...map[string]initRequest) map[string]any {
		return map[string]any{name: map[string]any{"request": reqs}}
	}
	doc := map[string]any{"initialize": []any{
		block("policies", map[string]initRequest{"policy-" + KVMount: {
			Operation: "update",
			Path:      "sys/policies/acl/" + KVMount,
			Data:      map[string]any{"policy": kvPolicy},
		}}),
		block("secrets", map[string]initRequest{"kv-mount": {
			Operation: "update",
			Path:      "sys/mounts/" + KVMount,
			Data:      map[string]any{"type": "kv", "options": map[string]any{"version": "2"}},
		}}),
		block("auth",
			map[string]initRequest{"enable-cert": {
				Operation: "update",
				Path:      "sys/auth/cert",
				Data:      map[string]any{"type": "cert"},
			}},
			map[string]initRequest{"role-" + ClientRole: {
				Operation: "update",
				Path:      "auth/cert/certs/" + ClientRole,
				Data: map[string]any{
					"certificate":          string(storeCAPEM),
					"allowed_common_names": []string{ClientRole},
					"token_policies":       []string{KVMount},
				},
			}},
		),
	}}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("secretstoretest: render init config: %w", err)
	}
	return b, nil
}
