package storepolicy_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storepolicy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storesession"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstoretest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// geekdojo/geekdojo-brain#1084: the author identity and the api's key
// identity on the real pinned store, bootstrapped with the production role
// set as PR 2's init.json makes it (rasputin-api, -seal-rotate, -provisioner,
// rasputin-bindable, and rasputin-author admitting the provisioner's leaf),
// plus a test-only inspector that reads what the identities must not change.

const (
	// appKeysInspector reads back what the test needs to compare.
	appKeysInspector = "test-keys-inspector"
	// fnApp and fnOther are the app IDs whose keys the test makes.
	fnApp   = "01J9ZK3Q0M8X7Y6W5V4T3S2R1A"
	fnOther = "01J9ZK3Q0M8X7Y6W5V4T3S2R1B"
)

var appKeysInspectorPolicy = append(slices.Clone(inspectorPolicy), []byte(`path "rasputin-app-keys/keys/*" { capabilities = ["read"] }
path "auth/token/lookup" { capabilities = ["update"] }
`)...)

// keyName is app appID's key name in the mount, as secrets.AppKey builds it.
func keyName(appID, name string) string { return "app-" + appID + "-" + name }

// TestAppKeys_AgainstTheRealStore: TC-1084-28 (the author path provisions the
// engine, policy and role), TC-1084-02 to -05 (the key identity's grant and
// its refusals, and the client's classification of the real answers) and
// TC-1084-27 (#806's attack chain replayed against the author, F-1084-12).
func TestAppKeys_AgainstTheRealStore(t *testing.T) {
	role := func(name string, pol []byte) secretstoretest.Role {
		return secretstoretest.Role{Name: name, Policy: name, PolicyText: pol}
	}
	author := role(storepolicy.AuthorPolicy, text(t, storepolicy.AuthorPolicy))
	author.CommonName = "rasputin-provisioner"
	st, ok := startStore(t, secretstoretest.Bootstrap{
		Mount: storepolicy.Mount,
		Roles: []secretstoretest.Role{
			role(storepolicy.APIPolicy, text(t, storepolicy.APIPolicy)),
			role(storepolicy.SealRotatePolicy, text(t, storepolicy.SealRotatePolicy)),
			role(storepolicy.ProvisionerPolicy, text(t, storepolicy.ProvisionerPolicy)),
			author,
			role(appKeysInspector, appKeysInspectorPolicy),
		},
		Policies: []secretstoretest.Policy{{Name: storepolicy.BindablePolicy, Text: text(t, storepolicy.BindablePolicy)}},
	})
	if !ok {
		return
	}
	s, do := st.s, st.do
	ctx := t.Context()
	caPEM := string(s.StoreCA().CertPEM)
	login := func(t *testing.T, cn, role string) string {
		t.Helper()
		v, err := s.Login(ctx, cn, role)
		if err != nil {
			t.Fatalf("login as %s with leaf %s: %v", role, cn, err)
		}
		return string(v.Reveal())
	}
	auth := login(t, "rasputin-provisioner", storepolicy.AuthorPolicy)
	insp := st.token(t, appKeysInspector)
	status := func(t *testing.T, who, tok string, p probe, want int) []byte {
		t.Helper()
		code, body := do(t, tok, p)
		t.Logf("%s %s %s -> %d", who, p.method, p.path, code)
		if code != want {
			t.Errorf("%s %s %s = %d, want %d: %s", who, p.method, p.path, code, want, body)
		}
		return body
	}
	// policiesOf is the policy list of tok, as the inspector looks it up.
	policiesOf := func(t *testing.T, tok string) []string {
		t.Helper()
		code, body := do(t, insp, probe{http.MethodPost, "auth/token/lookup", map[string]string{"token": tok}})
		var v struct {
			Data struct {
				Policies []string `json:"policies"`
			} `json:"data"`
		}
		if code != http.StatusOK || json.Unmarshal(body, &v) != nil {
			t.Fatalf("lookup = %d", code)
		}
		return v.Data.Policies
	}
	// goodRole is a fully valid app-keys role body, every value a string.
	goodRole := func(cn string) map[string]any {
		return map[string]any{
			"certificate": caPEM, "allowed_common_names": cn, "token_policies": storepolicy.AppKeysPolicy,
			"token_no_default_policy": "true", "token_ttl": "1h",
		}
	}
	with := func(m map[string]any, kv ...any) map[string]any {
		out := map[string]any{}
		for k, v := range m {
			out[k] = v
		}
		for i := 0; i+1 < len(kv); i += 2 {
			out[kv[i].(string)] = kv[i+1]
		}
		return out
	}
	mount := storepolicy.AppKeysMount

	// TC-1084-28: the author mounts transit, writes the policy from the
	// packed text and creates the role, all as strings; the policy reads back
	// byte-equal; the key leaf logs in with exactly that policy.
	t.Run("TC-1084-28 the author path provisions", func(t *testing.T) {
		status(t, "author", auth, probe{http.MethodPost, "sys/mounts/" + mount, map[string]any{"type": "transit"}}, http.StatusNoContent)
		pol := text(t, storepolicy.AppKeysPolicy)
		status(t, "author", auth, probe{http.MethodPut, "sys/policies/acl/" + storepolicy.AppKeysPolicy, map[string]string{"policy": string(pol)}}, http.StatusNoContent)
		status(t, "author", auth, probe{http.MethodPost, "auth/cert/certs/" + storepolicy.AppKeysPolicy, goodRole(storepolicy.AppKeysPolicy)}, http.StatusNoContent)
		body := status(t, "author", auth, probe{http.MethodGet, "sys/policies/acl/" + storepolicy.AppKeysPolicy, nil}, http.StatusOK)
		var rb struct {
			Data struct {
				Policy string `json:"policy"`
			} `json:"data"`
		}
		if json.Unmarshal(body, &rb) != nil || !bytes.Equal([]byte(rb.Data.Policy), pol) {
			t.Errorf("the policy reads back as %q, want the packed file byte for byte", rb.Data.Policy)
		}
		key := login(t, storepolicy.AppKeysPolicy, storepolicy.AppKeysPolicy)
		if got := policiesOf(t, key); !slices.Equal(got, []string{storepolicy.AppKeysPolicy}) {
			t.Errorf("the key token carries %v, want exactly [%s]: no default", got, storepolicy.AppKeysPolicy)
		}
	})
	if t.Failed() {
		t.FailNow()
	}
	key := login(t, storepolicy.AppKeysPolicy, storepolicy.AppKeysPolicy)
	k := keyName(fnApp, "wrap")
	plaintext := base64.StdEncoding.EncodeToString([]byte("sentinel-plaintext-1084"))
	var ciphertext string

	// TC-1084-02: create with the fixed type, encrypt, decrypt to the same
	// plaintext, set deletion_allowed as the string "true", delete.
	t.Run("TC-1084-02 the key identity's grant", func(t *testing.T) {
		const doomed = "doomed"
		dk := keyName(fnApp, doomed)
		status(t, "key", key, probe{http.MethodPost, mount + "/keys/" + dk, map[string]string{"type": secretstore.TransitKeyType}}, http.StatusOK)
		body := status(t, "key", key, probe{http.MethodPost, mount + "/encrypt/" + dk, map[string]string{"plaintext": plaintext}}, http.StatusOK)
		var enc struct {
			Data struct {
				Ciphertext string `json:"ciphertext"`
			} `json:"data"`
		}
		_ = json.Unmarshal(body, &enc)
		body = status(t, "key", key, probe{http.MethodPost, mount + "/decrypt/" + dk, map[string]string{"ciphertext": enc.Data.Ciphertext}}, http.StatusOK)
		var dec struct {
			Data struct {
				Plaintext string `json:"plaintext"`
			} `json:"data"`
		}
		if json.Unmarshal(body, &dec) != nil || dec.Data.Plaintext != plaintext {
			t.Errorf("the round trip returned %q, want the original plaintext", dec.Data.Plaintext)
		}
		status(t, "key", key, probe{http.MethodPost, mount + "/keys/" + dk + "/config", map[string]string{"deletion_allowed": "true"}}, http.StatusOK)
		status(t, "key", key, probe{http.MethodDelete, mount + "/keys/" + dk, nil}, http.StatusNoContent)

		status(t, "key", key, probe{http.MethodPost, mount + "/keys/" + k, map[string]string{"type": secretstore.TransitKeyType}}, http.StatusOK)
		body = status(t, "key", key, probe{http.MethodPost, mount + "/encrypt/" + k, map[string]string{"plaintext": plaintext}}, http.StatusOK)
		if json.Unmarshal(body, &enc) != nil || !strings.HasPrefix(enc.Data.Ciphertext, "vault:v1:") {
			t.Fatalf("encrypt answered %s", body)
		}
		ciphertext = enc.Data.Ciphertext
	})

	// TC-1084-03: every other key operation, key parameter at create, and
	// path outside the mount is refused; the key's config is unchanged and no
	// refused key exists.
	t.Run("TC-1084-03 the key identity's refusals", func(t *testing.T) {
		before := status(t, "inspector", insp, probe{http.MethodGet, mount + "/keys/" + k, nil}, http.StatusOK)
		var refusedKeys []string
		probes := []probe{
			{http.MethodPost, mount + "/keys/" + k + "/rotate", nil},
			{http.MethodPost, mount + "/keys/" + k + "/trim", map[string]any{"min_available_version": 1}},
			{http.MethodPost, mount + "/keys/" + k + "/import", map[string]any{"ciphertext": "x"}},
			{http.MethodPost, mount + "/keys/" + k + "/import_version", map[string]any{"ciphertext": "x"}},
			{http.MethodPost, mount + "/keys/" + k + "/config", map[string]any{"exportable": "true"}},
			{http.MethodPost, mount + "/keys/" + k + "/config", map[string]any{"min_decryption_version": "1"}},
			{http.MethodGet, mount + "/keys/" + k, nil},
			{"LIST", mount + "/keys", nil},
			{http.MethodGet, mount + "/export/encryption-key/" + k, nil},
			{http.MethodGet, mount + "/backup/" + k, nil},
			{http.MethodPost, mount + "/restore", map[string]any{"backup": "x"}},
			{http.MethodPost, mount + "/datakey/plaintext/" + k, nil},
			{http.MethodPost, mount + "/rewrap/" + k, map[string]any{"ciphertext": ciphertext}},
			{http.MethodGet, "sys/mounts", nil},
			{http.MethodGet, storepolicy.Mount + "/data/apps/" + fnApp + "/x", nil},
		}
		for i, param := range []map[string]any{
			{"exportable": "true"}, {"allow_plaintext_backup": "true"}, {"derived": "true"},
			{"auto_rotate_period": "1h"}, {"type": "rsa-2048"},
		} {
			name := keyName(fnApp, "refused-"+string(rune('a'+i)))
			refusedKeys = append(refusedKeys, name)
			body := map[string]any{"type": secretstore.TransitKeyType}
			for kk, v := range param {
				body[kk] = v
			}
			probes = append(probes, probe{http.MethodPost, mount + "/keys/" + name, body})
		}
		for _, p := range probes {
			status(t, "key", key, p, http.StatusForbidden)
		}
		after := status(t, "inspector", insp, probe{http.MethodGet, mount + "/keys/" + k, nil}, http.StatusOK)
		strip := func(b []byte) string {
			var v struct {
				Data json.RawMessage `json:"data"`
			}
			_ = json.Unmarshal(b, &v)
			return string(v.Data)
		}
		if strip(before) != strip(after) {
			t.Errorf("the key changed:\n before %s\n after  %s", strip(before), strip(after))
		}
		for _, name := range refusedKeys {
			if code, _ := do(t, insp, probe{http.MethodGet, mount + "/keys/" + name, nil}); code == http.StatusOK {
				t.Errorf("the refused key %s exists", name)
			}
		}
	})

	// TC-1084-04: encrypt cannot create a key.
	t.Run("TC-1084-04 encrypt cannot create a key", func(t *testing.T) {
		ghost := keyName(fnApp, "ghost")
		status(t, "key", key, probe{http.MethodPost, mount + "/encrypt/" + ghost, map[string]string{"plaintext": plaintext}}, http.StatusForbidden)
		body := status(t, "key", key, probe{http.MethodPost, mount + "/decrypt/" + ghost, map[string]string{"ciphertext": ciphertext}}, http.StatusBadRequest)
		if !bytes.Contains(body, []byte("encryption key not found")) {
			t.Errorf("a decrypt under the ghost says %s, want encryption key not found", body)
		}
	})

	// TC-1084-05: the client classifies the real store's answers.
	t.Run("TC-1084-05 the real answers are classified", func(t *testing.T) {
		client := keyClient(t, s, s.URL())
		tok := secret.New([]byte(key))
		absent, _ := secretstore.NewTransitKey(mount, keyName(fnApp, "absent"))
		err := client.TransitDestroyKey(ctx, tok, absent)
		var se *secretstore.Error
		if !errors.Is(err, secretstore.ErrNotFound) || !errors.As(err, &se) || se.Status != http.StatusBadRequest {
			t.Errorf("destroy of an absent key = %v, want ErrNotFound from the config step's 400", err)
		}
		// The DELETE step's 400: a proxy answers the config step for a key
		// that does not exist, so the real store's DELETE answers the absence.
		proxied := keyClient(t, s, configAnsweringProxy(t, s))
		if err := proxied.TransitDestroyKey(ctx, tok, absent); !errors.Is(err, secretstore.ErrNotFound) || !errors.As(err, &se) || se.Status != http.StatusBadRequest {
			t.Errorf("destroy whose DELETE finds no key = %v, want ErrNotFound from the DELETE step's 400", err)
		}
		other := keyName(fnOther, "wrap")
		if err := client.TransitCreateKey(ctx, tok, mustKey(t, mount, other)); err != nil {
			t.Fatal(err)
		}
		otherCT, err := client.TransitEncrypt(ctx, tok, mustKey(t, mount, other), secret.New([]byte(plaintext)))
		if err != nil {
			t.Fatal(err)
		}
		tampered := []byte(ciphertext)
		tampered[len(tampered)-3] ^= 1 // still base64, no longer authentic
		for name, ct := range map[string]secret.Value{"tampered": secret.New(tampered), "another key's": otherCT} {
			if _, err := client.TransitDecrypt(ctx, tok, mustKey(t, mount, k), ct); !errors.Is(err, secretstore.ErrInvalidCiphertext) {
				t.Errorf("decrypt of %s ciphertext = %v, want ErrInvalidCiphertext", name, err)
			}
		}
		if _, err := client.TransitDecrypt(ctx, tok, absent, secret.New([]byte(ciphertext))); !errors.Is(err, secretstore.ErrNotFound) {
			t.Errorf("decrypt under an absent key = %v, want ErrNotFound", err)
		}
		// The destroy layer, secrets.Service.DestroyKey over the key session,
		// counts an absent key as destroyed.
		svc := keyService(t, client)
		ref, _ := secrets.AppKey(fnApp, "absent")
		if err := svc.DestroyKey(ctx, secrets.OperatorActor("u1"), ref); err != nil {
			t.Errorf("the service's destroy of an absent key = %v, want nil", err)
		}
	})

	// TC-1084-27 (F-1084-12): the author rewrites rasputin-app-keys to sudo,
	// which is a text write and succeeds; every route to USING such text, to a
	// fixed name, to the audit settings or to data is refused; no
	// rasputin-app-* role admits the provisioner's leaf; a leaf not chained to
	// the store CA fails the handshake; and no token holds root.
	t.Run("TC-1084-27 the author cannot reach root, a fixed name or data", func(t *testing.T) {
		sudo := `path "*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }`
		status(t, "author", auth, probe{http.MethodPut, "sys/policies/acl/" + storepolicy.AppKeysPolicy, map[string]string{"policy": sudo}}, http.StatusNoContent)
		const x = storepolicy.AuthorNamespace + "x"
		type row struct {
			route string
			p     probe
		}
		var rows []row
		roleWrite := func(route, name string, body map[string]any) {
			rows = append(rows, row{route, probe{http.MethodPost, "auth/cert/certs/" + name, body}})
		}
		roleWrite("re-point rasputin-app-keys to the provisioner's CN", storepolicy.AppKeysPolicy, goodRole("rasputin-provisioner"))
		roleWrite("a new namespace role with the provisioner's CN", x, goodRole("rasputin-provisioner"))
		roleWrite("a comma list of CNs", x, goodRole(x+",rasputin-provisioner"))
		roleWrite("the CN as a JSON list", x, with(goodRole(x), "allowed_common_names", []string{x, "rasputin-provisioner"}))
		for _, fixed := range []string{storepolicy.APIPolicy, storepolicy.SealRotatePolicy, storepolicy.ProvisionerPolicy,
			storepolicy.BindablePolicy, storepolicy.AuthorPolicy, "root", "default"} {
			roleWrite("token_policies="+fixed, x, with(goodRole(x), "token_policies", fixed))
			roleWrite("policies="+fixed, x, with(goodRole(x), "policies", fixed))
		}
		roleWrite("token_no_default_policy=false", x, with(goodRole(x), "token_no_default_policy", "false"))
		roleWrite("token_ttl=24h", x, with(goodRole(x), "token_ttl", "24h"))
		for kk, v := range map[string]string{"token_period": "1h", "token_bound_cidrs": "127.0.0.1/32", "allowed_names": "x"} {
			roleWrite("unlisted "+kk, x, with(goodRole(x), kk, v))
		}
		for _, fixed := range []string{storepolicy.AuthorPolicy, storepolicy.APIPolicy, storepolicy.SealRotatePolicy} {
			roleWrite("write role "+fixed, fixed, goodRole("rasputin-provisioner"))
		}
		for _, fixed := range []string{storepolicy.APIPolicy, storepolicy.SealRotatePolicy, storepolicy.ProvisionerPolicy,
			storepolicy.BindablePolicy, storepolicy.AuthorPolicy, "default"} {
			rows = append(rows, row{"policy write " + fixed, probe{http.MethodPut, "sys/policies/acl/" + fixed, map[string]string{"policy": sudo}}})
		}
		rows = append(rows,
			row{"a pki mount", probe{http.MethodPost, "sys/mounts/" + x, map[string]any{"type": "pki"}}},
			row{"a kv-v2 mount", probe{http.MethodPost, "sys/mounts/" + x, map[string]any{"type": "kv-v2"}}},
			row{"a transit mount with non-HMAC audit keys", probe{http.MethodPost, "sys/mounts/" + x, map[string]any{"type": "transit",
				"config": map[string]any{"audit_non_hmac_request_keys": []string{"plaintext"}}}}},
			row{"tune with non-HMAC audit keys", probe{http.MethodPost, "sys/mounts/" + mount + "/tune", map[string]any{"audit_non_hmac_request_keys": "plaintext"}}},
			row{"tune with default_lease_ttl", probe{http.MethodPost, "sys/mounts/" + mount + "/tune", map[string]any{"default_lease_ttl": "1h"}}},
			row{"unmount rasputin-app-keys", probe{http.MethodDelete, "sys/mounts/" + mount, nil}},
			row{"read kv data", probe{http.MethodGet, storepolicy.Mount + "/data/apps/" + fnApp + "/x", nil}},
			row{"encrypt under an app key", probe{http.MethodPost, mount + "/encrypt/" + k, map[string]string{"plaintext": plaintext}}},
			row{"generate-root-token attempt", probe{http.MethodPost, "sys/generate-root-token/attempt", nil}},
			row{"rotate recovery init", probe{http.MethodPost, "sys/rotate/recovery/init", nil}},
			row{"rotate root", probe{http.MethodPost, "sys/rotate/root", nil}},
		)
		for _, r := range rows {
			code, body := do(t, auth, r.p)
			t.Logf("author route | %-55s | %s %s | %d", r.route, r.p.method, r.p.path, code)
			if code != http.StatusForbidden {
				t.Errorf("author route %s = %d, want 403: %s", r.route, code, body)
			}
		}
		refusedAtListener(t, do, "author", auth)

		// No rasputin-app-* role admits the provisioner's leaf.
		code, body := do(t, insp, probe{"LIST", "auth/cert/certs", nil})
		var lr struct {
			Data struct {
				Keys []string `json:"keys"`
			} `json:"data"`
		}
		if code != http.StatusOK || json.Unmarshal(body, &lr) != nil {
			t.Fatalf("LIST roles = %d", code)
		}
		var nsRoles []string
		for _, r := range lr.Data.Keys {
			if strings.HasPrefix(r, storepolicy.AuthorNamespace) {
				nsRoles = append(nsRoles, r)
				if v, err := s.Login(ctx, "rasputin-provisioner", r); err == nil {
					t.Errorf("the provisioner's leaf logged in through %s", r)
					v.Destroy()
				}
			}
		}
		if !slices.Equal(nsRoles, []string{storepolicy.AppKeysPolicy}) {
			t.Errorf("namespace roles = %v, want only %s", nsRoles, storepolicy.AppKeysPolicy)
		}

		// A leaf not chained to the store CA fails the handshake.
		foreign, err := tlsca.Ensure(tlsca.StoreConfig(), t.TempDir(), "foreign", tlscatest.Deps())
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := foreign.MintLeafToDisk(filepath.Join(t.TempDir(), "foreign"), tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: "rasputin-provisioner"})
		if err != nil {
			t.Fatal(err)
		}
		ftls, err := secretstore.NewTLSConfig(s.StoreCA().CertPEM, leaf.CertPath, leaf.KeyPath)
		if err != nil {
			t.Fatal(err)
		}
		fc := &http.Client{Transport: &http.Transport{TLSClientConfig: ftls}}
		defer fc.CloseIdleConnections()
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, s.URL()+"/v1/auth/cert/login", strings.NewReader(`{"name":"rasputin-author"}`))
		if resp, err := fc.Do(req); err == nil {
			_ = resp.Body.Close()
			t.Errorf("a foreign leaf's login answered %d, want a failed handshake", resp.StatusCode)
		} else {
			t.Logf("foreign leaf: %v", err)
		}

		// No token in the store holds root.
		code, body = do(t, insp, probe{"LIST", "auth/token/accessors", nil})
		var acc struct {
			Data struct {
				Keys []string `json:"keys"`
			} `json:"data"`
		}
		if code != http.StatusOK || json.Unmarshal(body, &acc) != nil || len(acc.Data.Keys) == 0 {
			t.Fatalf("LIST accessors = %d", code)
		}
		roots := 0
		for _, a := range acc.Data.Keys {
			code, body := do(t, insp, probe{http.MethodPost, "auth/token/lookup-accessor", map[string]string{"accessor": a}})
			var la struct {
				Data struct {
					Policies []string `json:"policies"`
				} `json:"data"`
			}
			if code != http.StatusOK || json.Unmarshal(body, &la) != nil {
				t.Fatalf("lookup-accessor = %d", code)
			}
			if slices.Contains(la.Data.Policies, "root") {
				roots++
			}
		}
		t.Logf("%d tokens in the store, %d holding root", len(acc.Data.Keys), roots)
		if roots != 0 {
			t.Errorf("%d tokens hold root, want 0", roots)
		}
	})
}

func mustKey(t *testing.T, mount, name string) secretstore.TransitKey {
	t.Helper()
	k, err := secretstore.NewTransitKey(mount, name)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// keyClient is the production client presenting the api's key leaf, for the
// store at base.
func keyClient(t *testing.T, s *secretstoretest.Store, base string) *secretstore.Client {
	t.Helper()
	tc, err := s.ClientTLSFor(storepolicy.AppKeysPolicy)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	c, err := secretstore.New(secretstore.Config{Addr: u, TLS: tc, CallTimeout: 10 * time.Second, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	return c
}

// configAnsweringProxy is a TLS front for the real store, serving a store-CA
// leaf for 127.0.0.1, that answers every keys/<k>/config call itself with 200
// and passes every other request to the store unchanged, presenting the key
// leaf, so the client's DELETE step meets the store's own answer for a key
// that does not exist.
func configAnsweringProxy(t *testing.T, s *secretstoretest.Store) string {
	t.Helper()
	certPEM, keyV, err := s.StoreCA().MintLeaf(tlsca.LeafSpec{Usage: tlsca.UsageServer, CommonName: "proxy", IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyV.Reveal())
	keyV.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	upstreamTLS, err := s.ClientTLSFor(storepolicy.AppKeysPolicy)
	if err != nil {
		t.Fatal(err)
	}
	up := &http.Client{Transport: &http.Transport{TLSClientConfig: upstreamTLS}}
	t.Cleanup(up.CloseIdleConnections)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/config") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{}}`))
			return
		}
		req, _ := http.NewRequestWithContext(r.Context(), r.Method, s.URL()+r.URL.RequestURI(), r.Body)
		req.Header = r.Header.Clone()
		resp, err := up.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL
}

// keyService is the secrets service with the key session over client as its
// Transit store: the destroy layer the delete paths call.
func keyService(t *testing.T, client *secretstore.Client) *secrets.Service {
	t.Helper()
	sess, err := storesession.New(storesession.Config{Role: storepolicy.AppKeysPolicy, Login: client, Transit: client,
		Observer: nopObserver{}, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	repo, err := secrets.NewRepository(sess)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := secrets.NewService(secrets.Deps{Repo: repo, Transit: sess, Apps: noApps{}, Switch: noSwitch{}, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

type nopObserver struct{}

func (nopObserver) ObserveAudited(context.Context, error) {}

type noApps struct{}

func (noApps) TargetNode(context.Context, string) (string, bool, error) { return "", false, nil }

type noSwitch struct{}

func (noSwitch) MarkSwitched(context.Context) error { return nil }
