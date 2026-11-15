package main

// The identity CA's leaves against the real pinned identity service
// (geekdojo/geekdojo-brain#977): the api's production specs, minted by
// wireIdentityLeaves under the harness's test CA (made from
// tlsca.IdentityConfig), presented straight to Keycloak's own port for a
// client_credentials grant on the realm's client-x509 administrator client.
// It skips without RASPUTIN_IDENTITY_HOME and fails instead under
// RASPUTIN_IDENTITY_FUNCTIONAL=required, as CI's backend job sets it
// (docs/testing-identity.md).

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identitytest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

var (
	// identityRec records every record the harness logs, Keycloak's output
	// lines included, for TC-977-16's token scan.
	identityRec *logkittest.Recorder

	identityPkg = identitytest.NewPackage(func() (identitytest.Config, error) {
		cfg, err := identitytest.ConfigFromEnv()
		if err != nil {
			return cfg, err
		}
		var recLog *slog.Logger
		recLog, identityRec = logkittest.New()
		cfg.Logger = slog.New(slog.NewMultiHandler(cfg.Logger.Handler(), recLog.Handler()))
		return cfg, nil
	})
)

// TestMain tears the identity service down with proof after the package's
// tests; a package run that never asked for it is unaffected.
func TestMain(m *testing.M) { os.Exit(identityPkg.Run(m)) }

// identityFunctionalLeaves starts (or shares) the Env and mints the six
// identity leaves under its CA in a temp data dir, through wireIdentityLeaves
// and the startup sweep's report. Reloads go to a recorder: nothing here
// touches systemd.
func identityFunctionalLeaves(t *testing.T) (*identitytest.Env, string) {
	t.Helper()
	env := identityPkg.Env(t)
	dataDir := t.TempDir()
	rep := identitySweep(t, wireIdentityCALeaves(t, env.CA(), dataDir, (&scriptedRun{}).run), slog.New(slog.DiscardHandler))
	if !slices.Equal(rep.Renewed, identityLeafOrder) {
		t.Fatalf("the startup sweep renewed %v, want all six", rep.Renewed)
	}
	return env, dataDir
}

func loadLeafPair(t *testing.T, dir string) tls.Certificate {
	t.Helper()
	paths := tlsca.LeafPathsIn(dir)
	pair, err := tls.LoadX509KeyPair(paths.CertPath, paths.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

// tokenAnswer is the token endpoint's JSON answer.
type tokenAnswer struct {
	AccessToken string `json:"access_token"`
	Error       string `json:"error"`
}

// adminToken asks for a client_credentials token for the administrator
// client, over TLS 1.3 trusting only the test CA, presenting pair whatever
// the server's acceptable-CA list says, so Go can never withhold it. A nil
// response with an error is a refusal before any HTTP status.
func adminToken(t *testing.T, env *identitytest.Env, pair tls.Certificate) (*http.Response, []byte, error) {
	t.Helper()
	tr := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    env.Roots(),
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &pair, nil
		},
	}}
	defer tr.CloseIdleConnections()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {identitytest.AdminClientID}}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		env.KeycloakURL()+"/realms/"+identitytest.Realm+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	return resp, body, err
}

func decodeToken(t *testing.T, body []byte) tokenAnswer {
	t.Helper()
	var a tokenAnswer
	if err := json.Unmarshal(body, &a); err != nil {
		t.Fatalf("the token endpoint's answer is not JSON (%d bytes)", len(body))
	}
	return a
}

// TC-977-16: the api's identity-CA leaf, whose subject is the administrator
// client's, gets HTTP 200 and an access token, and the token appears in no
// record.
func TestIdentityCA_APILeafIsAdministrator(t *testing.T) {
	env, dataDir := identityFunctionalLeaves(t)
	dir := identityDir(dataDir, identityAPIClientLeafName)
	if got := parseLeaf(t, filepath.Join(dir, "leaf.pem")).Subject.String(); got != identitytest.AdminSubjectDN {
		t.Fatalf("api leaf subject %q, want %q", got, identitytest.AdminSubjectDN)
	}
	resp, body, err := adminToken(t, env, loadLeafPair(t, dir))
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	a := decodeToken(t, body)
	if resp.StatusCode != http.StatusOK || a.AccessToken == "" {
		t.Fatalf("status %d, error %q, token present %v; want 200 with a token", resp.StatusCode, a.Error, a.AccessToken != "")
	}
	if identityRec == nil || len(identityRec.Records()) == 0 {
		t.Fatal("no records were recorded; the token scan would prove nothing")
	}
	if strings.Contains(identityRec.Text(), a.AccessToken) {
		t.Error("a record holds the access token; the value is not printed")
	}
}

// TC-977-17: the door's identity-CA leaf completes TLS and is refused as the
// administrator: 401 invalid_client and no token.
func TestIdentityCA_DoorLeafIsNotAdministrator(t *testing.T) {
	env, dataDir := identityFunctionalLeaves(t)
	resp, body, err := adminToken(t, env, loadLeafPair(t, identityDir(dataDir, identityDoorClientLeafName)))
	if err != nil {
		t.Fatalf("token request: %v; want TLS to complete and an HTTP answer", err)
	}
	if resp.TLS == nil || !resp.TLS.HandshakeComplete {
		t.Error("the answer did not arrive over a completed TLS handshake")
	}
	a := decodeToken(t, body)
	if resp.StatusCode != http.StatusUnauthorized || a.Error != "invalid_client" || a.AccessToken != "" {
		t.Errorf("status %d, error %q, token present %v; want 401 invalid_client and no token", resp.StatusCode, a.Error, a.AccessToken != "")
	}
}

// refusedAtTLS asserts that presenting pair gets no HTTP status at all.
func refusedAtTLS(t *testing.T, env *identitytest.Env, pair tls.Certificate) {
	t.Helper()
	resp, _, err := adminToken(t, env, pair)
	if err == nil || resp != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("got HTTP status %d (err %v); want the handshake refused and no status", status, err)
	}
}

// TC-977-18: a leaf from the api's production controlplane-CA spec is refused
// at TLS. TC-977-16 is the control: the same client code with the identity
// api leaf gets 200.
func TestIdentityCA_ControlplaneLeafRefusedAtTLS(t *testing.T) {
	env := identityPkg.Env(t)
	cp, err := tlsca.Ensure(tlsca.ControlplaneConfig(), t.TempDir(), "home1", tlscatest.Deps())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err := cp.MintLeafToDisk(dir, apiLeafSpec("home1", net.IPv4(127, 0, 0, 1))); err != nil {
		t.Fatal(err)
	}
	refusedAtTLS(t, env, loadLeafPair(t, dir))
}

// TC-977-19: a store-CA leaf from the production storeClientLeafSpec, with
// exactly the api identity leaf's subject and EKU, is refused at TLS: the
// identity service admits by chain, not by name.
func TestIdentityCA_StoreLeafRefusedAtTLS(t *testing.T) {
	env, dataDir := identityFunctionalLeaves(t)
	store, err := tlsca.Ensure(tlsca.StoreConfig(), t.TempDir(), "home1", tlscatest.Deps())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err := store.MintLeafToDisk(dir, storeClientLeafSpec()); err != nil {
		t.Fatal(err)
	}
	storeLeaf := parseLeaf(t, filepath.Join(dir, "leaf.pem"))
	apiLeaf := parseLeaf(t, filepath.Join(identityDir(dataDir, identityAPIClientLeafName), "leaf.pem"))
	if !bytes.Equal(storeLeaf.RawSubject, apiLeaf.RawSubject) {
		t.Fatalf("store leaf subject %q, api leaf %q; the case needs them equal", storeLeaf.Subject, apiLeaf.Subject)
	}
	if !slices.Equal(storeLeaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) ||
		!slices.Equal(storeLeaf.ExtKeyUsage, apiLeaf.ExtKeyUsage) {
		t.Fatalf("store leaf EKU %v, api leaf %v; want both exactly clientAuth", storeLeaf.ExtKeyUsage, apiLeaf.ExtKeyUsage)
	}
	refusedAtTLS(t, env, loadLeafPair(t, dir))
}
