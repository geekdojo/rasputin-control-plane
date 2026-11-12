package identitytest_test

// The harness's functional self-test: the real pinned Keycloak, PostgreSQL,
// Headscale and Chrome, through the same Package every identity test package
// uses. It skips without RASPUTIN_IDENTITY_HOME and fails instead when
// RASPUTIN_IDENTITY_FUNCTIONAL=required, as CI's backend job sets it
// (docs/testing-identity.md).

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/chromedp"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identitytest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitytest/signin"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

var (
	// rec records every record the harness and the client log, Keycloak's
	// DEBUG output lines included, for TC-966-20's scan.
	rec    *logkittest.Recorder
	recLog *slog.Logger
	// seen holds the authorization codes and token bytes the flow carried,
	// read off the wire by the recording transport, for the same scan.
	seen sentinels

	// pkg is the composition root's Config with the recorder teed in.
	pkg = identitytest.NewPackage(func() (identitytest.Config, error) {
		cfg, err := identitytest.ConfigFromEnv()
		if err != nil {
			return cfg, err
		}
		recLog, rec = logkittest.New()
		cfg.Logger = slog.New(slog.NewMultiHandler(cfg.Logger.Handler(), recLog.Handler()))
		return cfg, nil
	})
)

func TestMain(m *testing.M) { os.Exit(pkg.Run(m)) }

type sentinels struct {
	mu     sync.Mutex
	values []string
	nonce  string
}

func (s *sentinels) add(v string) {
	if v == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values = append(s.values, v)
}

func (s *sentinels) all() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.values...)
}

// recording reads the nonce off the authorization request, the code off the
// redirect to the client, and the tokens off the token answer.
type recording struct{ inner http.RoundTripper }

func (r recording) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasSuffix(req.URL.Path, "/protocol/openid-connect/auth") {
		seen.mu.Lock()
		seen.nonce = req.URL.Query().Get("nonce")
		seen.mu.Unlock()
	}
	resp, err := r.inner.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	if loc, err := resp.Location(); err == nil && strings.HasPrefix(loc.String(), identitytest.RedirectURI) {
		seen.add(loc.Query().Get("code"))
	}
	if strings.HasSuffix(req.URL.Path, "/protocol/openid-connect/token") {
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		var tok map[string]any
		if json.Unmarshal(body, &tok) == nil {
			for _, k := range []string{"access_token", "id_token", "refresh_token"} {
				s, _ := tok[k].(string)
				seen.add(s)
			}
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}
	return resp, nil
}

// TC-966-02: a password code flow with PKCE S256 completes through the
// harness, sees exactly #959's FL2 page sequence, and the ID token is the
// issuer's, for the client, carrying the nonce sent.
func TestIdentity_PasswordCodeFlowPKCE(t *testing.T) {
	env := pkg.Env(t)
	name, password := env.User()
	c, err := signin.New(signin.Config{
		Transport: recording{inner: &http.Transport{TLSClientConfig: env.ClientTLS()}},
		Issuer:    env.Issuer(), ClientID: identitytest.ClientID, RedirectURI: identitytest.RedirectURI,
		Rand: rand.Reader, Logger: recLog,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.PasswordCodeFlow(t.Context(), name, password)
	if err != nil {
		t.Fatalf("PasswordCodeFlow: %v (pages %v)", err, res.PageIDs)
	}
	if strings.Join(res.PageIDs, ",") != "login-login" {
		t.Errorf("PageIDs = %v, want [login-login]", res.PageIDs)
	}
	if want := env.FrontURL() + "/realms/" + identitytest.Realm; env.Issuer() != want || res.Claims.Iss != want {
		t.Errorf("iss = %q, Issuer() = %q; want both %q", res.Claims.Iss, env.Issuer(), want)
	}
	aud := false
	for _, a := range res.Claims.Aud {
		aud = aud || a == identitytest.ClientID
	}
	if !aud {
		t.Errorf("aud = %v, want it to hold %s", res.Claims.Aud, identitytest.ClientID)
	}
	seen.mu.Lock()
	nonce := seen.nonce
	seen.mu.Unlock()
	if nonce == "" || res.Claims.Nonce != nonce {
		t.Errorf("nonce = %q, want the one sent, %q", res.Claims.Nonce, nonce)
	}
	if res.Claims.Sub == "" {
		t.Error("sub is empty")
	}
	if len(seen.all()) < 2 {
		t.Errorf("the recording transport caught %d code/token values; the log scan would prove little", len(seen.all()))
	}
}

// TC-966-12: /health/ready on the management port answers 200 UP to the
// client leaf; a client with no certificate fails at TLS, never with an
// HTTP status; the start record names the pinned Keycloak and JVM.
func TestIdentity_ReadyOverMutualTLS(t *testing.T) {
	env := pkg.Env(t)
	ok := &http.Client{Transport: &http.Transport{TLSClientConfig: env.ClientTLS()}}
	resp, err := ok.Get(env.ManagementURL() + "/health/ready")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(strings.ReplaceAll(string(body), " ", ""), `"status":"UP"`) {
		t.Errorf("ready = %d %s", resp.StatusCode, body)
	}

	noCert := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: env.Roots()}}}
	resp, err = noCert.Get(env.ManagementURL() + "/health/ready")
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("a client with no certificate got HTTP %d, want a TLS failure", resp.StatusCode)
	}
	if !strings.Contains(err.Error(), "tls") {
		t.Errorf("no-certificate error = %v, want a TLS alert", err)
	}

	started := rec.Matching(slog.LevelInfo, "identity service started")
	if len(started) != 1 {
		t.Fatalf("%d 'identity service started' records, want 1", len(started))
	}
	v, _ := logkittest.Attr(started[0], "version")
	jvm, _ := logkittest.Attr(started[0], "jvm")
	if v != "26.8.2" || !strings.Contains(jvm, "25.0.5+8") {
		t.Errorf("started record version %q jvm %q, want 26.8.2 on 25.0.5+8", v, jvm)
	}
}

// TC-966-13: Headscale runs at the digest mesh-images.json pins and answers
// /health over a client trusting only the returned CA.
func TestIdentity_Headscale(t *testing.T) {
	url, env := pkg.Headscale(t)
	_, roots, err := env.Headscale(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ref, ok := mesh.BakedImageRef("headscale")
	if !ok {
		t.Fatal("mesh-images.json has no headscale")
	}
	digest := ref[strings.LastIndex(ref, "@")+1:]
	image, err := exec.CommandContext(t.Context(), "docker", "inspect", "--format", "{{.Image}}", env.HeadscaleContainer()).Output()
	if err != nil {
		t.Fatal(err)
	}
	digests, err := exec.CommandContext(t.Context(), "docker", "image", "inspect", "--format", "{{json .RepoDigests}}",
		strings.TrimSpace(string(image))).Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(digests), "headscale/headscale@"+digest) {
		t.Errorf("the container's image has repo digests %s, want headscale/headscale@%s", digests, digest)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}}
	resp, err := client.Get(url + "/health")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/health = %d, want 200", resp.StatusCode)
	}
}

// TC-966-14: the pinned Chrome renders Keycloak's sign-in page through the
// front: CDP reports the pinned version, and the page id is login-login.
func TestIdentity_Browser(t *testing.T) {
	ctx, env := pkg.Browser(t)
	v, err := cdp.Call(ctx, chromedp.FromContext(ctx).Browser, browser.GetVersion, cdp.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	want := identitytest.ChromeForTestingRelease[strings.LastIndex(identitytest.ChromeForTestingRelease, ":")+1:]
	if _, got, _ := strings.Cut(v.Product, "/"); got != want {
		t.Errorf("product = %q, want version %s", v.Product, want)
	}
	q := url.Values{
		"client_id": {identitytest.ClientID}, "redirect_uri": {identitytest.RedirectURI},
		"response_type": {"code"}, "scope": {"openid"}, "state": {"browser-state"},
		"code_challenge": {signin.Challenge("browser-verifier-browser-verifier-browser-verifier")}, "code_challenge_method": {"S256"},
	}
	if err := chromedp.Do(ctx, chromedp.Navigate(env.Issuer()+"/protocol/openid-connect/auth?"+q.Encode())); err != nil {
		t.Fatal(err)
	}
	attr, err := chromedp.Run(ctx, chromedp.AttributeValue(chromedp.CSS("body[data-page-id]"), "data-page-id"))
	if err != nil {
		t.Fatal(err)
	}
	if attr.Value != "login-login" {
		t.Errorf("data-page-id = %q, want login-login", attr.Value)
	}
}

// TC-966-20: no recorded record, Keycloak's DEBUG output included, holds the
// user password, the database password, an authorization code or token
// bytes. It runs last, so it scans what the tests above logged.
func TestIdentity_NoSecretInLogs(t *testing.T) {
	env := pkg.Env(t)
	_, pw := env.User()
	values := append(seen.all(), string(pw.Reveal()), string(env.DBPassword().Reveal()))
	text := rec.Text()
	if len(rec.Records()) == 0 {
		t.Fatal("no records were recorded; the scan would prove nothing")
	}
	for i, v := range values {
		if len(v) < 8 {
			t.Fatalf("a sentinel %d bytes long is too short to scan for", len(v))
		}
		if strings.Contains(text, v) {
			t.Errorf("a record holds secret value %d of %d (%d bytes); the value is not printed", i+1, len(values), len(v))
		}
	}
}
