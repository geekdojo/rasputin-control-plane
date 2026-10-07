package secretstoretest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

const (
	// binEnv names the bao binary to run. CI installs the pinned release with
	// scripts/install-openbao.sh and points this at it.
	binEnv = "RASPUTIN_SECRETSTORE_BIN"
	// switchEnv set to "required" turns a missing binary into a failure, so
	// the required backend job cannot pass by skipping
	// (docs/testing-secret-store.md).
	switchEnv = "RASPUTIN_SECRETSTORE_FUNCTIONAL"
)

// TestSecretStore_SmokeWriteReadKV runs the real pinned store through the
// harness: S8's transport, PebbleDB, a static test seal, temporary storage
// and self-init. It proves the listener's config took effect (no client
// certificate is refused at the handshake; the unauthenticated generate-root
// endpoint is disabled), logs in with a store-CA client leaf through cert
// auth, writes and reads one KV v2 value, and proves teardown left nothing.
// TC-753-12 and TC-753-13.
func TestSecretStore_SmokeWriteReadKV(t *testing.T) {
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
	text := slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelDebug})
	h, err := New(Config{
		BinaryPath: bin,
		TempParent: t.TempDir(),
		Logger:     slog.New(slog.NewMultiHandler(log.Handler(), text)),
		Now:        time.Now,
		Rand:       rand.Reader,
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := h.Start(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// t.Context() is cancelled before Cleanup runs, which would turn the
	// SIGTERM wait into a SIGKILL; Background lets the store stop cleanly.
	t.Cleanup(func() {
		if err := s.Close(context.Background()); err != nil {
			t.Errorf("cleanup Close: %v", err)
		}
	})
	pid, root := s.cmd.Process.Pid, s.root
	sealKey, err := os.ReadFile(filepath.Join(root, "seal-key"))
	if err != nil {
		t.Fatal(err)
	}

	// TC-753-12: the started record.
	started := rec.Matching(slog.LevelInfo, "secret store started")
	if len(started) != 1 {
		t.Fatalf("%d 'secret store started' records, want 1", len(started))
	}
	addr, _ := logkittest.Attr(started[0], "addr")
	if host, _, err := net.SplitHostPort(addr); err != nil || host != "127.0.0.1" {
		t.Errorf("started addr = %q, want 127.0.0.1:<port>", addr)
	}
	if got, _ := logkittest.Attr(started[0], "pid"); got != strconv.Itoa(pid) {
		t.Errorf("started pid = %q, want %d", got, pid)
	}
	if got, _ := logkittest.Attr(started[0], "version"); got != "v2.7.0" {
		t.Errorf("started version = %q, want v2.7.0", got)
	}
	if got, _ := logkittest.Attr(started[0], "dir"); got != root {
		t.Errorf("started dir = %q, want %q", got, root)
	}

	// TC-753-12: the served leaf is the serverAuth one and chains to the
	// store CA (the only root ClientTLS trusts); ours is the clientAuth one.
	conn, err := tls.Dial("tcp", addr, s.ClientTLS())
	if err != nil {
		t.Fatalf("handshake with the client leaf: %v", err)
	}
	cs := conn.ConnectionState()
	if err := conn.Close(); err != nil {
		t.Errorf("close the handshake connection: %v", err)
	}
	srv := cs.PeerCertificates[0]
	if !slices.Equal(srv.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Errorf("served leaf EKU = %v, want serverAuth only", srv.ExtKeyUsage)
	}
	if len(srv.IPAddresses) != 1 || !srv.IPAddresses[0].Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("served leaf IP SANs = %v, want [127.0.0.1]", srv.IPAddresses)
	}
	if len(cs.VerifiedChains) == 0 {
		t.Error("served leaf did not verify against the store CA")
	}
	cli := s.ClientTLS().Certificates[0].Leaf
	if cli == nil || !slices.Equal(cli.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) ||
		cli.Subject.CommonName != ClientRole {
		t.Errorf("client leaf = %v, want EKU clientAuth only and CN %s", cli, ClientRole)
	}

	// TC-753-13 (a): no client certificate fails at the TLS layer, with no
	// HTTP status.
	noCert := s.ClientTLS()
	noCert.Certificates = nil
	resp, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: noCert}}).Get(s.URL() + "/v1/sys/health")
	if err == nil {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("close the response body: %v", err)
		}
		t.Errorf("a client with no certificate got HTTP %d, want a TLS failure", resp.StatusCode)
	} else if !strings.Contains(err.Error(), "tls: ") {
		t.Errorf("a client with no certificate failed with %v, want a TLS error", err)
	}

	c := &http.Client{Transport: &http.Transport{TLSClientConfig: s.ClientTLS()}}
	defer c.CloseIdleConnections()

	// TC-753-13 (b): the unauthenticated generate-root endpoint is disabled.
	if code, _ := call(t, c, http.MethodGet, s.URL()+"/v1/sys/generate-root/attempt", "", nil); code != http.StatusMethodNotAllowed {
		t.Errorf("token-less generate-root/attempt = %d, want 405", code)
	}

	// TC-753-12: cert login.
	code, body := call(t, c, http.MethodPost, s.URL()+"/v1/auth/cert/login", "", map[string]any{"name": ClientRole})
	var login struct {
		Auth struct {
			ClientToken string   `json:"client_token"`
			Policies    []string `json:"policies"`
		} `json:"auth"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &login) != nil || login.Auth.ClientToken == "" {
		t.Fatalf("cert login = %d, want 200 with a token", code)
	}
	token := login.Auth.ClientToken
	if !slices.Contains(login.Auth.Policies, KVMount) {
		t.Errorf("login policies = %v, want %s among them", login.Auth.Policies, KVMount)
	}

	// TC-753-12: one synthetic KV v2 value, written and read back.
	raw := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		t.Fatal(err)
	}
	key, value := "smoke-"+hex.EncodeToString(raw[:8]), hex.EncodeToString(raw[8:])
	path := s.URL() + "/v1/" + KVMount + "/data/" + key
	code, body = call(t, c, http.MethodPost, path, token, map[string]any{"data": map[string]string{"value": value}})
	var wrote struct {
		Data struct {
			Version int `json:"version"`
		} `json:"data"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &wrote) != nil || wrote.Data.Version != 1 {
		t.Fatalf("KV write = %d (version %d), want 200 at version 1", code, wrote.Data.Version)
	}
	code, body = call(t, c, http.MethodGet, path, token, nil)
	var read struct {
		Data struct {
			Data     map[string]string `json:"data"`
			Metadata struct {
				Version int `json:"version"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &read) != nil {
		t.Fatalf("KV read = %d, want 200", code)
	}
	if read.Data.Data["value"] != value || read.Data.Metadata.Version != 1 {
		t.Errorf("KV read back a different value or version %d (want the written value at version 1)",
			read.Data.Metadata.Version)
	}

	// TC-753-12: asserted teardown.
	c.CloseIdleConnections()
	if err := s.Close(context.Background()); err != nil {
		t.Errorf("Close = %v", err)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Errorf("kill -0 %d = %v after Close, want ESRCH", pid, err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("root %s still there after Close: %v", root, err)
	}
	if w := rec.Matching(slog.LevelWarn, "ignored SIGTERM"); len(w) != 0 {
		t.Errorf("the store was SIGKILLed: %d WARN records", len(w))
	}
	logged := rec.Text()
	for name, secret := range map[string]string{
		"token":        token,
		"KV value":     value,
		"seal key":     string(sealKey),
		"seal key hex": hex.EncodeToString(sealKey),
	} {
		if strings.Contains(logged, secret) {
			t.Errorf("the %s appears in the log", name)
		}
	}
	if strings.Contains(logged, "PRIVATE KEY") {
		t.Error("a private key appears in the log")
	}
}

// call makes one request and returns the status and body. Neither the token
// nor the body is ever logged.
func call(t *testing.T, c *http.Client, method, url, token string, payload any) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
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
		t.Fatalf("%s %s: %v", method, strings.TrimPrefix(url, "https://"), err)
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
