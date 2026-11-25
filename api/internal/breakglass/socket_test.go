package breakglass

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	"strings"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// fakeIssuer records the hashes it was handed.
type fakeIssuer struct {
	mu     sync.Mutex
	hashes [][32]byte
}

func (f *fakeIssuer) Issue(_ context.Context, h [32]byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hashes = append(f.hashes, h)
	return nil
}

func (f *fakeIssuer) RepairURLs() []string {
	return []string{"https://ci.local/repair", "https://192.0.2.1/repair"}
}

func (f *fakeIssuer) got() [][32]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][32]byte(nil), f.hashes...)
}

// identityLeaf is a real identity CA and its repair-code leaf on disk.
func identityLeaf(t *testing.T) (*tlsca.CA, tlsca.LeafPaths) {
	t.Helper()
	ca, err := tlsca.Ensure(tlsca.IdentityConfig(), t.TempDir(), "test", tlscatest.Deps())
	if err != nil {
		t.Fatal(err)
	}
	paths, err := ca.MintLeafToDisk(filepath.Join(t.TempDir(), "identity-repair-code"), tlsca.LeafSpec{
		Usage: tlsca.UsageServer, CommonName: "rasputin repair code", DNSNames: []string{"repair-code.rasputin.invalid"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ca, paths
}

// socketDir is a short directory for a Unix socket (darwin's sun_path is
// 104 bytes, which a test's temp dir can pass).
func socketDir(t *testing.T) string {
	t.Helper()
	parent, err := os.MkdirTemp("/tmp", "bg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
	return filepath.Join(parent, "repair")
}

type socketRig struct {
	sock   *Socket
	issuer *fakeIssuer
	rec    *logkittest.Recorder
	ca     *tlsca.CA
	cancel context.CancelFunc
}

func newSocketRig(t *testing.T, edit func(*SocketDeps)) *socketRig {
	t.Helper()
	ca, leaf := identityLeaf(t)
	log, rec := logkittest.New()
	r := &socketRig{issuer: &fakeIssuer{}, rec: rec, ca: ca}
	d := SocketDeps{Issuer: r.issuer, Log: log, Leaf: &leaf, Dir: socketDir(t), OwnerUID: os.Geteuid(),
		PeerUID: func(net.Conn) (int, error) { return 0, nil }, Linux: true}
	if edit != nil {
		edit(&d)
	}
	s, err := NewSocket(d)
	if err != nil {
		t.Fatal(err)
	}
	r.sock = s
	return r
}

func (r *socketRig) start(t *testing.T) bool {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	t.Cleanup(cancel)
	return r.sock.Start(ctx)
}

// post sends body to the socket over TLS 1.3, verifying the server by chain
// to the rig's CA as the command does.
func (r *socketRig) post(t *testing.T, body []byte) (*http.Response, *tls.ConnectionState, error) {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(r.ca.CertPEM)
	var state *tls.ConnectionState
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", r.sock.Path())
		},
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "repair-code.rasputin.invalid", MinVersion: tls.VersionTLS13,
			VerifyConnection: func(cs tls.ConnectionState) error { state = &cs; return nil }},
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequest(http.MethodPost, "https://repair-code.rasputin.invalid"+CodePath, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err == nil {
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(b))
	}
	return resp, state, err
}

func hashBody(h [32]byte) []byte {
	b, _ := json.Marshal(CodeRequest{SHA256: hex.EncodeToString(h[:])})
	return b
}

func (r *socketRig) notServed() []slog.Record {
	var out []slog.Record
	for _, rec := range r.rec.Records() {
		if e, _ := logkittest.Attr(rec, "event"); e == "breakglass.socket_not_served" {
			out = append(out, rec)
		}
	}
	return out
}

// TC-321-05: a real Unix socket and real TLS. A valid hash reaches Issue as
// exactly its 32 bytes and the reply carries both URLs over TLS 1.3; invalid
// hex, a wrong length and a body over the cap are refused with Issue not
// called.
func TestSocket_RealTLS_TC321_05(t *testing.T) {
	r := newSocketRig(t, nil)
	if !r.start(t) {
		t.Fatalf("not served:\n%s", r.rec.Text())
	}
	h := sha256.Sum256([]byte("ABCDEFGHIJKLMNOPQRST"))
	resp, state, err := r.post(t, hashBody(h))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("post: %v %v", resp, err)
	}
	if state == nil || state.Version != tls.VersionTLS13 {
		t.Errorf("negotiated %+v, want TLS 1.3", state)
	}
	var out CodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || len(out.URLs) != 2 {
		t.Fatalf("reply %+v %v", out, err)
	}
	if got := r.issuer.got(); len(got) != 1 || got[0] != h {
		t.Fatalf("Issue got %x, want %x", got, h)
	}
	for name, body := range map[string][]byte{
		"invalid hex":  []byte(`{"sha256":"zz"}`),
		"wrong length": []byte(`{"sha256":"` + hex.EncodeToString(h[:16]) + `"}`),
		"over the cap": []byte(`{"sha256":"` + strings.Repeat("a", 2048) + `"}`),
		"not json":     []byte(`sha256=` + hex.EncodeToString(h[:])),
	} {
		resp, _, err := r.post(t, body)
		if err != nil || resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %v %v, want 400", name, resp, err)
		}
	}
	if got := r.issuer.got(); len(got) != 1 {
		t.Errorf("Issue called %d times, want only the valid one", len(got))
	}
	r.cancel()
}

// TC-321-04: the peer uid is the authentication. A peer that reads as uid
// 1000, or whose uid can't be read, is closed before TLS, with a WARN
// breakglass.socket_refused, and Issue is never called.
func TestSocket_PeerUID_TC321_04(t *testing.T) {
	for name, c := range map[string]struct {
		uid  int
		err  error
		attr string
		want string
	}{
		"uid 1000":   {uid: 1000, attr: "peer_uid", want: "1000"},
		"unreadable": {err: errors.New("no creds"), attr: "reason", want: "peercred"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newSocketRig(t, func(d *SocketDeps) {
				d.PeerUID = func(net.Conn) (int, error) { return c.uid, c.err }
			})
			if !r.start(t) {
				t.Fatal("not served")
			}
			if _, _, err := r.post(t, hashBody(sha256.Sum256([]byte("x")))); err == nil {
				t.Fatal("a refused peer's request was answered")
			}
			if len(r.issuer.got()) != 0 {
				t.Fatal("Issue was called for a refused peer")
			}
			found := false
			for _, rec := range r.rec.AtLevel(slog.LevelWarn) {
				if e, _ := logkittest.Attr(rec, "event"); e != "breakglass.socket_refused" {
					continue
				}
				if v, _ := logkittest.Attr(rec, c.attr); v == c.want {
					found = true
				}
			}
			if !found {
				t.Errorf("no WARN socket_refused with %s=%s:\n%s", c.attr, c.want, r.rec.Text())
			}
		})
	}
}

// TC-321-06: a socket an earlier listener left at the path never disables
// the last resort; a regular file or a symlink at the path is never removed,
// and the socket is then not served, with an ERROR naming the path.
func TestSocket_LeftoverPath_TC321_06(t *testing.T) {
	r := newSocketRig(t, nil)
	if err := os.MkdirAll(r.sock.d.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// An earlier listener that was never closed: its file stays.
	ln, err := net.Listen("unix", r.sock.Path())
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = ln.Close()
	if fi, err := os.Lstat(r.sock.Path()); err != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("no leftover socket: %v", err)
	}
	if !r.start(t) {
		t.Fatalf("a leftover socket kept the socket from being served:\n%s", r.rec.Text())
	}
	if resp, _, err := r.post(t, hashBody(sha256.Sum256([]byte("x")))); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("issue after the leftover: %v %v", resp, err)
	}

	for name, plant := range map[string]func(path string) error{
		"regular file": func(p string) error { return os.WriteFile(p, []byte("x"), 0o600) },
		"symlink":      func(p string) error { return os.Symlink("/etc/hosts", p) },
	} {
		t.Run(name, func(t *testing.T) {
			r := newSocketRig(t, nil)
			if err := os.MkdirAll(r.sock.d.Dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := plant(r.sock.Path()); err != nil {
				t.Fatal(err)
			}
			if r.start(t) {
				t.Fatal("served over a non-socket")
			}
			if _, err := os.Lstat(r.sock.Path()); err != nil {
				t.Errorf("the %s was removed: %v", name, err)
			}
			recs := r.notServed()
			if len(recs) != 1 || recs[0].Level != slog.LevelError {
				t.Fatalf("records %v", recs)
			}
			if p, _ := logkittest.Attr(recs[0], "path"); p != r.sock.Path() {
				t.Errorf("path %q", p)
			}
			if reason, _ := logkittest.Attr(recs[0], "reason"); reason != "not_a_socket" {
				t.Errorf("reason %q", reason)
			}
		})
	}
}

// TC-321-07: without the identity CA on Linux the socket is not served, at
// ERROR with the reason; off Linux it is never served, at INFO. Neither
// leaves a listener.
func TestSocket_NotServed_TC321_07(t *testing.T) {
	for name, c := range map[string]struct {
		edit   func(*SocketDeps)
		level  slog.Level
		reason string
	}{
		"no identity CA on Linux": {func(d *SocketDeps) { d.Leaf = nil }, slog.LevelError, "no_identity_ca"},
		"off Linux":               {func(d *SocketDeps) { d.Linux = false }, slog.LevelInfo, "not_linux"},
		"a bad directory":         {func(d *SocketDeps) { d.Dir = "relative/dir" }, slog.LevelError, "dir"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newSocketRig(t, c.edit)
			if r.start(t) {
				t.Fatal("served")
			}
			recs := r.notServed()
			if len(recs) != 1 || recs[0].Level != c.level {
				t.Fatalf("records %v", recs)
			}
			if reason, _ := logkittest.Attr(recs[0], "reason"); reason != c.reason {
				t.Errorf("reason %q, want %q", reason, c.reason)
			}
			if _, err := os.Lstat(r.sock.Path()); err == nil {
				t.Error("a socket file exists")
			}
		})
	}
}

func TestNewSocket_RefusesAMissingCollaborator(t *testing.T) {
	good := SocketDeps{Issuer: &fakeIssuer{}, Log: slog.New(slog.DiscardHandler), Dir: "/run/x", PeerUID: PeerUID}
	for name, edit := range map[string]func(*SocketDeps){
		"Issuer": func(d *SocketDeps) { d.Issuer = nil }, "Log": func(d *SocketDeps) { d.Log = nil },
		"Dir": func(d *SocketDeps) { d.Dir = "" }, "PeerUID": func(d *SocketDeps) { d.PeerUID = nil },
	} {
		d := good
		edit(&d)
		if _, err := NewSocket(d); err == nil {
			t.Errorf("NewSocket with no %s succeeded", name)
		}
	}
}
