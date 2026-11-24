package repaircode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/breakglass"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
)

// terminal is a stdout that reports a descriptor, so IsTerminal is asked.
type terminal struct{ bytes.Buffer }

func (*terminal) Fd() uintptr { return 1 }

// countingReader counts reads of its inner reader.
type countingReader struct {
	r     io.Reader
	reads int
}

func (c *countingReader) Read(p []byte) (int, error) { c.reads++; return c.r.Read(p) }

// codeServer is an in-test repair-code socket: TLS over a Unix socket with
// a leaf from ca, recording every request body.
type codeServer struct {
	path   string
	mu     sync.Mutex
	bodies [][]byte
}

func (s *codeServer) got() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.bodies...)
}

func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "rc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "repair-code.sock")
}

func identityCA(t *testing.T) *tlsca.CA {
	t.Helper()
	ca, err := tlsca.Ensure(tlsca.IdentityConfig(), t.TempDir(), "test", tlscatest.Deps())
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func newCodeServer(t *testing.T, ca *tlsca.CA, names []string) *codeServer {
	t.Helper()
	paths, err := ca.MintLeafToDisk(t.TempDir(), tlsca.LeafSpec{Usage: tlsca.UsageServer, CommonName: "x", DNSNames: names})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(paths.CertPath, paths.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	s := &codeServer{path: socketPath(t)}
	ln, err := net.Listen("unix", s.path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.bodies = append(s.bodies, b)
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(breakglass.CodeResponse{URLs: []string{"https://ci.local/repair", "https://192.0.2.1/repair"}})
	})}
	go func() {
		_ = srv.Serve(tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}))
	}()
	t.Cleanup(func() { _ = srv.Close() })
	return s
}

func dialer(path string) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "unix", path) }
}

// fixedRand is 13 fixed bytes: base-32 "AEBAGBAFAYDQQCIKBMGA2", whose first 20
// characters are the code.
var fixedRand = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}

// TC-321-01: with stdout not a terminal the command exits 2 with the
// sentence, reads no random bits, dials nothing and prints nothing.
func TestRun_RefusesANonTerminal_TC321_01(t *testing.T) {
	for name, stdout := range map[string]io.Writer{"a buffer": &bytes.Buffer{}, "a descriptor that isn't a terminal": &terminal{}} {
		t.Run(name, func(t *testing.T) {
			var stderr bytes.Buffer
			rnd := &countingReader{r: bytes.NewReader(fixedRand)}
			dials := 0
			code := Run(context.Background(), Deps{
				Stdout: stdout, Stderr: &stderr, IsTerminal: func(uintptr) bool { return false }, Rand: rnd,
				Dial:  func(context.Context) (net.Conn, error) { dials++; return nil, io.EOF },
				CAPEM: identityCA(t).CertPEM,
			})
			if code != 2 {
				t.Errorf("exit %d, want 2", code)
			}
			if got := strings.TrimSpace(stderr.String()); got != "This prints a one-time repair code, so run it in a terminal (ssh -t gives it one)." {
				t.Errorf("stderr %q", got)
			}
			if rnd.reads != 0 || dials != 0 {
				t.Errorf("Rand read %d times and Dial called %d times, want 0 and 0", rnd.reads, dials)
			}
			if b, ok := stdout.(interface{ Len() int }); ok && b.Len() != 0 {
				t.Error("something was printed to stdout")
			}
		})
	}
}

// TC-321-02: only the hash crosses, and the code is printed once. The
// request body is exactly {"sha256":"<hex of sha256(code)>"} and holds no
// run of the code; stdout shows the code once as XXXXX-XXXXX-XXXXX-XXXXX,
// 20 base-32 characters, with both URLs.
func TestRun_SendsOnlyTheHash_TC321_02(t *testing.T) {
	ca := identityCA(t)
	srv := newCodeServer(t, ca, []string{ServerName})
	var stdout terminal
	var stderr bytes.Buffer
	exit := Run(context.Background(), Deps{
		Stdout: &stdout, Stderr: &stderr, IsTerminal: func(fd uintptr) bool { return fd == 1 },
		Rand: bytes.NewReader(fixedRand), Dial: dialer(srv.path), CAPEM: ca.CertPEM,
	})
	if exit != 0 {
		t.Fatalf("exit %d: %s", exit, stderr.String())
	}
	out := stdout.String()
	shown := regexp.MustCompile(`\b[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{5}\b`).FindAllString(out, -1)
	if len(shown) != 1 {
		t.Fatalf("the code appears %d times in:\n%s", len(shown), out)
	}
	code := strings.ReplaceAll(shown[0], "-", "")
	if code != "AEBAGBAFAYDQQCIKBMGA" || len(code) != 20 {
		t.Errorf("code %q, want the first 20 base-32 characters of the drawn bits", code)
	}
	for _, u := range []string{"https://ci.local/repair", "https://192.0.2.1/repair"} {
		if !strings.Contains(out, u) {
			t.Errorf("stdout lacks %s", u)
		}
	}
	bodies := srv.got()
	if len(bodies) != 1 {
		t.Fatalf("%d requests, want 1", len(bodies))
	}
	sum := sha256.Sum256([]byte(code))
	if want := `{"sha256":"` + hex.EncodeToString(sum[:]) + `"}`; string(bodies[0]) != want {
		t.Errorf("body %s, want %s", bodies[0], want)
	}
	for i := 0; i+4 <= len(code); i++ {
		if bytes.Contains(bodies[0], []byte(code[i:i+4])) {
			t.Errorf("the body carries the code's run %q", code[i:i+4])
		}
	}
	if strings.Contains(stderr.String(), code) {
		t.Error("the code reached stderr")
	}
}

// TC-321-03: an unverifiable or absent api is refused, with no code printed
// and nothing issued: (a) a leaf from another CA, or one without the name;
// (b) no socket; (c) a socket nobody is listening on.
func TestRun_RefusesAnUnverifiedOrAbsentAPI_TC321_03(t *testing.T) {
	const unverified = "The control plane's api couldn't be verified, so no code was made."
	const absent = "The control plane's api isn't taking repair codes. Is rasputin-api running?"
	trusted := identityCA(t)
	other := newCodeServer(t, identityCA(t), []string{ServerName})
	unnamed := newCodeServer(t, trusted, []string{"other.rasputin.invalid"})
	noSocket := socketPath(t)
	refused := socketPath(t)
	ln, err := net.Listen("unix", refused)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = ln.Close()

	for name, c := range map[string]struct {
		path   string
		srv    *codeServer
		ca     []byte
		stderr string
	}{
		"(a) another CA":       {other.path, other, trusted.CertPEM, unverified},
		"(a) without the name": {unnamed.path, unnamed, trusted.CertPEM, unverified},
		"(a) no CA to verify":  {unnamed.path, unnamed, nil, unverified},
		"(b) no socket":        {noSocket, nil, trusted.CertPEM, absent},
		"(c) refused":          {refused, nil, trusted.CertPEM, absent},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout terminal
			var stderr bytes.Buffer
			exit := Run(context.Background(), Deps{
				Stdout: &stdout, Stderr: &stderr, IsTerminal: func(uintptr) bool { return true },
				Rand: bytes.NewReader(fixedRand), Dial: dialer(c.path), CAPEM: c.ca,
			})
			if exit != 1 || strings.TrimSpace(stderr.String()) != c.stderr {
				t.Errorf("exit %d, stderr %q; want 1, %q", exit, stderr.String(), c.stderr)
			}
			if stdout.Len() != 0 {
				t.Errorf("printed %q", stdout.String())
			}
			if c.srv != nil && len(c.srv.got()) != 0 {
				t.Error("the server was handed a hash")
			}
		})
	}
}

// IsTerminal reads a real descriptor: a regular file is not a terminal.
func TestIsTerminal_RegularFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if IsTerminal(f.Fd()) {
		t.Fatal("a regular file reads as a terminal")
	}
}
