//go:build alloyprobe

// TestAlloyProbe runs the PINNED Grafana Alloy image (defaultAlloyImage)
// against an in-process TLS 1.3 server on this machine, with the exact
// tls_config a collector is rendered with (collectorTLSConfig), to prove the
// half of collector trust no unit test can: what Alloy itself does with it.
// See docs/testing-collector-trust.md (geekdojo/geekdojo-brain#672).
//
// What it proves, each case on the pinned image:
//
//   - positive (TC-672-17): Alloy presents a self-signed client pair made with
//     the agent's parameters (ECDSA P-256, PKCS#8 "PRIVATE KEY" PEM, clientAuth
//     EKU, 1970 to 9999), verifies the server leaf by chain to the Mesh CA via
//     ca_file, sends SNI = server_name, and delivers a remote_write POST to
//     /api/obs/ingest. The server sees the generated key's SPKI.
//   - no certificate pinned (TC-672-20): the server swaps in a re-minted leaf
//     (fresh key, same CA, same SAN) and drops its connections; Alloy delivers
//     again under the new serial with no config change and no restart.
//   - chain enforced (TC-672-18): a leaf from a foreign CA gets an x509: error
//     in Alloy's log and no delivery.
//   - name enforced (TC-672-19): a Mesh-CA leaf for other.rasputin.test gets an
//     x509: name-mismatch error and no delivery.
//
// What it does not prove: the real fleet (the bench procedure in the doc),
// the linux docker route (the --add-host branch has not been run), or loki.write,
// which renders the same block (TC-672-05) but is not exercised here.
//
// Run (on this Mac, Docker is Rancher Desktop and not on PATH by default):
//
//	PATH="$HOME/.rd/bin:$PATH" go test -tags=alloyprobe -run TestAlloyProbe -count=1 -v ./api/internal/obs/
//
// It FAILS, never skips, when docker is missing or its daemon is unreachable.
// Files live under $HOME/.cache/rasputin-alloy-probe because Docker on macOS
// only bind-mounts paths shared with its VM ($HOME is; t.TempDir is not).
// Every container it starts (rasputin-alloy-probe-*) and that directory are
// removed when it ends. Each wait is on a fact — a delivery, a log line, or
// the container exiting — bounded by a 90 s deadline.

package obs

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/api/internal/nodekeytest"
)

const (
	probeServerName    = "probe.rasputin.test"
	probeContainerBase = "rasputin-alloy-probe-"
	probeDeadline      = 90 * time.Second
)

// probeDelivery is one request the probe server received.
type probeDelivery struct {
	path   string
	sni    string
	spki   []byte
	serial string
}

// probeServer is the stand-in for the api's node listener: TLS 1.3, any
// client certificate required, its leaf served from an atomic pointer so it
// can be swapped mid-run.
type probeServer struct {
	addr       *net.TCPAddr
	leaf       atomic.Pointer[tls.Certificate]
	deliveries chan probeDelivery

	mu     sync.Mutex
	served map[net.Conn]string // raw conn -> serial of the leaf served on it
	conns  map[net.Conn]struct{}
	srv    *http.Server
}

type probeConnKey struct{}

func startProbeServer(t *testing.T, leaf tls.Certificate) *probeServer {
	t.Helper()
	ps := &probeServer{
		deliveries: make(chan probeDelivery, 64),
		served:     map[net.Conn]string{},
		conns:      map[net.Conn]struct{}{},
	}
	ps.leaf.Store(&leaf)
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAnyClientCert,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			c := ps.leaf.Load()
			ps.mu.Lock()
			ps.served[hello.Conn] = c.Leaf.SerialNumber.String()
			ps.mu.Unlock()
			return c, nil
		},
	}
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	ps.addr = ln.Addr().(*net.TCPAddr)
	ps.srv = &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, probeConnKey{}, c)
		},
		ConnState: func(c net.Conn, s http.ConnState) {
			ps.mu.Lock()
			defer ps.mu.Unlock()
			switch s {
			case http.StateNew:
				ps.conns[c] = struct{}{}
			case http.StateClosed, http.StateHijacked:
				delete(ps.conns, c)
			}
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			d := probeDelivery{path: r.URL.Path, sni: r.TLS.ServerName}
			if len(r.TLS.PeerCertificates) > 0 {
				d.spki = r.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo
			}
			if tc, ok := r.Context().Value(probeConnKey{}).(*tls.Conn); ok {
				ps.mu.Lock()
				d.serial = ps.served[tc.NetConn()]
				ps.mu.Unlock()
			}
			select {
			case ps.deliveries <- d:
			default: // the buffer only needs the first few
			}
			w.WriteHeader(http.StatusNoContent)
		}),
	}
	go func() { _ = ps.srv.Serve(tls.NewListener(ln, cfg)) }()
	t.Cleanup(func() { _ = ps.srv.Close() })
	return ps
}

// swap serves next from now on and closes every open connection, so the
// client's next request needs a fresh handshake.
func (ps *probeServer) swap(next tls.Certificate) {
	ps.leaf.Store(&next)
	ps.mu.Lock()
	defer ps.mu.Unlock()
	for c := range ps.conns {
		_ = c.Close()
	}
}

func probeLeaf(t *testing.T, ca *mesh.MeshCA, dnsName string) tls.Certificate {
	t.Helper()
	certPEM, keyPEM, err := mesh.MintLeaf(ca, mesh.LeafSpec{CommonName: "probe-api", DNSNames: []string{dnsName}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func writeProbeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// probeAlloy is one running Alloy container and the facts it produces.
type probeAlloy struct {
	name   string
	exited chan string      // closed-over exit status, once the container stops
	lines  chan string      // every log line, as it is written
	logBuf *strings.Builder // everything seen so far, for failure output
	logMu  sync.Mutex
}

// runAlloy writes the config and certs for one case under dir and starts the
// pinned image against the server at port.
func runAlloy(t *testing.T, dir, name string, ca *mesh.MeshCA, port int) (*probeAlloy, []byte) {
	t.Helper()
	certDir := filepath.Join(dir, "certs")
	// A client pair made the way the agent writes its collector key. 0644 (via
	// writeProbeFile): a throwaway key, readable by whatever uid the VM's file
	// sharing maps the container's root to.
	pair := nodekeytest.New(t, "collector")
	writeProbeFile(t, filepath.Join(certDir, filepath.Base(collectorNodeKeyCertPath)), pair.CertPEM())
	writeProbeFile(t, filepath.Join(certDir, filepath.Base(collectorNodeKeyPath)), pair.KeyPEM(t))
	spki := pair.Leaf.RawSubjectPublicKeyInfo
	writeProbeFile(t, filepath.Join(certDir, filepath.Base(collectorMeshCAPath)), ca.CertPEM)
	config := fmt.Sprintf(`prometheus.exporter.self "probe" { }

prometheus.scrape "probe" {
  targets         = prometheus.exporter.self.probe.targets
  forward_to      = [prometheus.remote_write.probe.receiver]
  scrape_interval = "1s"
  scrape_timeout  = "1s"
}

prometheus.remote_write "probe" {
  endpoint {
    url = "https://host.docker.internal:%d%s"
    tls_config {
%s
    }
  }
}
`, port, obsMetricsIngestPath, collectorTLSConfig(collectorNodeKeyCertPath, collectorNodeKeyPath, probeServerName))
	writeProbeFile(t, filepath.Join(dir, "config.alloy"), []byte(config))

	args := []string{"run", "-d", "--name", name}
	if runtime.GOOS == "linux" {
		// Not verified: on Rancher Desktop (darwin) host.docker.internal
		// already reaches the Mac, and this flag would override it with the
		// VM bridge, where nothing listens.
		args = append(args, "--add-host=host.docker.internal:host-gateway")
	}
	args = append(args,
		"-v", certDir+":"+filepath.Dir(collectorMeshCAPath)+":ro",
		"-v", filepath.Join(dir, "config.alloy")+":"+collectorConfigPath+":ro",
		defaultAlloyImage,
		"run", "--server.http.listen-addr=127.0.0.1:12345", collectorConfigPath)
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("docker run %s: %v\n%s", name, err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	a := &probeAlloy{name: name, exited: make(chan string, 1), lines: make(chan string, 4096), logBuf: &strings.Builder{}}
	// The container stopping is a fact; `docker wait` reports it.
	go func() {
		out, _ := exec.Command("docker", "wait", name).CombinedOutput()
		a.exited <- strings.TrimSpace(string(out))
	}()
	// Every log line, as Alloy writes it. Ends when the container is removed.
	logs := exec.Command("docker", "logs", "-f", name)
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	logs.Stdout, logs.Stderr = pw, pw
	if err := logs.Start(); err != nil {
		t.Fatalf("docker logs -f: %v", err)
	}
	_ = pw.Close()
	go func() {
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			l := sc.Text()
			a.logMu.Lock()
			a.logBuf.WriteString(l + "\n")
			a.logMu.Unlock()
			select {
			case a.lines <- l:
			default:
			}
		}
		_ = pr.Close()
	}()
	t.Cleanup(func() { _ = logs.Process.Kill(); _ = logs.Wait() })
	return a, spki
}

func (a *probeAlloy) log() string {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	return a.logBuf.String()
}

// waitDelivery waits for a delivery matching ok, failing at the deadline or if
// the container exits first.
func waitDelivery(t *testing.T, a *probeAlloy, ps *probeServer, what string, ok func(probeDelivery) bool) probeDelivery {
	t.Helper()
	deadline := time.After(probeDeadline)
	for {
		select {
		case d := <-ps.deliveries:
			if ok(d) {
				return d
			}
		case st := <-a.exited:
			t.Fatalf("%s: container %s exited (status %s) before it happened\n--- alloy log ---\n%s", what, a.name, st, a.log())
		case <-deadline:
			t.Fatalf("%s: not seen within %s\n--- alloy log ---\n%s", what, probeDeadline, a.log())
		}
	}
}

// waitLogLine waits for a log line containing every one of want.
func waitLogLine(t *testing.T, a *probeAlloy, what string, want ...string) string {
	t.Helper()
	deadline := time.After(probeDeadline)
	for {
		select {
		case l := <-a.lines:
			match := true
			for _, w := range want {
				if !strings.Contains(l, w) {
					match = false
				}
			}
			if match {
				return l
			}
		case st := <-a.exited:
			t.Fatalf("%s: container %s exited (status %s) first\n--- alloy log ---\n%s", what, a.name, st, a.log())
		case <-deadline:
			t.Fatalf("%s: no log line containing %q within %s\n--- alloy log ---\n%s", what, want, probeDeadline, a.log())
		}
	}
}

func containerStart(t *testing.T, name string) string {
	t.Helper()
	out, err := exec.Command("docker", "inspect", "-f", "{{.RestartCount}} {{.State.StartedAt}}", name).CombinedOutput()
	if err != nil {
		t.Fatalf("docker inspect %s: %v\n%s", name, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestAlloyProbe(t *testing.T) {
	// TC-672-21: a missing dependency fails the probe; it never skips.
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("docker is not on PATH (%v). On this Mac: PATH=\"$HOME/.rd/bin:$PATH\"", err)
	}
	if out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		t.Fatalf("docker daemon unreachable: %v\n%s", err, out)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(home, ".cache", "rasputin-alloy-probe")
	_ = os.RemoveAll(cache)
	t.Cleanup(func() { _ = os.RemoveAll(cache) })
	for _, c := range []string{"positive", "foreign-ca", "wrong-name"} {
		_ = exec.Command("docker", "rm", "-f", probeContainerBase+c).Run()
	}
	t.Logf("image %s", defaultAlloyImage)

	ca, err := mesh.EnsureMeshCA(filepath.Join(t.TempDir(), "mesh"), "alloy-probe")
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := mesh.EnsureMeshCA(filepath.Join(t.TempDir(), "foreign"), "alloy-probe-foreign")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("positive and re-minted leaf", func(t *testing.T) {
		// TC-672-17
		first := probeLeaf(t, ca, probeServerName)
		ps := startProbeServer(t, first)
		a, spki := runAlloy(t, filepath.Join(cache, "positive"), probeContainerBase+"positive", ca, ps.addr.Port)
		firstSerial := first.Leaf.SerialNumber.String()
		d := waitDelivery(t, a, ps, "a delivery under the first leaf", func(d probeDelivery) bool { return d.serial == firstSerial })
		if d.path != obsMetricsIngestPath {
			t.Errorf("delivered to %q, want %q", d.path, obsMetricsIngestPath)
		}
		if string(d.spki) != string(spki) {
			t.Error("the server saw an SPKI other than the generated client key's")
		}
		if d.sni != probeServerName {
			t.Errorf("SNI = %q, want %q", d.sni, probeServerName)
		}
		t.Logf("TC-672-17: POST %s delivered; SNI %q; client SPKI matches the generated key; leaf serial %s", d.path, d.sni, d.serial)

		// TC-672-20
		before := containerStart(t, a.name)
		next := probeLeaf(t, ca, probeServerName)
		nextSerial := next.Leaf.SerialNumber.String()
		ps.swap(next)
		t.Logf("TC-672-20: swapped to a re-minted leaf (fresh key, same CA, same SAN): serial %s -> %s; open connections dropped", firstSerial, nextSerial)
		d = waitDelivery(t, a, ps, "a delivery under the re-minted leaf", func(d probeDelivery) bool { return d.serial == nextSerial })
		if after := containerStart(t, a.name); after != before {
			t.Errorf("the container restarted across the swap: %q -> %q", before, after)
		}
		t.Logf("TC-672-20: POST %s delivered under serial %s with no config change and no restart (restarts/started: %s)", d.path, d.serial, before)
	})

	t.Run("chain enforced", func(t *testing.T) {
		// TC-672-18
		ps := startProbeServer(t, probeLeaf(t, foreign, probeServerName))
		a, _ := runAlloy(t, filepath.Join(cache, "foreign-ca"), probeContainerBase+"foreign-ca", ca, ps.addr.Port)
		l := waitLogLine(t, a, "a chain failure", "x509:")
		if n := len(ps.deliveries); n != 0 {
			t.Errorf("%d request(s) delivered to a server with a foreign-CA leaf", n)
		}
		t.Logf("TC-672-18: no delivery; alloy: %s", l)
	})

	t.Run("name enforced", func(t *testing.T) {
		// TC-672-19
		ps := startProbeServer(t, probeLeaf(t, ca, "other.rasputin.test"))
		a, _ := runAlloy(t, filepath.Join(cache, "wrong-name"), probeContainerBase+"wrong-name", ca, ps.addr.Port)
		l := waitLogLine(t, a, "a name mismatch", "x509:", "other.rasputin.test", probeServerName)
		if n := len(ps.deliveries); n != 0 {
			t.Errorf("%d request(s) delivered to a server whose leaf names another host", n)
		}
		t.Logf("TC-672-19: no delivery; alloy: %s", l)
	})
}
