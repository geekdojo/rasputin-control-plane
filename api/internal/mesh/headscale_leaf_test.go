package mesh

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
)

// The Headscale supervisor is a consumer of the controlplane CA: these are its
// leaf tests, and the small CA helpers the rest of the package's tests share.

// ensureLeaf must mint a cert valid for the ServerURL host (the name clients
// actually dial), not just the resolved ListenAddr. Pinning server_url to
// rasputin.local previously left the leaf valid only for localhost/IP, and the
// api's own client rejected it: "x509: certificate is valid for localhost, not
// rasputin.local" (bench 2026-06-18).
func TestEnsureLeaf_CoversServerURLHost(t *testing.T) {
	ca := newCAForTest(t)
	stateDir := t.TempDir()
	sup, err := NewDockerSupervisor(DockerSupervisorConfig{
		StateDir:   stateDir,
		ListenAddr: "127.0.0.1:18080", // deterministic — avoids the dial-trick
		ServerURL:  "https://rasputin.local:18080",
		MeshCA:     ca,
	})
	if err != nil {
		t.Fatalf("NewDockerSupervisor: %v", err)
	}
	if err := sup.ensureLeaf(); err != nil {
		t.Fatalf("ensureLeaf: %v", err)
	}
	certPEM, err := os.ReadFile(filepath.Join(stateDir, "certs", "leaf.pem"))
	if err != nil {
		t.Fatalf("read leaf: %v", err)
	}
	cert := mustParseCert(t, certPEM)
	if err := cert.VerifyHostname("rasputin.local"); err != nil {
		t.Errorf("leaf not valid for rasputin.local: %v (DNS=%v IP=%v)", err, cert.DNSNames, cert.IPAddresses)
	}
	if err := cert.VerifyHostname("127.0.0.1"); err != nil {
		t.Errorf("leaf not valid for loopback: %v", err)
	}
}

// Headscale reads its certificate at container start, so its reload hook
// restarts the container — and only when it is actually running.
func TestHeadscaleLeafConsumer_RestartsOnlyARunningContainer(t *testing.T) {
	ca := newCAForTest(t)
	fd := newFakeDocker()
	s := newTestSupervisor(t, fd, func(c *DockerSupervisorConfig) {
		c.MeshCA = ca
		c.ListenAddr = "127.0.0.1:18080"
	})
	c := s.LeafConsumer()
	if c.Name != headscaleLeafName || c.Spec == nil || c.Reload == nil {
		t.Fatalf("LeafConsumer = %+v, want a named consumer with a spec and a reload hook", c)
	}
	if want := filepath.Join(s.cfg.StateDir, "certs"); c.Dir != want {
		t.Errorf("Dir = %q, want %q", c.Dir, want)
	}

	// No container yet: nothing to restart, and that is not an error — the
	// next Start creates it and reads the leaf then.
	if err := c.Reload(context.Background(), tlsca.LeafPathsIn(c.Dir)); err != nil {
		t.Fatalf("reload with no container: %v", err)
	}
	if slices.Contains(fd.cmdNames(), "restart") {
		t.Error("restarted a container that does not exist")
	}

	fd.containerExists, fd.containerState = true, "running"
	if err := c.Reload(context.Background(), tlsca.LeafPathsIn(c.Dir)); err != nil {
		t.Fatalf("reload with a running container: %v", err)
	}
	if !slices.Contains(fd.cmdNames(), "restart") {
		t.Errorf("a running container was not restarted; calls = %v", fd.cmdNames())
	}
}

// The spec the sweep checks against is the one Start mints with, so a leaf
// Start is happy with is not re-minted on every sweep.
func TestHeadscaleLeafConsumer_SpecMatchesWhatStartMints(t *testing.T) {
	ca := newCAForTest(t)
	fd := newFakeDocker()
	s := newTestSupervisor(t, fd, func(c *DockerSupervisorConfig) {
		c.MeshCA = ca
		c.ListenAddr = "127.0.0.1:18080"
	})
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	sweeper := tlsca.NewLeafSweeper(ca)
	if err := sweeper.Register(s.LeafConsumer()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	rep := sweeper.Sweep(context.Background(), nil)
	if rep.Checked != 1 || len(rep.Renewed) != 0 {
		t.Errorf("report = %+v, want the freshly-minted leaf left alone", rep)
	}
}

func newCAForTest(t *testing.T) *tlsca.MeshCA {
	t.Helper()
	ca, err := tlsca.EnsureMeshCA(t.TempDir(), "test-install")
	if err != nil {
		t.Fatalf("newCAForTest: %v", err)
	}
	return ca
}

func mustParseCert(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("PEM block did not decode")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func mustParseCertFile(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return mustParseCert(t, b)
}

func mustHavePerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return // file mode bits don't map cleanly
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	got := info.Mode().Perm()
	if got != want {
		t.Errorf("%s perm: got %#o, want %#o", path, got, want)
	}
}
