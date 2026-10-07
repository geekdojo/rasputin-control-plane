package mesh

import (
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"os"
)

// gateCA returns a CA whose leaf mints go through a counting clock gate.
func gateCA(t *testing.T, answer bool) (*tlsca.MeshCA, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	ca, err := tlsca.EnsureMeshCA(t.TempDir(), "clockgate", tlsca.WithLeafClockGate(func() bool {
		calls.Add(1)
		return answer
	}))
	if err != nil {
		t.Fatalf("EnsureMeshCA: %v", err)
	}
	return ca, &calls
}

// Every route to a Mesh-CA leaf goes through MintLeaf, so every route is
// gated. This asserts that for each of them by name, because a new mint path
// that bypassed the gate is exactly the sprawl this closes.
func TestLeafMintsWaitForATrustworthyClock(t *testing.T) {
	spec := tlsca.LeafSpec{CommonName: "x.local", DNSNames: []string{"x.local"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	mints := []struct {
		name string
		mint func(t *testing.T, ca *tlsca.MeshCA)
	}{
		{"MintLeaf", func(t *testing.T, ca *tlsca.MeshCA) {
			if _, _, err := tlsca.MintLeaf(ca, spec); err != nil {
				t.Fatalf("MintLeaf: %v", err)
			}
		}},
		{"MintLeafToDisk", func(t *testing.T, ca *tlsca.MeshCA) {
			if _, err := tlsca.MintLeafToDisk(ca, t.TempDir(), spec); err != nil {
				t.Fatalf("MintLeafToDisk: %v", err)
			}
		}},
		{"PrepareAppLeaf", func(t *testing.T, ca *tlsca.MeshCA) {
			_, _, renewed, err := PrepareAppLeaf(ca, t.TempDir(), "c1", "jellyfin")
			if err != nil {
				t.Fatalf("PrepareAppLeaf: %v", err)
			}
			if !renewed {
				t.Fatal("PrepareAppLeaf did not mint, so the test proves nothing")
			}
		}},
	}
	for _, m := range mints {
		t.Run(m.name, func(t *testing.T) {
			ca, calls := gateCA(t, true)
			m.mint(t, ca)
			if n := calls.Load(); n != 1 {
				t.Errorf("the clock gate was consulted %d times, want exactly 1", n)
			}
		})
	}
}

// A clock the gate could not vouch for does not stop the mint: a node with no
// reachable NTP still has to serve TLS, and the gate has already said so.
func TestLeafMintProceedsWhenTheClockNeverSyncs(t *testing.T) {
	ca, calls := gateCA(t, false)
	certPEM, keyPEM, err := tlsca.MintLeaf(ca, tlsca.LeafSpec{CommonName: "x.local", DNSNames: []string{"x.local"}})
	if err != nil {
		t.Fatalf("MintLeaf: %v", err)
	}
	if len(certPEM) == 0 || keyPEM.Len() == 0 {
		t.Fatal("no leaf was minted")
	}
	if calls.Load() != 1 {
		t.Errorf("the gate was consulted %d times, want 1", calls.Load())
	}
}

// Reusing a leaf that is still good asks nothing of the clock — the gate
// guards the moment a validity window is STAMPED, not every call.
func TestUnchangedLeafDoesNotConsultTheClock(t *testing.T) {
	ca, calls := gateCA(t, true)
	dir := t.TempDir()
	spec := tlsca.LeafSpec{CommonName: "x.local", DNSNames: []string{"x.local"}}
	if _, err := tlsca.MintLeafToDisk(ca, dir, spec); err != nil {
		t.Fatalf("MintLeafToDisk: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("first mint consulted the gate %d times, want 1", got)
	}
	if _, err := tlsca.MintLeafToDisk(ca, dir, spec); err != nil {
		t.Fatalf("MintLeafToDisk (again): %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("re-using the existing leaf consulted the gate; calls = %d, want still 1", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "leaf.pem")); err != nil {
		t.Fatal("leaf missing")
	}
}

// A CA built without the option mints exactly as before — every existing
// caller, and every test, is unaffected.
func TestNoGateMeansNoChange(t *testing.T) {
	ca, err := tlsca.EnsureMeshCA(t.TempDir(), "nogate")
	if err != nil {
		t.Fatalf("EnsureMeshCA: %v", err)
	}
	if _, _, err := tlsca.MintLeaf(ca, tlsca.LeafSpec{CommonName: "x.local", DNSNames: []string{"x.local"}}); err != nil {
		t.Fatalf("MintLeaf: %v", err)
	}
}
