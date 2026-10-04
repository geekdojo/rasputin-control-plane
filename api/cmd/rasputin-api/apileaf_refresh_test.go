package main

import (
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
)

// The api's HTTPS leaf renews in place: refresh swaps in whatever is now on
// disk at the same address, where load — correctly, for its own job — short
// -circuits. That difference is the whole reason the sweep has a hook here:
// without it a renewed file would sit unserved until the api restarted.
func TestAPILeaf_RefreshPicksUpARenewedLeaf(t *testing.T) {
	dir := t.TempDir()
	ca, err := mesh.EnsureMeshCA(dir, "test")
	if err != nil {
		t.Fatalf("EnsureMeshCA: %v", err)
	}
	// Two leaves for the same address, distinguishable by NotAfter — "the
	// file the sweep replaced" and "what it replaced it with".
	hostname, _ := os.Hostname()
	ip := net.ParseIP("192.168.1.2")
	mintInto := func(lifetime time.Duration) mesh.LeafPaths {
		t.Helper()
		spec := apiLeafSpec(hostname, ip)
		spec.Lifetime = lifetime
		out := filepath.Join(dir, "tls", lifetime.String())
		paths, err := mesh.MintLeafToDisk(ca, out, spec)
		if err != nil {
			t.Fatalf("MintLeafToDisk: %v", err)
		}
		return paths
	}
	before := mintInto(200 * 24 * time.Hour)
	after := mintInto(400 * 24 * time.Hour)

	current := before
	leaf := &apiLeaf{mint: func(net.IP) (mesh.LeafPaths, error) { return current, nil }}
	if err := leaf.load(ip); err != nil {
		t.Fatalf("load: %v", err)
	}
	served := func() time.Time {
		t.Helper()
		c, err := leaf.getCertificate(&tls.ClientHelloInfo{})
		if err != nil {
			t.Fatal(err)
		}
		return c.Leaf.NotAfter
	}
	first := served()

	current = after
	if err := leaf.load(ip); err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := served(); !got.Equal(first) {
		t.Fatal("load must keep its same-address short-circuit")
	}
	if err := leaf.refresh(ip); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if got := served(); !got.After(first) {
		t.Errorf("refresh did not swap in the renewed leaf (NotAfter still %s)", first)
	}
	// And the address it is loaded for is still recorded, so a later address
	// change is still noticed.
	if leaf.ip != ipString(ip) {
		t.Errorf("leaf.ip = %q, want %q", leaf.ip, ipString(ip))
	}
}
