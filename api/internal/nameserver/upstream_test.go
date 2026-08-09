package nameserver

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveUpstream_ConfiguredVerbatim(t *testing.T) {
	self := net.IPv4(192, 168, 1, 1)
	if u := ResolveUpstream("8.8.8.8", self, []net.IP{net.IPv4(192, 168, 1, 254)}); u.Addr != "8.8.8.8:53" || u.FellBack {
		t.Errorf("configured bare ip should get :53, no fallback; got %+v", u)
	}
	if u := ResolveUpstream("8.8.8.8:5353", self, nil); u.Addr != "8.8.8.8:5353" || u.FellBack {
		t.Errorf("configured ip:port should be verbatim; got %+v", u)
	}
}

func TestResolveUpstream_InheritsFirstSafe(t *testing.T) {
	self := net.IPv4(192, 168, 1, 1)
	// self and loopback are skipped; the first safe candidate is inherited.
	cands := []net.IP{self, net.IPv4(127, 0, 0, 53), net.IPv4(192, 168, 1, 254), net.IPv4(9, 9, 9, 9)}
	if u := ResolveUpstream("", self, cands); u.Addr != "192.168.1.254:53" || u.FellBack {
		t.Errorf("should inherit first non-self non-loopback; got %+v", u)
	}
}

func TestResolveUpstream_FallsBackToPublic(t *testing.T) {
	self := net.IPv4(192, 168, 1, 1)
	if u := ResolveUpstream("", self, []net.IP{self, net.IPv4(127, 0, 0, 53)}); u.Addr != DefaultPublicUpstream || !u.FellBack {
		t.Errorf("only self/loopback → public fallback + FellBack; got %+v", u)
	}
	if u := ResolveUpstream("", self, nil); u.Addr != DefaultPublicUpstream || !u.FellBack {
		t.Errorf("no candidates → public fallback; got %+v", u)
	}
}

func TestSystemUpstreams_ParsesLeasesThenResolvConf(t *testing.T) {
	dir := t.TempDir()
	leaseDir := filepath.Join(dir, "leases")
	if err := os.MkdirAll(leaseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(path, content string) {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Lease "2" lists two DNS on one line; "3" repeats one (deduped).
	write(filepath.Join(leaseDir, "2"), "ADDRESS=192.168.1.5\nDNS=192.168.1.1 192.168.1.2\n")
	write(filepath.Join(leaseDir, "3"), "DNS=192.168.1.1\n")
	resolv := filepath.Join(dir, "resolv.conf")
	write(resolv, "# comment\nnameserver 127.0.0.53\nnameserver 9.9.9.9\n")

	got := SystemUpstreams(resolv, leaseDir)
	want := []string{"192.168.1.1", "192.168.1.2", "127.0.0.53", "9.9.9.9"} // leases first, deduped, resolv.conf after
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("[%d] got %s want %s", i, got[i], want[i])
		}
	}
}

func TestSystemUpstreams_MissingSourcesAreEmpty(t *testing.T) {
	if got := SystemUpstreams("/nonexistent/resolv.conf", "/nonexistent/leases"); len(got) != 0 {
		t.Errorf("missing sources should yield no candidates, got %v", got)
	}
}
