package nameserver

import (
	"net"
	"strings"
	"testing"
)

func ip(s string) net.IP { return net.ParseIP(s) }

func TestClusterSource_Projection(t *testing.T) {
	nodes := []NodeAddr{
		{ID: "cp", Hostname: "home1-cp", IP: ip("192.168.1.2")},
		{ID: "n2", Hostname: "home1-compute1.home1.local", IP: ip("192.168.1.3")}, // dotted → first label
		{ID: "n3", Hostname: "pending", IP: nil},                                  // no LAN IP yet
		{ID: "n4", Hostname: "BAD_HOST", IP: ip("192.168.1.5")},                   // invalid label, valid IP
	}
	apps := []AppRec{
		{Name: "jellyfin", TargetNode: "cp"},  // → cp's IP
		{Name: "plex", TargetNode: "n4"},      // node record skipped, but app joins on id → n4's IP
		{Name: "radarr", TargetNode: "n3"},    // target has no IP → skipped
		{Name: "sonarr", TargetNode: "ghost"}, // unknown target → skipped
		{Name: "my_app", TargetNode: "cp"},    // grandfathered invalid label → skipped
	}
	src := NewClusterSource(testZone,
		func() []NodeAddr { return nodes },
		func() []AppRec { return apps })

	got := src.Records()

	want := map[string]string{
		"home1-cp.home1.internal.":       "192.168.1.2", // node record
		"home1-compute1.home1.internal.": "192.168.1.3", // dotted hostname → first label
		"jellyfin.home1.internal.":       "192.168.1.2", // app on cp
		"plex.home1.internal.":           "192.168.1.5", // app joins by node id despite bad hostname
	}
	if len(got) != len(want) {
		t.Fatalf("got %d records %v, want %d %v", len(got), keys(got), len(want), want)
	}
	for name, wantIP := range want {
		g, ok := got[name]
		if !ok {
			t.Errorf("missing record %s", name)
			continue
		}
		if !g.Equal(ip(wantIP)) {
			t.Errorf("%s = %v, want %s", name, g, wantIP)
		}
	}

	// Explicit negatives — these must NOT be present.
	for _, absent := range []string{
		"pending.home1.internal.",  // node with no IP
		"bad_host.home1.internal.", // invalid hostname label
		"radarr.home1.internal.",   // app target has no IP
		"sonarr.home1.internal.",   // app target unknown
		"my_app.home1.internal.",   // grandfathered invalid app name
	} {
		if _, ok := got[absent]; ok {
			t.Errorf("record %s should be absent", absent)
		}
	}
}

func TestClusterSource_EmptyProviders(t *testing.T) {
	src := NewClusterSource(testZone,
		func() []NodeAddr { return nil },
		func() []AppRec { return nil })
	if got := src.Records(); len(got) != 0 {
		t.Errorf("empty providers should yield no records, got %v", keys(got))
	}
}

func TestHostLabel(t *testing.T) {
	cases := map[string]string{
		"home1-cp":              "home1-cp",
		"HOME1-CP":              "home1-cp",              // lowercased
		"host.home1.internal":   "host",                  // first label only
		"  home1-cp  ":          "home1-cp",              // trimmed
		"a":                     "a",                     // single char is a valid label (len==1 boundary)
		"bad_host":              "",                      // underscore invalid
		"-lead":                 "",                      // leading hyphen invalid
		"app-":                  "",                      // trailing hyphen invalid (len-1 boundary)
		"a-":                    "",                      // trailing hyphen, minimal
		"":                      "",                      // empty (len<1 boundary)
		strings.Repeat("a", 63): strings.Repeat("a", 63), // 63 chars is the max valid label
		strings.Repeat("a", 64): "",                      // 64 chars exceeds the label cap
	}
	for in, want := range cases {
		if got := hostLabel(in); got != want {
			t.Errorf("hostLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func keys(m map[string]net.IP) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
