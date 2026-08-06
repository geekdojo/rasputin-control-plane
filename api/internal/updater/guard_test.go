package updater

import "testing"

func TestIsLoopbackURL(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{"http://localhost:8080/api/bundles/abc", true},
		{"http://localhost/api/bundles/abc", true},
		{"http://127.0.0.1:8080/api/bundles/abc", true},
		{"http://127.9.9.9/api/bundles/abc", true}, // all of 127.0.0.0/8
		{"http://[::1]:8080/api/bundles/abc", true},
		{"https://rasputin.local/api/bundles/abc", false},
		{"https://rasputin.local:443/api/bundles/abc", false},
		{"https://192.168.1.20/api/bundles/abc", false},
		{"https://cp.example.ts.net/api/bundles/abc", false},
		{"", false},
		{"://not a url", false},
	}
	for _, c := range cases {
		if got := IsLoopbackURL(c.raw); got != c.want {
			t.Errorf("IsLoopbackURL(%q) = %v, want %v", c.raw, got, c.want)
		}
	}
}

func TestRemoteLoopbackBundleURL(t *testing.T) {
	const loopback = "http://localhost:8080/api/bundles/abc"
	const routable = "https://rasputin.local/api/bundles/abc"
	cases := []struct {
		name         string
		bundleURL    string
		selfNodeID   string
		targetNodeID string
		want         bool
	}{
		// Dev / not a provisioned appliance: the check is disabled entirely so a
		// single-box loopback setup keeps working.
		{"dev loopback allowed", loopback, "", "node-a", false},
		// The api's own co-located node can always use loopback (self-update, or
		// a single-box appliance).
		{"self node loopback allowed", loopback, "cp", "cp", false},
		// The actual bug: a remote node handed a loopback URL it can't reach.
		{"remote loopback refused", loopback, "cp", "node-a", true},
		// Correctly-derived URLs are fine for remote nodes.
		{"remote routable allowed", routable, "cp", "node-a", false},
	}
	for _, c := range cases {
		if got := remoteLoopbackBundleURL(c.bundleURL, c.selfNodeID, c.targetNodeID); got != c.want {
			t.Errorf("%s: remoteLoopbackBundleURL(%q, %q, %q) = %v, want %v",
				c.name, c.bundleURL, c.selfNodeID, c.targetNodeID, got, c.want)
		}
	}
}
