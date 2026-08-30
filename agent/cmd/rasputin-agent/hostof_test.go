package main

import "testing"

// hostOf feeds clusterdns its control-plane address. Returning "" means "we do
// not know where the control plane is", which withdraws the DNS pin — correct,
// but silent, so the parsing that decides it is worth pinning down.
func TestHostOf(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
	}{
		{"ipv4 host:port", "192.168.1.183:4222", "192.168.1.183"},
		{"ipv6 host:port", "[fd7a:115c:a1e0::1]:4222", "fd7a:115c:a1e0::1"},
		{"empty", "", ""},
		{"no port", "192.168.1.183", ""},
		{"garbage", "not-a-host-port", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hostOf(tc.in); got != tc.want {
				t.Errorf("hostOf(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
