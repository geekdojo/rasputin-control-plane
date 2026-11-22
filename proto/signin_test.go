package proto

import "testing"

// TC-983-18: BaseDomain replaces three copies with no byte change. The golden
// strings are the outputs of the copies it replaced, for the same inputs.
func TestBaseDomain_GoldenStrings(t *testing.T) {
	for in, want := range map[string]string{
		"":        "rasputin.internal",
		"bench":   "bench.internal",
		" bench ": "bench.internal",
	} {
		if got := BaseDomain(in); got != want {
			t.Errorf("BaseDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

// TC-983-01 (proto half): the door names are built from the constants, and the
// reserved check matches exactly the app door's first label and radius.
func TestSignInNames(t *testing.T) {
	if got := SignInFQDN("bench"); got != "signin.bench.internal" {
		t.Errorf("SignInFQDN = %q", got)
	}
	if got := SignInHomeFQDN("bench"); got != "sso-bench.local" {
		t.Errorf("SignInHomeFQDN = %q", got)
	}
	for _, s := range []string{"signin", "radius"} {
		if !IsReservedLabel(s) {
			t.Errorf("IsReservedLabel(%q) = false", s)
		}
	}
	for _, s := range []string{"", "signin2", "my-signin", "SIGNIN", "sso-bench", "radius1"} {
		if IsReservedLabel(s) {
			t.Errorf("IsReservedLabel(%q) = true", s)
		}
	}
}
