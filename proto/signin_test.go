package proto

import (
	"errors"
	"strings"
	"testing"
)

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

// TC-995-16 (proto half): the one copy of the cluster-id rule. 59 characters
// is the longest id, 60 is too long, and only the whole sso- prefix is
// reserved.
func TestCheckClusterID(t *testing.T) {
	if ClusterIDMaxLen != 59 {
		t.Fatalf("ClusterIDMaxLen = %d, want 59", ClusterIDMaxLen)
	}
	for id, want := range map[string]error{
		strings.Repeat("a", 59): nil,
		strings.Repeat("a", 60): ErrClusterIDTooLong,
		"sso-x":                 ErrClusterIDReservedPrefix,
		"sso-bench":             ErrClusterIDReservedPrefix,
		"ssobench":              nil,
		"sso":                   nil,
		"bench":                 nil,
		// Length first: an over-long sso- id is reported as too long.
		"sso-" + strings.Repeat("a", 56): ErrClusterIDTooLong,
	} {
		if got := CheckClusterID(id); !errors.Is(got, want) || (want == nil && got != nil) {
			t.Errorf("CheckClusterID(%q) = %v, want %v", id, got, want)
		}
	}
}
