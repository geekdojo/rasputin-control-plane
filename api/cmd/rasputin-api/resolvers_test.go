package main

import (
	"os"
	"slices"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
)

// setOrUnset sets key to value, or makes it absent when absent is true. It is
// restored after the test either way.
func setOrUnset(t *testing.T, key string, absent bool, value string) {
	t.Helper()
	t.Setenv(key, value)
	if absent {
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("unset %s: %v", key, err)
		}
	}
}

// blankShapes are the inputs every path resolver must treat as "not set".
var blankShapes = []struct {
	name   string
	absent bool
	value  string
}{
	{"absent", true, ""},
	{"empty", false, ""},
	{"blank", false, "   "},
}

// pathResolverCase runs the shared table for a trim-or-default path resolver:
// every blank shape gives def, never "", and a set value is trimmed and used.
func pathResolverCase(t *testing.T, env, def string, resolve func() string) {
	t.Helper()
	for _, b := range blankShapes {
		t.Run(b.name, func(t *testing.T) {
			setOrUnset(t, env, b.absent, b.value)
			got := resolve()
			if got != def {
				t.Errorf("%s %s: got %q, want %q", env, b.name, got, def)
			}
			if got == "" {
				t.Errorf("%s %s: resolved to an empty path", env, b.name)
			}
		})
	}
	for _, tc := range []struct{ name, value, want string }{
		{"padded", "  /x  ", "/x"},
		{"set", "/x", "/x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(env, tc.value)
			if got := resolve(); got != tc.want {
				t.Errorf("%s=%q: got %q, want %q", env, tc.value, got, tc.want)
			}
		})
	}
}

// TC-591-12: fail-closed table test for trustDirFromEnv (security-resolvers R35).
func TestTrustDirFromEnv_FailsClosedOnEveryShapeOfInput(t *testing.T) {
	pathResolverCase(t, "RASPUTIN_TRUST_DIR", "/d/trust", func() string { return trustDirFromEnv("/d") })
}

// TC-591-13: fail-closed table test for cpAuthorizedKeysFromEnv
// (security-resolvers R36).
func TestCPAuthorizedKeysFromEnv_FailsClosedOnEveryShapeOfInput(t *testing.T) {
	pathResolverCase(t, "RASPUTIN_CP_AUTHORIZED_KEYS", "/var/lib/rasputin/dropbear/authorized_keys", cpAuthorizedKeysFromEnv)
}

// Fail-closed table test for rpIDFromEnv (security-resolvers R37). The resolver
// supplies the derived default for a blank value; a malformed value is refused
// by the real auth.NewService, one layer down.
func TestRPIDFromEnv_FailsClosedOnEveryShapeOfInput(t *testing.T) {
	const env = "RASPUTIN_RP_ID"

	// TC-591-14: absent or blank gives the derived default.
	for _, cluster := range []struct {
		name   string
		absent bool
		id     string
		want   string
	}{
		{"dev", true, "", "localhost"},
		{"appliance", false, "c1", "c1.local"},
	} {
		for _, b := range blankShapes {
			t.Run("TC-591-14 "+cluster.name+" "+b.name, func(t *testing.T) {
				setOrUnset(t, "RASPUTIN_CLUSTER_ID", cluster.absent, cluster.id)
				setOrUnset(t, env, b.absent, b.value)
				if got := rpIDFromEnv(); got != cluster.want {
					t.Errorf("%s %s with cluster %q: got %q, want %q", env, b.name, cluster.id, got, cluster.want)
				}
			})
		}
	}
	t.Run("TC-591-14 set", func(t *testing.T) {
		t.Setenv("RASPUTIN_CLUSTER_ID", "c1")
		t.Setenv(env, "x.local")
		if got := rpIDFromEnv(); got != "x.local" {
			t.Errorf("%s=x.local: got %q", env, got)
		}
	})

	// TC-591-15: a malformed RP ID reaches auth.NewService, which refuses it.
	for _, v := range []string{"https://x.local", "x.local:443", "x.local/", "192.168.1.1"} {
		t.Run("TC-591-15 malformed "+v, func(t *testing.T) {
			t.Setenv(env, v)
			svc, err := auth.NewService(nil, auth.Config{RPID: rpIDFromEnv(), RPOrigins: []string{"https://x.local"}})
			if err == nil {
				t.Errorf("%s=%q: auth.NewService accepted it", env, v)
			}
			if svc != nil {
				t.Errorf("%s=%q: auth.NewService returned a service", env, v)
			}
		})
	}
	// The same call with a well-formed RP ID succeeds, so the refusals above
	// are the RP ID's and not the fixture's.
	t.Run("TC-591-15 well-formed control", func(t *testing.T) {
		t.Setenv(env, "x.local")
		if _, err := auth.NewService(nil, auth.Config{RPID: rpIDFromEnv(), RPOrigins: []string{"https://x.local"}}); err != nil {
			t.Fatalf("well-formed RP ID refused: %v", err)
		}
	})
}

// Fail-closed table test for rpOriginsFromEnv (security-resolvers R38).
func TestRPOriginsFromEnv_FailsClosedOnEveryShapeOfInput(t *testing.T) {
	const env = "RASPUTIN_RP_ORIGINS"

	// TC-591-16: an input that yields no origin gives the derived origins,
	// never an empty list, so auth.NewService's localhost fallback is never
	// reached on an appliance.
	shapes := append(slices.Clone(blankShapes), []struct {
		name   string
		absent bool
		value  string
	}{{"comma", false, ","}, {"padded comma", false, " , "}}...)
	for _, cluster := range []struct {
		name   string
		absent bool
		id     string
		want   []string
	}{
		{"dev", true, "", []string{"http://localhost:3000", "http://localhost:8080"}},
		{"appliance", false, "c1", []string{"https://c1.local"}},
	} {
		for _, s := range shapes {
			t.Run("TC-591-16 "+cluster.name+" "+s.name, func(t *testing.T) {
				setOrUnset(t, "RASPUTIN_CLUSTER_ID", cluster.absent, cluster.id)
				setOrUnset(t, env, s.absent, s.value)
				got := rpOriginsFromEnv()
				if !slices.Equal(got, cluster.want) {
					t.Errorf("%s %s with cluster %q: got %q, want %q", env, s.name, cluster.id, got, cluster.want)
				}
				if len(got) == 0 {
					t.Errorf("%s %s: resolved to no origins", env, s.name)
				}
			})
		}
	}
	t.Run("TC-591-16 set", func(t *testing.T) {
		t.Setenv("RASPUTIN_CLUSTER_ID", "c1")
		t.Setenv(env, "https://a.local,https://b.local")
		want := []string{"https://a.local", "https://b.local"}
		if got := rpOriginsFromEnv(); !slices.Equal(got, want) {
			t.Errorf("%s set: got %q, want %q", env, got, want)
		}
	})

	// TC-591-17: a malformed origin reaches auth.NewService, which refuses it.
	// The case text pairs the origins with RPID "x", which go-webauthn refuses
	// by itself (not a domain), so every row also runs against the well-formed
	// RPID "x.local": there the refusal can only be the origin's.
	for _, v := range []string{"rasputin.local", "ftp://x", "https://x/path", "null"} {
		for _, rpID := range []string{"x", "x.local"} {
			t.Run("TC-591-17 malformed "+v+" rp-id "+rpID, func(t *testing.T) {
				t.Setenv(env, v)
				if _, err := auth.NewService(nil, auth.Config{RPID: rpID, RPOrigins: rpOriginsFromEnv()}); err == nil {
					t.Errorf("%s=%q with RPID %q: auth.NewService accepted it", env, v, rpID)
				}
			})
		}
	}
	// A well-formed origin with the well-formed RPID succeeds, so the
	// "x.local" refusals above are the origins' and not the fixture's.
	t.Run("TC-591-17 well-formed control", func(t *testing.T) {
		t.Setenv(env, "https://x.local")
		if _, err := auth.NewService(nil, auth.Config{RPID: "x.local", RPOrigins: rpOriginsFromEnv()}); err != nil {
			t.Fatalf("well-formed origin refused: %v", err)
		}
	})
}
