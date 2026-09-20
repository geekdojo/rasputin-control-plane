package main

import (
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Fail-closed table test for bmcConfigFromEnv, the resolver declared in
// .github/security-resolvers.tsv (gate 4, geekdojo/geekdojo-brain#491).
//
// TestBMCConfigFromEnvCoversEveryField already checks that every field is
// wired. This checks the other half: what each security-relevant field does
// when its variable is absent, empty or malformed. Two of them decide whether
// a BMC's certificate is checked at all, so "unrecognised" has to mean "check
// it", never "skip it".
func TestBMCConfigFromEnv_FailsClosedOnEveryShapeOfInput(t *testing.T) {
	t.Run("nothing set at all", func(t *testing.T) {
		t.Setenv("RASPUTIN_BMC_TURINGPI_INSECURE", "")
		t.Setenv("RASPUTIN_BMC_TURINGPI_FINGERPRINT", "")
		cfg := bmcConfigFromEnv(t.TempDir())
		if cfg.TuringPiInsecure {
			t.Fatal("TuringPiInsecure is true with nothing set — verification must be on by default")
		}
		if cfg.TuringPiFingerprint != "" {
			t.Fatalf("TuringPiFingerprint = %q with nothing set, want empty", cfg.TuringPiFingerprint)
		}
	})

	for _, tc := range []struct {
		name string
		env  string
		want bool
	}{
		{"empty", "", false},
		{"a word that is not a boolean", "maybe", false},
		{"the name of the variable", "RASPUTIN_BMC_TURINGPI_INSECURE", false},
		{"a near-miss spelling", "yes", false},
		{"a typo of true", "ture", false},
		{"a number that is not 0 or 1", "2", false},
		{"punctuation", "-", false},
		{"only whitespace", "   ", false},
		// The two that must still work, or the escape hatch is unusable and
		// someone reaches for a worse one.
		{"true", "true", true},
		{"1 with surrounding whitespace", " 1 ", true},
		{"TRUE in capitals", "TRUE", true},
	} {
		t.Run("TuringPiInsecure: "+tc.name, func(t *testing.T) {
			t.Setenv("RASPUTIN_BMC_TURINGPI_INSECURE", tc.env)
			if got := bmcConfigFromEnv(t.TempDir()).TuringPiInsecure; got != tc.want {
				t.Fatalf("TuringPiInsecure = %v for %q, want %v — an unrecognised value "+
					"must never be the one that switches verification off", got, tc.env, tc.want)
			}
		})
	}
}

// controlplanePinFile is a security resolver (.github/security-resolvers.tsv
// R23): it decides whether the last bus-pin source exists. This is its
// fail-closed table — every shape of input, and what must come back.
//
// The two directions it must never go: handing a path to a role that has no
// such file, and handing "" to a controlplane, which would drop the source and
// let a self-initialised controlplane fall back to dialing in the clear.
func TestControlplanePinFile_FailsClosedOnEveryShapeOfInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		role proto.NodeRole
		env  string
		set  bool
		want string
	}{
		// Absent, empty and blank all resolve to the appliance location for a
		// controlplane. None of them resolves to "".
		{"controlplane, variable absent", proto.RoleControlPlane, "", false, proto.BusAgentPinPath},
		{"controlplane, variable empty", proto.RoleControlPlane, "", true, proto.BusAgentPinPath},
		{"controlplane, variable blank", proto.RoleControlPlane, "   \t ", true, proto.BusAgentPinPath},
		{"controlplane, override", proto.RoleControlPlane, "/tmp/dev/bus/agent.pin", true, "/tmp/dev/bus/agent.pin"},
		{"controlplane, override with surrounding space", proto.RoleControlPlane, "  /tmp/dev/bus/agent.pin\n", true, "/tmp/dev/bus/agent.pin"},

		// No other role ever gets a path, however the variable is set. A
		// compute node must not be pointed at a file the api wrote for a
		// different machine.
		{"compute, variable absent", proto.RoleCompute, "", false, ""},
		{"compute, override set", proto.RoleCompute, "/tmp/dev/bus/agent.pin", true, ""},
		{"firewall, override set", proto.RoleFirewall, "/tmp/dev/bus/agent.pin", true, ""},
		{"storage, override set", proto.RoleStorage, "/tmp/dev/bus/agent.pin", true, ""},
		{"an unknown role, override set", proto.NodeRole("wat"), "/tmp/dev/bus/agent.pin", true, ""},
		{"an empty role, override set", proto.NodeRole(""), "/tmp/dev/bus/agent.pin", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv(EnvControlplanePinFile, tc.env)
			} else {
				t.Setenv(EnvControlplanePinFile, "")
			}
			if got := controlplanePinFile(tc.role); got != tc.want {
				t.Fatalf("controlplanePinFile(%q) = %q, want %q", tc.role, got, tc.want)
			}
		})
	}
}
