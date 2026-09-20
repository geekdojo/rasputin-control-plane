package main

import (
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/bmc"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// bmcNewForTest builds the turingpi backend the way main does, so this test
// asks the real constructor whether a pin is usable.
func bmcNewForTest(cfg bmc.Config) (bmc.Backend, error) { return bmc.New("turingpi", cfg) }

// Fail-closed table test for bmcConfigFromEnv, the resolver declared in
// .github/security-resolvers.tsv (gate 4, geekdojo/geekdojo-brain#491).
//
// TestBMCConfigFromEnvCoversEveryField already checks that every field is
// wired. This checks the other half: what the security-relevant input does
// when it is absent, empty or malformed. It decides whether the agent talks
// to a BMC at all, so "unrecognised" has to mean "do not talk to it", never
// "talk to it unpinned".
//
// It used to be a table over RASPUTIN_BMC_TURINGPI_INSECURE, asserting that
// no spelling of a boolean but the intended ones could switch verification
// off. That variable is gone (geekdojo/geekdojo-brain#548): there is no
// unpinned mode to switch on, so the question this test asks instead is
// whether an env selection is REFUSED when it cannot be trusted.
func TestBMCConfigFromEnv_FailsClosedOnEveryShapeOfInput(t *testing.T) {
	const goodPin = "sha256/epr81hmPYzpdyR6LUQ2gb+spADtZSHpXfIQ5fF+AHqs="

	t.Run("nothing set at all", func(t *testing.T) {
		cfg := bmcConfigFromEnv(t.TempDir())
		if cfg.TuringPiPin != "" {
			t.Fatalf("TuringPiPin = %q with nothing set, want empty", cfg.TuringPiPin)
		}
		if reason := retiredBMCEnvInUse("turingpi", bmcConfigFromEnv(t.TempDir()).TuringPiPin); reason == "" {
			t.Fatal("a turingpi selection with no pin must be refused — there is no unpinned mode")
		}
	})

	// Every shape of pin that is not a pin must refuse the selection. The
	// backend refuses to construct on each of these too; this is the earlier
	// gate, which is what keeps the agent up and the node reachable.
	for _, tc := range []struct{ name, pin string }{
		{"empty", ""},
		{"only whitespace", "   "},
		{"the name of the variable", "RASPUTIN_BMC_TURINGPI_PIN"},
		{"a cert-DER fingerprint, the retired form", "41:7C:1E:EA:B9:42:7F:10:33:63:4C:7A:F2:D2:DD:F1:E8:75:8A:92:26:CE:1F:63:3F:E1:FF:D5:11:0F:B9:E1"},
		{"the right length, wrong prefix", "sha512/epr81hmPYzpdyR6LUQ2gb+spADtZSHpXfIQ5fF+AHqs="},
		{"the digest with no prefix", "epr81hmPYzpdyR6LUQ2gb+spADtZSHpXfIQ5fF+AHqs="},
		{"not base64", "sha256/................................this-is-not-base64"},
		{"truncated", "sha256/epr81hmPYzpdyR6LUQ2gb+spADtZSHpXfIQ5fF+AHq"},
	} {
		t.Run("pin: "+tc.name, func(t *testing.T) {
			t.Setenv("RASPUTIN_BMC_TURINGPI_PIN", tc.pin)
			if strings.TrimSpace(tc.pin) == "" {
				if reason := retiredBMCEnvInUse("turingpi", bmcConfigFromEnv(t.TempDir()).TuringPiPin); reason == "" {
					t.Fatal("an empty pin must refuse the selection before anything is constructed")
				}
				return
			}
			// A non-empty but unusable pin passes the env gate and is refused
			// one layer down, at construction, where the parse happens. Either
			// way no client is built: what must never happen is a client built
			// WITHOUT a checked pin.
			cfg := bmcConfigFromEnv(t.TempDir())
			cfg.TuringPiEndpoint = "turingpi.local"
			cfg.TuringPiUser = "root"
			cfg.TuringPiMap = "tp-cp1:1"
			if _, err := bmcNewForTest(cfg); err == nil {
				t.Fatalf("a turingpi backend was built with pin %q — an unreadable pin must refuse", tc.pin)
			}
		})
	}

	t.Run("a real pin is honoured", func(t *testing.T) {
		t.Setenv("RASPUTIN_BMC_TURINGPI_PIN", goodPin)
		if got := bmcConfigFromEnv(t.TempDir()).TuringPiPin; got != goodPin {
			t.Fatalf("TuringPiPin = %q, want the pin that was set", got)
		}
		if reason := retiredBMCEnvInUse("turingpi", bmcConfigFromEnv(t.TempDir()).TuringPiPin); reason != "" {
			t.Fatalf("a pinned selection must be honoured; got %q", reason)
		}
	})

	// A retired variable refuses the selection even alongside a good pin: the
	// operator's configuration says something this agent no longer does, and
	// guessing which half they meant is how a box ends up trusting the wrong
	// thing quietly.
	for _, key := range retiredBMCEnv {
		t.Run("retired: "+key, func(t *testing.T) {
			t.Setenv("RASPUTIN_BMC_TURINGPI_PIN", goodPin)
			t.Setenv(key, "true")
			reason := retiredBMCEnvInUse("turingpi", bmcConfigFromEnv(t.TempDir()).TuringPiPin)
			if reason == "" {
				t.Fatalf("%s is set; the selection must be refused", key)
			}
			if !strings.Contains(reason, key) {
				t.Errorf("the refusal must name the variable to fix; got %q", reason)
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
