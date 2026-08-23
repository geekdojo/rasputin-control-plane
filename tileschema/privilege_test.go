package tileschema

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Every dimension the extractor captures, scored. The table IS the policy: if
// a line here changes, an owner's consent screen changes, so a reviewer should
// be able to read the whole mapping in one place rather than reconstruct it
// from branches in DerivePrivilege.
func TestDerivePrivilege_ScoresEveryDimension(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(*SafetyFacts)
		tier  string
		grant string // "" means: contributes no grant at all
	}{
		// --- host-trusting: effectively root on the node ---
		{"privileged", func(f *SafetyFacts) { f.Privileged = true }, TierHostTrusting, GrantPrivileged},
		{"seccomp unconfined", func(f *SafetyFacts) { f.SecurityOpt = []string{"seccomp=unconfined"} }, TierHostTrusting, GrantSeccompUnconfined},
		{"apparmor unconfined", func(f *SafetyFacts) { f.SecurityOpt = []string{"apparmor=unconfined"} }, TierHostTrusting, GrantApparmorDisabled},
		{"selinux disabled", func(f *SafetyFacts) { f.SecurityOpt = []string{"label=disable"} }, TierHostTrusting, GrantSELinuxDisabled},
		{"userns host", func(f *SafetyFacts) { f.UsernsMode = []string{"host"} }, TierHostTrusting, GrantUsernsHost},
		{"docker group", func(f *SafetyFacts) { f.GroupAdd = []string{"docker"} }, TierHostTrusting, GrantPrefixGroup + "docker"},
		{"disk group", func(f *SafetyFacts) { f.GroupAdd = []string{"disk"} }, TierHostTrusting, GrantPrefixGroup + "disk"},
		{"escape capability", func(f *SafetyFacts) { f.CapAdd = []string{"SYS_ADMIN"} }, TierHostTrusting, GrantPrefixCap + "SYS_ADMIN"},
		{"escape capability with CAP_ prefix", func(f *SafetyFacts) { f.CapAdd = []string{"CAP_SYS_MODULE"} }, TierHostTrusting, GrantPrefixCap + "SYS_MODULE"},
		{"root filesystem", func(f *SafetyFacts) { f.BindMounts = []string{"/"} }, TierHostTrusting, GrantPrefixBind + "/"},
		{"whole dev tree", func(f *SafetyFacts) { f.BindMounts = []string{"/dev"} }, TierHostTrusting, GrantPrefixBind + "/dev"},
		{"proc subpath", func(f *SafetyFacts) { f.BindMounts = []string{"/proc/1/root"} }, TierHostTrusting, GrantPrefixBind + "/proc/1/root"},
		{"cgroup tree", func(f *SafetyFacts) { f.BindMounts = []string{"/sys/fs/cgroup"} }, TierHostTrusting, GrantPrefixBind + "/sys/fs/cgroup"},
		{"host etc", func(f *SafetyFacts) { f.BindMounts = []string{"/etc/ssh"} }, TierHostTrusting, GrantPrefixBind + "/etc/ssh"},
		{"docker data root", func(f *SafetyFacts) { f.BindMounts = []string{"/var/lib/rasputin/docker"} }, TierHostTrusting, GrantDockerDataRoot},

		// --- elevated: reaches past itself, not root-equivalent ---
		{"host network", func(f *SafetyFacts) { f.HostNetwork = true }, TierElevated, GrantHostNetwork},
		{"host pid or ipc", func(f *SafetyFacts) { f.HostPIDOrIPC = true }, TierElevated, GrantHostPIDOrIPC},
		{"ordinary capability", func(f *SafetyFacts) { f.CapAdd = []string{"NET_ADMIN"} }, TierElevated, GrantPrefixCap + "NET_ADMIN"},
		{"usb dongle", func(f *SafetyFacts) { f.Devices = []string{"/dev/bus/usb/001/004"} }, TierElevated, GrantPrefixDevice + "/dev/bus/usb/001/004"},
		{"gpu reservation", func(f *SafetyFacts) { f.ReservedDevices = []string{"gpu x1"} }, TierElevated, GrantPrefixReservedDev + "gpu x1"},
		{"ordinary group", func(f *SafetyFacts) { f.GroupAdd = []string{"video"} }, TierElevated, GrantPrefixGroup + "video"},
		{"other security opt", func(f *SafetyFacts) { f.SecurityOpt = []string{"apparmor=custom"} }, TierElevated, GrantPrefixSecurityOpt + "apparmor=custom"},
		{"other userns", func(f *SafetyFacts) { f.UsernsMode = []string{"keep-id"} }, TierElevated, GrantPrefixUserns + "keep-id"},
		{"volumes from", func(f *SafetyFacts) { f.VolumesFrom = []string{"data"} }, TierElevated, GrantPrefixVolumesFrom + "data"},
		{"cgroup parent", func(f *SafetyFacts) { f.CgroupParent = []string{"/rasputin.slice"} }, TierElevated, GrantPrefixCgroupParent + "/rasputin.slice"},
		{"joins a container outside the stack", func(f *SafetyFacts) { f.NamespaceJoins = []string{"network:container:abc"} }, TierElevated, GrantPrefixNamespaceJoin + "network:container:abc"},
		{"extra host path", func(f *SafetyFacts) { f.BindMounts = []string{"/srv/media"} }, TierElevated, GrantPrefixBind + "/srv/media"},

		// --- routine: recorded by #195, but not authority ---
		{"app data", func(f *SafetyFacts) { f.BindMounts = []string{"/var/lib/rasputin/apps/kuma/data"} }, TierRoutine, ""},
		{"localtime", func(f *SafetyFacts) { f.BindMounts = []string{"/etc/localtime"} }, TierRoutine, ""},
		{"sysctls", func(f *SafetyFacts) { f.Sysctls = []string{"net.core.somaxconn=1024"} }, TierRoutine, ""},
		{"tmpfs", func(f *SafetyFacts) { f.Tmpfs = []string{"/tmp"} }, TierRoutine, ""},
		{"ulimits", func(f *SafetyFacts) { f.Ulimits = []string{"nofile=65535"} }, TierRoutine, ""},
		{"no-new-privileges is a restriction", func(f *SafetyFacts) { f.SecurityOpt = []string{"no-new-privileges=true"} }, TierRoutine, ""},
		{"vpn sidecar in the same stack", func(f *SafetyFacts) { f.NamespaceJoins = []string{"network:service:vpn"} }, TierRoutine, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := okFacts()
			tc.mut(&f)
			got := DerivePrivilege(f)
			if got.Tier != tc.tier {
				t.Fatalf("tier: got %q want %q (grants %v)", got.Tier, tc.tier, got.Grants)
			}
			if tc.grant == "" {
				if len(got.Grants) != 0 {
					t.Fatalf("expected no grant, got %v", got.Grants)
				}
				return
			}
			if !reflect.DeepEqual(got.Grants, []string{tc.grant}) {
				t.Fatalf("grants: got %v want [%s]", got.Grants, tc.grant)
			}
		})
	}
}

// The socket is named separately from the tier (Decision 12b) because it is not
// merely root-equivalent — it is the ability to escape any constraint added
// later, and the specific footgun of this hobby.
func TestDerivePrivilege_DockerSocketIsNamed(t *testing.T) {
	for _, sock := range DockerSocketPaths {
		f := okFacts()
		f.BindMounts = []string{sock}
		got := DerivePrivilege(f)
		if !got.DockerSocket {
			t.Errorf("%s: dockerSocket not set", sock)
		}
		if got.Tier != TierHostTrusting {
			t.Errorf("%s: tier %q, want host-trusting", sock, got.Tier)
		}
		if !reflect.DeepEqual(got.Grants, []string{GrantDockerSocket}) {
			t.Errorf("%s: grants %v, want [%s]", sock, got.Grants, GrantDockerSocket)
		}
	}
}

// A tile can mount the socket and still be refused for the declaration, and a
// tile can declare host-trusting and still be refused for not naming the
// socket. Both directions, because the socket flag is the one field a tier
// alone cannot carry.
func TestValidateTileSafety_DockerSocketMustBeDeclaredByName(t *testing.T) {
	f := okFacts()
	f.BindMounts = []string{"/var/run/docker.sock"}

	x := okTile()
	x.Privilege = Privilege{Tier: TierHostTrusting, Grants: []string{GrantDockerSocket}}
	x.Requires = []string{CapabilityPrivilegeTiers}
	err := ValidateTileSafety(x, f)
	if err == nil || !strings.Contains(err.Error(), "dockerSocket") {
		t.Fatalf("tier and grant declared but the socket flag missing must be refused, got %v", err)
	}

	x.Privilege.DockerSocket = true
	if err := ValidateTileSafety(x, f); err != nil {
		t.Fatalf("fully declared socket mount must be accepted, got %v", err)
	}
}

// The tier is a floor, not an equality. A publisher choosing to badge itself
// more loudly than its stack requires is not a cluster's problem — and
// forbidding it would mean a tile could not be conservative.
func TestValidateTileSafety_OverDeclarationIsAllowed(t *testing.T) {
	x, f := okTile(), okFacts()
	x.Privilege = Privilege{
		Tier:   TierHostTrusting,
		Grants: []string{GrantPrivileged, GrantHostNetwork},
		Why:    "we would rather over-warn",
	}
	x.Requires = []string{CapabilityPrivilegeTiers}
	if err := ValidateTileSafety(x, f); err != nil {
		t.Fatalf("a tile declaring more than it takes must be accepted, got %v", err)
	}
}

// Decision 12d. Without the capability an older control plane installs a
// privileged tile with no tier, no badge and no consent prompt — so the
// capability is not documentation, it is the refusal mechanism.
func TestValidateTileSafety_NonRoutineMustNameTheCapability(t *testing.T) {
	f := okFacts()
	f.HostNetwork = true
	x := okTile()
	x.Privilege = Privilege{Tier: TierElevated, Grants: []string{GrantHostNetwork}}

	err := ValidateTileSafety(x, f)
	if err == nil || !strings.Contains(err.Error(), CapabilityPrivilegeTiers) {
		t.Fatalf("elevated tile without the capability must be refused, got %v", err)
	}

	x.Requires = []string{CapabilityPrivilegeTiers}
	if err := ValidateTileSafety(x, f); err != nil {
		t.Fatalf("elevated tile naming the capability must be accepted, got %v", err)
	}
}

// A ROUTINE tile must NOT be forced to name it. Every tile in the field today
// is routine, and every cluster in the field today predates the capability —
// requiring it universally would refuse the entire live catalog in order to
// announce that the apps in it are ordinary.
func TestValidateTileSafety_RoutineNeedsNoCapability(t *testing.T) {
	x, f := okTile(), okFacts()
	f.BindMounts = []string{"/var/lib/rasputin/apps/kuma/data", "/etc/localtime"}
	f.Tmpfs = []string{"/tmp"}
	f.Sysctls = []string{"net.core.somaxconn=1024"}
	if len(x.Requires) != 0 {
		t.Fatal("fixture drift: okTile must declare no capabilities")
	}
	if err := ValidateTileSafety(x, f); err != nil {
		t.Fatalf("a routine tile must validate with no privilege declaration at all, got %v", err)
	}
}

// Decision 12e. Not risk-based: consent is only meaningful while the thing
// asking for it is still trustworthy, so the paths that authorise future
// updates are the one thing no tier can cover.
func TestTrustChainViolation(t *testing.T) {
	refused := []string{
		"/etc/rasputin",
		"/etc/rasputin/trust",
		"/etc/rasputin/trust/root-ca.pem",
		"/etc/rasputin/seed.env",
		"/var/lib/rasputin",
		"/var/lib/rasputin/trust",
		"/var/lib/rasputin/rasputin.db",
		"/var/lib/rasputin/bus",
		"/var/lib/rasputin/tls",
		"/var/lib/rasputin/mesh",
		"/var/lib/rasputin/bundles",
		"/var/lib/rasputin/agent-state",
		"/var/lib/rasputin/node.env",
		"/var/lib/rasputin/tailscale",
		"/var/lib/rasputin/dropbear",
		// Ancestors reach the roots just as completely as descendants do.
		// This is the half an enumeration of leaf files would have missed.
		"/",
		"/etc",
		"/var",
		"/var/lib",
		// Traversal is cleaned before the test.
		"/var/lib/rasputin/apps/../trust",
		// A lookalike sibling is not the carve-out.
		"/var/lib/rasputin/appsEVIL/x",
		// Unknowable is not the same as safe.
		"relative/path",
	}
	for _, p := range refused {
		if hit := TrustChainViolation(p); hit == "" {
			t.Errorf("%q must be refused as trust-chain reach", p)
		}
	}

	allowed := []string{
		"/var/lib/rasputin/apps",
		"/var/lib/rasputin/apps/kuma/data",
		// Declarable, not refused: Decision 12b makes the runtime consentable,
		// so its storage cannot be more protected than the API that writes it.
		"/var/lib/rasputin/docker",
		"/var/lib/rasputin/containerd",
		"/etc/localtime",
		"/srv/media",
		"/dev/bus/usb",
	}
	for _, p := range allowed {
		if hit := TrustChainViolation(p); hit != "" {
			t.Errorf("%q must not be a trust-chain violation, got %q", p, hit)
		}
	}
}

// THE ACID TEST. Home Assistant is must-carry (ACC-4) and #1 in the 2025
// favourites vote, and the validator refused it outright until Decision 12.
// Its upstream compose needs privileged, host networking, a USB radio and
// D-Bus — none of which touches the trust chain.
func TestValidateTileSafety_CarriesHomeAssistant(t *testing.T) {
	f := SafetyFacts{
		Images:      []string{"ghcr.io/home-assistant/home-assistant@" + goodDigest},
		Privileged:  true,
		HostNetwork: true,
		Devices:     []string{"/dev/ttyUSB0"},
		BindMounts:  []string{"/var/lib/rasputin/apps/home-assistant/config", "/etc/localtime", "/run/dbus"},
	}
	derived := DerivePrivilege(f)
	if derived.Tier != TierHostTrusting {
		t.Fatalf("tier: got %q want host-trusting", derived.Tier)
	}

	x := okTile()
	x.ID = "home-assistant"
	x.NeedsHardware = "zigbee or z-wave radio (optional)"
	x.Requires = []string{CapabilityPrivilegeTiers}
	x.Privilege = Privilege{
		Tier:   TierHostTrusting,
		Grants: derived.Grants,
		Why:    "discovers and controls devices on your network, and talks to USB radios",
	}
	if err := ValidateTileSafety(x, f); err != nil {
		t.Fatalf("Home Assistant must be carryable once declared, got %v", err)
	}
}

// Grants are sorted, and the whole derivation is a pure function of the facts.
// The store re-derives from the SAME persisted bytes on every boot, so an
// order that depended on map iteration would change a cluster's badges across
// a restart with nothing having been published.
func TestDerivePrivilege_IsDeterministic(t *testing.T) {
	f := okFacts()
	f.HostNetwork = true
	f.CapAdd = []string{"NET_ADMIN", "SYS_TIME"}
	f.BindMounts = []string{"/srv/b", "/srv/a", "/var/run/docker.sock"}
	f.GroupAdd = []string{"video"}

	first := DerivePrivilege(f)
	if !sort.StringsAreSorted(first.Grants) {
		t.Fatalf("grants not sorted: %v", first.Grants)
	}
	for i := 0; i < 50; i++ {
		if !reflect.DeepEqual(DerivePrivilege(f), first) {
			t.Fatalf("derivation is not stable across runs")
		}
	}
}

// A tier string outside the vocabulary is caught on the AUTHORED metadata, so
// a typo in a preview tile — which never reaches the safety validator — still
// fails at publish rather than on the day it flips to available.
func TestValidateTile_RejectsAnUnknownTier(t *testing.T) {
	for _, status := range []string{StatusAvailable, StatusPreview} {
		x := okTile()
		x.Status = status
		if status == StatusPreview {
			x.ComposeYAML = ""
			x.Ports = nil
		}
		x.Privilege = Privilege{Tier: "root"}
		if err := ValidateTile(x); err == nil {
			t.Errorf("status %q: unknown tier must be refused", status)
		}
	}
}
