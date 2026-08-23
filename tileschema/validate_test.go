package tileschema

import (
	"encoding/json"
	"strings"
	"testing"
)

const goodDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func okTile() Tile {
	return Tile{
		ID: "uptime-kuma", Name: "Uptime Kuma", Tagline: "Watch your things",
		Collection: CollectionEssentials, Arch: "both", ExposureDefault: "lan-only",
		RAMFloorMB: 512, ComposeYAML: "services: {}",
		Ports: []Port{{Name: "web", Container: 3001, Published: 3001, Primary: true}},
	}
}

func okFacts() SafetyFacts {
	return SafetyFacts{Images: []string{"docker.io/louislam/uptime-kuma@" + goodDigest}}
}

func TestValidateTile_AcceptsAShippedShape(t *testing.T) {
	if err := ValidateTile(okTile()); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestValidateTile_Rejects(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Tile)
	}{
		{"empty id", func(x *Tile) { x.ID = "" }},
		{"uppercase id", func(x *Tile) { x.ID = "Uptime" }},
		{"leading hyphen id", func(x *Tile) { x.ID = "-kuma" }},
		{"trailing hyphen id", func(x *Tile) { x.ID = "kuma-" }},
		{"underscore id", func(x *Tile) { x.ID = "up_time" }},
		{"no name", func(x *Tile) { x.Name = " " }},
		{"no tagline", func(x *Tile) { x.Tagline = "" }},
		{"bad collection", func(x *Tile) { x.Collection = "misc" }},
		{"bad arch", func(x *Tile) { x.Arch = "riscv" }},
		{"bad placement", func(x *Tile) { x.PlacementHint = "prefer-pi" }},
		{"bad exposure", func(x *Tile) { x.ExposureDefault = "internet" }},
		{"bad category", func(x *Tile) { x.Category = "misc" }},
		{"bad status", func(x *Tile) { x.Status = "soon" }},
		{"zero ram floor", func(x *Tile) { x.RAMFloorMB = 0 }},
		{"container port high", func(x *Tile) { x.Ports[0].Container = 70000 }},
		{"published port zero", func(x *Tile) { x.Ports[0].Published = 0 }},
		{"bad protocol", func(x *Tile) { x.Ports[0].Protocol = "sctp" }},
		{"available with empty compose", func(x *Tile) { x.ComposeYAML = "  " }},
		{"two primaries", func(x *Tile) {
			x.Ports = append(x.Ports, Port{Name: "b", Container: 2, Published: 2, Primary: true})
		}},
		{"zero primaries", func(x *Tile) { x.Ports[0].Primary = false }},
		{"public with no primary", func(x *Tile) {
			x.ExposureDefault = "public"
			x.Ports = nil
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x := okTile()
			tc.mut(&x)
			if err := ValidateTile(x); err == nil {
				t.Fatalf("expected rejection for %s", tc.name)
			}
		})
	}
}

func TestValidateTile_PreviewIsExemptFromComposeAndPorts(t *testing.T) {
	x := okTile()
	x.Status = StatusPreview
	x.ComposeYAML = ""
	x.Ports = nil
	if err := ValidateTile(x); err != nil {
		t.Fatalf("preview tile should validate without compose or ports, got %v", err)
	}
}

func TestValidateTileSafety_AcceptsACleanStack(t *testing.T) {
	if err := ValidateTileSafety(okTile(), okFacts()); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

// want is a substring of the expected error. It exists because Decision 12
// turned several of these from "not permitted" into "not declared" — the same
// verdict for a different reason — and a table that only asserts "some error"
// would have gone on passing while the rule underneath it changed meaning.
func TestValidateTileSafety_Rejects(t *testing.T) {
	cases := []struct {
		name string
		want string
		mut  func(*Tile, *SafetyFacts)
	}{
		{"no images", "", func(_ *Tile, f *SafetyFacts) { f.Images = nil }},
		{"tag not digest", "", func(_ *Tile, f *SafetyFacts) { f.Images = []string{"nginx:1.27"} }},
		{"latest", "", func(_ *Tile, f *SafetyFacts) { f.Images = []string{"nginx:latest"} }},
		{"bare name", "", func(_ *Tile, f *SafetyFacts) { f.Images = []string{"nginx"} }},
		{"md5 digest", "", func(_ *Tile, f *SafetyFacts) { f.Images = []string{"nginx@md5:abc"} }},
		{"short sha", "", func(_ *Tile, f *SafetyFacts) { f.Images = []string{"nginx@sha256:abc"} }},
		{"non-hex sha", "", func(_ *Tile, f *SafetyFacts) {
			f.Images = []string{"nginx@sha256:zzzz56789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"}
		}},
		{"digest with no name", "", func(_ *Tile, f *SafetyFacts) { f.Images = []string{"@" + goodDigest} }},
		{"undeclared privileged", `takes "host-trusting" (privileged)`, func(_ *Tile, f *SafetyFacts) { f.Privileged = true }},
		{"undeclared host network", `takes "elevated" (host-network)`, func(_ *Tile, f *SafetyFacts) { f.HostNetwork = true }},
		{"undeclared host pid or ipc", `takes "elevated" (host-pid-ipc)`, func(_ *Tile, f *SafetyFacts) { f.HostPIDOrIPC = true }},
		{"undeclared cap add", `takes "elevated" (cap:NET_ADMIN)`, func(_ *Tile, f *SafetyFacts) { f.CapAdd = []string{"NET_ADMIN"} }},
		{"undeclared bind outside roots", `takes "host-trusting" (bind:/etc/shadow)`, func(_ *Tile, f *SafetyFacts) { f.BindMounts = []string{"/etc/shadow"} }},
		// Cleaned before classification, so the traversal is scored on where
		// it LANDS. Three levels up from the app root is /var, not /, which is
		// why the want here is /var/etc/shadow and not what the string reads
		// like at a glance.
		{"bind traversal out of the app root", "bind:/var/etc/shadow", func(_ *Tile, f *SafetyFacts) {
			f.BindMounts = []string{"/var/lib/rasputin/apps/../../../etc/shadow"}
		}},
		// The traversal that matters: out of the app root and sideways into
		// the trust store, which is Decision 12e's absolute refusal and not a
		// tier at all.
		{"bind traversal into the trust store", "trust chain", func(_ *Tile, f *SafetyFacts) {
			f.BindMounts = []string{"/var/lib/rasputin/apps/../trust"}
		}},
		{"bind relative", "not an absolute path", func(_ *Tile, f *SafetyFacts) { f.BindMounts = []string{"data"} }},
		{"bind prefix lookalike", "trust chain", func(_ *Tile, f *SafetyFacts) {
			f.BindMounts = []string{"/var/lib/rasputin/appsEVIL/x"}
		}},
		// Declared as elevated, so the ONLY thing left to fail is the
		// needsHardware pairing — otherwise this would pass on the privilege
		// check and stop testing what it names.
		{"devices without needsHardware", "declares no needsHardware", func(x *Tile, f *SafetyFacts) {
			f.Devices = []string{"/dev/bus/usb/001/004"}
			x.Privilege = Privilege{Tier: TierElevated, Grants: []string{"device:/dev/bus/usb/001/004"}}
			x.Requires = []string{CapabilityPrivilegeTiers}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x, f := okTile(), okFacts()
			tc.mut(&x, &f)
			err := ValidateTileSafety(x, f)
			if err == nil {
				t.Fatalf("expected rejection for %s", tc.name)
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%s: rejected for the wrong reason\n got: %v\nwant substring: %q", tc.name, err, tc.want)
			}
		})
	}
}

func TestValidateTileSafety_AllowsDeclaredHardwareAndAllowedMounts(t *testing.T) {
	x, f := okTile(), okFacts()
	x.NeedsHardware = "rtl-sdr"
	f.Devices = []string{"/dev/bus/usb/001/004"}
	f.BindMounts = []string{"/var/lib/rasputin/apps/uptime-kuma/data", "/etc/localtime"}
	// The two routine bind roots contribute NO grant — that is the line
	// between routine and elevated, and a tile keeping to it stays routine.
	// The USB device does, so this tile is elevated and names the capability.
	x.Privilege = Privilege{
		Tier:   TierElevated,
		Grants: []string{"device:/dev/bus/usb/001/004"},
		Why:    "talks to an RTL-SDR dongle",
	}
	x.Requires = []string{CapabilityPrivilegeTiers}
	if err := ValidateTileSafety(x, f); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

// The must-understand rule is the one that protects clusters older than the
// tile they are handed, so it is asserted in both directions.
func TestValidateTileSafety_KnownCapabilityIsAccepted(t *testing.T) {
	KnownCapabilities["test-cap"] = true
	defer delete(KnownCapabilities, "test-cap")

	x, f := okTile(), okFacts()
	x.Requires = []string{"test-cap"}
	if err := ValidateTileSafety(x, f); err != nil {
		t.Fatalf("a known capability must be accepted, got %v", err)
	}
}

func TestValidDNSLabel(t *testing.T) {
	for _, s := range []string{"a", "pi-hole", "a1", "x-y-z"} {
		if !ValidDNSLabel(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	long := make([]byte, 64)
	for i := range long {
		long[i] = 'a'
	}
	for _, s := range []string{"", "-a", "a-", "A", "a_b", "a.b", string(long)} {
		if ValidDNSLabel(s) {
			t.Errorf("%q should be invalid", s)
		}
	}
}

// --- #195: the privilege facts the extractor was blind to. ---

// The SafetyFacts JSON keys are a signed-bundle contract: a publisher writes
// them and a control plane of a different vintage reads them. Renaming one
// silently drops a privilege fact on the floor at the reader, which is the
// exact failure #195 exists to end. Pin the wire names.
func TestSafetyFacts_PrivilegeJSONKeysArePinned(t *testing.T) {
	f := SafetyFacts{
		Images:          []string{"img@" + goodDigest},
		SecurityOpt:     []string{"seccomp=unconfined"},
		UsernsMode:      []string{"host"},
		GroupAdd:        []string{"docker"},
		Sysctls:         []string{"net.ipv4.ip_forward=1"},
		VolumesFrom:     []string{"other"},
		ReservedDevices: []string{"nvidia:gpu"},
		NamespaceJoins:  []string{"network:container:abc"},
		CgroupParent:    []string{"/rasputin"},
		Tmpfs:           []string{"/tmp/cache"},
		Ulimits:         []string{"nofile=65535"},
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{
		"securityOpt", "usernsMode", "groupAdd", "sysctls", "volumesFrom",
		"reservedDevices", "namespaceJoins", "cgroupParent", "tmpfs", "ulimits",
	} {
		if !strings.Contains(string(b), `"`+key+`":`) {
			t.Errorf("SafetyFacts JSON is missing key %q — a renamed key is a privilege fact the reader drops silently\ngot: %s", key, b)
		}
	}
}

// Every new field must be omitempty: an unprivileged tile's manifest should not
// grow ten empty arrays, and a reader distinguishing "absent" from "empty" would
// be reading noise.
func TestSafetyFacts_PrivilegeFieldsOmitWhenEmpty(t *testing.T) {
	b, err := json.Marshal(SafetyFacts{Images: []string{"img@" + goodDigest}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{
		"securityOpt", "usernsMode", "groupAdd", "sysctls", "volumesFrom",
		"reservedDevices", "namespaceJoins", "cgroupParent", "tmpfs", "ulimits",
	} {
		if strings.Contains(string(b), key) {
			t.Errorf("empty SafetyFacts still emits %q; want omitempty\ngot: %s", key, b)
		}
	}
}

// THE GAP #195 OPENED AND #196 CLOSED. This test used to assert the opposite:
// #195 captured ten privilege dimensions that the validator read nowhere, so a
// stack could take seccomp=unconfined, userns host and the docker group and be
// waved through as routine while Home Assistant was refused outright. Its
// comment said it should FAIL and be rewritten when #196 landed. It did, and
// this is the rewrite.
func TestValidateTileSafety_PrivilegeFactsAreTiered(t *testing.T) {
	f := okFacts()
	f.SecurityOpt = []string{"seccomp=unconfined"}
	f.UsernsMode = []string{"host"}
	f.GroupAdd = []string{"docker"}

	err := ValidateTileSafety(okTile(), f)
	if err == nil {
		t.Fatal("an undeclared host-trusting stack must be refused, not silently accepted as routine")
	}
	if !strings.Contains(err.Error(), TierHostTrusting) {
		t.Fatalf("want the verdict to name the host-trusting tier, got: %v", err)
	}

	// And accepted once declared — the point of Decision 12 is that this is a
	// consent prompt, not a wall.
	x := okTile()
	x.Privilege = Privilege{
		Tier:   TierHostTrusting,
		Grants: []string{GrantSeccompUnconfined, GrantUsernsHost, GrantPrefixGroup + "docker"},
		Why:    "builds container images locally",
	}
	x.Requires = []string{CapabilityPrivilegeTiers}
	if err := ValidateTileSafety(x, f); err != nil {
		t.Fatalf("a fully declared host-trusting stack must be accepted, got %v", err)
	}
}

// The must-understand rule applies to EVERY tile, not just installable ones
// (#162). It used to live in ValidateTileSafety, which is skipped for preview
// tiles — so the class of tile most likely to be newer than the reader was the
// one class never checked. Decision 7 is unconditional.
func TestValidateTile_UnknownCapabilityIsRefusedWhateverTheStatus(t *testing.T) {
	for _, status := range []string{StatusAvailable, StatusPreview, ""} {
		name := status
		if name == "" {
			name = "(unset, means available)"
		}
		t.Run(name, func(t *testing.T) {
			x := okTile()
			x.Status = status
			x.Requires = []string{"gpu-passthrough-v2"}
			if err := ValidateTile(x); err == nil {
				t.Fatal("a tile naming a capability this build does not understand must be refused")
			}
			// And a KNOWN capability must not be refused, or the gate is just
			// "any requires entry is fatal".
			KnownCapabilities["gpu-passthrough-v2"] = true
			defer delete(KnownCapabilities, "gpu-passthrough-v2")
			if err := ValidateTile(x); err != nil {
				t.Fatalf("a known capability must be accepted: %v", err)
			}
		})
	}
}
