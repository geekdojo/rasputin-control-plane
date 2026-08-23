// Package tileschema is the app-catalog tile contract: the types a catalog
// publisher writes and the control plane reads, plus the validation both sides
// run against them.
//
// It is a MODULE, not an internal package, because it has two consumers in two
// repositories. rasputin-app-catalog imports it to validate a tile before
// publishing; rasputin-control-plane imports it to validate a tile before
// loading one into a running cluster. ADR-0006 Decision 8 requires exactly one
// implementation of the safety rules — a second one is that decision failing,
// and it fails silently because each side stays internally green.
//
// It deliberately does NOT live in proto/. That module is the api-to-agent wire
// contract; this is the publisher-to-control-plane content contract. Folding
// them together would make the catalog repo depend on NATS subject definitions
// it has no use for.
//
// Design: projects/rasputin/adr/0006-app-catalog-delivery.md (geekdojo-brain).
package tileschema

// SchemaVersion is the tile-contract version this module implements.
//
// ADR-0006 Decision 7: within a major version a reader IGNORES fields it does
// not recognise, and refuses a bundle whose major exceeds what it understands.
// Tolerance alone is not safe, so a tile may also declare Requires — see
// SafetyFacts and ValidateTileSafety.
const SchemaVersion = 1

// Collections group tiles in the catalog UI. Order here is display order.
const (
	CollectionEssentials = "essentials"
	CollectionShowoff    = "show-off"
	CollectionEveryday   = "everyday"
	CollectionDongle     = "dongle"
)

// CollectionOrder maps a collection to its display rank.
var CollectionOrder = map[string]int{
	CollectionEssentials: 0,
	CollectionShowoff:    1,
	CollectionEveryday:   2,
	CollectionDongle:     3,
}

// Status gates installability. A preview tile is shown in the grid (so the
// catalog reflects the full roadmap) but cannot be installed until it clears
// the ACC-1 bench and flips to available.
const (
	StatusAvailable = "available"
	StatusPreview   = "preview"
)

// ValidExposure mirrors the app-access resolution tiers.
var ValidExposure = map[string]bool{"lan-only": true, "tailnet": true, "public": true}

// ValidArch, ValidPlacement, ValidCategory and ValidStatus are the closed
// vocabularies a tile's metadata fields draw from. An empty Status means
// available — the five originally-shipped tiles omit the field entirely.
var (
	ValidArch      = map[string]bool{"both": true, "arm64": true, "amd64": true}
	ValidPlacement = map[string]bool{"": true, "any": true, "prefer-x86": true, "prefer-arm64": true}
	ValidStatus    = map[string]bool{"": true, StatusAvailable: true, StatusPreview: true}
	ValidCategory  = map[string]bool{
		"": true, "media": true, "photos": true, "network": true, "monitoring": true,
		"automation": true, "productivity": true, "ai": true, "games": true,
		"data": true, "radio": true, "security": true, "tools": true,
	}
)

// KnownCapabilities is the set of Requires entries this implementation
// understands. ADR-0006 Decision 7's must-understand rule reads from it: a tile
// naming a capability absent here is REFUSED rather than loaded without it.
//
// It was empty until 2026-08-22 by design — the mechanism shipped before its
// first user precisely so that an older control plane already knew to refuse a
// future tile it could not reason about. That foresight is what makes the entry
// below safe to add now.
//
// privilege-tiers-v1 is the first (Decision 12d, #198). A tile taking any
// privilege above routine names it, so a control plane predating Decision 12
// refuses that tile rather than installing it with no tier, no badge and no
// consent. Bounded because #162 landed first: before per-tile refusal, one
// unknown capability cost a cluster its entire catalog.
var KnownCapabilities = map[string]bool{
	CapabilityPrivilegeTiers: true,
}

// Port is a structured published port. The reverse proxy must route
// <app>.<zone> to a concrete host port without parsing compose, so every
// web-facing tile declares its ports here and marks exactly one Primary.
type Port struct {
	Name      string `json:"name"`
	Container int    `json:"container"`
	Published int    `json:"published"`
	Protocol  string `json:"protocol,omitempty"` // "tcp" (default) | "udp"
	Primary   bool   `json:"primary,omitempty"`
}

// Tile is one catalog entry as AUTHORED — the hand-written tile.json. Facts
// that can only be derived by parsing the compose stack live in SafetyFacts,
// not here.
type Tile struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Tagline         string   `json:"tagline"`
	Description     string   `json:"description"`
	Collection      string   `json:"collection"`
	Arch            string   `json:"arch"`
	PlacementHint   string   `json:"placementHint"`
	RAMFloorMB      int      `json:"ramFloorMB"`
	NeedsHardware   string   `json:"needsHardware,omitempty"`
	NeedsFeedKey    []string `json:"needsFeedKey,omitempty"`
	ExposureDefault string   `json:"exposureDefault"`
	Ports           []Port   `json:"ports"`
	Category        string   `json:"category,omitempty"`
	Status          string   `json:"status,omitempty"`
	Website         string   `json:"website,omitempty"`
	Icon            string   `json:"icon,omitempty"`
	PostInstall     string   `json:"postInstall,omitempty"`

	// Requires names capabilities a reader must understand to load this tile
	// safely (ADR-0006 Decision 7). Unknown OPTIONAL fields are ignored;
	// unknown REQUIRED capabilities are fatal to this tile and only this tile.
	Requires []string `json:"requires,omitempty"`

	// Privilege is the tile's declaration of what its compose stack takes
	// (ADR-0006 Decision 12a). Absent means routine, which is what every tile
	// published before 2026-08-22 is by construction — they passed the five
	// absolute refusals Decision 12 replaces.
	//
	// It is AUTHORED, and checked against the derived SafetyFacts by
	// ValidateTileSafety. That pairing is the whole mechanism: the declaration
	// is what an owner reads and consents to, and the derivation is what keeps
	// it honest. See privilege.go.
	//
	// A POINTER, because `omitempty` does nothing for a struct: as a value
	// this emitted `"privilege":{}` on all 23 routine tiles in every published
	// bundle. Read it through DeclaredPrivilege rather than dereferencing.
	Privilege *Privilege `json:"privilege,omitempty"`

	// ComposeYAML is loaded from the sibling docker-compose.yml, not tile.json.
	// A preview tile may omit it — it cannot be installed.
	ComposeYAML string `json:"-"`
}

// SafetyFacts are the security-relevant properties of a tile's compose stack,
// DERIVED BY THE PUBLISHER and carried in the signed bundle manifest.
//
// Why derived rather than re-parsed: the control plane deliberately treats
// compose as opaque bytes (api/internal/catalog never imports a YAML parser),
// and ADR-0006 Decision 4 exists to narrow what stands between an attacker-
// supplied bundle and the cluster. Putting a YAML parser there would widen it.
// The publisher already parses compose because it must; the bundle signature
// makes these derived facts exactly as trustworthy as the compose they came
// from, which is the property that lets the reader validate them cheaply —
// no YAML, no registry, no filesystem.
type SafetyFacts struct {
	// Images is every image reference in the stack, expected digest-pinned.
	Images []string `json:"images"`
	// Privileged is true if any service requests privileged mode.
	Privileged bool `json:"privileged"`
	// HostNetwork is true if any service uses host networking.
	HostNetwork bool `json:"hostNetwork"`
	// HostPIDOrIPC is true if any service shares the host PID or IPC namespace.
	HostPIDOrIPC bool `json:"hostPidOrIpc"`
	// CapAdd is every added Linux capability across the stack.
	CapAdd []string `json:"capAdd,omitempty"`
	// BindMounts is every host path bind-mounted into a container.
	BindMounts []string `json:"bindMounts,omitempty"`
	// Devices is every host device mapped into a container.
	Devices []string `json:"devices,omitempty"`

	// --- Added 2026-08-20 (#195). ---
	//
	// The fields above were the whole of the extractor's view, and a compose
	// key it does not read is a privilege the validator cannot see. Proven,
	// not theorised: buildah fails in a plain container with
	// unshare(CLONE_NEWUSER) denied, and one `security_opt: seccomp=unconfined`
	// line — no privileged, no cap_add, no mounts — makes it build images while
	// passing every gate. Capture is deliberately separate from policy: what we
	// permit is #196's call, but nothing can be enforced over facts nobody
	// collects, and these are signature-covered, so a tile's privilege is
	// visible to a reviewer and to the operator either way.

	// SecurityOpt is every security_opt entry, normalised to "key=value".
	// `seccomp=unconfined` removes the kernel syscall filter and
	// `apparmor=unconfined` the MAC policy — the closest a stack gets to
	// privileged without spelling it that way.
	SecurityOpt []string `json:"securityOpt,omitempty"`

	// UsernsMode is every user-namespace override. "host" disables the
	// remapping that stops container root being host root.
	UsernsMode []string `json:"usernsMode,omitempty"`

	// GroupAdd is every supplementary group joined. Membership of a host group
	// (docker, disk, video) is authority the image was not built with.
	GroupAdd []string `json:"groupAdd,omitempty"`

	// Sysctls is every kernel tunable a service sets, as "name=value".
	Sysctls []string `json:"sysctls,omitempty"`

	// VolumesFrom is every source a service inherits mounts from. It reaches
	// around BindMounts entirely: the inheriting service receives paths this
	// struct never recorded.
	VolumesFrom []string `json:"volumesFrom,omitempty"`

	// ReservedDevices is every deploy.resources.reservations.devices entry —
	// how GPUs are actually requested. Without it a stack reaches hardware
	// while declaring no `devices:`, and so no NeedsHardware.
	ReservedDevices []string `json:"reservedDevices,omitempty"`

	// NamespaceJoins is every namespace a service joins instead of creating,
	// as "<kind>:<target>" (e.g. "network:service:vpn", "pid:container:abc").
	// A `service:` target names a sibling inside the stack — the ordinary
	// VPN-sidecar shape. A `container:` target names something outside it,
	// which the signed bundle does not describe.
	NamespaceJoins []string `json:"namespaceJoins,omitempty"`

	// CgroupParent is every cgroup a service attaches to rather than its own.
	CgroupParent []string `json:"cgroupParent,omitempty"`

	// Tmpfs is every tmpfs mount path. Unbounded, it is host memory.
	Tmpfs []string `json:"tmpfs,omitempty"`

	// Ulimits is every resource limit a service overrides, as "name=value".
	Ulimits []string `json:"ulimits,omitempty"`
}

// DeclaredPrivilege is the tile's declaration, or the zero value — routine,
// nothing declared — when it has none. Every caller should use this rather
// than the field, so "absent" and "declared routine" cannot diverge.
func (t Tile) DeclaredPrivilege() Privilege {
	if t.Privilege == nil {
		return Privilege{}
	}
	return *t.Privilege
}

// Available reports whether the tile can be installed now.
func (t Tile) Available() bool { return t.Status != StatusPreview }

// PrimaryPort returns the published host port the reverse proxy fronts, or 0
// if the tile declares none (a headless tile).
func (t Tile) PrimaryPort() int {
	for _, p := range t.Ports {
		if p.Primary {
			return p.Published
		}
	}
	return 0
}
