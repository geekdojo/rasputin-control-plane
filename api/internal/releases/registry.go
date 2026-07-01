package releases

import "github.com/geekdojo/rasputin-control-plane/proto"

// Kind classifies how a component's update is delivered.
type Kind string

const (
	// KindRAUC is an atomic A/B RAUC bundle (.raucb). Pullable into the
	// bundle store and deployable through the existing node.update saga.
	KindRAUC Kind = "raucb"
	// KindSysupgrade is an OpenWrt sysupgrade image. Legacy — the firewall used
	// this while it was display-only; it now ships KindRootfsAB. Kept so an old
	// manifest still parses.
	KindSysupgrade Kind = "sysupgrade"
	// KindRootfsAB is the firewall's custom A/B OTA artifact: a bare rootfs
	// squashfs (the manifest's `rootfs`/`rootfsSha256`) the agent's
	// OpenWrtABBackend dd's into the inactive slot. Deployable through the same
	// node.update saga as KindRAUC — only the on-agent backend differs.
	KindRootfsAB Kind = "rootfs-ab"
)

// FirewallCompatible is the SKU string a firewall (Node N) OTA artifact must
// carry — the firewall accepts only its own image, never an OS bundle.
const FirewallCompatible = "rasputin-fw-n100"

// Component describes one updatable/observable part of a Rasputin system and
// how to find its latest release + which node's installed version to compare
// against.
type Component struct {
	ID    string // stable id used in the API + UI ("os", "fw", "cp")
	Label string // human label

	// TagPrefix namespaces this component's releases in the public channel
	// repo, e.g. "os-" for tag "os-2026.06.0-dev.24".
	TagPrefix string
	// Compatible is the hardware-compat string the release manifest's
	// artifact must match for this component (the n100 SKUs in v1).
	Compatible string
	Scheme     Scheme
	Kind       Kind
	Deployable bool // true → has a Download & stage button

	// CompareRoles are the node roles that run this component's image. The
	// component reads "update available" if ANY node in these roles reports a
	// version older than latest — so an OS update surfaces while a single
	// compute node lags, even when the controlplane is already current. (The OS
	// image runs on every node but the firewall; the firewall runs its own.)
	CompareRoles []proto.NodeRole
	// CompareField selects which reported field holds the installed version:
	// "image" → Node.ImageVersion (CalVer OS), "agent" → Node.AgentVersion
	// (semver control-plane software).
	CompareField string
}

// Components is the v1 registry of independently-checkable update targets. Both
// OS (KindRAUC) and the firewall (KindRootfsAB) are deployable through the
// node.update saga; they differ only in the on-agent backend (rauc vs
// openwrt-ab) and the OTA artifact (.raucb vs the rootfs squashfs).
//
// The control-plane software is deliberately NOT a component here: it ships
// *inside* the OS image (pinned in rasputin-os' package .mk files), so it can
// never be updated on its own — updating the OS updates it. Presenting it as a
// peer row with its own status badge implied an action that doesn't exist (and
// would read "update available" the moment a cp release is mirrored ahead of an
// OS image vendoring it). Instead Check folds the running control-plane version
// into the OS row as a display-only detail. See ControlPlaneVersion.
var Components = []Component{
	{
		ID: "os", Label: "Rasputin OS",
		TagPrefix: "os-", Compatible: "rasputin-n100",
		Scheme: SchemeCalVer, Kind: KindRAUC, Deployable: true,
		CompareRoles: []proto.NodeRole{proto.RoleControlPlane, proto.RoleCompute, proto.RoleStorage},
		CompareField: "image",
	},
	{
		ID: "fw", Label: "Firewall",
		TagPrefix: "fw-", Compatible: FirewallCompatible,
		Scheme: SchemeCalVer, Kind: KindRootfsAB, Deployable: true,
		CompareRoles: []proto.NodeRole{proto.RoleFirewall},
		CompareField: "image",
	},
}

// ArchCompatible maps a node CPU architecture to the OS release manifest's
// `compatible` SKU string. The node OS ships one image per arch (role selected
// at runtime), so this is all the flasher needs to pick the right artifact:
// amd64 → the N100 (Intel) board, arm64 → the `rpi` SKU (one unified image for
// Raspberry Pi 4 / Pi 5 / CM5). An empty arch defaults to amd64. The firewall
// is a separate, x86-only image and is not selectable here. Returns false for
// an unrecognized arch.
func ArchCompatible(arch string) (string, bool) {
	switch arch {
	case "", "amd64":
		return "rasputin-n100", true
	case "arm64":
		return "rasputin-rpi-arm64", true
	default:
		return "", false
	}
}

// ComponentByID returns the registry entry for id.
func ComponentByID(id string) (Component, bool) {
	for _, c := range Components {
		if c.ID == id {
			return c, true
		}
	}
	return Component{}, false
}
