package releases

import "github.com/geekdojo/rasputin-control-plane/proto"

// Kind classifies how a component's update is delivered.
type Kind string

const (
	// KindRAUC is an atomic A/B RAUC bundle (.raucb). Pullable into the
	// bundle store and deployable through the existing node.update saga.
	KindRAUC Kind = "raucb"
	// KindSysupgrade is an OpenWrt sysupgrade image. Display-only in v1 —
	// there is no automated push path for the firewall yet (see the backlog
	// "automated firewall push" item), so we surface the available version
	// and manual instructions instead of a deploy button.
	KindSysupgrade Kind = "sysupgrade"
	// KindInfo is informational only: a version we display but never deploy
	// directly (it ships inside another component's image).
	KindInfo Kind = "info"
)

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

	// CompareRole is the node role whose reported version represents the
	// "installed" version of this component.
	CompareRole proto.NodeRole
	// CompareField selects which reported field holds the installed version:
	// "image" → Node.ImageVersion (CalVer OS), "agent" → Node.AgentVersion
	// (semver control-plane software).
	CompareField string
}

// Components is the v1 registry. OS is the one fully-deployable component;
// the firewall is display-only; the control-plane software is informational
// (it ships inside the OS image, so updating the OS updates it).
var Components = []Component{
	{
		ID: "os", Label: "Rasputin OS",
		TagPrefix: "os-", Compatible: "rasputin-n100",
		Scheme: SchemeCalVer, Kind: KindRAUC, Deployable: true,
		CompareRole: proto.RoleControlPlane, CompareField: "image",
	},
	{
		ID: "fw", Label: "Firewall",
		TagPrefix: "fw-", Compatible: "rasputin-fw-n100",
		Scheme: SchemeCalVer, Kind: KindSysupgrade, Deployable: false,
		CompareRole: proto.RoleFirewall, CompareField: "image",
	},
	{
		ID: "cp", Label: "Control-plane software",
		TagPrefix: "cp-", Compatible: "",
		Scheme: SchemeSemver, Kind: KindInfo, Deployable: false,
		CompareRole: proto.RoleControlPlane, CompareField: "agent",
	},
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
