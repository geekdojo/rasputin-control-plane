package setup

// Mode is the deployment topology the operator picks in the wizard, right
// after naming the installation. It changes which subsystems even run — see
// the wiki backlog (setup-wizard SW-1) for the full consequence matrix.
//
// The stored string values are a stable contract: the UI SideNav, the
// firewall/IDS/DHCP gating, and the mesh subnet-advertise rules all switch on
// them. Don't rename a value without migrating the settings table.
type Mode string

const (
	// ModeUnset is the zero value — no choice recorded yet. The wizard's
	// deployment_mode step is un-done while the stored value is empty.
	ModeUnset Mode = ""
	// ModeRouter — "Rasputin is my router." WAN into the firewall node; it
	// owns DHCP/firewall/NAT/IDS for the whole LAN. Requires a firewall node.
	ModeRouter Mode = "router"
	// ModeLANPeer — "Plug into my existing LAN." The existing router
	// firewalls; the cluster is just compute/storage nodes. No firewall job.
	ModeLANPeer Mode = "lan_peer"
	// ModeSubSegment — "Sub-segment / learn-the-firewall." The firewall node
	// firewalls a downstream segment behind the existing router (double-NAT
	// accepted). The learning persona's mode. Requires a firewall node.
	ModeSubSegment Mode = "sub_segment"
)

// Valid reports whether m is a recognised deployment mode (excluding unset).
func (m Mode) Valid() bool {
	switch m {
	case ModeRouter, ModeLANPeer, ModeSubSegment:
		return true
	default:
		return false
	}
}

// RequiresFirewallNode reports whether m can only be realised on an
// installation that has a firewall-capable node (Node N). Modes A and C run a
// firewall; Mode B does not. Used to gate the choice — we don't offer a mode
// the hardware can't deliver (a Pi-only cluster can never firewall, per locked
// decision #4).
func (m Mode) RequiresFirewallNode() bool {
	return m == ModeRouter || m == ModeSubSegment
}
