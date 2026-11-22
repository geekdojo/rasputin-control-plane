package mesh

import (
	"fmt"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// EnrolPrefs are the two tailnet settings an enrolment sets on a node's
// tailscaled: whether it takes the tailnet's subnet routes and its DNS.
type EnrolPrefs struct {
	AcceptRoutes bool
	AcceptDNS    bool
}

// enrolPrefsForRole is the settings each auto-enrolled role gets, and false
// for a role with none (geekdojo/geekdojo-brain#984). The control plane takes
// neither: an approved route covering its own LAN, or the tailnet's resolver,
// would take its console, sign-in doors and bus off the LAN path every other
// node and every person reaches it on. The other roles keep the settings they
// have always had.
func enrolPrefsForRole(role proto.NodeRole) (EnrolPrefs, bool) {
	switch role {
	case proto.RoleControlPlane:
		return EnrolPrefs{AcceptRoutes: false, AcceptDNS: false}, true
	case proto.RoleCompute, proto.RoleStorage, proto.RoleFirewall:
		return EnrolPrefs{AcceptRoutes: true, AcceptDNS: true}, true
	}
	return EnrolPrefs{}, false
}

// enrolTargetRole is nodeID's role, read once for an enrolment from the api's
// one in-memory node registry (geekdojo/geekdojo-brain#585) — the list
// validate and converge read. No inventory, no entry, or an entry that is no
// longer a member is an error: the login server and the settings both derive
// from the role, so an enrolment without one fails rather than guesses.
func enrolTargetRole(inv *inventory.Store, nodeID string) (proto.NodeRole, error) {
	if inv == nil {
		return "", fmt.Errorf("node %s: inventory unavailable, its role cannot be read", nodeID)
	}
	e, ok := inv.Registry().Lookup(nodeID)
	if !ok || !e.Member {
		return "", fmt.Errorf("node %s is not registered", nodeID)
	}
	return e.Role, nil
}
