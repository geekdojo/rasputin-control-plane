package busauth

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// EnvEnforce is the api's bus-auth switch: anything but "off" enforces.
const EnvEnforce = "RASPUTIN_BUS_AUTH"

// OffValue is the one value that turns enforcement off.
const OffValue = "off"

// ErrOffOffLoopback is returned when RASPUTIN_BUS_AUTH=off is paired with a bus
// that is not bound to loopback.
var ErrOffOffLoopback = errors.New("bus auth cannot be turned off on a bus that is reachable from the network")

// ResolveEnforcement decides whether the bus enforces join tokens, given the
// RASPUTIN_BUS_AUTH value and the host the embedded NATS server will bind.
//
// Anything but "off" enforces, which is the fail-closed default: an incomplete
// seed that omits the variable gets a closed bus rather than an open one.
//
// "off" is accepted ONLY when the bus binds loopback. With auth off every
// connection lands in the `$G` account with full permissions and can claim any
// node's id, so on a bus bound to 0.0.0.0 or a LAN address that is every device
// on the network, and nothing on the wire distinguishes them from a real node.
// Bound to loopback it is a local-user question, which is what the dev loop in
// docs/testing-updates.md relies on.
//
// There is deliberately no other escape hatch here
// (geekdojo/geekdojo-brain#511). "off" is not a recovery lever for a node whose
// join token was lost or revoked: the bus has no re-mint path, and a node in
// that state is recovered by reflashing it and rejoining it with a fresh seed.
// Opening the whole bus to recover one node is not that, and it is not
// reversible for the nodes it exposes in the meantime.
func ResolveEnforcement(value, natsHost string) (enforce bool, err error) {
	if strings.TrimSpace(value) != OffValue {
		return true, nil
	}
	if IsLoopbackHost(natsHost) {
		return false, nil
	}
	return true, fmt.Errorf("%s=%s with %s=%q: %w. With bus auth off every connection gets the bus's full permissions and can claim any node's id, "+
		"and on %q that is any device that can reach this host. "+
		"Either bind the bus to loopback (unset %s, or set it to 127.0.0.1) or leave bus auth enforced and give each node a join token bound to its node id. "+
		"If a node has lost or had revoked the token it needs: there is no way to re-mint one to a node over the bus — reflash it and rejoin it with a fresh seed. "+
		"Turning bus auth off does not recover that node, and it opens every other node on this bus while it is off",
		EnvEnforce, OffValue, EnvNATSHost, natsHost, ErrOffOffLoopback, natsHost, EnvNATSHost)
}

// EnvNATSHost is the variable that binds the embedded NATS server, named here
// so the refusal above can tell an operator which one to change.
const EnvNATSHost = "RASPUTIN_NATS_HOST"

// IsLoopbackHost reports whether host names an address the embedded bus can
// only be reached on from this machine.
//
// It accepts a literal loopback IP (127.0.0.0/8, ::1, and an IPv4-mapped form
// of either) and the name "localhost", which RFC 6761 §6.3 reserves to resolve
// to loopback and nothing else. It accepts no other name: a hostname would have
// to be resolved to be judged, the answer could change after this process read
// it, and a name that resolves off-box is exactly the case this refuses. An
// empty host, "0.0.0.0" and "::" are not loopback — they are every interface.
func IsLoopbackHost(host string) bool {
	h := strings.TrimSpace(host)
	if strings.EqualFold(h, "localhost") {
		return true
	}
	// A bracketed IPv6 literal, as it would appear in a URL.
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
