package nameserver

import (
	"net"
	"strings"
)

// NodeAddr is the minimal node projection the cluster source needs: an id (to
// join apps to the node they are homed on), the node's hostname (which becomes
// its DNS label), and its LAN IPv4. main builds these from proto.Node so this
// package stays free of the inventory/apps/proto types.
type NodeAddr struct {
	ID       string
	Hostname string
	IP       net.IP
}

// AppRec is the minimal app projection: the instance name (already an RFC 1123
// label, enforced at create — ADR-0004 §5) and the id of the node it targets.
type AppRec struct {
	Name       string
	TargetNode string
}

// ClusterSource projects the cluster's node and app A records for the zone it is
// given, read live on every query from the provided listers (main backs them
// with the inventory + apps stores). main constructs it with the **.lan
// subzone** (lan.<cluster-id>.internal, ADR-0004 §9), so in production it serves:
//
//   - node record: <hostname-label>.lan.<cluster-id>.internal  -> the node's LAN IP
//   - app record:  <app-name>.lan.<cluster-id>.internal        -> its target node's LAN IP
//
// The bare base domain is the tailnet name (MagicDNS / extra_records), not this
// source's concern. The type itself is zone-agnostic — it projects under
// whatever zone it's constructed with — so the .lan choice lives in main.
//
// A record is omitted (→ the responder answers NXDOMAIN) rather than served
// wrong whenever the data isn't resolvable yet: a node with no LAN IP, an app
// whose target node is unregistered or IP-less, or a name that isn't a valid
// DNS label. Reading live means a lease change or app move is reflected on the
// next query with no reload (ADR-0004 §8).
type ClusterSource struct {
	zone      string
	listNodes func() []NodeAddr
	listApps  func() []AppRec
}

// NewClusterSource builds the cluster projection for zone (any case / trailing
// dot accepted). The listers are called on every Records call and must be safe
// for concurrent use; returning an empty slice (e.g. on a store error main
// swallows) is valid and means "project nothing this round."
func NewClusterSource(zone string, listNodes func() []NodeAddr, listApps func() []AppRec) *ClusterSource {
	return &ClusterSource{zone: canonical(zone), listNodes: listNodes, listApps: listApps}
}

// Records implements [Source].
func (c *ClusterSource) Records() map[string]net.IP {
	nodes := c.listNodes()
	out := make(map[string]net.IP, len(nodes))
	ipByNode := make(map[string]net.IP, len(nodes))

	for _, n := range nodes {
		ip := usableIPv4(n.IP)
		if ip == nil {
			continue // node hasn't reported a LAN IP yet
		}
		ipByNode[n.ID] = ip
		if label := hostLabel(n.Hostname); label != "" {
			out[label+"."+c.zone] = ip
		}
	}

	for _, a := range c.listApps() {
		ip := ipByNode[a.TargetNode]
		if ip == nil {
			continue // target node unregistered or has no LAN IP
		}
		label := hostLabel(a.Name)
		if label == "" {
			continue // grandfathered non-DNS-safe name: no record until renamed
		}
		out[label+"."+c.zone] = ip
	}
	return out
}

// usableIPv4 returns the 4-byte form of ip, or nil if ip is nil or not IPv4
// (Rasputin is IPv4-only, LOCKED decision #9).
func usableIPv4(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	return ip.To4()
}

// hostLabel reduces a hostname or app name to a single lowercase RFC 1123 DNS
// label: it takes the first dot-separated element and validates it, returning ""
// if the result isn't a valid label. Using the hostname's first label keeps LAN
// node names aligned with MagicDNS's <hostname>.<zone> synthesis for well-formed
// hostnames (exact sanitization parity with Headscale is an AA-4 refinement).
func hostLabel(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if i := strings.IndexByte(name, '.'); i >= 0 {
		name = name[:i]
	}
	if !isDNSLabel(name) {
		return ""
	}
	return name
}

// isDNSLabel reports whether s is a valid RFC 1123 DNS label: 1-63 chars,
// lowercase alphanumerics and interior hyphens. This is the DNS-layer copy of
// the same rule catalog.ValidDNSLabel enforces on tile ids and validAppName on
// app names — kept local so this package depends only on net + miekg/dns.
func isDNSLabel(s string) bool {
	if len(s) < 1 || len(s) > 63 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-':
			if i == 0 || i == len(s)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
