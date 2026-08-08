package mesh

import "net"

// appTailnetFQDN is an app's bare (tailnet) name — <app>.<cluster-id>.internal.
// The app's TLS leaf SAN and its Headscale extra_record MUST be this exact
// string or TLS breaks, so both go through here (ADR-0004 §9).
func appTailnetFQDN(clusterID, appName string) string {
	return appName + "." + baseDomainFor(clusterID)
}

// appLANFQDN is an app's .lan name — <app>.lan.<cluster-id>.internal — served by
// the CP nameserver when the app is LAN-exposed (ADR-0004 §9).
func appLANFQDN(clusterID, appName string) string {
	return appName + ".lan." + baseDomainFor(clusterID)
}

// AppLeafDNSNames returns the SANs for an app's TLS leaf: the tailnet name
// always, plus the .lan name when the app is LAN-exposed. The tailnet name is
// first (it's the CommonName). These must match the names the nameserver /
// extra_records resolve, which is why they share the constructors above.
func AppLeafDNSNames(clusterID, appName string, exposeLAN bool) []string {
	names := []string{appTailnetFQDN(clusterID, appName)}
	if exposeLAN {
		names = append(names, appLANFQDN(clusterID, appName))
	}
	return names
}

// MintAppLeaf mints a Mesh-CA server leaf for an app, valid for its tailnet
// FQDN (and its .lan FQDN when LAN-exposed). This is the per-app leaf of
// ADR-0004 §6 — the node-local Caddy terminates TLS with it. Pure: no disk I/O;
// the caller (the deploy saga) ships the returned PEMs to the target node over
// the bus (slice 3). 127.0.0.1 is included so a same-host health probe can hit
// the proxy over loopback.
func MintAppLeaf(ca *MeshCA, clusterID, appName string, exposeLAN bool) (certPEM, keyPEM []byte, err error) {
	names := AppLeafDNSNames(clusterID, appName, exposeLAN)
	return MintLeaf(ca, LeafSpec{
		CommonName:  names[0],
		DNSNames:    names,
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	})
}
