package mesh

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

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

// AppLeafDNSNames returns the SANs for an app's TLS leaf: BOTH of the app's
// names, always, whatever its current exposure. The tailnet name is first (it's
// the CommonName). These must match the names the nameserver / extra_records
// resolve, which is why they share the constructors above.
//
// The SAN set is deliberately INDEPENDENT of exposeLAN. A certificate asserts
// identity — "this really is jellyfin on this cluster" — and is not an access
// control; what makes a name reachable is a route on a bound listener, and
// nothing else. Withholding the .lan name from the leaf was a second, redundant
// lock on the same door, and it cost a re-mint plus a re-ship of the whole leaf
// every time an operator flipped a toggle.
//
// Exposure now lives in exactly one place on this path: AppRouteHosts, which
// decides whether the app gets a LAN route at all. See RenderCaddyConfig — the
// LAN listener only ever carries apps with a LAN route, so a leaf bearing an
// unused .lan name is inert: the handshake can succeed and there is still no
// route to match, so nothing answers.
func AppLeafDNSNames(clusterID, appName string) []string {
	return []string{
		appTailnetFQDN(clusterID, appName),
		appLANFQDN(clusterID, appName),
	}
}

// AppRouteHosts returns the hostnames the node-local proxy should route for an
// app: the tailnet name always, and the .lan name only when the app is
// LAN-exposed (lan is "" otherwise).
//
// This is THE exposure decision on the delivery path, and it is deliberately a
// separate function from AppLeafDNSNames so that the split is impossible to
// miss: the leaf carries both names, the ROUTE carries the policy. They share
// the FQDN constructors so a route host and its SAN can never disagree.
func AppRouteHosts(clusterID, appName string, exposeLAN bool) (tailnet, lan string) {
	tailnet = appTailnetFQDN(clusterID, appName)
	if exposeLAN {
		lan = appLANFQDN(clusterID, appName)
	}
	return tailnet, lan
}

// MintAppLeaf mints a Mesh-CA server leaf for an app, valid for BOTH of its
// FQDNs regardless of exposure. This is the per-app leaf of ADR-0004 §6 — the
// node-local Caddy terminates TLS with it. Pure: no disk I/O; the caller (the
// deploy saga) ships the returned PEMs to the target node over the bus
// (slice 3). 127.0.0.1 is included so a same-host health probe can hit the
// proxy over loopback.
func MintAppLeaf(ca *MeshCA, clusterID, appName string) (certPEM, keyPEM []byte, err error) {
	return MintLeaf(ca, appLeafSpec(clusterID, appName))
}

func appLeafSpec(clusterID, appName string) LeafSpec {
	names := AppLeafDNSNames(clusterID, appName)
	return LeafSpec{
		CommonName: names[0],
		DNSNames:   names,
		// The SAN set no longer moves with exposure, but ExactDNSNames stays
		// on: it is what forces a re-mint when the app's IDENTITY changes (a
		// rename, a cluster-id change) rather than letting a leaf keep a name
		// that is no longer the app's. It is also the migration path — every
		// leaf minted before this change carries only the tailnet name, and
		// the exact check is what notices and re-mints it with both.
		ExactDNSNames: true,
		IPAddresses:   []net.IP{net.IPv4(127, 0, 0, 1)},
	}
}

func appLeafPaths(dir string) LeafPaths {
	return LeafPaths{
		CertPath: filepath.Join(dir, "leaf.pem"),
		KeyPath:  filepath.Join(dir, "leaf.key"),
	}
}

// PrepareAppLeaf is the rotation-aware form of MintAppLeaf (ADR-0004 §6). It
// answers one question for the caller: does this app need a delivery to its
// node right now? renewed=true means yes.
//
// Two independent things can make the answer yes:
//
//  1. The CERT needs replacing — nothing on disk, less than renewWindow of life
//     left, or a SAN set that no longer matches the app's identity. A fresh leaf
//     is minted in memory and returned, NOT persisted.
//  2. The ROUTE the node holds is stale — the app's exposure has changed since
//     the last accepted delivery. The existing cert is returned unchanged (it is
//     valid for both names either way); what has to reach the node is the new
//     route, and AppLeafCmd is what carries it.
//
// Before this split, (2) was inferred from (1): exposure was encoded in the SAN
// set, so toggling it forced a re-mint and that re-mint was what shipped the new
// route. Making the leaf exposure-independent removes that side effect, so the
// route needs a trigger of its own — the delivered-route marker below — or
// revoking LAN exposure would silently stop reaching the node, which is #197's
// original defect in a new place.
//
// The split from CommitAppLeaf is deliberate and is what makes an offline node
// safe: the caller ships first and commits only on acceptance, so neither a
// fresh cert nor a new route is recorded as delivered until the node has taken
// it. A node that is down during a toggle keeps returning renewed=true on every
// sweep until it comes back.
func PrepareAppLeaf(ca *MeshCA, dir, clusterID, appName string, exposeLAN bool) (certPEM, keyPEM []byte, renewed bool, err error) {
	if ca == nil {
		return nil, nil, false, errors.New("mesh: PrepareAppLeaf: nil CA")
	}
	spec := appLeafSpec(clusterID, appName)
	paths := appLeafPaths(dir)
	if loadLeafIfUsable(paths, ca, spec) != nil {
		certPEM, err = os.ReadFile(paths.CertPath)
		if err != nil {
			return nil, nil, false, fmt.Errorf("mesh: read app leaf cert: %w", err)
		}
		keyPEM, err = os.ReadFile(paths.KeyPath)
		if err != nil {
			return nil, nil, false, fmt.Errorf("mesh: read app leaf key: %w", err)
		}
		// Cert is fine. Ship it anyway if the node is holding a stale route.
		return certPEM, keyPEM, !routeDelivered(dir, exposeLAN), nil
	}
	certPEM, keyPEM, err = MintLeaf(ca, spec)
	if err != nil {
		return nil, nil, false, err
	}
	return certPEM, keyPEM, true, nil
}

// deliveredRoute is the marker written beside an app's leaf recording the
// exposure the target node has actually ACCEPTED. It is the route half of the
// commit-on-delivery discipline the PEMs already follow.
type deliveredRoute struct {
	ExposeLAN bool `json:"exposeLan"`
}

// routeDelivered reports whether the node is known to hold the route implied by
// exposeLAN. A missing or unreadable marker reads as NOT delivered, which is the
// safe direction twice over: an app installed before this marker existed gets
// one re-delivery that also migrates its leaf to the two-name SAN set, and a
// corrupt marker costs an extra delivery rather than a silently stale route.
func routeDelivered(dir string, exposeLAN bool) bool {
	raw, err := os.ReadFile(appRoutePath(dir))
	if err != nil {
		return false
	}
	var d deliveredRoute
	if err := json.Unmarshal(raw, &d); err != nil {
		return false
	}
	return d.ExposeLAN == exposeLAN
}

func appRoutePath(dir string) string { return filepath.Join(dir, "route.json") }

// CommitAppLeaf atomically persists what the target node has accepted: the PEMs
// PrepareAppLeaf returned, and the exposure whose route was delivered with them.
// The next PrepareAppLeaf reads both — the cert as the usable current leaf, the
// marker as the route the node already holds. Call only after the node has
// accepted the delivery.
//
// The marker is written LAST and deliberately so. If it fails, the cert is
// persisted and the route is not, so the next sweep re-delivers an identical
// leaf and route — wasteful and harmless. The reverse order could record a route
// as delivered while the cert that carried it was lost.
func CommitAppLeaf(dir string, certPEM, keyPEM []byte, exposeLAN bool) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mesh: mkdir app leaf dir: %w", err)
	}
	paths := appLeafPaths(dir)
	if err := writeAtomic(paths.CertPath, certPEM, 0o644); err != nil {
		return err
	}
	if err := writeAtomic(paths.KeyPath, keyPEM, 0o600); err != nil {
		return err
	}
	marker, err := json.Marshal(deliveredRoute{ExposeLAN: exposeLAN})
	if err != nil {
		return fmt.Errorf("mesh: marshal delivered route: %w", err)
	}
	return writeAtomic(appRoutePath(dir), marker, 0o644)
}
