package mesh

import (
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
// returns the app's current on-disk leaf when that leaf is still usable — more
// than renewWindow of life left, and a SAN set that still matches the app's
// identity — with renewed=false. When there is no usable leaf on disk (first
// rotation for the app, near-expiry, a rename, a new cluster id, or a leaf
// minted before the SAN set became exposure-independent) it mints a FRESH leaf
// in memory and returns it with renewed=true WITHOUT persisting it.
//
// renewed answers exactly one question — "is this certificate new?" — and its
// only consumer is the decision to COMMIT. It is deliberately not a "does this
// app need a delivery?" signal: the caller delivers the app's desired state
// every time regardless, because the alternative is detecting change, and a
// change detector that misses is indistinguishable from nothing happening. That
// is the shape of #197, where exposure was propagated only as a side effect of
// the SAN set drifting, and a revoke that drifted nothing reached no node for
// ten months. Asserting desired state cannot fail that way; there is nothing to
// miss. (Bryce, 2026-08-30.)
//
// The split from CommitAppLeaf is deliberate: the caller ships the fresh leaf
// and only then commits it, so a node that is offline during its renew window
// keeps triggering a re-mint + retry on every sweep — the on-disk leaf never
// advances ahead of what the node has actually accepted.
func PrepareAppLeaf(ca *MeshCA, dir, clusterID, appName string) (certPEM, keyPEM []byte, renewed bool, err error) {
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
		return certPEM, keyPEM, false, nil
	}
	certPEM, keyPEM, err = MintLeaf(ca, spec)
	if err != nil {
		return nil, nil, false, err
	}
	return certPEM, keyPEM, true, nil
}

// CommitAppLeaf atomically persists a freshly-minted app leaf (the PEMs
// PrepareAppLeaf returned with renewed=true) under dir, so the next
// PrepareAppLeaf sees it as the usable current leaf. Call only after the target
// node has accepted the leaf.
func CommitAppLeaf(dir string, certPEM, keyPEM []byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mesh: mkdir app leaf dir: %w", err)
	}
	paths := appLeafPaths(dir)
	if err := writeAtomic(paths.CertPath, certPEM, 0o644); err != nil {
		return err
	}
	return writeAtomic(paths.KeyPath, keyPEM, 0o600)
}
