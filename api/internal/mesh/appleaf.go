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
	return MintLeaf(ca, appLeafSpec(clusterID, appName, exposeLAN))
}

func appLeafSpec(clusterID, appName string, exposeLAN bool) LeafSpec {
	names := AppLeafDNSNames(clusterID, appName, exposeLAN)
	return LeafSpec{
		CommonName:  names[0],
		DNSNames:    names,
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
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
// than renewWindow of life left and its SANs still match exposeLAN — with
// renewed=false, meaning the target node already holds it and nothing needs
// re-shipping. When no usable leaf is on disk (first rotation for the app,
// near-expiry, or a SAN change from an exposeLAN toggle) it mints a FRESH leaf
// in memory and returns it with renewed=true WITHOUT persisting it.
//
// The split from CommitAppLeaf is deliberate: the caller ships the fresh leaf
// and only then commits it, so a node that is offline during its renew window
// keeps triggering a re-mint + retry on every sweep — the on-disk leaf never
// advances ahead of what the node has actually accepted.
func PrepareAppLeaf(ca *MeshCA, dir, clusterID, appName string, exposeLAN bool) (certPEM, keyPEM []byte, renewed bool, err error) {
	if ca == nil {
		return nil, nil, false, errors.New("mesh: PrepareAppLeaf: nil CA")
	}
	spec := appLeafSpec(clusterID, appName, exposeLAN)
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
	if err := writeAtomic(paths.KeyPath, keyPEM, 0o600); err != nil {
		return err
	}
	return nil
}
