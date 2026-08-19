package tileschema

import (
	"fmt"
	"path"
	"strings"
)

// AllowedBindRoots are the host path prefixes a tile may bind-mount. Anything
// else is refused: a catalog tile has no business reaching into the host
// filesystem, and the two entries here are the ones a normal self-hosted stack
// legitimately needs.
//
// /var/lib/rasputin/apps/ is per-app persistent data. /etc/localtime is the
// near-universal read-only timezone mount.
var AllowedBindRoots = []string{
	"/var/lib/rasputin/apps/",
	"/etc/localtime",
}

// ValidateTile checks the AUTHORED metadata of a tile — everything expressible
// in tile.json. It does not look at the compose stack beyond "is it present",
// because the properties worth checking there cannot be seen without parsing
// it; those live in ValidateTileSafety.
func ValidateTile(t Tile) error {
	if !ValidDNSLabel(t.ID) {
		return fmt.Errorf("id must be a DNS-1123 label (1-63 chars, [a-z0-9-], no leading/trailing hyphen)")
	}
	if strings.TrimSpace(t.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if strings.TrimSpace(t.Tagline) == "" {
		return fmt.Errorf("tagline is required")
	}
	if _, ok := CollectionOrder[t.Collection]; !ok {
		return fmt.Errorf("collection %q is not one of essentials|show-off|everyday|dongle", t.Collection)
	}
	if !ValidArch[t.Arch] {
		return fmt.Errorf("arch %q is not one of both|arm64|amd64", t.Arch)
	}
	if !ValidPlacement[t.PlacementHint] {
		return fmt.Errorf("placementHint %q is not one of any|prefer-x86|prefer-arm64", t.PlacementHint)
	}
	if !ValidExposure[t.ExposureDefault] {
		return fmt.Errorf("exposureDefault %q is not one of lan-only|tailnet|public", t.ExposureDefault)
	}
	if !ValidCategory[t.Category] {
		return fmt.Errorf("category %q is not a known functional category", t.Category)
	}
	if !ValidStatus[t.Status] {
		return fmt.Errorf("status %q is not one of available|preview", t.Status)
	}
	if t.RAMFloorMB <= 0 {
		return fmt.Errorf("ramFloorMB must be > 0")
	}

	primaries := 0
	for i, p := range t.Ports {
		if p.Container < 1 || p.Container > 65535 {
			return fmt.Errorf("ports[%d] container %d out of range", i, p.Container)
		}
		if p.Published < 1 || p.Published > 65535 {
			return fmt.Errorf("ports[%d] published %d out of range", i, p.Published)
		}
		if p.Protocol != "" && p.Protocol != "tcp" && p.Protocol != "udp" {
			return fmt.Errorf("ports[%d] protocol %q is not tcp|udp", i, p.Protocol)
		}
		if p.Primary {
			primaries++
		}
	}

	// Installable tiles must ship a compose stack and, if web-facing, mark
	// exactly one primary port so the proxy knows which host:port to front.
	// Preview tiles are exempt — metadata only until they bench.
	if t.Available() {
		if strings.TrimSpace(t.ComposeYAML) == "" {
			return fmt.Errorf("docker-compose.yml is empty")
		}
		if len(t.Ports) > 0 && primaries != 1 {
			return fmt.Errorf("exactly one port must be primary (found %d)", primaries)
		}
	}

	// A tile promising public exposure with nothing to expose is a metadata
	// bug that would otherwise surface as a broken proxy route at install.
	if t.ExposureDefault == "public" && t.Available() && primaries != 1 {
		return fmt.Errorf("exposureDefault %q requires exactly one primary port to expose (found %d)", t.ExposureDefault, primaries)
	}

	return nil
}

// ValidateTileSafety checks the DERIVED, signature-covered properties of a
// tile's compose stack. This is the set that protects a cluster from a
// compromised or simply buggy publish, and it is the set the control plane runs
// at catalog load — so it is cheap by construction: no network, no registry, no
// filesystem, no YAML.
//
// ADR-0006 Decision 8: one implementation, two callers. The publisher runs this
// before signing; the control plane runs it before loading. If the two ever
// disagree the cluster's answer wins, because it is the one with something to
// lose.
func ValidateTileSafety(t Tile, f SafetyFacts) error {
	// Must-understand check first (Decision 7). A tile naming a capability
	// this reader does not know is refused outright — ignoring it is exactly
	// how a future safety constraint becomes a no-op on old clusters.
	for _, cap := range t.Requires {
		if !KnownCapabilities[cap] {
			return fmt.Errorf("requires unknown capability %q (schema %d) — refusing rather than loading without it", cap, SchemaVersion)
		}
	}

	if len(f.Images) == 0 {
		return fmt.Errorf("no images declared — a stack that pulls nothing cannot be verified")
	}
	for _, img := range f.Images {
		if err := validateImagePin(img); err != nil {
			return fmt.Errorf("image %q: %w", img, err)
		}
	}

	if f.Privileged {
		return fmt.Errorf("privileged containers are not permitted in the catalog")
	}
	if f.HostNetwork {
		return fmt.Errorf("host networking is not permitted in the catalog")
	}
	if f.HostPIDOrIPC {
		return fmt.Errorf("sharing the host PID or IPC namespace is not permitted in the catalog")
	}
	if len(f.CapAdd) > 0 {
		return fmt.Errorf("added capabilities are not permitted in the catalog (found %s)", strings.Join(f.CapAdd, ", "))
	}

	for _, m := range f.BindMounts {
		if !allowedBindMount(m) {
			return fmt.Errorf("bind mount %q is outside the allowed roots (%s)", m, strings.Join(AllowedBindRoots, ", "))
		}
	}

	// A stack mapping host devices must say so in its metadata, so the catalog
	// can badge it and the operator is never surprised by a tile reaching for
	// hardware. This is the check that keeps needsHardware honest.
	if len(f.Devices) > 0 && strings.TrimSpace(t.NeedsHardware) == "" {
		return fmt.Errorf("maps host devices (%s) but declares no needsHardware", strings.Join(f.Devices, ", "))
	}

	return nil
}

// validateImagePin requires a digest-pinned reference. A tag — including a
// version tag — is mutable at the registry, so a tile pinned to one does not
// describe a fixed stack no matter how specific the tag looks.
func validateImagePin(img string) error {
	if strings.TrimSpace(img) == "" {
		return fmt.Errorf("empty image reference")
	}
	at := strings.Index(img, "@")
	if at < 0 {
		return fmt.Errorf("must be digest-pinned (name@sha256:...), not a tag")
	}
	digest := img[at+1:]
	if !strings.HasPrefix(digest, "sha256:") {
		return fmt.Errorf("digest must be sha256, got %q", digest)
	}
	hex := strings.TrimPrefix(digest, "sha256:")
	if len(hex) != 64 {
		return fmt.Errorf("sha256 digest must be 64 hex chars, got %d", len(hex))
	}
	for _, r := range hex {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return fmt.Errorf("sha256 digest contains a non-hex character %q", r)
		}
	}
	// "repo:tag@sha256:..." is legal in the OCI grammar and resolves by digest,
	// so the tag is cosmetic — but an EMPTY name is not a reference at all.
	if strings.TrimSpace(img[:at]) == "" {
		return fmt.Errorf("missing image name before the digest")
	}
	return nil
}

// allowedBindMount reports whether a host path sits under an allowed root.
// Cleaned first so that /var/lib/rasputin/apps/../../../etc/shadow does not
// pass a naive prefix test.
func allowedBindMount(p string) bool {
	if !strings.HasPrefix(p, "/") {
		return false // relative paths are resolved by the daemon's cwd — refuse
	}
	clean := path.Clean(p)
	for _, root := range AllowedBindRoots {
		if clean == path.Clean(root) {
			return true
		}
		if strings.HasSuffix(root, "/") && strings.HasPrefix(clean+"/", root) {
			return true
		}
	}
	return false
}

// ValidDNSLabel reports whether s is a valid RFC-1123 DNS label: 1-63 chars,
// lowercase alphanumerics and hyphens, no leading/trailing hyphen. This keeps
// every catalog id usable as-is in <app>.<cluster-domain>, so an installed tile
// never needs renaming to get a hostname.
func ValidDNSLabel(s string) bool {
	if len(s) < 1 || len(s) > 63 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-':
			if i == 0 || i == len(s)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
