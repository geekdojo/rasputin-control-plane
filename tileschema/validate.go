package tileschema

import (
	"fmt"
	"strings"
)

// The range a tile may declare for Tile.DeployBudgetSeconds. Absent (0) is
// always valid and means the reader's default.
//
// These are the AUTHORING bounds, checked here so a bad value is a publish-time
// failure rather than a runtime surprise. The reader clamps to the same range
// again on the way to the agent — see proto.AppDeployWorkFor — because a value
// that reaches the api from a row it did not write must not be able to hand the
// agent an unbounded context.
const (
	DeployBudgetMinSeconds = 60
	DeployBudgetMaxSeconds = 1800
)

// ValidateTile checks the AUTHORED metadata of a tile — everything expressible
// in tile.json. It does not look at the compose stack beyond "is it present",
// because the properties worth checking there cannot be seen without parsing
// it; those live in ValidateTileSafety.
func ValidateTile(t Tile) error {
	// Must-understand check FIRST, and deliberately here rather than in
	// ValidateTileSafety (moved 2026-08-22, #162).
	//
	// It lived in the safety validator, which reads as the natural home and is
	// the wrong one: ValidateTileSafety only runs for tiles that are
	// Available(), because a preview tile ships no compose and so has no stack
	// to have facts about. That gate is right for safety facts and wrong for
	// this. The result was that a PREVIEW tile naming a capability this build
	// does not understand was never checked at all — the one class of tile
	// where the reader is most likely to be older than the publisher, since
	// preview is where new tiles land first.
	//
	// This is not a safety check. It is a comprehension check: the tile is
	// telling the reader "I mean something you may not know", and Decision 7's
	// answer is unconditional — refuse that tile, load the rest. Coupling it
	// to installability made a must-understand rule quietly optional.
	for _, capability := range t.Requires {
		if !KnownCapabilities[capability] {
			return fmt.Errorf("requires unknown capability %q (schema %d) — refusing rather than loading without it", capability, SchemaVersion)
		}
	}

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
	// The declared tier is authored metadata, so it is checked here rather
	// than in ValidateTileSafety — a PREVIEW tile ships no compose and never
	// reaches the safety validator, and a typo in its tier should surface at
	// publish rather than at the moment it flips to available.
	declaredPriv := t.DeclaredPrivilege()
	if declaredPriv.Tier != "" {
		if _, ok := TierRank[declaredPriv.Tier]; !ok {
			return fmt.Errorf("privilege.tier %q is not one of routine|elevated|host-trusting", declaredPriv.Tier)
		}
	}
	for i, g := range declaredPriv.Grants {
		if strings.TrimSpace(g) == "" {
			return fmt.Errorf("privilege.grants[%d] is empty", i)
		}
	}
	if t.RAMFloorMB <= 0 {
		return fmt.Errorf("ramFloorMB must be > 0")
	}
	if t.DeployBudgetSeconds != 0 &&
		(t.DeployBudgetSeconds < DeployBudgetMinSeconds || t.DeployBudgetSeconds > DeployBudgetMaxSeconds) {
		return fmt.Errorf("deployBudgetSeconds %d is out of range: omit it to take the default, or choose %d-%d",
			t.DeployBudgetSeconds, DeployBudgetMinSeconds, DeployBudgetMaxSeconds)
	}

	// Volume classification is authored metadata, so it is checked here for the
	// same reason the privilege tier is: a PREVIEW tile ships no compose and
	// never reaches ValidateTileSafety, and an unclassified volume should
	// surface at publish rather than on the day the tile flips to available.
	if err := validateVolumes(t.Volumes); err != nil {
		return err
	}

	webPorts := 0
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
		if p.Web {
			webPorts++
		}
		if p.TLS && !p.Web {
			return fmt.Errorf("ports[%d] sets tls without web: tls describes the proxy's upstream leg to the web port, and a port the proxy does not front has no upstream leg", i)
		}
	}

	// ZERO OR ONE web port (ADR-0006 Decision 13). Zero is a page-less app —
	// a database, a game server, a headless sync backend — and is a declared
	// shape rather than an omission, which is what the tile.web-port capability
	// is for. Two is still refused: it is real ambiguity about where OPEN
	// points, it is cheap to keep, and nothing has asked for it.
	//
	// The rule this replaces was `len(ports) > 0 && primaries != 1`, which
	// refused precisely the shape a client-connect app wants — declare the port
	// clients dial, front none of it — while letting a tile with no ports at
	// all through. It was a product assumption living in a validator.
	if webPorts > 1 {
		return fmt.Errorf("at most one port may be marked web (found %d): the proxy fronts one port per app", webPorts)
	}

	// Installable tiles must ship a compose stack. Preview tiles are exempt —
	// metadata only until they bench.
	if t.Available() && strings.TrimSpace(t.ComposeYAML) == "" {
		return fmt.Errorf("docker-compose.yml is empty")
	}

	// A tile promising public exposure with nothing to expose is a metadata
	// bug that would otherwise surface as a broken proxy route at install.
	// Public exposure is a WEB affordance: there is no public-facing story for
	// a port the proxy does not front.
	if t.ExposureDefault == "public" && t.Available() && webPorts != 1 {
		return fmt.Errorf("exposureDefault %q requires exactly one web port to expose (found %d)", t.ExposureDefault, webPorts)
	}

	return nil
}

// validateVolumes enforces storage.md §4.2: every volume a tile declares
// carries a backup class, and §4.3: it carries a quiesce strategy too. Both
// from closed enums, neither with a default.
//
// THE MESSAGES ARE THE FEATURE. A tile author who omits a class is not reading
// this file — they are reading one line of CI output — so every refusal names
// the volume by index AND by name (so a tile with a dozen volumes says WHICH
// one), names the field, and prints the legal set. "there is no default" is
// said out loud rather than left to be inferred from the absence of one,
// because the first thing anyone tries on a required-field error is to find
// out what it defaults to.
func validateVolumes(volumes []Volume) error {
	seen := make(map[string]bool, len(volumes))
	for i, v := range volumes {
		name := strings.TrimSpace(v.Name)
		if name == "" {
			return fmt.Errorf("volumes[%d]: name is required — it must match the volume the compose stack declares", i)
		}
		if seen[name] {
			return fmt.Errorf("volumes[%d] %q: duplicate volume name — a classification attached to an ambiguous name is attached to nothing", i, name)
		}
		seen[name] = true

		// Absent and empty are the same case on purpose. Both decode to "",
		// and an empty string is exactly the value a half-finished tile
		// carries; letting it through would reintroduce the default by the
		// back door.
		if strings.TrimSpace(v.Backup) == "" {
			return fmt.Errorf("volumes[%d] %q: backup is required and has no default — declare one of %s",
				i, name, legalValues(BackupClasses))
		}
		if !ValidBackupClass[v.Backup] {
			return fmt.Errorf("volumes[%d] %q: backup %q is not one of %s",
				i, name, v.Backup, legalValues(BackupClasses))
		}
		if strings.TrimSpace(v.Quiesce) == "" {
			return fmt.Errorf("volumes[%d] %q: quiesce is required and has no default — declare one of %s (%q suits most apps; the engine-aware dumps are for the few where a brief outage is harmful)",
				i, name, legalValues(QuiesceStrategies), QuiesceStop)
		}
		if !ValidQuiesce[v.Quiesce] {
			return fmt.Errorf("volumes[%d] %q: quiesce %q is not one of %s",
				i, name, v.Quiesce, legalValues(QuiesceStrategies))
		}

		// --- The one cross-field rule, and the reason it is only one. ---
		//
		// §4.3 observes that `none` is what `cache` AND `bulk` volumes take in
		// the current catalog. Only half of that is an invariant.
		//
		// `cache` is: §4.2 says a cache volume is NEVER copied, so a quiesce
		// strategy on one describes work that cannot happen. It is the same
		// shape as the tls-without-web refusal above — a field qualifying an
		// operation the tile has just said it does not perform — and it fails
		// the same way if allowed, by reading to a reviewer as protection that
		// is not there. Refusing it is cheap and the fix is one word.
		//
		// `bulk` is NOT, and is deliberately left free. A bulk volume IS
		// copied once its app opts in, so a `stop` on a media library the app
		// writes continuously is a legitimate thing for an author to declare.
		// §4.3's table describes how today's eighteen tiles came out, which is
		// an observation about the catalog and not a property of the class;
		// promoting it to a rule would refuse a correct future tile to enforce
		// a pattern nothing depends on. The schema's job here is to make the
		// author answer, not to grade the answer — except where the answer
		// contradicts itself.
		if v.Backup == BackupCache && v.Quiesce != QuiesceNone {
			return fmt.Errorf("volumes[%d] %q: backup %q is never copied, so quiesce %q describes work that never runs — declare quiesce %q, or reclassify the volume if it does need backing up",
				i, name, BackupCache, v.Quiesce, QuiesceNone)
		}
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
//
// WHAT IT NO LONGER DOES, as of Decision 12 (#198). It used to refuse five
// things outright — privileged, host networking, host PID/IPC, any cap_add,
// and bind mounts outside two roots — while reading none of the ten privilege
// dimensions #195 captured. So it blocked Home Assistant, which is must-carry,
// and waved through seccomp=unconfined, which is the closest a stack gets to
// privileged without spelling it that way. Neither half was defensible.
//
// The posture now is "no UNDECLARED privilege": a tile states what it takes,
// this checks the statement against the derived facts, and the owner consents
// to the difference. One absolute refusal survives — the platform's own trust
// chain (12e) — because consent is only meaningful while the thing asking for
// it is still trustworthy. See privilege.go.
func ValidateTileSafety(t Tile, f SafetyFacts) error {
	if len(f.Images) == 0 {
		return fmt.Errorf("no images declared — a stack that pulls nothing cannot be verified")
	}
	for _, img := range f.Images {
		if err := validateImagePin(img); err != nil {
			return fmt.Errorf("image %q: %w", img, err)
		}
	}

	// --- ADR-0006 Decision 12e: the only absolute refusals. ---
	//
	// Everything else below is declarable and consentable. These are not,
	// because consent is only meaningful while the thing asking for it is
	// still trustworthy: an app that can rewrite the trust store authorises
	// every future update, so consenting to it destroys the basis of every
	// later consent. See TrustChainViolation.
	for _, m := range f.BindMounts {
		if !strings.HasPrefix(strings.TrimSpace(m), "/") {
			return fmt.Errorf("bind mount %q is not an absolute path — the daemon resolves it against its own working directory, which nothing here can see", m)
		}
		if hit := TrustChainViolation(m); hit != "" {
			return fmt.Errorf("bind mount %q reaches the platform's own trust chain (%s) — the one privilege no consent can cover", m, hit)
		}
	}
	for _, d := range f.Devices {
		if hit := TrustChainViolation(d); hit != "" {
			return fmt.Errorf("device %q reaches the platform's own trust chain (%s) — the one privilege no consent can cover", d, hit)
		}
	}

	// --- ADR-0006 Decision 12a: the declaration must cover the facts. ---
	//
	// Exactly the shape of the needsHardware check below, which was the one
	// dimension already working this way, generalised to all of them.
	// UNDER-declaration is the error; over-declaration is allowed, because a
	// badge scarier than the stack deserves is a publisher's problem and not a
	// cluster's.
	derived := DerivePrivilege(f)
	declared := t.DeclaredPrivilege()

	if TierRank[declared.EffectiveTier()] < TierRank[derived.Tier] {
		return fmt.Errorf("declares privilege tier %q but its compose takes %q (%s)",
			declared.EffectiveTier(), derived.Tier, strings.Join(derived.Grants, ", "))
	}
	if missing := undeclaredGrants(declared, derived); len(missing) > 0 {
		return fmt.Errorf("compose takes privileges the tile does not declare: %s", strings.Join(missing, ", "))
	}
	if derived.DockerSocket && !declared.DockerSocket {
		return fmt.Errorf("mounts the container runtime socket but does not declare privilege.dockerSocket — it is named separately from the tier because it is the ability to escape any constraint added later")
	}

	// --- ADR-0006 Decision 12d: an older reader must refuse this tile. ---
	//
	// A control plane predating Decision 12 has no privilege vocabulary, so it
	// would install a host-trusting tile with no tier, no badge and no consent
	// prompt. Naming the capability makes Decision 7's must-understand rule
	// refuse it instead — that tile, and only that tile (#162).
	//
	// Routine tiles do NOT name it: requiring it everywhere would make every
	// tile already in the field refused by every cluster already in the field,
	// in order to communicate "this app is ordinary".
	if TierRank[derived.Tier] > TierRank[TierRoutine] && !requires(t, CapabilityPrivilegeTiers) {
		return fmt.Errorf("takes %q privilege but does not list %q in requires — an older control plane must refuse this tile rather than install it unbadged",
			derived.Tier, CapabilityPrivilegeTiers)
	}

	// A stack mapping host devices must say so in its metadata, so the catalog
	// can badge it and the operator is never surprised by a tile reaching for
	// hardware. This is the check that keeps needsHardware honest.
	if len(f.Devices) > 0 && strings.TrimSpace(t.NeedsHardware) == "" {
		return fmt.Errorf("maps host devices (%s) but declares no needsHardware", strings.Join(f.Devices, ", "))
	}

	return nil
}

// undeclaredGrants returns the derived grants the tile did not declare, in
// derivation order (already sorted).
func undeclaredGrants(declared, derived Privilege) []string {
	have := declared.grantSet()
	var missing []string
	for _, g := range derived.Grants {
		if !have[g] {
			missing = append(missing, g)
		}
	}
	return missing
}

// requires reports whether a tile names a capability in its Requires array.
func requires(t Tile, capability string) bool {
	for _, c := range t.Requires {
		if c == capability {
			return true
		}
	}
	return false
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
