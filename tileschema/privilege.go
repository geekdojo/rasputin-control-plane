package tileschema

import (
	"path"
	"sort"
	"strings"
)

// ADR-0006 Decision 12: privilege is DECLARED and CONSENTED, not refused.
//
// This file is the whole of that mechanism on the contract side. Three pieces:
//
//   - a vocabulary — three tiers plus a named grant per privilege a stack takes
//   - DerivePrivilege, which computes that vocabulary from the signed
//     SafetyFacts, so the declaration can be checked against reality
//   - TrustChainViolation, the one thing that stays an absolute refusal (12e)
//
// WHY DERIVE AT ALL, IF THE TILE ALSO DECLARES. Because the declaration is what
// the owner reads and consents to, and the derivation is what makes it honest.
// The pattern already existed for exactly one dimension — host devices must be
// matched by needsHardware — and Decision 12 generalises it. Under-declaration
// is the error; over-declaration is allowed (a scarier badge than the stack
// deserves is a publisher's problem, not a cluster's).
//
// AND WHY THE READER RE-DERIVES rather than trusting the publisher's tier: a
// cluster runs the validator it shipped with. When this file learns to see a
// privilege the publishing build could not, the reader is the side that knows
// more, and the tile is refused — by that cluster, and only that tile (#162).
// That is the intended direction of failure, not an accident of it.

// CapabilityPrivilegeTiers is the Requires capability a tile names when it
// takes ANY privilege above routine (Decision 12d).
//
// The point is what an OLDER control plane does: it has never heard of this
// string, so Decision 7's must-understand rule makes it refuse the tile
// outright rather than install it with no tier, no badge and no consent
// prompt. Silently ignoring a restriction is the failure Decision 7 exists to
// prevent, and an unbadged host-trusting tile is that failure with root
// attached.
//
// A routine tile does NOT name it. Requiring it everywhere would make every
// tile already in the field refused by every cluster already in the field, to
// communicate "this app is ordinary".
const CapabilityPrivilegeTiers = "privilege-tiers-v1"

// The three tiers (Decision 12b).
const (
	// TierRoutine reaches nothing outside its own container.
	TierRoutine = "routine"
	// TierElevated reaches past itself but is not root-equivalent: host
	// networking, specific capabilities, extra bind mounts, a USB dongle.
	TierElevated = "elevated"
	// TierHostTrusting is effectively root on the node.
	TierHostTrusting = "host-trusting"
)

// TierRank orders the tiers. Comparison is always on the rank, never the
// string, so a tier can be inserted later without hunting for < and >.
var TierRank = map[string]int{
	TierRoutine:      0,
	TierElevated:     1,
	TierHostTrusting: 2,
}

// Grant identifiers. Stable machine strings — the UI renders them into
// sentences (#200), and the catalog lints against them (#199), so changing one
// is a contract change, not a copy edit.
const (
	GrantPrivileged        = "privileged"
	GrantHostNetwork       = "host-network"
	GrantHostPIDOrIPC      = "host-pid-ipc"
	GrantDockerSocket      = "docker-socket"
	GrantDockerDataRoot    = "docker-data-root"
	GrantUsernsHost        = "userns-host"
	GrantSeccompUnconfined = "seccomp-unconfined"
	GrantApparmorDisabled  = "apparmor-unconfined"
	GrantSELinuxDisabled   = "selinux-disabled"
)

// Grant prefixes for the dimensions that name a thing.
const (
	GrantPrefixCap           = "cap:"
	GrantPrefixBind          = "bind:"
	GrantPrefixDevice        = "device:"
	GrantPrefixReservedDev   = "reserved-device:"
	GrantPrefixGroup         = "group:"
	GrantPrefixSecurityOpt   = "security-opt:"
	GrantPrefixUserns        = "userns:"
	GrantPrefixVolumesFrom   = "volumes-from:"
	GrantPrefixNamespaceJoin = "namespace-join:"
	GrantPrefixCgroupParent  = "cgroup-parent:"
)

// Privilege is a tile's AUTHORED statement of what its stack takes, and also
// the shape DerivePrivilege returns so the two can be compared directly.
type Privilege struct {
	// Tier is routine | elevated | host-trusting. Empty means routine — the
	// tiles published before Decision 12 omit the field entirely and are all
	// routine by construction, since they passed the absolute refusals this
	// replaces.
	Tier string `json:"tier,omitempty"`

	// DockerSocket is called out separately from the tier (Decision 12b)
	// because it is not merely root-equivalent: it is the ability to escape
	// any FUTURE constraint we add, and it is the specific footgun of this
	// hobby. A tier that hides it inside a general category teaches nothing.
	DockerSocket bool `json:"dockerSocket,omitempty"`

	// Grants is every named privilege the stack takes, sorted. The consent
	// screen is built from this, so "elevated" is never the whole story an
	// owner is shown.
	Grants []string `json:"grants,omitempty"`

	// Why is the author's one-line, owner-facing reason. Not validated beyond
	// its presence for non-routine tiles — a machine cannot tell a good reason
	// from a bad one, but a missing one is visible to a reviewer.
	Why string `json:"why,omitempty"`
}

// EffectiveTier resolves the empty tier to routine.
func (p Privilege) EffectiveTier() string {
	if p.Tier == "" {
		return TierRoutine
	}
	return p.Tier
}

// AtLeast reports whether p's tier is at least as high as other's.
func (p Privilege) AtLeast(tier string) bool {
	return TierRank[p.EffectiveTier()] >= TierRank[tier]
}

// grants renders Grants as a set for superset comparison.
func (p Privilege) grantSet() map[string]bool {
	m := make(map[string]bool, len(p.Grants))
	for _, g := range p.Grants {
		m[strings.TrimSpace(g)] = true
	}
	return m
}

// --- path vocabularies -------------------------------------------------

// RoutineBindRoots are the host paths a tile may bind-mount without that being
// a privilege at all. Formerly AllowedBindRoots, when they were the only paths
// permitted; Decision 12 turns the allowlist into the routine/elevated line.
//
// /var/lib/rasputin/apps/ is per-app persistent data. /etc/localtime is the
// near-universal read-only timezone mount.
var RoutineBindRoots = []string{
	"/var/lib/rasputin/apps/",
	"/etc/localtime",
}

// DockerSocketPaths are the container-runtime control sockets.
var DockerSocketPaths = []string{
	"/var/run/docker.sock",
	"/run/docker.sock",
	"/var/run/containerd/containerd.sock",
	"/run/containerd/containerd.sock",
}

// hostTrustingBindExact are whole trees whose mount is root-equivalent, but
// whose CHILDREN are not. /dev is the reason this list is separate from the
// prefix list: mounting /dev is every device on the node, while mounting
// /dev/bus/usb is a $30 dongle.
var hostTrustingBindExact = []string{"/", "/dev"}

// hostTrustingBindPrefixes are trees where any path at or under them is
// root-equivalent. /proc and /sys are here rather than above because
// /sys/fs/cgroup and /proc/<pid> are exactly the reach that makes a monitoring
// stack host-trusting — the subpath is the point, not a narrowing of it.
//
// /etc is here even though /etc/localtime is routine: RoutineBindRoots is
// consulted FIRST in classifyHostPath, so the timezone file stays free while
// /etc/shadow, /etc/passwd, /etc/sudoers and /etc/ssh are what they are.
//
// The runtime data roots precede /var/lib/rasputin because the loop returns on
// the first match and they have their own grant name.
//
// PlatformStateRoots appear at the end even though TrustChainViolation refuses
// them outright and no tier is ever consulted for a refused tile. Coherence:
// DerivePrivilege is a public function and a caller other than the validator
// may render its answer, so "reaching the trust store is elevated" must not be
// a sentence this package can produce.
var hostTrustingBindPrefixes = []string{
	"/boot", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/root", "/proc", "/sys",
	"/var/lib/docker", "/var/lib/containerd",
	"/var/lib/rasputin/docker", "/var/lib/rasputin/containerd",
	"/var/lib/rasputin", "/etc/rasputin",
}

// escapeCaps are the Linux capabilities that are container escape in practice
// rather than a narrow extra power, so they land host-trusting instead of
// elevated. Named without the CAP_ prefix; the classifier strips it.
//
// Erring high is cheap HERE and only here: nothing in Decision 12 is refused
// for its tier, so over-classifying costs a scarier badge, while
// under-classifying costs an owner who consented to the wrong thing.
var escapeCaps = map[string]bool{
	"ALL":             true, // everything, by definition
	"SYS_ADMIN":       true, // the "new root" — mount, pivot_root, most escapes
	"SYS_MODULE":      true, // load kernel modules
	"SYS_RAWIO":       true, // raw port and /dev/mem access
	"SYS_PTRACE":      true, // attach to processes outside the container with host PID
	"DAC_READ_SEARCH": true, // open_by_handle_at — read any host file given a mount
	"DAC_OVERRIDE":    true, // bypass file permissions on anything mounted
	"BPF":             true, // load BPF programs
}

// hostTrustingGroups are host groups whose membership is root-equivalent.
var hostTrustingGroups = map[string]bool{
	"docker": true, // the runtime socket's group — root by another door
	"disk":   true, // raw block devices, i.e. every filesystem on the node
	"kmem":   true, // kernel memory
}

// --- Decision 12e: the one absolute refusal ---------------------------

// PlatformStateRoots hold the platform's own trust chain and state: the trust
// store, the control plane's database and keys, the agent's credentials.
//
// A ROOT rather than an enumeration of files, deliberately. RASPUTIN_DATA_DIR
// is /var/lib/rasputin on the appliance (rasputin-api.service), so the trust
// dir, the SQLite database, the NATS issuer key, the mesh CA, the TLS leaf
// keys, the staged OS bundles, the agent state, node.env, the tailscale node
// keys and the dropbear host keys are all siblings of the app data directory.
// An enumeration would go stale the first time a feature adds a subdirectory,
// and going stale here means silently becoming mountable.
var PlatformStateRoots = []string{
	"/etc/rasputin",
	"/var/lib/rasputin",
}

// PlatformStateExceptions are the paths inside those roots that are NOT part
// of the trust chain.
//
// The runtime data roots are here because Decision 12b makes the container
// runtime declarable rather than forbidden — the socket is consentable, so its
// storage cannot be more protected than the API that writes it. They are still
// host-trusting; see hostTrustingBindPrefixes.
var PlatformStateExceptions = []string{
	"/var/lib/rasputin/apps",       // per-app persistent data — the whole point
	"/var/lib/rasputin/docker",     // docker data root
	"/var/lib/rasputin/containerd", // containerd data root
}

// TrustChainViolation reports the protected root a host path reaches, or "" if
// it reaches none.
//
// The test is containment in BOTH directions. A path inside a root obviously
// reaches it; a path that CONTAINS a root reaches it just as completely, which
// is why mounting / or /var/lib or /etc is refused and why an enumeration of
// leaf files would not have caught it.
//
// Decision 12e's reasoning is not risk-based, and that matters: a risk-based
// line cannot survive "escape hatches everywhere", because someone will always
// want the risky thing and will usually be right. This line is different.
// Consent is only meaningful while the thing asking for it is still
// trustworthy, and an app that can rewrite the trust store authorises every
// future update. Refusing it is not protecting the owner from themselves; it
// is keeping intact the mechanism by which they choose.
func TrustChainViolation(p string) string {
	if !strings.HasPrefix(p, "/") {
		// A relative path is resolved against the daemon's cwd, which this
		// module cannot see. Unknowable is not the same as safe.
		return "(relative path)"
	}
	clean := path.Clean(p)
	for _, exc := range PlatformStateExceptions {
		if clean == exc || under(clean, exc) {
			return ""
		}
	}
	for _, root := range PlatformStateRoots {
		if clean == root || under(clean, root) || under(root, clean) {
			return root
		}
	}
	return ""
}

// under reports whether a sits strictly inside b.
func under(a, b string) bool {
	return strings.HasPrefix(a, strings.TrimSuffix(b, "/")+"/")
}

// --- the derivation ----------------------------------------------------

type privilegeBuilder struct {
	grants map[string]int
	socket bool
}

func (b *privilegeBuilder) add(tier, grant string) {
	if rank, seen := b.grants[grant]; !seen || TierRank[tier] > rank {
		b.grants[grant] = TierRank[tier]
	}
}

// tierByRank is TierRank inverted, so the derivation can go from "the highest
// rank any grant reached" back to a tier name without searching a map.
var tierByRank = []string{TierRoutine, TierElevated, TierHostTrusting}

func (b *privilegeBuilder) result() Privilege {
	p := Privilege{DockerSocket: b.socket}
	top := 0
	for g, rank := range b.grants {
		p.Grants = append(p.Grants, g)
		if rank > top {
			top = rank
		}
	}
	p.Tier = tierByRank[top]
	sort.Strings(p.Grants)
	return p
}

// DerivePrivilege computes the privilege a stack actually takes from the
// signature-covered facts the publisher derived from its compose.
//
// Pure: no network, no registry, no filesystem, no YAML. That is what lets the
// control plane run it at catalog load, and it is the same constraint
// ValidateTileSafety has always had.
//
// THREE DIMENSIONS #195 CAPTURES ARE DELIBERATELY NOT GRANTS, because a fact
// worth recording for a reviewer is not automatically a privilege:
//
//   - Sysctls — Docker only permits NAMESPACED sysctls, and refuses the rest
//     unless the service also has host networking or host IPC, which are
//     grants in their own right. Tiering every net.core.somaxconn as elevated
//     would make the badge meaningless.
//   - Tmpfs — a mount inside the container. Unbounded it is a memory-exhaustion
//     concern, which is a resource question, not a reach outside the sandbox.
//   - Ulimits — the same: resource shaping, not authority.
//
// VolumesFrom IS a grant, but it needs no special reach-around handling:
// SafetyFacts aggregates bind mounts across the WHOLE stack, so a service
// inheriting the socket from a sibling is already covered by that sibling's
// entry in BindMounts.
func DerivePrivilege(f SafetyFacts) Privilege {
	b := &privilegeBuilder{grants: map[string]int{}}

	if f.Privileged {
		b.add(TierHostTrusting, GrantPrivileged)
	}
	if f.HostNetwork {
		b.add(TierElevated, GrantHostNetwork)
	}
	if f.HostPIDOrIPC {
		// Namespace visibility, not authority: seeing host processes is not
		// signalling them without a capability. Pairing it with SYS_PTRACE is
		// what makes it root, and that pairing raises the tier on its own.
		b.add(TierElevated, GrantHostPIDOrIPC)
	}

	for _, c := range f.CapAdd {
		name := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(c)), "CAP_")
		if name == "" {
			continue
		}
		tier := TierElevated
		if escapeCaps[name] {
			tier = TierHostTrusting
		}
		b.add(tier, GrantPrefixCap+name)
	}

	for _, m := range f.BindMounts {
		classifyHostPath(b, m, GrantPrefixBind)
	}

	for _, d := range f.Devices {
		// /dev whole is host-trusting; a specific node is the dongle tier.
		classifyHostPath(b, d, GrantPrefixDevice)
	}

	for _, o := range f.SecurityOpt {
		switch normalizedOpt(o) {
		case "seccomp=unconfined":
			b.add(TierHostTrusting, GrantSeccompUnconfined)
		case "apparmor=unconfined":
			b.add(TierHostTrusting, GrantApparmorDisabled)
		case "label=disable":
			b.add(TierHostTrusting, GrantSELinuxDisabled)
		case "no-new-privileges=true":
			// A RESTRICTION, not a grant. Recording it as privilege would
			// punish the one security_opt worth encouraging.
		default:
			b.add(TierElevated, GrantPrefixSecurityOpt+normalizedOpt(o))
		}
	}

	for _, u := range f.UsernsMode {
		if strings.EqualFold(strings.TrimSpace(u), "host") {
			b.add(TierHostTrusting, GrantUsernsHost)
			continue
		}
		b.add(TierElevated, GrantPrefixUserns+strings.TrimSpace(u))
	}

	for _, g := range f.GroupAdd {
		name := strings.ToLower(strings.TrimSpace(g))
		tier := TierElevated
		if hostTrustingGroups[name] {
			tier = TierHostTrusting
		}
		b.add(tier, GrantPrefixGroup+strings.TrimSpace(g))
	}

	for _, v := range f.VolumesFrom {
		b.add(TierElevated, GrantPrefixVolumesFrom+strings.TrimSpace(v))
	}
	for _, d := range f.ReservedDevices {
		b.add(TierElevated, GrantPrefixReservedDev+strings.TrimSpace(d))
	}
	for _, c := range f.CgroupParent {
		b.add(TierElevated, GrantPrefixCgroupParent+strings.TrimSpace(c))
	}

	for _, j := range f.NamespaceJoins {
		// "<kind>:service:<name>" names a sibling INSIDE this signed stack —
		// the ordinary VPN-sidecar shape, fully described by the bundle, and
		// no reach outside it. "<kind>:container:<name>" names something the
		// bundle does not describe at all.
		if strings.Contains(j, ":service:") {
			continue
		}
		b.add(TierElevated, GrantPrefixNamespaceJoin+strings.TrimSpace(j))
	}

	return b.result()
}

// classifyHostPath adds the grant for one host path at the right tier, and
// flags the container-runtime socket by name.
func classifyHostPath(b *privilegeBuilder, p, prefix string) {
	raw := strings.TrimSpace(p)
	if raw == "" {
		return
	}
	if !strings.HasPrefix(raw, "/") {
		// Refused outright by ValidateTileSafety; classify defensively in case
		// this is ever called from somewhere that does not.
		b.add(TierHostTrusting, prefix+raw)
		return
	}
	clean := path.Clean(raw)

	for _, sock := range DockerSocketPaths {
		if clean == sock {
			b.socket = true
			b.add(TierHostTrusting, GrantDockerSocket)
			return
		}
	}

	for _, root := range RoutineBindRoots {
		if clean == path.Clean(root) || (strings.HasSuffix(root, "/") && under(clean, root)) {
			return // routine — no grant at all
		}
	}

	for _, exact := range hostTrustingBindExact {
		if clean == exact {
			b.add(TierHostTrusting, prefix+clean)
			return
		}
	}
	for _, pre := range hostTrustingBindPrefixes {
		if clean == pre || under(clean, pre) {
			if pre == "/var/lib/docker" || pre == "/var/lib/rasputin/docker" ||
				pre == "/var/lib/containerd" || pre == "/var/lib/rasputin/containerd" {
				b.add(TierHostTrusting, GrantDockerDataRoot)
				return
			}
			b.add(TierHostTrusting, prefix+clean)
			return
		}
	}

	b.add(TierElevated, prefix+clean)
}

// normalizedOpt lower-cases a security_opt for comparison. The extractor
// already renders it as key=value; this only defends against case.
func normalizedOpt(o string) string { return strings.ToLower(strings.TrimSpace(o)) }
