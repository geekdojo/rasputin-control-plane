package releases

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Update-status values reported per component.
const (
	StatusUpToDate        = "up_to_date"
	StatusUpdateAvailable = "update_available"
	StatusNoRelease       = "no_release" // channel has no release for this component
	StatusUnknown         = "unknown"    // can't compare (no node, unparseable version, fetch error)
	// StatusNeedsAttention: the comparison says up to date, but at least one
	// node running this component has an UNCONFIRMED version — inventory is
	// holding a value an update outcome told us not to trust (ADR-0005
	// Decision 4). Distinct from unknown, which means we could not compare at
	// all; here we compared fine and the inputs are suspect.
	//
	// It exists because the alternative is worse in exactly the case that
	// matters: a stranded node reporting the version it was MEANT to reach
	// makes the whole component read green, which is how bench node c08
	// disappeared from "what needs updating" while sitting on the old image.
	StatusNeedsAttention = "needs_attention"
)

// ComponentStatus is the per-component result of a check.
type ComponentStatus struct {
	Component  string `json:"component"`
	Label      string `json:"label"`
	Channel    string `json:"channel"`
	Installed  string `json:"installed"`
	Latest     string `json:"latest"`
	Status     string `json:"status"`
	Kind       string `json:"kind"`
	Deployable bool   `json:"deployable"`

	// Populated for deployable (OS) updates so the UI can offer a one-click
	// "Download & stage" → POST /api/updates/pull.
	BundleSHA256 string `json:"bundleSha256,omitempty"`
	AssetName    string `json:"assetName,omitempty"`
	SizeBytes    int64  `json:"sizeBytes,omitempty"`
	SignedBy     string `json:"signedBy,omitempty"`
	// Staged is set by the api handler (not Check). True only when every
	// artifact the FLEET NEEDS is present in the local bundle store — see
	// Artifacts. A component whose amd64 bundle is staged and whose arm64
	// bundle is not is emphatically not "staged" on a cluster with Pis in it,
	// and reading it as such is how a half-staged release stayed invisible.
	Staged bool `json:"staged,omitempty"`

	// Artifacts is every deployable artifact in the latest release — one per
	// architecture — with whether it is staged and how many nodes need it.
	// A release is one artifact per arch, so a single `staged` bool and a
	// single bundleSha256 could never describe a mixed-arch cluster's real
	// state. ADR-0005 Decision 11.
	Artifacts []ArtifactStatus `json:"artifacts,omitempty"`

	// Display-only components (firewall) carry a neutral instruction + the
	// image asset name to copy.
	ManualInstructions string `json:"manualInstructions,omitempty"`
	Note               string `json:"note,omitempty"`

	// Bundled lists software that ships *inside* this component's image rather
	// than as its own updatable component — e.g. the control-plane binary
	// inside the OS. Display-only: a detail line on the row, never its own
	// update status. Populated by Check for the OS row.
	Bundled []BundledComponent `json:"bundled,omitempty"`

	// Diagnostic detail when Status == unknown.
	Error string `json:"error,omitempty"`
}

// ArtifactStatus is one architecture's deployable artifact within a release,
// and whether this cluster has it staged. The set of these is what makes a
// half-staged release visible: three arm64 nodes and no arm64 bundle is a
// fact the operator can act on, where a bare "staged" tick is not.
type ArtifactStatus struct {
	Architecture string `json:"architecture"`
	Compatible   string `json:"compatible"`
	BundleSHA256 string `json:"bundleSha256"`
	AssetName    string `json:"assetName,omitempty"`
	SizeBytes    int64  `json:"sizeBytes,omitempty"`
	// Staged is filled by the api handler from the local bundle store.
	Staged bool `json:"staged"`
	// NeededBy is how many inventory nodes would take this artifact. Zero
	// means the cluster has no hardware of that arch, which is why a missing
	// artifact is not automatically a problem — an all-N100 cluster is fully
	// staged without ever downloading the Pi bundle.
	NeededBy int `json:"neededBy"`
}

// BundledComponent is a piece of software carried inside another component's
// image, surfaced for visibility (support/debugging) without implying it can
// be updated on its own.
type BundledComponent struct {
	Label   string `json:"label"`
	Version string `json:"version"`
}

// CheckResult is the full report returned to the UI.
type CheckResult struct {
	Channel    string            `json:"channel"`
	CheckedAt  time.Time         `json:"checkedAt"`
	Components []ComponentStatus `json:"components"`
}

const firewallManualNote = "Automated firewall updates aren't available yet. Download the firewall image below and apply it from the firewall's recovery console, then re-run setup."

// controlPlaneLabel names the control-plane software where it's folded into the
// OS row's bundled detail.
const controlPlaneLabel = "Control-plane software"

// Check fetches the latest release for every registered component on the
// given channel and compares it against the installed version reported by the
// matching node. Pure given a Source + node list (the api handler supplies
// inventory). Never returns an error: per-component failures degrade to a
// StatusUnknown row so the UI can render a partial report.
func Check(ctx context.Context, src Source, channel string, nodes []*proto.Node) CheckResult {
	res := CheckResult{Channel: channel, CheckedAt: time.Now().UTC()}
	for _, comp := range Components {
		res.Components = append(res.Components, checkOne(ctx, src, channel, comp, nodes))
	}
	// Fold the running control-plane version into the OS row as a display-only
	// detail — the cp software ships inside the OS image, so it has no update
	// path of its own. Shown for support visibility, never as a status row.
	if cp := controlPlaneVersion(nodes); cp != "" {
		for i := range res.Components {
			if res.Components[i].Component == "os" {
				res.Components[i].Bundled = append(res.Components[i].Bundled,
					BundledComponent{Label: controlPlaneLabel, Version: cp})
				break
			}
		}
	}
	return res
}

// controlPlaneVersion returns the control-plane software version reported by
// the controlplane node (its agent version), or "" if no controlplane node has
// reported yet.
func controlPlaneVersion(nodes []*proto.Node) string {
	for _, n := range nodes {
		if n.Role == proto.RoleControlPlane {
			return n.AgentVersion
		}
	}
	return ""
}

func checkOne(ctx context.Context, src Source, channel string, comp Component, nodes []*proto.Node) ComponentStatus {
	cs := ComponentStatus{
		Component: comp.ID, Label: comp.Label, Channel: channel,
		Kind: string(comp.Kind), Deployable: comp.Deployable,
	}
	cs.Installed = installedVersion(nodes, comp)

	info, err := src.LatestFor(ctx, comp, channel)
	if err != nil {
		// The raw error can name internal hosts, the upstream resolver IP, and
		// Go net internals — log it for operators, but show the UI a short,
		// vendor-neutral, actionable message instead.
		log.Printf("releases: check %s on channel %q: %v", comp.ID, channel, err)
		cs.Status, cs.Error = StatusUnknown, friendlyFetchError(err)
		return cs
	}
	if info == nil {
		cs.Status = StatusNoRelease
		return cs
	}
	cs.Latest = info.Version

	if cs.Installed == "" {
		// No node of the compare role is registered (e.g. no firewall yet),
		// or it never reported a version. Show what's available, mark unknown.
		cs.Status = StatusUnknown
	} else if newer, err := IsNewer(comp.Scheme, cs.Installed, cs.Latest); err != nil {
		cs.Status, cs.Error = StatusUnknown, err.Error()
	} else if newer {
		cs.Status = StatusUpdateAvailable
		// Name the node(s) that lag latest so the operator knows where to deploy
		// — the controlplane may already be current while a compute node trails.
		if lag := laggingNodes(nodes, comp, cs.Latest); len(lag) > 0 {
			cs.Note = "Behind latest: " + strings.Join(lag, ", ")
		}
	} else {
		cs.Status = StatusUpToDate
	}

	// An unconfirmed node poisons a green verdict, and only a green one. If the
	// component already reads update_available the operator is being sent to the
	// Updates page regardless, so the unconfirmed node is a note on top of an
	// action they are already taking; if it reads up to date, that verdict is
	// resting on a version we have been told not to trust, and it must not
	// stand. ADR-0005 Decision 4.
	//
	// Note that excluding unconfirmed nodes from the comparison instead would
	// NOT fix this: the c08 case is a single stranded node among a fleet that
	// genuinely is current, so dropping it just leaves the remaining nodes
	// agreeing on latest — green again, with the stranded node now invisible
	// rather than merely miscounted.
	if unconfirmed := unconfirmedNodes(nodes, comp); len(unconfirmed) > 0 {
		if cs.Status == StatusUpToDate {
			cs.Status = StatusNeedsAttention
		}
		cs.Note = appendNote(cs.Note, "Version unconfirmed (last update didn't verify): "+strings.Join(unconfirmed, ", "))
	}

	cs.Artifacts = artifactStatuses(info, comp, nodes)

	// Attach deploy/display metadata from the matching artifact.
	if art, ok := info.Artifact(comp.Compatible); ok {
		cs.SignedBy = art.SignedBy
		switch comp.Kind {
		case KindRAUC:
			cs.BundleSHA256 = art.SHA256
			cs.AssetName = art.Raucb
			cs.SizeBytes = art.SizeBytes
		case KindRootfsAB:
			// Firewall A/B: the deployable OTA artifact is the rootfs squashfs.
			cs.BundleSHA256 = art.RootfsSha256
			cs.AssetName = art.Rootfs
			cs.SizeBytes = art.RootfsSizeBytes
		case KindSysupgrade:
			cs.AssetName = art.Image
			if cs.Status == StatusUpdateAvailable {
				cs.ManualInstructions = firewallManualNote
			}
		}
	}
	return cs
}

// artifactStatuses enumerates every deployable artifact in the release — one
// per arch — and counts the nodes that would take each. Staged is left false;
// only the api handler can see the local bundle store.
//
// A component with no deployable OTA artifact (KindSysupgrade, the display-only
// firewall path) yields none, which is correct: there is nothing to stage.
func artifactStatuses(info *ReleaseInfo, comp Component, nodes []*proto.Node) []ArtifactStatus {
	if info == nil {
		return nil
	}
	var out []ArtifactStatus
	for i := range info.Manifest.Artifacts {
		a := &info.Manifest.Artifacts[i]
		name, sha, size, ok := a.OTAAsset(comp.Kind)
		if !ok {
			continue
		}
		out = append(out, ArtifactStatus{
			Architecture: a.Architecture,
			Compatible:   a.Compatible,
			BundleSHA256: sha,
			AssetName:    name,
			SizeBytes:    size,
			NeededBy:     nodesNeeding(nodes, comp, a.Compatible),
		})
	}
	return out
}

// nodesNeeding counts the nodes that run comp's image AND whose architecture
// resolves to this artifact's SKU. This is what makes "not staged" actionable
// rather than alarming: an all-N100 cluster genuinely does not need the Pi
// bundle, and must not be told it is half-staged for lacking it.
//
// A node whose arch does not resolve is counted against NO artifact. It is
// not silently attributed to one either — that is exactly the guess #67 is
// about, and inventing a number here would put it back in a second place.
func nodesNeeding(nodes []*proto.Node, comp Component, compatible string) int {
	n := 0
	for _, node := range nodes {
		if !runsComponent(node, comp) {
			continue
		}
		want, known := ArchCompatible(node.Architecture)
		if comp.Kind == KindRootfsAB {
			// The firewall's artifact is selected by its own SKU, not by arch.
			want, known = comp.Compatible, true
		}
		if known && want == compatible {
			n++
		}
	}
	return n
}

// runsComponent reports whether a node runs comp's image (by role).
func runsComponent(n *proto.Node, comp Component) bool {
	for _, r := range comp.CompareRoles {
		if n.Role == r {
			return true
		}
	}
	return false
}

// nodeVersion is the installed version a node reports for comp's field.
func nodeVersion(n *proto.Node, comp Component) string {
	if comp.CompareField == "agent" {
		return n.AgentVersion
	}
	return n.ImageVersion
}

// installedVersion returns the OLDEST version reported across all nodes that run
// comp's image, so the component reads "update available" if ANY node lags
// latest — not only the controlplane. "" when no such node has reported one.
func installedVersion(nodes []*proto.Node, comp Component) string {
	oldest := ""
	for _, n := range nodes {
		if !runsComponent(n, comp) {
			continue
		}
		v := nodeVersion(n, comp)
		if v == "" {
			continue
		}
		if oldest == "" {
			oldest = v
			continue
		}
		// IsNewer(scheme, v, oldest) == "oldest is newer than v" → v is older.
		if older, err := IsNewer(comp.Scheme, v, oldest); err == nil && older {
			oldest = v
		}
	}
	return oldest
}

// unconfirmedNodes lists "id (version)" for every node running comp whose
// image version carries no confirmation — inventory is holding the last thing
// it was told by a node that an update outcome then failed to verify.
//
// Only meaningful for image versions. A component compared on the AGENT version
// (CompareField == "agent") is unaffected: image_version_confirmed_at says
// nothing about agent_version, and treating it as if it did would make an
// unrelated component read yellow for a reason its operator cannot act on.
func unconfirmedNodes(nodes []*proto.Node, comp Component) []string {
	if comp.CompareField == "agent" {
		return nil
	}
	var out []string
	for _, n := range nodes {
		if !runsComponent(n, comp) || n.ImageVersionConfirmedAt != nil {
			continue
		}
		v := n.ImageVersion
		if v == "" {
			v = "no version reported"
		}
		out = append(out, fmt.Sprintf("%s (%s)", n.ID, v))
	}
	return out
}

// appendNote joins note fragments so a row can carry both "behind latest" and
// "unconfirmed" without one silently replacing the other — they are different
// problems on (possibly) different nodes.
func appendNote(existing, add string) string {
	if existing == "" {
		return add
	}
	return existing + " · " + add
}

// laggingNodes lists "id (version)" for every node running comp whose version is
// older than latest — the nodes the operator needs to deploy the update to.
func laggingNodes(nodes []*proto.Node, comp Component, latest string) []string {
	var out []string
	for _, n := range nodes {
		if !runsComponent(n, comp) {
			continue
		}
		v := nodeVersion(n, comp)
		if v == "" {
			continue
		}
		if behind, err := IsNewer(comp.Scheme, v, latest); err == nil && behind {
			out = append(out, fmt.Sprintf("%s (%s)", n.ID, v))
		}
	}
	return out
}
