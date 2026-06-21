package releases

import (
	"context"
	"log"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Update-status values reported per component.
const (
	StatusUpToDate        = "up_to_date"
	StatusUpdateAvailable = "update_available"
	StatusNoRelease       = "no_release" // channel has no release for this component
	StatusUnknown         = "unknown"    // can't compare (no node, unparseable version, fetch error)
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
	// Staged is set by the api handler (not Check) when the bundle for this
	// update is already present in the local bundle store.
	Staged bool `json:"staged,omitempty"`

	// Display-only components (firewall) carry a neutral instruction + the
	// image asset name to copy; informational components (cp) carry a note.
	ManualInstructions string `json:"manualInstructions,omitempty"`
	Note               string `json:"note,omitempty"`

	// Diagnostic detail when Status == unknown.
	Error string `json:"error,omitempty"`
}

// CheckResult is the full report returned to the UI.
type CheckResult struct {
	Channel    string            `json:"channel"`
	CheckedAt  time.Time         `json:"checkedAt"`
	Components []ComponentStatus `json:"components"`
}

const firewallManualNote = "Automated firewall updates aren't available yet. Download the firewall image below and apply it from the firewall's recovery console, then re-run setup."
const cpShipsInOSNote = "Control-plane software ships inside the OS image — update the OS to update it."

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
	return res
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
	} else {
		cs.Status = StatusUpToDate
	}

	// Informational components (cp) carry their note regardless of whether the
	// release ships a hardware artifact (it ships only a version manifest).
	if comp.Kind == KindInfo {
		cs.Note = cpShipsInOSNote
	}
	// Attach deploy/display metadata from the matching artifact.
	if art, ok := info.Artifact(comp.Compatible); ok {
		cs.SignedBy = art.SignedBy
		switch comp.Kind {
		case KindRAUC:
			cs.BundleSHA256 = art.SHA256
			cs.AssetName = art.Raucb
			cs.SizeBytes = art.SizeBytes
		case KindSysupgrade:
			cs.AssetName = art.Image
			if cs.Status == StatusUpdateAvailable {
				cs.ManualInstructions = firewallManualNote
			}
		}
	}
	return cs
}

func installedVersion(nodes []*proto.Node, comp Component) string {
	for _, n := range nodes {
		if n.Role != comp.CompareRole {
			continue
		}
		if comp.CompareField == "agent" {
			return n.AgentVersion
		}
		return n.ImageVersion
	}
	return ""
}
