package storage

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// §4.5's per-node volume fan-out, planned: which volumes a run will try to
// capture, in what order, and — for every one it will not — the reason, by
// name, written down before anything is staged.
//
// # Where the list comes from
//
// There is exactly one source and it is a JOIN, not a new record. The api holds
// an `apps` row per installed app (its id, its instance name, the node it was
// deployed to, and the catalog tile it came from); the catalog holds the tile,
// and the tile's `volumes` array is where §4.2's classification lives — one
// `backup` class and one `quiesce` strategy per compose volume, mandatory,
// authored once and reviewed like any other line of the tile. Joining the two
// on SourceTile is the whole enumeration.
//
// Nothing here invents a parallel source. An app installed from a custom
// compose file has no tile and therefore no classification — see
// ReasonUnclassified for why that is recorded rather than skipped.
//
// # What this build can actually capture, and why the rest is named
//
// A staged copy has to travel from the node that made it to the node holding
// the backup target. For a volume on the CONTROLPLANE node that journey is
// zero: the agent's staging root and the api's are the same directory on the
// same filesystem, which is why this fan-out reads the staged tar directly. For
// a volume on any other node there is no journey at all — the per-node
// streaming path (#295) and the ingest endpoint (#296) are unbuilt.
//
// So the run captures local `critical` and `state` volumes, and RECORDS every
// other classified volume as not captured, by name, with the reason. The one
// thing it must never do is skip one silently: an operator discovering on
// restore day that an app was missing must be able to find the line that said
// so, in the manifest, on the night it happened.

// The reasons a classified volume was not captured. Each is the sentence an
// operator reads beside the volume's name in the manifest, so each says what
// happened AND what would change it.
const (
	// ReasonOffNode is the big one, and the reason this build's scope is
	// proto.BackupScopeControlplaneLocal rather than `full`.
	ReasonOffNode = "hosted on a node other than the controlplane, and nothing yet moves a staged copy off the node that made it: " +
		"the per-node streaming path (geekdojo/geekdojo-brain#295) and the ingest endpoint (#296) are unbuilt"
	// ReasonBulkStreamsDirect: §4.7 streams `bulk` direct rather than staging
	// it — a terabyte media library cannot be staged on a boot medium smaller
	// than it — and the agent's stage verb refuses one by design.
	ReasonBulkStreamsDirect = "classed `bulk`: §4.7 streams bulk volumes direct rather than staging them, and the direct path " +
		"(geekdojo/geekdojo-brain#295) is unbuilt. The agent's staging verb refuses a bulk volume by design"
	// ReasonUnclassified: the app was installed from a custom compose file, so
	// no tile declares its volumes and nothing knows which of them matter.
	//
	// Recorded per APP rather than per volume, because with no tile there is no
	// list of volume names to record — which is precisely the gap worth stating.
	ReasonUnclassified = "installed from a custom compose file rather than a catalog tile, so no tile declares its volumes or " +
		"their backup class (§4.2). Nothing knows which of this app's volumes hold data worth keeping"
	// ReasonTileWithdrawn: the app names a tile the catalog no longer has.
	ReasonTileWithdrawn = "was installed from a catalog tile this build no longer ships, so its volumes have no classification to act on"
)

// AppVolumeStagePrefix is the directory every captured volume lands under
// inside the archive, and it is the restore side's contract (#291, unbuilt).
//
// One member per volume, named `app-volumes/<app>/<volume>.tar`, whose content
// is the agent's tar of that volume's contents with paths relative to the
// volume root. A flattened tree would make a restore guess which file belonged
// to which app; this way the name carries both, and an operator holding a
// decrypted archive can see what they have with `tar tf`.
const AppVolumeStagePrefix = "app-volumes"

// PlannedVolume is one volume this run intends to stage, in the order it will
// be staged.
type PlannedVolume struct {
	AppID   string
	AppName string
	TileID  string
	NodeID  string
	Volume  string
	Class   string
	Quiesce string
}

// ArchivePath is where this volume's staged tar goes inside the archive.
func (p PlannedVolume) ArchivePath() string {
	return path.Join(AppVolumeStagePrefix, sanitizeMember(p.AppName), sanitizeMember(p.Volume)+".tar")
}

// String is the "app/volume" identifier used in log lines and in the report's
// Captured list. Short enough for a log line, unambiguous enough to grep for.
func (p PlannedVolume) String() string { return p.AppName + "/" + p.Volume }

// sanitizeMember keeps an app or volume name to characters that are safe and
// obvious inside a tar member path.
//
// App names and tile volume names are already constrained upstream — an app
// name is a DNS label and a tile's volume name is a compose volume — but this
// path is written into an archive a restore will later expand, and a member
// path is the classic way a tar becomes a write outside its destination. So the
// shape is enforced HERE, at the moment of writing, rather than trusted from
// two validators away: anything that is not [A-Za-z0-9._-] becomes an
// underscore, and a leading dot is refused a leading position.
func sanitizeMember(s string) string {
	s = strings.TrimSpace(s)
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	res := strings.TrimLeft(string(out), ".")
	if res == "" {
		return "unnamed"
	}
	return res
}

// VolumeRecord is the manifest's row for ONE classified volume — captured or
// not, and it is present either way.
//
// Every field §4.5 and §4.7 make an operator's business: what it is, how it was
// made consistent, whether it is actually in the archive, and what it cost the
// service to take. A record with Captured false and an empty Reason is a bug,
// and the fan-out will not produce one.
type VolumeRecord struct {
	// App is the instance name, AppID the ULID, Node the node the app is
	// deployed to. All three, because an operator reads the name and a restore
	// matches the id.
	App    string `json:"app"`
	AppID  string `json:"appId,omitempty"`
	TileID string `json:"tile,omitempty"`
	Node   string `json:"node,omitempty"`
	// Volume is the tile's declared compose volume name; Class its §4.2 class;
	// Strategy the §4.3 quiesce strategy the tile declared for it.
	Volume   string `json:"volume"`
	Class    string `json:"class"`
	Strategy string `json:"strategy,omitempty"`

	// Captured is the only field a hurried reader will look at, so everything
	// else is arranged around making it honest.
	Captured bool `json:"captured"`
	// Reason is why it is NOT in the archive. Mandatory whenever Captured is
	// false — a volume that vanished without a sentence is the failure this
	// whole structure exists to prevent.
	Reason string `json:"reason,omitempty"`

	// Path is the member inside the archive, present only when Captured.
	Path string `json:"path,omitempty"`
	// SizeBytes is the staged tar's length, PlaintextBytes the sum of the
	// volume's own file sizes, FileCount how many regular files it held.
	SizeBytes      uint64 `json:"sizeBytes,omitempty"`
	PlaintextBytes uint64 `json:"plaintextBytes,omitempty"`
	FileCount      int    `json:"fileCount,omitempty"`
	// SHA256 is over the staged tar, lower-case hex — the digest the agent
	// computed while writing AND the api re-computed before consuming it. They
	// agreed, or this record would not exist.
	SHA256 string `json:"sha256,omitempty"`

	// Consistency is proto.BackupConsistency — what this copy is consistent
	// WITH — and Window the same thing in an operator's words. A restore reads
	// these to know what it is holding.
	Consistency string `json:"consistency,omitempty"`
	Window      string `json:"window,omitempty"`

	// ServiceInterrupting says taking this copy took the app down, and
	// DowntimeMillis says for how long. §4.7's cost, measured and recorded:
	// an operator should be able to read that Vaultwarden was down for four
	// seconds without having to reconstruct it from timestamps.
	ServiceInterrupting bool  `json:"serviceInterrupting"`
	DowntimeMillis      int64 `json:"downtimeMillis"`
	// AppRestored is false when the app was stopped for this copy and did not
	// come back. It is the loudest field in the file: §4.7 says an app left
	// down by a backup is worse than a failed backup, and a run that sees one
	// ends FAILED with the app named.
	AppRestored   bool   `json:"appRestored"`
	RestoreDetail string `json:"restoreDetail,omitempty"`
	// Databases lists, for `sqlite`, the databases snapshotted through the
	// running app rather than copied live, and SnapshotTool what took them.
	Databases    []string `json:"databases,omitempty"`
	SnapshotTool string   `json:"snapshotTool,omitempty"`
}

// notCaptured builds the record for a volume this run will not take.
func notCaptured(v PlannedVolume, reason string) VolumeRecord {
	return VolumeRecord{
		App: v.AppName, AppID: v.AppID, TileID: v.TileID, Node: v.NodeID,
		Volume: v.Volume, Class: v.Class, Strategy: v.Quiesce,
		Captured: false, Reason: reason,
		// An app that was never touched is, trivially, in the state it was
		// found in. Saying so explicitly keeps the "any app left down" scan a
		// scan of one field rather than of a field and a condition.
		AppRestored: true,
	}
}

// TileVolumes is the catalog lookup the plan needs, narrowed to the one method
// it calls.
//
// An interface rather than *catalog.Catalog so a test can plan against a tile
// set it wrote three lines ago instead of against the shipped catalog — the
// classification is content, and a planner test that broke every time a tile
// was re-classified would be testing the content rather than the join.
type TileVolumes interface {
	Get(id string) (tileschema.Tile, bool)
}

// PlanAppVolumes is §4.5's contents list, resolved against what is actually
// installed.
//
// It returns two things and both matter: the volumes this run will STAGE, in
// the order it will stage them, and the records for every classified volume it
// will NOT — already complete, already carrying their reason, so a run that
// dies in the middle still has them.
//
// # The order, and why it is this one
//
// Class first (`critical` before `state`), then app name, then volume name.
//
// Class first because staging is serial and a run can die part-way — the disk
// fills, the power goes, an RPC times out. When it does, what is already in the
// growing archive should be the data whose loss costs the most: §4.2's
// `critical` is defined as the class whose loss costs the owner their password
// vault rather than an afternoon. Alphabetical within a class because the order
// then depends on nothing but the input, so two runs over an unchanged cluster
// produce the same sequence and a diff between two generations means something.
//
// Grouping by app instead would be the obvious alternative — it would look like
// it reduced the number of times an app is stopped. It does not: the agent's
// verb (proto.BackupStageVolumeCmd) stages ONE volume and applies the tile's
// strategy for it, so a `stop`-strategy app with two volumes is stopped twice
// whichever order they are asked for in. Batching them into one stop is a
// change to that verb, and this fan-out consumes the verb rather than
// redesigning it.
func PlanAppVolumes(installed []*apps.App, tiles TileVolumes, controlplaneNodeID string) (stage []PlannedVolume, skipped []VolumeRecord) {
	self := strings.TrimSpace(controlplaneNodeID)
	for _, a := range installed {
		if a == nil {
			continue
		}
		tileID := strings.TrimSpace(a.SourceTile)
		if tileID == "" {
			skipped = append(skipped, notCaptured(PlannedVolume{
				AppID: a.ID, AppName: a.Name, NodeID: a.TargetNode,
				Volume: "(unknown — no tile)", Class: "unclassified",
			}, ReasonUnclassified))
			continue
		}
		tile, ok := tiles.Get(tileID)
		if !ok {
			skipped = append(skipped, notCaptured(PlannedVolume{
				AppID: a.ID, AppName: a.Name, TileID: tileID, NodeID: a.TargetNode,
				Volume: "(unknown — tile withdrawn)", Class: "unclassified",
			}, ReasonTileWithdrawn))
			continue
		}
		for _, v := range tile.Volumes {
			pv := PlannedVolume{
				AppID: a.ID, AppName: a.Name, TileID: tileID, NodeID: a.TargetNode,
				Volume: strings.TrimSpace(v.Name), Class: v.Backup, Quiesce: v.Quiesce,
			}
			switch v.Backup {
			case tileschema.BackupCache:
				// §4.2: never copied, ever. Not a gap and not a record — it is
				// in the manifest's Excluded list, which is where "we
				// deliberately do not take this" belongs. Counting it as a
				// missed volume would mean no archive could ever be complete.
				continue
			case tileschema.BackupBulk:
				skipped = append(skipped, notCaptured(pv, ReasonBulkStreamsDirect))
				continue
			case tileschema.BackupCritical, tileschema.BackupState:
				if self == "" || strings.TrimSpace(pv.NodeID) != self {
					skipped = append(skipped, notCaptured(pv, ReasonOffNode))
					continue
				}
				stage = append(stage, pv)
			default:
				// A class the validator does not allow. It cannot reach a
				// shipped tile, and if it ever did, the honest answer is that
				// nothing knows what to do with it — not that it was fine.
				skipped = append(skipped, notCaptured(pv, fmt.Sprintf(
					"declares backup class %q, which is not one of %s. Nothing knows whether this volume holds data worth keeping",
					v.Backup, strings.Join(tileschema.BackupClasses, "|"))))
			}
		}
	}
	sort.SliceStable(stage, func(i, j int) bool {
		if ri, rj := classRank(stage[i].Class), classRank(stage[j].Class); ri != rj {
			return ri < rj
		}
		if stage[i].AppName != stage[j].AppName {
			return stage[i].AppName < stage[j].AppName
		}
		return stage[i].Volume < stage[j].Volume
	})
	sort.SliceStable(skipped, func(i, j int) bool {
		if ri, rj := classRank(skipped[i].Class), classRank(skipped[j].Class); ri != rj {
			return ri < rj
		}
		if skipped[i].App != skipped[j].App {
			return skipped[i].App < skipped[j].App
		}
		return skipped[i].Volume < skipped[j].Volume
	})
	return stage, skipped
}

// classRank orders the classes by what their loss costs, which is the order a
// partial run should have captured them in.
func classRank(class string) int {
	switch class {
	case tileschema.BackupCritical:
		return 0
	case tileschema.BackupState:
		return 1
	case tileschema.BackupBulk:
		return 2
	case tileschema.BackupCache:
		return 3
	default:
		return 4
	}
}
