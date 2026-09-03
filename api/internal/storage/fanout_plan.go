package storage

import (
	"fmt"
	"sort"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/proto"
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
// # Every node, one path
//
// A staged copy travels from the node that made it to the backup target
// through the transport in backupxfer: the hosting agent stages the volume
// (proto.BackupStageVolumeCmd), seals it to the target's public key and
// uploads it to the api's ingest endpoint on a credential minted for that one
// member (proto.BackupTransferCmd), and the api unstages it. The controlplane's
// own volumes take exactly the same path over loopback — there is no local
// shortcut, so there is one layout on the disk and one code path to test.
//
// So the plan stages every `critical` and `state` volume on every node. What
// it will NOT take is still recorded, by name, with the reason: `bulk` (a
// different lane, §4.7), an app with no tile, a tile the catalog withdrew, a
// tile that declares nothing. The one thing it must never do is skip one
// silently.
//
// # Failed, not skipped
//
// §4.4: a node offline at backup time makes that app's backup FAILED, not
// skipped. The plan cannot know which nodes are up — that is discovered when
// the stage verb is sent — so the distinction is on the record, not the plan:
// VolumeRecord.Failed marks a volume this run TRIED to take and could not,
// and any such record ends the run failed with the volume named (runPrune).
// A volume the run never intended to take (bulk, unclassified) is not
// captured and not failed; it makes the archive incomplete without making
// the run red.

// The reasons a classified volume was not captured. Each is the sentence an
// operator reads beside the volume's name in the manifest, so each says what
// happened AND what would change it.
const (
	// ReasonBulkStreamsDirect: §4.7 streams `bulk` direct rather than staging
	// it — a terabyte media library cannot be staged on a boot medium smaller
	// than it — and the agent's stage verb refuses one by design. The direct
	// lane is not part of this transport: it needs a stream-as-it-reads walk
	// with no staged copy, no known length before the first byte, and (per
	// §4.6's decision) no seal, and it is opt-in per app. It is recorded here
	// so no `bulk` volume ever vanishes from a manifest.
	ReasonBulkStreamsDirect = "classed `bulk`: §4.7 streams bulk volumes direct rather than staging them, and the direct-stream lane " +
		"is not built — this transport carries staged, sealed `critical`/`state` volumes only. The agent's staging verb refuses a bulk volume by design"
	// ReasonUnclassified: the app was installed from a custom compose file, so
	// no tile declares its volumes and nothing knows which of them matter.
	//
	// Recorded per APP rather than per volume, because with no tile there is no
	// list of volume names to record — which is precisely the gap worth stating.
	ReasonUnclassified = "installed from a custom compose file rather than a catalog tile, so no tile declares its volumes or " +
		"their backup class (§4.2). Nothing knows which of this app's volumes hold data worth keeping"
	// ReasonTileWithdrawn: the app names a tile the catalog no longer has.
	ReasonTileWithdrawn = "was installed from a catalog tile this build no longer ships, so its volumes have no classification to act on"
	// ReasonTileDeclaresNoVolumes: the tile exists in the catalog in effect and
	// declares NO volumes. A format, filled with the tile id, the catalog that
	// answered (TileVolumes.Source) and the tile id again.
	//
	// This is the record the 2026-09-03 e3bench run did not have. The plan
	// found the tile, the tile's `volumes` was empty, the inner loop never ran,
	// and the app fell out of the manifest without a line — which is
	// indistinguishable from an app that has no data. tileschema says it in
	// Tile.Volumes: an empty array "is NOT a promise that the stack has no
	// volumes", it is what every tile published before §4.2 looks like. So the
	// app is recorded, per app, exactly like ReasonUnclassified, and the
	// record names the catalog so an operator can tell "the floor a fresh
	// cluster boots on" from "the published catalog still has this gap".
	ReasonTileDeclaresNoVolumes = "was installed from catalog tile `%s`, and that tile as this cluster holds it (catalog %s) declares no volumes. " +
		"An absent `volumes` array is what every tile published before §4.2's classification looks like — it is not a promise that the app has no data — " +
		"so nothing knows which of this app's volumes hold data worth keeping, and none was captured. " +
		"A catalog whose `%s` tile classifies its volumes is needed: Apps → Catalog → CHECK NOW fetches the newest"
)

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

// Member is this volume's sealed member inside the generation directory —
// volumes/<app>/<volume>.rasputin-archive, the restore side's contract (#291).
// One member per volume, named for both, so a restore never guesses which
// file belonged to which app; the name is minted by proto so the ingest
// endpoint's containment check and this minting cannot disagree.
func (p PlannedVolume) Member() string { return proto.BackupMemberPath(p.AppName, p.Volume) }

// String is the "app/volume" identifier used in log lines and in the report's
// Captured list.
func (p PlannedVolume) String() string { return p.AppName + "/" + p.Volume }

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
	// Failed is true when this run TRIED to take the volume and could not —
	// the node was offline, the agent refused, the upload did not land, a
	// digest disagreed. §4.4: failed, not skipped, and a run with one ends
	// FAILED with the volume named. False on a volume the run never intended
	// to take (bulk, unclassified), which makes the archive incomplete
	// without making the run red.
	Failed bool `json:"failed"`
	// Reason is why it is NOT in the generation. Mandatory whenever Captured
	// is false — a volume that vanished without a sentence is the failure
	// this whole structure exists to prevent.
	Reason string `json:"reason,omitempty"`

	// Member is the sealed file inside the generation directory, relative to
	// it: volumes/<app>/<volume>.rasputin-archive. Present only when
	// Captured. THE index entry a restore reads — a file in the generation
	// that no record names is not part of the generation.
	Member string `json:"member,omitempty"`
	// SealedBy is the node that sealed the member — where the ephemeral key
	// was minted and where the bytes were encrypted. KeyID is the target
	// keypair it is sealed to, the same for every member of a generation.
	SealedBy string `json:"sealedBy,omitempty"`
	KeyID    string `json:"keyId,omitempty"`
	// SealedSHA256 and SealedSizeBytes are over the member as it sits on the
	// disk, computed by the ingest endpoint over the bytes it wrote and equal
	// to what the sealing node declared. What a restore verifies BEFORE
	// spending a passphrase.
	SealedSHA256    string `json:"sealedSha256,omitempty"`
	SealedSizeBytes uint64 `json:"sealedSizeBytes,omitempty"`
	// SizeBytes is the staged tar's length inside the seal, PlaintextBytes the
	// sum of the volume's own file sizes, FileCount how many regular files it
	// held.
	SizeBytes      uint64 `json:"sizeBytes,omitempty"`
	PlaintextBytes uint64 `json:"plaintextBytes,omitempty"`
	FileCount      int    `json:"fileCount,omitempty"`
	// SHA256 is over the staged tar — the plaintext inside the member — as
	// the agent computed it while staging and re-computed it while sealing.
	// They agreed, or this record would be a failure. What a restore verifies
	// AFTER decrypting.
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

// failedVolume builds the record for a volume this run tried to take and
// could not. §4.4's "failed, not skipped".
func failedVolume(v PlannedVolume, reason string) VolumeRecord {
	rec := notCaptured(v, reason)
	rec.Failed = true
	return rec
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

// TileVolumes is the catalog lookup the plan needs: the tile by id, and a name
// for the catalog that answered.
//
// An interface rather than a concrete catalog type so a test can plan against
// a tile set it wrote three lines ago instead of against the shipped catalog —
// the classification is content, and a planner test that broke every time a
// tile was re-classified would be testing the content rather than the join.
//
// In production this is *catalogsync.Store, the catalog /api/catalog serves:
// the verified fetch, or the embedded floor until one succeeds. It is
// deliberately NOT *catalog.Catalog, the tile set embedded in the binary —
// that one does not implement Source, and cannot be wired here by accident.
// The 2026-09-03 e3bench run had it wired there, and its tiles carry no
// `volumes`, so the plan saw every installed app as volume-less.
type TileVolumes interface {
	Get(id string) (tileschema.Tile, bool)
	// Source names the catalog for the records that have to say which one
	// answered — "v17 (verified fetch)", "v14 (embedded floor — …)".
	Source() string
}

// AppEnumeration is the plan's account of what it LOOKED AT, carried into the
// manifest beside the per-volume records.
//
// It exists so that an empty record list can be read. Zero records with
// AppsInstalled 0 is a cluster with no apps; zero records with AppsInstalled 1
// and AppsResolved 0 cannot happen (the unresolved app leaves a record); and a
// report with no enumeration at all is one nobody built. Before this the three
// rendered identically, and the middle one shipped as `complete: true`.
type AppEnumeration struct {
	// AppsInstalled is how many installed apps the plan enumerated.
	AppsInstalled int `json:"appsInstalled"`
	// AppsResolved is how many of them resolved to a tile that declares at
	// least one volume — the apps the plan could actually classify. Every app
	// that did not is a not-captured record naming why.
	AppsResolved int `json:"appsResolved"`
	// Catalog is TileVolumes.Source: which catalog the tiles came from.
	Catalog string `json:"catalog,omitempty"`
}

// AppVolumePlan is §4.5's contents list, resolved: what to stage, in order,
// every classified volume that will not be, and the enumeration both came from.
type AppVolumePlan struct {
	Stage   []PlannedVolume
	Skipped []VolumeRecord
	AppEnumeration
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
func PlanAppVolumes(installed []*apps.App, tiles TileVolumes) AppVolumePlan {
	var stage []PlannedVolume
	var skipped []VolumeRecord
	enum := AppEnumeration{Catalog: tiles.Source()}
	for _, a := range installed {
		if a == nil {
			continue
		}
		enum.AppsInstalled++
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
		if len(tile.Volumes) == 0 {
			// The tile is there and says nothing. Recorded per app, like the
			// two cases above — the alternative is the loop below running zero
			// times and the app vanishing, which is what the bench did.
			skipped = append(skipped, notCaptured(PlannedVolume{
				AppID: a.ID, AppName: a.Name, TileID: tileID, NodeID: a.TargetNode,
				Volume: "(unknown — tile declares no volumes)", Class: "unclassified",
			}, fmt.Sprintf(ReasonTileDeclaresNoVolumes, tileID, enum.Catalog, tileID)))
			continue
		}
		enum.AppsResolved++
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
				if strings.TrimSpace(pv.NodeID) == "" {
					// An app with no node has no agent to stage it. It is a
					// FAILURE of this run rather than a skip: the app is
					// installed, classified, and not backed up.
					skipped = append(skipped, failedVolume(pv, "the app is not deployed to any node, so no agent can stage its volume"))
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
	return AppVolumePlan{Stage: stage, Skipped: skipped, AppEnumeration: enum}
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
