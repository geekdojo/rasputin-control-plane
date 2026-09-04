package storage

import (
	"archive/tar"
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/backupxfer/fsat"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// design/storage.md §4.5's restore, phase 2: ONE APP's classified volumes,
// from ONE generation, back to the node that hosts the app (geekdojo-brain
// #291 — the reverse transport; the gate is #300).
//
// # Explicit, per app, operator-initiated. Never automatic.
//
// Phase 1 restores the identity set and leaves app volumes alone, and that
// stays true. On the cluster this was designed against (e3bench, 2026-09-04)
// the controlplane was wiped and restored while compute1 kept running
// Vaultwarden with NEWER data than the backup; an automatic push would have
// clobbered it. So the default is keep-live, and restoring is a deliberate
// choice: "Restore this app's data from generation X", after a confirmation
// that says which volumes, from when, that the current data will be
// REPLACED, and that the app will be stopped for the swap — the same
// informed shape as #399's uninstall prompt.
//
// # Where the key goes, and where it does not
//
// The members were sealed on their hosting nodes to the target's PUBLIC
// key. The private key is unwrapped in the browser from a custody secret
// and lent to this api once, over TLS, for this one restore (RestoreSessions
// — never the job spec). THE API UNSEALS; THE KEY DOES NOT FAN OUT. Each
// node fetches its volume's PLAINTEXT tar from this api's restore-stream
// endpoint over the api's HTTPS — the mesh-CA leaf and the tailnet the OS
// update bundles already travel over — on a credential minted for that one
// member, that one node, this one restore, with a TTL. The trade, stated
// once: plaintext app data crosses the LAN inside TLS, as update bundles
// do; decrypting on N nodes would put the key on N nodes, and decrypting
// centrally keeps it on one, in memory, for one operation, then zeroed.
//
// # The saga
//
//	1 validate          api    the session holds a key; no backup.run in
//	                           flight; the app is INSTALLED and on a node
//	                           that is ONLINE; custody proven against the
//	                           disk's marker; the generation's manifest read
//	                           from INSIDE the sealed identity archive; the
//	                           per-volume plan built and every skip named
//	2 restore_volumes   agent  one volume at a time, `critical` first: mint
//	                           the credential, send the verb, record the
//	                           outcome, continue. STOPS THE APP, per volume.
//	3 record            api    the report into restore_reports, per volume;
//	                           then the job FAILS if any volume did not go
//	                           back or the app is not running
//
// # Edge cases, decided here
//
//   - The app is on a DIFFERENT node than the one that made the backup:
//     restored to where it is now. The manifest's node is recorded beside
//     it as CapturedFrom.
//   - The app is not installed: REFUSED — "install it first". A restore
//     puts data into an existing install; it never invents a deployment.
//   - The node hosting the app is offline: REFUSED with the node named,
//     not queued.
//   - A volume in the generation classed `cache` or `bulk`: SKIPPED, said.
//   - The manifest lists a volume the tile no longer declares: SKIPPED,
//     said. A tile volume the generation does not hold: SKIPPED with the
//     run's own reason for not capturing it.
//   - The app was reinstalled since the backup (new app id): a record is
//     matched by tile AND instance name when no record carries the app id,
//     and the report says so.

// RestoreAppJobKind is the workflow kind. In the Tasks feed like every
// other job.
const RestoreAppJobKind = "backup.restore_app"

// RestorePhaseAppVolumes stamps a phase-2 report.
const RestorePhaseAppVolumes = "app-volumes"

// Step budgets. validate mounts a disk and reads a manifest through one
// unseal pass over its first chunks; restore_volumes is serial and each
// verb has the agent's own budget plus slack; record is a row.
const (
	restoreValidateTimeout = 5 * time.Minute
	restoreVolumeRPCBudget = proto.BackupRestoreVolumeWork + 90*time.Second
	restoreVolumesBudget   = 2 * time.Hour
	restoreRecordTimeout   = 30 * time.Second
)

// AppGetter is the one question this saga asks the apps ledger.
type AppGetter interface {
	Get(ctx context.Context, id string) (*apps.App, error)
}

// RestoreAppConfig is the environment an app restore runs in.
type RestoreAppConfig struct {
	// NC is the bus, for the co-located agent's mount verb.
	NC *nats.Conn
	// SelfNodeID is the node this api runs on; the target disk is mounted
	// there and read through the filesystem.
	SelfNodeID string
	// Apps and Tiles: what is installed, on which node, from which tile; and
	// what that tile declares. Both required.
	Apps  AppGetter
	Tiles TileVolumes
	// Inventory answers "is the node online" before anything is sent, and
	// reads a silence afterwards.
	Inventory *inventory.Store
	// Sessions holds the lent key; Egress serves the plaintext stream and
	// mints its credentials; EgressBaseURL is the public base the nodes are
	// handed for it.
	Sessions      *RestoreSessions
	Egress        *RestoreEgress
	EgressBaseURL string
	// Store is the backup ledger: claimed targets, in-flight runs, and the
	// restore_reports table the record step writes.
	Store *Store
}

// RestoreAppSpec is the spec body of a backup.restore_app job. NO KEY: the
// session id is a handle this process alone can resolve, for as long as the
// session is open.
type RestoreAppSpec struct {
	AppID        string `json:"appId"`
	PartUUID     string `json:"partUuid"`
	GenerationID string `json:"generationId"`
	KeyID        string `json:"keyId"`
	SessionID    string `json:"sessionId"`
	// Volumes, when set, restricts the restore to these tile volume names.
	// Empty means every classified volume the generation holds for the app.
	Volumes []string `json:"volumes,omitempty"`
}

// ParseRestoreAppSpec decodes and validates a spec. Every failure is a
// step-1 refusal: nothing has been touched.
func ParseRestoreAppSpec(raw json.RawMessage) (*RestoreAppSpec, error) {
	var spec RestoreAppSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return nil, fmt.Errorf("invalid spec: %w", err)
	}
	if strings.TrimSpace(spec.AppID) == "" {
		return nil, errors.New("appId is required")
	}
	if !safePartUUID.MatchString(spec.PartUUID) {
		return nil, fmt.Errorf("%q is not a partition UUID", spec.PartUUID)
	}
	if !proto.BackupValidGenerationID(spec.GenerationID) {
		return nil, fmt.Errorf("%q is not a generation id", spec.GenerationID)
	}
	if strings.TrimSpace(spec.KeyID) == "" {
		return nil, errors.New("keyId is required")
	}
	if strings.TrimSpace(spec.SessionID) == "" {
		return nil, errors.New("sessionId is required: the restore's key is held by the api for one restore, and this names which")
	}
	return &spec, nil
}

// ----- Listing: which generations hold this app's volumes -----------------

// AppRestoreSources is GET /api/apps/{id}/restore-sources: the generations
// on the claimed target that hold any of this app's volumes, with what the
// UI needs to confirm and to unwrap.
type AppRestoreSources struct {
	AppID   string `json:"appId"`
	AppName string `json:"appName"`
	TileID  string `json:"tileId,omitempty"`
	// Installed is true when the app has a row and a node; NodeID is that
	// node and NodeOnline whether inventory sees it. A restore is refused
	// unless all three hold, and the UI says so before the operator types a
	// secret.
	Installed  bool   `json:"installed"`
	NodeID     string `json:"nodeId,omitempty"`
	NodeOnline bool   `json:"nodeOnline"`
	// Target is the claimed backup target the generations live on, and
	// Marker its on-disk marker: the key id, the PUBLIC key and the two
	// WRAPPED copies of the private key the browser unwraps.
	Target *BackupTarget           `json:"target,omitempty"`
	Marker *proto.StorageBackupSet `json:"marker,omitempty"`
	// DeclaredVolumes is what the tile classifies today, so the UI can show
	// a generation's volumes against the current declaration.
	DeclaredVolumes []tileschema.Volume `json:"declaredVolumes"`
	// Generations holds only those with at least one member for this app,
	// newest first.
	Generations []AppRestoreGeneration `json:"generations"`
	// Problem says why nothing can be restored, when that is so.
	Problem string `json:"problem,omitempty"`
}

// AppRestoreGeneration is one generation as it concerns one app.
type AppRestoreGeneration struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"createdAt"`
	AgeHuman  string    `json:"ageHuman"`
	Scope     string    `json:"scope,omitempty"`
	Complete  bool      `json:"complete"`
	KeyID     string    `json:"keyId,omitempty"`
	// Volumes are this app's members in the generation, each with the plan's
	// verdict for it as things stand now (restorable, or skipped with why).
	Volumes []AppRestoreVolumeView `json:"volumes"`
	// MatchedBy says how the records were tied to this app: "appId" or
	// "tile+name" (a reinstall since the backup).
	MatchedBy  string `json:"matchedBy"`
	Restorable bool   `json:"restorable"`
	Problem    string `json:"problem,omitempty"`
}

// AppRestoreVolumeView is one volume of one generation, as the picker and
// the confirmation show it.
type AppRestoreVolumeView struct {
	Volume       string `json:"volume"`
	Class        string `json:"class"`
	SizeBytes    uint64 `json:"sizeBytes"`
	FileCount    int    `json:"fileCount"`
	CapturedFrom string `json:"capturedFrom,omitempty"`
	Consistency  string `json:"consistency,omitempty"`
	// Restorable is the plan's verdict; Reason says why not.
	Restorable bool   `json:"restorable"`
	Reason     string `json:"reason,omitempty"`
}

// ListAppRestoreSources lists the generations that hold app's volumes.
// Read-only: it mounts the claimed target through the co-located agent and
// reads the clear-text sidecar manifests. The sidecar is what an operator
// SEES; the restore itself trusts the copy inside the sealed archive.
func ListAppRestoreSources(ctx context.Context, cfg RestoreAppConfig, app *apps.App) (*AppRestoreSources, error) {
	if app == nil {
		return nil, errors.New("no app")
	}
	out := &AppRestoreSources{AppID: app.ID, AppName: app.Name, TileID: app.SourceTile,
		DeclaredVolumes: []tileschema.Volume{}, Generations: []AppRestoreGeneration{}}
	out.Installed = strings.TrimSpace(app.TargetNode) != ""
	out.NodeID = app.TargetNode
	if out.Installed && cfg.Inventory != nil {
		if n, err := cfg.Inventory.Get(ctx, app.TargetNode); err == nil && n != nil {
			out.NodeOnline = inventory.ComputeStatus(n.LastSeen) == proto.StatusOnline
		}
	}
	var tile tileschema.Tile
	haveTile := false
	if cfg.Tiles != nil && strings.TrimSpace(app.SourceTile) != "" {
		tile, haveTile = cfg.Tiles.Get(app.SourceTile)
	}
	if haveTile {
		out.DeclaredVolumes = append(out.DeclaredVolumes, tile.Volumes...)
	}
	if cfg.Store == nil {
		out.Problem = "backups are not configured on this api"
		return out, nil
	}
	claimed, err := cfg.Store.ListClaimed(ctx)
	if err != nil {
		return nil, err
	}
	if len(claimed) == 0 {
		out.Problem = "no backup target is claimed, so there is no generation to restore from"
		return out, nil
	}
	target := claimed[0]
	out.Target = target
	if strings.TrimSpace(cfg.SelfNodeID) == "" || target.NodeID != cfg.SelfNodeID {
		out.Problem = fmt.Sprintf("the claimed target is on node %s and this api runs on %s; the disk is read beside the api", target.NodeID, displayLabel(cfg.SelfNodeID))
		return out, nil
	}
	mountPath, err := mountTarget(ctx, cfg.NC, cfg.SelfNodeID, target.PartUUID)
	if err != nil {
		out.Problem = "the backup target could not be mounted: " + err.Error()
		return out, nil
	}
	root, err := fsat.OpenRoot(mountPath)
	if err != nil {
		out.Problem = err.Error()
		return out, nil
	}
	defer func() { _ = root.Close() }()
	if raw, err := readBounded(root, proto.StorageMarkerFile, maxMarkerBytes); err == nil {
		var marker proto.StorageBackupSet
		if json.Unmarshal(raw, &marker) == nil {
			out.Marker = &marker
		}
	}
	if out.Marker == nil || out.Marker.PublicKey == "" || out.Marker.WrappedByPassphrase == "" || out.Marker.WrappedByRecoveryCode == "" {
		out.Problem = "the backup disk's marker carries no wrapped archive key this build can open; its generations cannot be restored"
		return out, nil
	}
	gens, err := listRestoreGenerations(mountPath, out.Marker.KeyID)
	if err != nil {
		out.Problem = "the generations directory could not be read: " + err.Error()
		return out, nil
	}
	now := time.Now().UTC()
	for _, g := range gens {
		dir, err := openGenerationDir(root, g.ID)
		if err != nil {
			continue
		}
		raw, rerr := readBounded(dir, proto.BackupManifestFile, maxManifestBytes)
		_ = dir.Close()
		if rerr != nil {
			continue
		}
		var m Manifest
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		records, matchedBy := manifestRecordsFor(&m, app)
		if len(records) == 0 {
			continue
		}
		plan := PlanAppRestore(app, tile, haveTile, records, nil)
		view := AppRestoreGeneration{
			ID: g.ID, CreatedAt: g.CreatedAt, AgeHuman: humanAge(now.Sub(g.CreatedAt)), Scope: g.Scope,
			Complete: g.Complete, KeyID: g.KeyID, MatchedBy: matchedBy, Volumes: []AppRestoreVolumeView{},
		}
		for _, p := range plan.Restore {
			view.Volumes = append(view.Volumes, AppRestoreVolumeView{Volume: p.Volume, Class: p.Class, SizeBytes: p.SizeBytes, FileCount: p.FileCount,
				CapturedFrom: p.CapturedFrom, Consistency: p.Consistency, Restorable: true})
		}
		for _, s := range plan.Skipped {
			if s.Member == "" {
				continue // not in this generation at all: nothing to show under it
			}
			view.Volumes = append(view.Volumes, AppRestoreVolumeView{Volume: s.Volume, Class: s.Class, SizeBytes: s.SizeBytes,
				CapturedFrom: s.CapturedFrom, Reason: s.Reason})
		}
		sort.Slice(view.Volumes, func(i, j int) bool { return view.Volumes[i].Volume < view.Volumes[j].Volume })
		switch {
		case !g.Restorable:
			view.Problem = g.Problem
		case len(plan.Restore) == 0:
			view.Problem = "none of this app's volumes in this generation can be restored: " + plan.skipReasons()
		default:
			view.Restorable = true
		}
		out.Generations = append(out.Generations, view)
	}
	if len(out.Generations) == 0 {
		out.Problem = "no retained generation holds a volume of this app"
	}
	return out, nil
}

// openGenerationDir opens generations/<id> beneath the mount root.
func openGenerationDir(root *os.File, id string) (*os.File, error) {
	if !proto.BackupValidGenerationID(id) {
		return nil, fmt.Errorf("%q is not a generation id", id)
	}
	gens, err := fsat.OpenDir(root, proto.BackupGenerationsDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = gens.Close() }()
	return fsat.OpenDir(gens, id)
}

// manifestRecordsFor picks the manifest's records for app: by app id first;
// failing that, by tile and instance name — a reinstall since the backup.
func manifestRecordsFor(m *Manifest, app *apps.App) (records []VolumeRecord, matchedBy string) {
	for _, v := range m.AppVolumes.Volumes {
		if v.AppID != "" && strings.EqualFold(v.AppID, app.ID) {
			records = append(records, v)
		}
	}
	if len(records) > 0 {
		return records, "appId"
	}
	if strings.TrimSpace(app.SourceTile) == "" {
		return nil, ""
	}
	for _, v := range m.AppVolumes.Volumes {
		if v.TileID == app.SourceTile && v.App == app.Name {
			records = append(records, v)
		}
	}
	if len(records) > 0 {
		return records, "tile+name"
	}
	return nil, ""
}

// ----- The plan --------------------------------------------------------------

// RestoreVolumePlan is one volume the restore will put back.
type RestoreVolumePlan struct {
	Volume       string `json:"volume"`
	Class        string `json:"class"`
	Member       string `json:"member"`
	SizeBytes    uint64 `json:"sizeBytes"`
	SHA256       string `json:"sha256"`
	SealedSHA256 string `json:"sealedSha256"`
	SealedBytes  uint64 `json:"sealedSizeBytes"`
	FileCount    int    `json:"fileCount"`
	CapturedFrom string `json:"capturedFrom,omitempty"`
	Consistency  string `json:"consistency,omitempty"`
}

// AppVolumeRestoreRecord is the report's row for one volume — restored, or
// skipped/failed with its reason. Present for every volume the plan
// considered.
type AppVolumeRestoreRecord struct {
	App    string `json:"app"`
	AppID  string `json:"appId,omitempty"`
	Volume string `json:"volume"`
	Class  string `json:"class,omitempty"`
	// Node is where it was restored TO; CapturedFrom where the backup took
	// it from. They differ when the app moved.
	Node         string `json:"node,omitempty"`
	CapturedFrom string `json:"capturedFrom,omitempty"`
	Member       string `json:"member,omitempty"`
	Restored     bool   `json:"restored"`
	// Failed is true when the restore TRIED and could not — distinct from a
	// volume the plan never intended to touch.
	Failed bool   `json:"failed"`
	Reason string `json:"reason,omitempty"`
	// What went back, as the manifest recorded it and the agent verified it.
	SizeBytes   uint64 `json:"sizeBytes,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	FileCount   int    `json:"fileCount,omitempty"`
	Consistency string `json:"consistency,omitempty"`
	// The restart facts, from the agent's ack.
	WasRunning     bool   `json:"wasRunning"`
	Stopped        bool   `json:"stopped"`
	DowntimeMillis int64  `json:"downtimeMillis,omitempty"`
	AppRestored    bool   `json:"appRestored"`
	RestoreDetail  string `json:"restoreDetail,omitempty"`
	// PreviousKept is where the node moved the previous contents.
	PreviousKept string `json:"previousKept,omitempty"`
}

// AppRestorePlan is what the restore will do and everything it will not.
type AppRestorePlan struct {
	Restore []RestoreVolumePlan
	Skipped []AppVolumeRestoreRecord
}

func (p AppRestorePlan) skipReasons() string {
	parts := make([]string, 0, len(p.Skipped))
	for _, s := range p.Skipped {
		parts = append(parts, s.Volume+": "+s.Reason)
	}
	return strings.Join(parts, "; ")
}

// PlanAppRestore joins the tile's declaration TODAY against the generation's
// records for the app, and decides per volume. only, when non-empty,
// restricts the plan to those volume names (anything else is skipped as
// "not selected").
//
// Order is class first (`critical` before `state`), then name — the same
// order the backup took them in, for the same reason: if the restore dies
// part-way, what went back first is what costs the most to lose.
func PlanAppRestore(app *apps.App, tile tileschema.Tile, haveTile bool, records []VolumeRecord, only []string) AppRestorePlan {
	var plan AppRestorePlan
	selected := map[string]bool{}
	for _, v := range only {
		selected[strings.TrimSpace(v)] = true
	}
	declared := map[string]tileschema.Volume{}
	if haveTile {
		for _, v := range tile.Volumes {
			declared[strings.TrimSpace(v.Name)] = v
		}
	}
	byVolume := map[string]VolumeRecord{}
	for _, r := range records {
		byVolume[r.Volume] = r
	}
	skip := func(r VolumeRecord, class, reason string) {
		plan.Skipped = append(plan.Skipped, AppVolumeRestoreRecord{
			App: app.Name, AppID: app.ID, Volume: r.Volume, Class: class, Node: app.TargetNode, CapturedFrom: r.Node,
			Member: r.Member, SizeBytes: r.SizeBytes, Reason: reason, AppRestored: true,
		})
	}
	// Every record the generation holds for the app, judged against the
	// declaration.
	for _, r := range records {
		class := r.Class
		if d, ok := declared[r.Volume]; ok && d.Backup != "" {
			class = d.Backup
		}
		switch {
		case !haveTile:
			skip(r, class, "the app's tile is not in the catalog in effect, so nothing says which of its volumes hold data worth restoring")
			continue
		case !r.Captured:
			skip(r, class, "not in this generation: "+firstSentence(r.Reason))
			continue
		}
		d, ok := declared[r.Volume]
		if !ok {
			skip(r, class, fmt.Sprintf("the generation holds it but tile `%s` no longer declares a volume by that name; nothing knows where it would go", app.SourceTile))
			continue
		}
		switch d.Backup {
		case tileschema.BackupCache:
			skip(r, class, "classed `cache` by the tile: never captured and never restored (§4.2)")
			continue
		case tileschema.BackupBulk:
			skip(r, class, "classed `bulk` by the tile: streams direct and is never restored by this transport (§4.7)")
			continue
		case tileschema.BackupCritical, tileschema.BackupState:
		default:
			skip(r, class, fmt.Sprintf("declares backup class %q, which is not one of %s", d.Backup, strings.Join(tileschema.BackupClasses, "|")))
			continue
		}
		if len(selected) > 0 && !selected[r.Volume] {
			skip(r, class, "not selected for this restore")
			continue
		}
		if r.Member == "" || r.SHA256 == "" || r.SizeBytes == 0 {
			skip(r, class, "the manifest records it as captured but names no member, digest or size; a member nothing can verify is not restored")
			continue
		}
		plan.Restore = append(plan.Restore, RestoreVolumePlan{
			Volume: r.Volume, Class: d.Backup, Member: r.Member, SizeBytes: r.SizeBytes, SHA256: r.SHA256,
			SealedSHA256: r.SealedSHA256, SealedBytes: r.SealedSizeBytes, FileCount: r.FileCount,
			CapturedFrom: r.Node, Consistency: r.Consistency,
		})
	}
	// Every classified volume the tile declares that the generation has no
	// record of at all.
	if haveTile {
		for _, d := range tile.Volumes {
			name := strings.TrimSpace(d.Name)
			if _, ok := byVolume[name]; ok || d.Backup == tileschema.BackupCache || d.Backup == tileschema.BackupBulk {
				continue
			}
			plan.Skipped = append(plan.Skipped, AppVolumeRestoreRecord{
				App: app.Name, AppID: app.ID, Volume: name, Class: d.Backup, Node: app.TargetNode,
				Reason:      "the generation has no record of this volume at all — the tile declared it after the backup was taken, or the app had no such volume then",
				AppRestored: true,
			})
		}
	}
	sort.SliceStable(plan.Restore, func(i, j int) bool {
		if ri, rj := classRank(plan.Restore[i].Class), classRank(plan.Restore[j].Class); ri != rj {
			return ri < rj
		}
		return plan.Restore[i].Volume < plan.Restore[j].Volume
	})
	sort.SliceStable(plan.Skipped, func(i, j int) bool { return plan.Skipped[i].Volume < plan.Skipped[j].Volume })
	return plan
}

func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, ". "); i > 0 {
		return s[:i+1]
	}
	if len(s) > 160 {
		return s[:157] + "…"
	}
	return s
}

// humanAge renders an age for the picker.
func humanAge(d time.Duration) string {
	switch {
	case d < 0:
		return "in the future (clock skew)"
	case d < time.Hour:
		return fmt.Sprintf("%d minute(s) ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hour(s) ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%d day(s) ago", int(d.Hours()/24))
	}
}

// ----- Custody, checked before anything is stopped ------------------------

// CheckRestoreCustody proves the supplied private key belongs to the claimed
// target: it mounts the target, reads its marker, and requires the key to
// derive the marker's public key and the marker to name keyID. Called by the
// HTTP handler BEFORE a session is opened or a job submitted — a wrong
// secret is refused with nothing stopped and no job in the ledger — and
// again by step 1. The key is borrowed; the caller zeroes it.
func CheckRestoreCustody(ctx context.Context, cfg RestoreAppConfig, partUUID, keyID string, privateKey []byte) (mountPath string, marker *proto.StorageBackupSet, err error) {
	if strings.TrimSpace(cfg.SelfNodeID) == "" {
		return "", nil, errors.New("this api does not know which node it runs on (RASPUTIN_SELF_NODE_ID is unset); the backup disk is read beside it and needs that name")
	}
	if !safePartUUID.MatchString(partUUID) {
		return "", nil, fmt.Errorf("%w: %q is not a partition UUID", ErrRestoreArchive, partUUID)
	}
	suppliedPub, err := PublicKeyForPrivate(privateKey)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrRestoreArchive, err)
	}
	if allZero(privateKey) {
		return "", nil, fmt.Errorf("%w: the supplied key is all zeroes", ErrRestoreArchive)
	}
	if !fsat.Supported {
		return "", nil, fsat.ErrUnsupported
	}
	mountPath, err = mountTarget(ctx, cfg.NC, cfg.SelfNodeID, partUUID)
	if err != nil {
		return "", nil, err
	}
	root, err := fsat.OpenRoot(mountPath)
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = root.Close() }()
	rawMarker, err := readBounded(root, proto.StorageMarkerFile, maxMarkerBytes)
	if err != nil {
		return "", nil, fmt.Errorf("%w: the disk's marker could not be read: %v", ErrRestoreArchive, err)
	}
	var m proto.StorageBackupSet
	if err := json.Unmarshal(rawMarker, &m); err != nil {
		return "", nil, fmt.Errorf("%w: the disk's marker is not readable JSON", ErrRestoreArchive)
	}
	if m.PartUUID != "" && m.PartUUID != partUUID {
		return "", nil, fmt.Errorf("%w: the disk mounted for %s carries a marker for %s", ErrRestoreArchive, partUUID, m.PartUUID)
	}
	if m.KeyID != keyID {
		return "", nil, fmt.Errorf("%w: the request names key %s but the disk's marker names key %s", ErrRestoreArchive, keyID, m.KeyID)
	}
	if !publicKeysEqual(m.PublicKey, suppliedPub) {
		return "", nil, ErrRestoreKeyMismatch
	}
	return mountPath, &m, nil
}

// ----- The workflow -----------------------------------------------------------

// RestoreAppWorkflow returns the three-step backup.restore_app saga.
func RestoreAppWorkflow(store *Store, cfg RestoreAppConfig) jobs.Workflow {
	cfg.Store = store
	return jobs.Workflow{
		Kind: RestoreAppJobKind,
		Steps: []jobs.WorkflowStep{
			{Name: "validate", Timeout: restoreValidateTimeout, Do: restoreAppValidate(cfg)},
			// Retries: 0. A retried phase would stop the app a second time
			// and re-fetch gigabytes; a volume that did not go back is
			// recorded, and the record step fails the job for it.
			{Name: "restore_volumes", Timeout: restoreVolumesBudget, Retries: 0, Do: restoreAppVolumes(cfg)},
			{Name: "record", Timeout: restoreRecordTimeout, Do: restoreAppRecord(cfg)},
		},
		// The key dies with the job, whichever way it ended.
		OnTerminal: func(_ context.Context, jobID string, _ bool, _ string) {
			if cfg.Sessions != nil {
				cfg.Sessions.CloseJob(jobID)
			}
		},
	}
}

// restoreAppTarget is step 1's verdict. Identifiers, sizes, digests, prose.
// No key, and no field for one.
type restoreAppTarget struct {
	RestoreID           string    `json:"restoreId"`
	AppID               string    `json:"appId"`
	AppName             string    `json:"appName"`
	TileID              string    `json:"tileId,omitempty"`
	NodeID              string    `json:"nodeId"`
	PartUUID            string    `json:"partUuid"`
	SourceLabel         string    `json:"sourceLabel,omitempty"`
	GenerationID        string    `json:"generationId"`
	GenerationCreatedAt time.Time `json:"generationCreatedAt"`
	ClusterID           string    `json:"clusterId,omitempty"`
	KeyID               string    `json:"keyId"`
	Scope               string    `json:"scope,omitempty"`
	Complete            bool      `json:"complete"`
	ManifestVersion     int       `json:"manifestVersion"`
	MatchedBy           string    `json:"matchedBy"`
	// Source is the URI the node is handed for the plaintext stream.
	Source  string                   `json:"source"`
	Restore []RestoreVolumePlan      `json:"restore"`
	Skipped []AppVolumeRestoreRecord `json:"skipped"`
}

// restoreAppVolumesResult is step 2's: every volume's record.
type restoreAppVolumesResult struct {
	Volumes []AppVolumeRestoreRecord `json:"volumes"`
}

func restoreAppValidate(cfg RestoreAppConfig) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := ParseRestoreAppSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		if cfg.Sessions == nil || cfg.Egress == nil || cfg.Apps == nil || cfg.Tiles == nil || cfg.Store == nil {
			return nil, errors.New("this api is not wired for app-volume restores (sessions, egress, apps, tiles or the ledger is missing)")
		}
		// The session named by the spec is bound to THIS job — by the
		// handler after Submit, or here first, since Submit starts the
		// job's goroutine before it returns. A session bound to another job
		// is refused.
		if err := cfg.Sessions.Bind(spec.SessionID, sc.JobID); err != nil {
			return nil, fmt.Errorf("%w (%v)", ErrRestoreSessionGone, err)
		}
		session := cfg.Sessions.Get(spec.SessionID)
		if session == nil || session.jobID != sc.JobID {
			return nil, ErrRestoreSessionGone
		}
		source, err := backupxfer.EgressDestination(cfg.EgressBaseURL)
		if err != nil {
			return nil, fmt.Errorf("this api cannot tell the node where to fetch the volume from: %v (RASPUTIN_PUBLIC_BASE_URL). Nothing was touched", err)
		}
		running, err := cfg.Store.ListRunning(sc.Ctx)
		if err != nil {
			return nil, fmt.Errorf("in-flight runs: %w", err)
		}
		if len(running) > 0 {
			return nil, fmt.Errorf("a backup is running (job %s); a restore reads the target that run is writing to and would race its prune. Wait for it to finish", running[0].JobID)
		}

		// The app: installed, on a node, and the node is online. Refused, never
		// queued, and nothing is invented.
		app, err := cfg.Apps.Get(sc.Ctx, spec.AppID)
		if err != nil {
			return nil, fmt.Errorf("read app %s: %w", spec.AppID, err)
		}
		if app == nil {
			return nil, fmt.Errorf("app %s is not installed. A restore puts data into an existing install and never creates one — install the app first, then restore its data", spec.AppID)
		}
		node := strings.TrimSpace(app.TargetNode)
		if node == "" {
			return nil, fmt.Errorf("app %s (%s) is not deployed to any node, so there is no agent to put its data back; deploy it first", app.Name, app.ID)
		}
		if cfg.Inventory != nil {
			n, err := cfg.Inventory.Get(sc.Ctx, node)
			if err != nil {
				return nil, fmt.Errorf("inventory for node %s: %w", node, err)
			}
			if n == nil {
				return nil, fmt.Errorf("node %s, which hosts %s, is not registered; the restore is refused, not queued", node, app.Name)
			}
			if inventory.ComputeStatus(n.LastSeen) != proto.StatusOnline {
				return nil, fmt.Errorf("node %s, which hosts %s, is OFFLINE; the restore is refused, not queued — bring the node back and start it again", node, app.Name)
			}
		}
		tile, haveTile := cfg.Tiles.Get(strings.TrimSpace(app.SourceTile))
		if !haveTile {
			return nil, fmt.Errorf("app %s was installed from tile %q, which the catalog in effect (%s) does not carry, so nothing says which of its volumes hold data worth restoring", app.Name, app.SourceTile, cfg.Tiles.Source())
		}

		// Custody, against the disk, with the lent key — before the
		// generation is opened.
		mountPath, marker, err := CheckRestoreCustody(sc.Ctx, cfg, spec.PartUUID, spec.KeyID, session.key)
		if err != nil {
			return nil, err
		}
		root, err := fsat.OpenRoot(mountPath)
		if err != nil {
			return nil, err
		}
		defer func() { _ = root.Close() }()
		gen, err := openGenerationDir(root, spec.GenerationID)
		if err != nil {
			return nil, fmt.Errorf("%w: generation %s: %v", ErrRestoreArchive, spec.GenerationID, err)
		}
		defer func() { _ = gen.Close() }()
		archive, err := fsat.OpenFile(gen, proto.BackupArchiveFile)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrRestoreArchive, err)
		}
		// The manifest INSIDE the sealed identity archive is what is trusted
		// — the sidecar can be edited by anyone holding the disk; the sealed
		// copy's chunks are authenticated under the key.
		m, err := readSealedManifest(archive, session.key)
		_ = archive.Close()
		if err != nil {
			return nil, err
		}
		if m.GenerationID != "" && m.GenerationID != spec.GenerationID {
			return nil, fmt.Errorf("%w: the archive's manifest is for generation %s, not %s", ErrRestoreArchive, m.GenerationID, spec.GenerationID)
		}
		if m.KeyID != "" && m.KeyID != spec.KeyID {
			return nil, fmt.Errorf("%w: the archive's manifest names key %s, not %s", ErrRestoreArchive, m.KeyID, spec.KeyID)
		}
		records, matchedBy := manifestRecordsFor(m, app)
		if len(records) == 0 {
			return nil, fmt.Errorf("generation %s holds no volume of %s (app %s, tile %s) — not by app id and not by tile and name. Nothing was touched", spec.GenerationID, app.Name, app.ID, app.SourceTile)
		}
		plan := PlanAppRestore(app, tile, haveTile, records, spec.Volumes)
		if len(plan.Restore) == 0 {
			return nil, fmt.Errorf("nothing in generation %s can be restored to %s: %s. Nothing was touched", spec.GenerationID, app.Name, plan.skipReasons())
		}

		members := map[string]restoreMemberFacts{}
		for _, p := range plan.Restore {
			members[p.Member] = restoreMemberFacts{sealedSHA256: p.SealedSHA256, sealedBytes: p.SealedBytes, plaintextSHA256: p.SHA256, plaintextBytes: p.SizeBytes}
		}
		if err := cfg.Sessions.Arm(spec.SessionID, mountPath, spec.PartUUID, spec.GenerationID, node, members); err != nil {
			return nil, err
		}
		out := restoreAppTarget{
			RestoreID: "rs-" + randomHex(8), AppID: app.ID, AppName: app.Name, TileID: app.SourceTile, NodeID: node,
			PartUUID: spec.PartUUID, SourceLabel: marker.Label, GenerationID: spec.GenerationID, GenerationCreatedAt: m.CreatedAt.UTC(),
			ClusterID: m.ClusterID, KeyID: spec.KeyID, Scope: m.Scope, Complete: m.Complete, ManifestVersion: m.ManifestVersion,
			MatchedBy: matchedBy, Source: source, Restore: plan.Restore, Skipped: plan.Skipped,
		}
		if out.Skipped == nil {
			out.Skipped = []AppVolumeRestoreRecord{}
		}
		names := make([]string, 0, len(plan.Restore))
		for _, p := range plan.Restore {
			names = append(names, fmt.Sprintf("%s (%s, %s)", p.Volume, p.Class, humanBytes(p.SizeBytes)))
		}
		sc.Log("warn", fmt.Sprintf("RESTORE %s: %d volume(s) of %s on %s will be REPLACED from generation %s (%s, %s): %s. The app is stopped for the swap of each volume; the previous contents are kept beside the volume on %s",
			out.RestoreID, len(plan.Restore), app.Name, node, spec.GenerationID, humanAge(time.Since(m.CreatedAt)), completeWord(m.Complete), strings.Join(names, ", "), node))
		if matchedBy == "tile+name" {
			sc.Log("warn", fmt.Sprintf("the generation's records carry a different app id than %s: %s was reinstalled since the backup and is matched by tile `%s` and name", app.ID, app.Name, app.SourceTile))
		}
		for _, s := range plan.Skipped {
			sc.Log("warn", fmt.Sprintf("NOT restored: %s/%s (%s) — %s", app.Name, s.Volume, displayLabel(s.Class), s.Reason))
		}
		return json.Marshal(out)
	}
}

func completeWord(c bool) string {
	if c {
		return "complete"
	}
	return "INCOMPLETE"
}

func restoreAppVolumes(cfg RestoreAppConfig) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		var tgt restoreAppTarget
		if err := priorResult(sc, "validate", &tgt); err != nil {
			return nil, err
		}
		if cfg.Sessions.ByJob(sc.JobID) == nil {
			return nil, ErrRestoreSessionGone
		}
		records := append([]AppVolumeRestoreRecord(nil), tgt.Skipped...)
		for i, p := range tgt.Restore {
			if deadline, ok := sc.Ctx.Deadline(); ok && time.Until(deadline) < restoreVolumeRPCBudget {
				for _, rest := range tgt.Restore[i:] {
					records = append(records, failedRestore(tgt, rest, fmt.Sprintf("the restore's %s budget was exhausted before this volume was reached; each volume may take up to %s", restoreVolumesBudget, proto.BackupRestoreVolumeWork)))
				}
				sc.Log("error", fmt.Sprintf("out of time after %d of %d volume(s); the rest are NOT restored", i, len(tgt.Restore)))
				break
			}
			records = append(records, restoreOne(sc, cfg, tgt, p))
		}
		return json.Marshal(restoreAppVolumesResult{Volumes: records})
	}
}

func failedRestore(tgt restoreAppTarget, p RestoreVolumePlan, reason string) AppVolumeRestoreRecord {
	return AppVolumeRestoreRecord{
		App: tgt.AppName, AppID: tgt.AppID, Volume: p.Volume, Class: p.Class, Node: tgt.NodeID, CapturedFrom: p.CapturedFrom,
		Member: p.Member, SizeBytes: p.SizeBytes, SHA256: p.SHA256, FileCount: p.FileCount, Consistency: p.Consistency,
		Failed: true, Reason: reason, AppRestored: true,
	}
}

// restoreOne is the per-volume dance: mint, send, record. It never returns
// an error — every way it can go wrong is a record with Failed true.
func restoreOne(sc *jobs.StepCtx, cfg RestoreAppConfig, tgt restoreAppTarget, p RestoreVolumePlan) AppVolumeRestoreRecord {
	// The credential: one member, one generation, one node, this restore,
	// bounded to the plaintext's length, minted now and dead by the time
	// the verb's budget is. Into the command and nowhere else.
	cred, err := cfg.Egress.Mint(backupxfer.Grant{
		Generation: tgt.GenerationID, Member: p.Member, NodeID: tgt.NodeID, JobID: sc.JobID, MaxBytes: p.SizeBytes, Use: backupxfer.UseRestore,
	}, restoreVolumeRPCBudget)
	if err != nil {
		return failedRestore(tgt, p, fmt.Sprintf("could not mint a restore credential for %s: %v", p.Member, err))
	}
	cmd, err := json.Marshal(proto.BackupRestoreVolumeCmd{
		AppID: tgt.AppID, AppName: tgt.AppName, Volume: p.Volume, Class: p.Class,
		Source: tgt.Source, Credential: cred, GenerationID: tgt.GenerationID, Member: p.Member, RestoreID: tgt.RestoreID,
		PlaintextDigest: p.SHA256, PlaintextBytes: p.SizeBytes, FileCount: p.FileCount,
	})
	if err != nil {
		return failedRestore(tgt, p, "internal: "+err.Error())
	}
	sc.Log("warn", fmt.Sprintf("replacing %s/%s on %s from %s (%s) — the app is stopped while the volume is swapped", tgt.AppName, p.Volume, tgt.NodeID, p.Member, humanBytes(p.SizeBytes)))
	rctx, cancel := context.WithTimeout(sc.Ctx, restoreVolumeRPCBudget)
	subject := proto.BackupRestoreVolumeSubject(tgt.NodeID)
	msg, err := sc.NATS.RequestWithContext(rctx, subject, cmd)
	cancel()
	if err != nil {
		if errors.Is(err, nats.ErrNoResponders) {
			why := fmt.Sprintf("node %s did not answer the restore request; the volume was not touched", tgt.NodeID)
			if cfg.Inventory != nil {
				why = cfg.Inventory.ExplainNoResponder(sc.Ctx, subject).String() + "; the volume was not touched"
			}
			return failedRestore(tgt, p, why)
		}
		return failedRestore(tgt, p, fmt.Sprintf("the restore request to %s failed: %v. Whether the volume was replaced is unknown from here; the agent's guard restarts the app on a lost reply and again at its next start", tgt.NodeID, err))
	}
	var ack proto.BackupRestoreVolumeAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		return failedRestore(tgt, p, fmt.Sprintf("the reply from %s was unreadable: %v", tgt.NodeID, err))
	}
	rec := AppVolumeRestoreRecord{
		App: tgt.AppName, AppID: tgt.AppID, Volume: p.Volume, Class: p.Class, Node: tgt.NodeID, CapturedFrom: p.CapturedFrom,
		Member: p.Member, SizeBytes: p.SizeBytes, SHA256: p.SHA256, FileCount: ack.FileCount, Consistency: p.Consistency,
		WasRunning: ack.WasRunning, Stopped: ack.Stopped, DowntimeMillis: ack.DowntimeMillis,
		AppRestored: ack.AppRestored, RestoreDetail: ack.RestoreDetail, PreviousKept: ack.PreviousKept,
	}
	if !ack.OK || !ack.Replaced {
		rec.Failed = true
		rec.Reason = refusalReason(tgt.NodeID, ack.Refusal, ack.Detail)
		if ack.SourceCode != "" {
			rec.Reason += " (source said " + ack.SourceCode + ")"
		}
		sc.Log("error", fmt.Sprintf("NOT restored: %s/%s — %s", tgt.AppName, p.Volume, rec.Reason))
	} else {
		rec.Restored = true
		sc.Log("info", fmt.Sprintf("restored %s/%s on %s: %d file(s), %s, sha256 %s verified against the manifest; previous contents kept at %s%s",
			tgt.AppName, p.Volume, tgt.NodeID, ack.FileCount, humanBytes(ack.UnpackedBytes), short(ack.Digest), ack.PreviousKept, restoreDowntimeText(ack)))
	}
	if !ack.AppRestored {
		sc.Log("error", fmt.Sprintf("APP LEFT DOWN: %s was stopped to replace %s and did not come back: %s. The agent's guard keeps retrying and a boot sweep will restart it", tgt.AppName, p.Volume, ack.RestoreDetail))
	}
	return rec
}

func restoreDowntimeText(ack proto.BackupRestoreVolumeAck) string {
	if !ack.Stopped {
		return "; the app was not running and was not started"
	}
	return fmt.Sprintf("; the app was down for %.1fs", float64(ack.DowntimeMillis)/1000)
}

func restoreAppRecord(cfg RestoreAppConfig) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		var tgt restoreAppTarget
		if err := priorResult(sc, "validate", &tgt); err != nil {
			return nil, err
		}
		var vols restoreAppVolumesResult
		if err := priorResult(sc, "restore_volumes", &vols); err != nil {
			return nil, err
		}
		now := time.Now().UTC()
		report := &RestoreReport{
			ID: tgt.RestoreID, Phase: RestorePhaseAppVolumes, JobID: sc.JobID,
			GenerationID: tgt.GenerationID, GenerationCreatedAt: tgt.GenerationCreatedAt, ClusterID: tgt.ClusterID,
			KeyID: tgt.KeyID, Scope: tgt.Scope, Complete: tgt.Complete, ManifestVersion: tgt.ManifestVersion,
			PartUUID: tgt.PartUUID, SourceLabel: tgt.SourceLabel, NodeID: tgt.NodeID,
			AppID: tgt.AppID, AppName: tgt.AppName,
			Restored: []RestoredEntry{}, NotRestored: []NotRestoredItem{},
			AppVolumesPresent: []AppVolumeMention{}, AppVolumesAbsent: []AppVolumeMention{},
			AppVolumes: vols.Volumes,
			PreparedAt: now, AppliedAt: &now,
		}
		var restored, failed, down []string
		for _, v := range vols.Volumes {
			switch {
			case v.Restored:
				restored = append(restored, v.Volume)
			case v.Failed:
				failed = append(failed, v.Volume)
			}
			if !v.AppRestored {
				down = append(down, v.Volume)
			}
		}
		report.Warning = appRestoreWarning(tgt.AppName, tgt.NodeID, restored, failed, len(vols.Volumes)-len(restored)-len(failed))
		if err := cfg.Store.RecordRestore(sc.Ctx, report); err != nil {
			return nil, fmt.Errorf("record the restore: %w", err)
		}
		sc.Log("info", fmt.Sprintf("restore %s recorded: %d volume(s) restored, %d failed, %d skipped", tgt.RestoreID, len(restored), len(failed), len(vols.Volumes)-len(restored)-len(failed)))
		out, err := json.Marshal(report)
		if err != nil {
			return nil, err
		}
		if len(down) > 0 {
			return out, fmt.Errorf("%s is NOT RUNNING after this restore stopped it to replace %s; the agent keeps retrying and a boot sweep will start it. The volumes that went back are back", tgt.AppName, strings.Join(down, ", "))
		}
		if len(failed) > 0 {
			return out, fmt.Errorf("%d of %d volume(s) of %s did NOT go back (%s); each is named with its reason in the record. The volumes that went back are back, and the app is running", len(failed), len(failed)+len(restored), tgt.AppName, strings.Join(failed, ", "))
		}
		return out, nil
	}
}

func appRestoreWarning(app, node string, restored, failed []string, skipped int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "This restore put back %d volume(s) of app %s on node %s from a backup generation, REPLACING what was there; the previous contents were moved aside beside each volume on %s and were not deleted. ",
		len(restored), app, node, node)
	if len(failed) > 0 {
		fmt.Fprintf(&b, "%d volume(s) did NOT go back: %s. ", len(failed), strings.Join(failed, ", "))
	}
	if skipped > 0 {
		fmt.Fprintf(&b, "%d volume(s) were skipped by design and are named with their reason. ", skipped)
	}
	b.WriteString("This record concerns one app's data only; the control-plane identity is a separate restore.")
	return b.String()
}

// ----- Reading the trusted manifest ---------------------------------------

// readSealedManifest opens the identity archive far enough to read its first
// member — the manifest — and stops. The chunks that carry it are each
// authenticated under the key before a byte is yielded, so what comes back
// is the manifest the run wrote and not the sidecar anyone holding the disk
// could edit. The rest of the archive is not read.
func readSealedManifest(archive io.Reader, privateKey []byte) (*Manifest, error) {
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		_, err := Unseal(pw, bufio.NewReaderSize(archive, 256<<10), privateKey)
		_ = pw.CloseWithError(err)
		done <- err
	}()
	defer func() {
		_ = pr.Close()
		<-done
	}()
	tr := tar.NewReader(pr)
	hdr, err := tr.Next()
	if err != nil {
		select {
		case uerr := <-done:
			done <- uerr
			if uerr != nil {
				return nil, fmt.Errorf("%w: %v", ErrRestoreArchive, uerr)
			}
		default:
		}
		return nil, fmt.Errorf("%w: the archive did not open as a tar: %v", ErrRestoreArchive, err)
	}
	if hdr.Name != proto.BackupManifestFile || hdr.Typeflag != tar.TypeReg {
		return nil, fmt.Errorf("%w: the archive's first member is %q, not the manifest", ErrRestoreArchive, hdr.Name)
	}
	if hdr.Size > maxManifestBytes {
		return nil, fmt.Errorf("%w: the inner manifest is %d bytes; refusing to read more than %d", ErrRestoreArchive, hdr.Size, maxManifestBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(tr, maxManifestBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: reading the inner manifest: %v", ErrRestoreArchive, err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%w: the inner manifest is not readable JSON", ErrRestoreArchive)
	}
	if m.ManifestVersion < 1 || m.ManifestVersion > ManifestVersion {
		return nil, fmt.Errorf("%w: the manifest is version %d; this build reads versions 1 to %d", ErrRestoreArchive, m.ManifestVersion, ManifestVersion)
	}
	return &m, nil
}
