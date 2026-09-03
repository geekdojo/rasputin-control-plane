package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// App volumes and their backup state — geekdojo/geekdojo-brain#399.
//
// The uninstall confirmation asks "Delete volumes?", and design/storage.md
// §4.4 says the answer must be informed: an operator deleting a `critical`
// volume that has never been backed up is told so, in those words, before they
// confirm. These routes are where the prompt gets its facts:
//
//   GET  /api/apps/{id}/volumes         the app's volumes by name and class,
//                                       each with when it was last captured
//   GET  /api/volumes/orphans           rasp_<appID>_* volumes on every
//                                       reachable node whose appID has no row
//                                       in the ledger
//   POST /api/volumes/orphans/reclaim   remove named orphans on one node
//
// # What "last captured" means, and what it costs
//
// The backup manifest is the only per-volume record of what a generation
// holds. It travels in the backup.run job's `fan_out` step result as
// AppVolumeReport.Volumes, one VolumeRecord per classified volume with
// Captured true or false. The backup_runs ledger holds only the counts. So the
// cheapest honest read is: take the runs that wrote a generation, newest first,
// keep only the generations still on the target (the newest run's `prune` step
// result lists them — retention is four, §4.4), and walk each one's fan_out
// result until a record with Captured true names the volume. That is at most
// four step-list reads and four small JSON parses per request, which is
// nothing; it is NOT indexed, and it is not worth indexing at this size. If
// retention ever grows past a handful of generations, index it then.
//
// A generation retention has already pruned is deliberately NOT a capture: a
// manifest saying "captured" about an archive that no longer exists is exactly
// the false belief §4.4 forbids.

// volumeCaptureView is when a volume was last captured into a generation that
// is still on the backup target. nil in a response means never.
type volumeCaptureView struct {
	GenerationID string    `json:"generationId"`
	At           time.Time `json:"at"`
	RunJobID     string    `json:"runJobId,omitempty"`
}

// appVolumeView is one of an app's volumes as the uninstall prompt lists it.
type appVolumeView struct {
	// Name is the tile's compose volume name; DockerName is what the daemon
	// calls it (rasp_<appid>_<name>).
	Name       string `json:"name"`
	DockerName string `json:"dockerName"`
	// Backup is the tile's §4.2 class: critical | state | cache | bulk.
	Backup  string `json:"backup"`
	Quiesce string `json:"quiesce,omitempty"`
	// LastCaptured is null when no retained generation holds this volume.
	LastCaptured *volumeCaptureView `json:"lastCaptured"`
}

// appVolumesResponse is GET /api/apps/{id}/volumes.
type appVolumesResponse struct {
	AppID   string `json:"appId"`
	AppName string `json:"appName"`
	TileID  string `json:"tileId,omitempty"`
	// Catalog names which catalog classified the volumes — the same source
	// string /api/catalog/_status reports.
	Catalog string `json:"catalog,omitempty"`
	// Classified is false when the volumes could not be listed: a custom app
	// with no tile, a tile the catalog in effect does not carry, or an api
	// with no live catalog. Note says which.
	Classified bool   `json:"classified"`
	Note       string `json:"note,omitempty"`
	// BackupNote explains an absent capture history — "backups are not
	// configured", "no generation has ever been written" — so the prompt can
	// say why every volume reads "never".
	BackupNote string          `json:"backupNote,omitempty"`
	Volumes    []appVolumeView `json:"volumes"`
}

// orphanVolumeView is one reclaimable volume: a rasp_<appID>_* volume on a
// node whose appID has no row in the apps ledger.
type orphanVolumeView struct {
	NodeID    string    `json:"nodeId"`
	Name      string    `json:"name"`
	AppID     string    `json:"appId"`
	Volume    string    `json:"volume"`
	SizeBytes uint64    `json:"sizeBytes"`
	CreatedAt time.Time `json:"createdAt"`
	InUse     bool      `json:"inUse"`
	// AppName, TileID and Backup come from the backup manifest when a
	// retained generation ever recorded this volume — the app row is gone,
	// so the manifest is the only place its name and class survive. Empty
	// means no manifest knows it: the class is unknown and it was never
	// backed up.
	AppName      string             `json:"appName,omitempty"`
	TileID       string             `json:"tileId,omitempty"`
	Backup       string             `json:"backup,omitempty"`
	LastCaptured *volumeCaptureView `json:"lastCaptured"`
}

// unreachableNode is a node the orphan listing could not ask.
type unreachableNode struct {
	NodeID string `json:"nodeId"`
	Reason string `json:"reason"`
}

// orphanVolumesResponse is GET /api/volumes/orphans.
type orphanVolumesResponse struct {
	Volumes     []orphanVolumeView `json:"volumes"`
	NodesAsked  int                `json:"nodesAsked"`
	Unreachable []unreachableNode  `json:"unreachable"`
	BackupNote  string             `json:"backupNote,omitempty"`
}

// reclaimRequest is POST /api/volumes/orphans/reclaim.
type reclaimRequest struct {
	NodeID string   `json:"nodeId"`
	Names  []string `json:"names"`
}

// reclaimResponse is its reply: the agent's ack, verbatim.
type reclaimResponse struct {
	NodeID  string                   `json:"nodeId"`
	OK      bool                     `json:"ok"`
	Detail  string                   `json:"detail,omitempty"`
	Removed []string                 `json:"removed"`
	Refused []proto.AppVolumeRefusal `json:"refused"`
}

// GET /api/apps/{id}/volumes
func (s *Server) handleAppVolumes(w http.ResponseWriter, r *http.Request) {
	app, err := s.apps.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if app == nil {
		writeError(w, http.StatusNotFound, "app not found")
		return
	}
	idx := s.buildCaptureIndex(r.Context())
	resp := appVolumesResponse{
		AppID: app.ID, AppName: app.Name, TileID: app.SourceTile,
		BackupNote: idx.note, Volumes: []appVolumeView{},
	}
	switch {
	case app.SourceTile == "":
		resp.Note = "custom app: its compose was not installed from a catalog tile, so its volumes are not classified and cannot be listed here. Any volume named " +
			proto.AppProjectName(app.ID) + "_* on " + app.TargetNode + " belongs to it."
	case s.catalogStore == nil:
		resp.Note = "no live catalog on this api, so the tile's volume classification is unavailable"
	default:
		tile, ok := s.catalogStore.Get(app.SourceTile)
		resp.Catalog = s.catalogStore.Source()
		if !ok {
			resp.Note = fmt.Sprintf("tile %q is not in the catalog in effect (%s), so its volume classification is unavailable", app.SourceTile, resp.Catalog)
			break
		}
		resp.Classified = true
		for _, v := range tile.Volumes {
			resp.Volumes = append(resp.Volumes, appVolumeView{
				Name: v.Name, DockerName: proto.AppVolumeName(app.ID, v.Name),
				Backup: v.Backup, Quiesce: v.Quiesce,
				LastCaptured: idx.captured[captureKey(app.ID, v.Name)],
			})
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// GET /api/volumes/orphans
func (s *Server) handleListOrphanVolumes(w http.ResponseWriter, r *http.Request) {
	live, err := s.liveAppIDs(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	nodes, err := s.inv.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	idx := s.buildCaptureIndex(r.Context())
	resp := orphanVolumesResponse{Volumes: []orphanVolumeView{}, Unreachable: []unreachableNode{}, BackupNote: idx.note}
	for _, n := range nodes {
		if !hostsApps(n) {
			continue
		}
		resp.NodesAsked++
		if inventory.ComputeStatus(n.LastSeen) != proto.StatusOnline {
			resp.Unreachable = append(resp.Unreachable, unreachableNode{NodeID: n.ID, Reason: "node is offline"})
			continue
		}
		vols, err := listNodeVolumes(r.Context(), s.nc, n.ID)
		if err != nil {
			resp.Unreachable = append(resp.Unreachable, unreachableNode{NodeID: n.ID, Reason: err.Error()})
			continue
		}
		for _, v := range vols {
			if live[strings.ToUpper(v.AppID)] {
				continue
			}
			key := captureKey(v.AppID, v.Volume)
			meta := idx.known[key]
			resp.Volumes = append(resp.Volumes, orphanVolumeView{
				NodeID: n.ID, Name: v.Name, AppID: v.AppID, Volume: v.Volume,
				SizeBytes: v.SizeBytes, CreatedAt: v.CreatedAt, InUse: v.InUse,
				AppName: meta.appName, TileID: meta.tileID, Backup: meta.class,
				LastCaptured: idx.captured[key],
			})
		}
	}
	sort.Slice(resp.Volumes, func(i, j int) bool {
		if resp.Volumes[i].NodeID != resp.Volumes[j].NodeID {
			return resp.Volumes[i].NodeID < resp.Volumes[j].NodeID
		}
		return resp.Volumes[i].Name < resp.Volumes[j].Name
	})
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/volumes/orphans/reclaim
//
// Refuses, never queues: an offline node is a 409 naming the node. Refuses
// before sending: every name is checked against the shape rule and the ledger
// here, and one bad name refuses the whole request — a client that asked for a
// live app's volume is a client whose whole request is suspect. The agent then
// applies the same two rules again plus docker's labels and container refs.
func (s *Server) handleReclaimOrphanVolumes(w http.ResponseWriter, r *http.Request) {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req reclaimRequest
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	req.NodeID = strings.TrimSpace(req.NodeID)
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, "nodeId is required")
		return
	}
	if len(req.Names) == 0 {
		writeError(w, http.StatusBadRequest, "names is required: name the volumes to reclaim")
		return
	}
	node, err := s.inv.Get(r.Context(), req.NodeID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if node == nil {
		writeError(w, http.StatusNotFound, "node not registered")
		return
	}
	if !hostsApps(node) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("node %s has role %s and hosts no app volumes", node.ID, node.Role))
		return
	}
	if inventory.ComputeStatus(node.LastSeen) != proto.StatusOnline {
		writeError(w, http.StatusConflict, fmt.Sprintf("node %s is offline; reclaim is refused, not queued — retry when it is back", node.ID))
		return
	}
	live, err := s.liveAppIDs(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var refused []proto.AppVolumeRefusal
	for _, name := range req.Names {
		if reason := proto.RefuseAppVolumeName(name, live); reason != "" {
			refused = append(refused, proto.AppVolumeRefusal{Name: name, Reason: reason})
		}
	}
	if len(refused) > 0 {
		writeJSON(w, http.StatusBadRequest, reclaimResponse{
			NodeID: node.ID, OK: false,
			Detail:  "refused: nothing was removed",
			Removed: []string{}, Refused: refused,
		})
		return
	}
	liveList := make([]string, 0, len(live))
	for id := range live {
		liveList = append(liveList, id)
	}
	sort.Strings(liveList)
	cmd, _ := json.Marshal(proto.AppVolumesRemoveCmd{Names: req.Names, LiveAppIDs: liveList})
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	msg, err := s.nc.RequestWithContext(ctx, proto.AppVolumesRemoveSubject(node.ID), cmd)
	if err != nil {
		if errors.Is(err, nats.ErrNoResponders) {
			writeError(w, http.StatusConflict, fmt.Sprintf("node %s has no container runtime answering for volumes", node.ID))
			return
		}
		writeError(w, http.StatusBadGateway, "reclaim rpc to "+node.ID+": "+err.Error())
		return
	}
	var ack proto.AppVolumesRemoveAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		writeError(w, http.StatusBadGateway, "unreadable reply from "+node.ID+": "+err.Error())
		return
	}
	if ack.Removed == nil {
		ack.Removed = []string{}
	}
	if ack.Refused == nil {
		ack.Refused = []proto.AppVolumeRefusal{}
	}
	// Destroying data is worth a line in the api log with who asked for it,
	// whatever the outcome.
	log.Printf("apps: %s reclaimed orphan volumes on %s: removed=%v refused=%d ok=%v",
		creator(r), node.ID, ack.Removed, len(ack.Refused), ack.OK)
	writeJSON(w, http.StatusOK, reclaimResponse{
		NodeID: node.ID, OK: ack.OK, Detail: ack.Detail, Removed: ack.Removed, Refused: ack.Refused,
	})
}

// hostsApps reports whether a node's agent registers the docker verbs at all
// (agent/cmd/rasputin-agent: compute and controlplane roles).
func hostsApps(n *proto.Node) bool {
	return n.Role == proto.RoleCompute || n.Role == proto.RoleControlPlane
}

// liveAppIDs is every app id in the ledger, upper-cased as ParseAppVolumeName
// reports them.
func (s *Server) liveAppIDs(ctx context.Context) (map[string]bool, error) {
	all, err := s.apps.List(ctx)
	if err != nil {
		return nil, err
	}
	live := make(map[string]bool, len(all))
	for _, a := range all {
		live[strings.ToUpper(a.ID)] = true
	}
	return live, nil
}

// listNodeVolumes asks one node's agent for its Rasputin-managed volumes.
func listNodeVolumes(ctx context.Context, nc *nats.Conn, nodeID string) ([]proto.AppVolumeInfo, error) {
	cmd, _ := json.Marshal(proto.AppVolumesListCmd{})
	// Sizing walks every managed volume; give a node with a big one time.
	rctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	msg, err := nc.RequestWithContext(rctx, proto.AppVolumesListSubject(nodeID), cmd)
	if err != nil {
		if errors.Is(err, nats.ErrNoResponders) {
			return nil, errors.New("no container runtime answering for volumes on this node")
		}
		return nil, fmt.Errorf("volumes rpc: %w", err)
	}
	var ack proto.AppVolumesListAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		return nil, fmt.Errorf("unreadable volumes reply: %w", err)
	}
	if !ack.OK {
		return nil, errors.New(ack.Detail)
	}
	return ack.Volumes, nil
}

// --- the capture index --------------------------------------------------------

// manifestVolumeMeta is what a manifest record says about a volume besides
// whether it was captured: the app's name, its tile and its class. Kept for
// orphans, whose app row — the only other place those live — is gone.
type manifestVolumeMeta struct {
	appName string
	tileID  string
	class   string
}

// captureIndex is the answer to "when was each volume last captured into a
// generation that still exists?", built per request from the job ledger.
type captureIndex struct {
	// captured maps captureKey → the newest retained generation holding it.
	captured map[string]*volumeCaptureView
	// known maps captureKey → what the newest manifest mentioning it says.
	known map[string]manifestVolumeMeta
	// note explains an empty index, in words the prompt can show.
	note string
}

func captureKey(appID, volume string) string {
	return strings.ToUpper(appID) + "/" + volume
}

// manifestVolumeRecord is the slice of storage.VolumeRecord this reads. A
// local shape rather than the storage type so this package depends on the
// manifest's JSON contract, which is versioned and public, and not on the
// backup package's internals.
type manifestVolumeRecord struct {
	App      string `json:"app"`
	AppID    string `json:"appId"`
	TileID   string `json:"tile"`
	Volume   string `json:"volume"`
	Class    string `json:"class"`
	Captured bool   `json:"captured"`
}

// fanOutStepResult is the `fan_out` step result's shape, as far as this reads.
type fanOutStepResult struct {
	Report struct {
		Volumes []manifestVolumeRecord `json:"volumes"`
	} `json:"report"`
}

// pruneStepResult is the `prune` step result's shape, as far as this reads.
type pruneStepResult struct {
	Kept []string `json:"kept"`
}

func (s *Server) buildCaptureIndex(ctx context.Context) captureIndex {
	idx := captureIndex{captured: map[string]*volumeCaptureView{}, known: map[string]manifestVolumeMeta{}}
	if s.backup == nil {
		idx.note = "backups are not configured on this api, so no volume has ever been captured"
		return idx
	}
	runs, err := s.backup.ListRuns(ctx, 0)
	if err != nil {
		idx.note = "backup history could not be read: " + err.Error()
		return idx
	}
	// Runs that wrote a generation, newest first (ListRuns orders by start).
	var withGen []struct {
		jobID, generationID string
		at                  time.Time
	}
	for _, run := range runs {
		if run.GenerationID == "" {
			continue
		}
		at := run.StartedAt
		if run.FinishedAt != nil {
			at = *run.FinishedAt
		}
		withGen = append(withGen, struct {
			jobID, generationID string
			at                  time.Time
		}{run.JobID, run.GenerationID, at})
	}
	if len(withGen) == 0 {
		idx.note = "no backup generation has ever been written, so no volume has ever been captured"
		return idx
	}
	// Which generations are still on the target: the newest run's prune
	// result knows. Without one (a run that failed after write, an older
	// build) fall back to the retention count and say so.
	kept := map[string]bool{}
	if res, ok := stepResult[pruneStepResult](ctx, s.store, withGen[0].jobID, "prune"); ok {
		for _, g := range res.Kept {
			kept[g] = true
		}
	}
	if len(kept) == 0 {
		idx.note = fmt.Sprintf("retention state unknown: treating the newest %d generation(s) as retained", proto.BackupRetainGenerations)
		for i, g := range withGen {
			if i >= proto.BackupRetainGenerations {
				break
			}
			kept[g.generationID] = true
		}
	}
	for _, run := range withGen {
		if !kept[run.generationID] {
			continue
		}
		res, ok := stepResult[fanOutStepResult](ctx, s.store, run.jobID, "fan_out")
		if !ok {
			continue
		}
		for _, rec := range res.Report.Volumes {
			key := captureKey(rec.AppID, rec.Volume)
			if _, seen := idx.known[key]; !seen {
				idx.known[key] = manifestVolumeMeta{appName: rec.App, tileID: rec.TileID, class: rec.Class}
			}
			if rec.Captured {
				if _, seen := idx.captured[key]; !seen {
					idx.captured[key] = &volumeCaptureView{GenerationID: run.generationID, At: run.at, RunJobID: run.jobID}
				}
			}
		}
	}
	return idx
}

// stepResult decodes the succeeded step `name` of job jobID into T. Missing,
// failed, empty or undecodable all read as "no result".
func stepResult[T any](ctx context.Context, store *jobs.Store, jobID, name string) (T, bool) {
	var zero T
	steps, err := store.ListSteps(ctx, jobID)
	if err != nil {
		return zero, false
	}
	for _, st := range steps {
		if st.Name != name || st.Status != jobs.StepSucceeded || len(st.Result) == 0 {
			continue
		}
		var out T
		if err := json.Unmarshal(st.Result, &out); err != nil {
			return zero, false
		}
		return out, true
	}
	return zero, false
}
