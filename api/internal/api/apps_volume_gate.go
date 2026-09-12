package api

import (
	"context"
	"errors"
	"log"
	"net/http"
	"sort"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// The advisory half of the dropped-volume gate on PUT /api/apps/{id}/compose
// (geekdojo/geekdojo-brain#412). The authoritative half is the job's pull
// step; apps/volumegate.go says why there are two.

// advisoryVolumeCheckTimeout bounds the node round trip the PUT waits on. It
// is shorter than the saga's own check on purpose: past it the request stops
// waiting and lets the job ask, rather than holding an owner's request for as
// long as a job step may take.
const advisoryVolumeCheckTimeout = 10 * time.Second

// droppedVolumeView is one volume a compose change would orphan, as the 409
// lists it.
type droppedVolumeView struct {
	// Name is the docker volume name — what deleteVolumes takes.
	Name string `json:"name"`
	// Volume is its compose key.
	Volume string `json:"volume"`
	// Backup is the volume's backup class (critical | state | cache | bulk)
	// when a retained backup manifest recorded it, and absent when none did:
	// the volume is by definition one the new compose no longer declares, so
	// the new tile cannot classify it, and the manifest is the only record of
	// what it held.
	Backup string `json:"backup,omitempty"`
	// LastCaptured is null when no retained generation holds the volume.
	LastCaptured *volumeCaptureView `json:"lastCaptured"`
}

// volumeGateResponse is the 409 PUT /api/apps/{id}/compose answers a change
// that drops volumes deleteVolumes does not name, or names volumes it does
// not drop. The UI reads droppedVolumes to ask the owner about each one.
type volumeGateResponse struct {
	Error string `json:"error"`
	// DroppedVolumes is every named volume the app has on disk that the new
	// compose does not declare — named in deleteVolumes or not — so a client
	// resubmitting can send exactly these.
	DroppedVolumes []droppedVolumeView `json:"droppedVolumes"`
	// NotDropped is every deleteVolumes entry the change does not drop.
	NotDropped []string `json:"notDropped"`
}

// deleteVolumesFor applies the daemon-free rules to a body's deleteVolumes and
// returns the list as the job spec records it, sorted. A failure has been
// answered 400.
func (s *Server) deleteVolumesFor(w http.ResponseWriter, app *apps.App, names []string) ([]string, bool) {
	if err := apps.ValidateDeleteVolumes(app.ID, names); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return nil, false
	}
	if len(names) == 0 {
		return nil, true
	}
	out := append([]string(nil), names...)
	sort.Strings(out)
	return out, true
}

// droppedAnswer is what the advisory check learned: the dropped volumes, or
// that it has no answer.
type droppedAnswer struct {
	dropped []proto.AppDroppedVolume
	known   bool
}

// catalogDropped answers for an upgrade to tile. The keys the new compose
// declares come from the tile's own volume declarations, already in the
// verified store, so no compose is sent anywhere; which named volumes the app
// has on disk is the node's to say, through the listing the orphan page reads.
func (s *Server) catalogDropped(r *http.Request, app *apps.App, tile tileschema.Tile) droppedAnswer {
	node, err := s.inv.Get(r.Context(), app.TargetNode)
	if err != nil || node == nil {
		s.advisorySkipped(app, errors.New("the app's node is not in inventory"))
		return droppedAnswer{}
	}
	if inventory.ComputeStatus(node.LastSeen) != proto.StatusOnline {
		s.advisorySkipped(app, errors.New("node "+node.ID+" is offline"))
		return droppedAnswer{}
	}
	ctx, cancel := context.WithTimeout(r.Context(), advisoryVolumeCheckTimeout)
	defer cancel()
	vols, err := listNodeVolumesWith(ctx, s.nc, node, proto.AppVolumesListCmd{SkipSizes: true})
	if err != nil {
		s.advisorySkipped(app, err)
		return droppedAnswer{}
	}
	declared := make([]string, 0, len(tile.Volumes))
	for _, v := range tile.Volumes {
		declared = append(declared, v.Name)
	}
	return droppedAnswer{dropped: apps.DroppedByDeclared(app.ID, vols, declared), known: true}
}

// nodeDropped answers for a compose the api cannot read: the node's Compose
// reads it (docker.volumes.check), exactly as the job's pull step will.
func (s *Server) nodeDropped(r *http.Request, app *apps.App, compose string) droppedAnswer {
	ctx, cancel := context.WithTimeout(r.Context(), advisoryVolumeCheckTimeout)
	defer cancel()
	dropped, err := apps.DroppedVolumesOnNode(ctx, s.inv, s.nc, app, compose)
	if err != nil {
		s.advisorySkipped(app, err)
		return droppedAnswer{}
	}
	return droppedAnswer{dropped: dropped, known: true}
}

// advisorySkipped records a check that got no answer. The request goes on: an
// unanswered advisory check is not a refusal, because the job's pull step
// asks the node again before it pulls or writes anything, and refuses there
// if the node still cannot answer.
//
// The reason can carry a node's words (an agent's detail, compose's stderr),
// so it is logged with %q: a newline in it is escaped rather than starting a
// forged log line. The app id is the row's own ULID, not the request path.
func (s *Server) advisorySkipped(app *apps.App, err error) {
	log.Printf("apps: PUT compose for %s: advisory dropped-volume check got no answer, leaving it to the job: %q", app.ID, err.Error())
}

// refuseDroppedVolumes answers 409 when the advisory check has an answer and
// the gate refuses it, and reports whether it did.
func (s *Server) refuseDroppedVolumes(w http.ResponseWriter, r *http.Request, app *apps.App, named []string, answer droppedAnswer) bool {
	if !answer.known {
		return false
	}
	err := apps.GateDroppedVolumes(answer.dropped, named)
	var gate *apps.VolumeGateError
	if !errors.As(err, &gate) {
		return false
	}
	resp := volumeGateResponse{Error: gate.Error(), DroppedVolumes: []droppedVolumeView{}, NotDropped: []string{}}
	resp.NotDropped = append(resp.NotDropped, gate.NotDropped...)
	var idx captureIndex
	if len(gate.Dropped) > 0 {
		idx = s.buildCaptureIndex(r.Context())
	}
	for _, v := range gate.Dropped {
		key := captureKey(app.ID, v.Volume)
		resp.DroppedVolumes = append(resp.DroppedVolumes, droppedVolumeView{
			Name: v.Name, Volume: v.Volume,
			Backup: idx.known[key].class, LastCaptured: idx.captured[key],
		})
	}
	writeJSON(w, http.StatusConflict, resp)
	return true
}
