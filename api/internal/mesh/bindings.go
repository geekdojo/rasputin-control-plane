package mesh

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// A device is bound to a node (mesh_devices.rasputin_node_id) only by the
// record step of a mesh.enroll_node job, from the Headscale node id that
// node's agent reported over its own bus lane. Store.BindDevice writes the
// binding and the job that made it (enrol_job_id).
//
// Releases before that also bound any tag:rasputin-node device to the node
// named by its hostname, on every reconcile. VerifyBindings, run at api
// start, sorts those out: a binding the job ledger proves (a succeeded
// enroll for that node whose record step reported that device) is kept and
// gets its enrol_job_id; every other binding is cleared, and
// converge_enrollment then enrols the node again, which records a binding
// the proper way. Enrolling an already-enrolled node again keeps its
// Headscale id and tailnet IP (headscale 0.28 re-registers the same machine
// key in place) and, because the re-enrol carries the node's advertised
// routes (ReenrolRoutes), keeps its subnet routes too.

// EnrolRecord is one binding a mesh.enroll_node job recorded.
type EnrolRecord struct {
	JobID    string
	NodeID   string
	HSID     string
	Routes   []string // what the enrol sent the agent to advertise
	Finished time.Time
}

// EnrolLedger answers what the job ledger recorded about enrols.
type EnrolLedger interface {
	// Records returns every succeeded enrol's record, newest first.
	Records(ctx context.Context) ([]EnrolRecord, error)
}

// JobsLedger reads enrol records from the jobs store.
type JobsLedger struct{ Store *jobs.Store }

// Records reads every succeeded mesh.enroll_node job and its record step.
func (l JobsLedger) Records(ctx context.Context) ([]EnrolRecord, error) {
	if l.Store == nil {
		return nil, nil
	}
	all, err := l.Store.ListAllJobsByKind(ctx, "mesh.enroll_node")
	if err != nil {
		return nil, fmt.Errorf("list enrol jobs: %w", err)
	}
	var out []EnrolRecord
	for _, j := range all {
		if j.Status != jobs.StatusSucceeded {
			continue
		}
		steps, err := l.Store.ListSteps(ctx, j.ID)
		if err != nil {
			return nil, fmt.Errorf("steps of %s: %w", j.ID, err)
		}
		for _, st := range steps {
			if st.Name != "record" || st.Status != jobs.StepSucceeded || len(st.Result) == 0 {
				continue
			}
			var s enrollSession
			if json.Unmarshal(st.Result, &s) != nil || s.NodeID == "" || s.HSID == "" {
				continue
			}
			rec := EnrolRecord{JobID: j.ID, NodeID: s.NodeID, HSID: s.HSID, Routes: s.AdvertiseRoutes}
			switch {
			case st.FinishedAt != nil:
				rec.Finished = *st.FinishedAt
			case j.FinishedAt != nil:
				rec.Finished = *j.FinishedAt
			default:
				rec.Finished = j.CreatedAt
			}
			out = append(out, rec)
		}
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Finished.After(out[b].Finished) })
	return out, nil
}

// BindingReport is what VerifyBindings did.
type BindingReport struct {
	Kept    []string // "node=hsid" proven by the ledger (or by an earlier enrol)
	Cleared []string // "node=hsid" with no enrol behind it, or a duplicate
}

// VerifyBindings keeps each device→node binding an enrol recorded and
// clears the rest (see the comment at the top of this file), then makes a
// second binding for the same node impossible. Idempotent: once every
// binding carries its enrol job it reads nothing from the ledger and
// changes nothing. With no job history at all every legacy binding is
// cleared, and every node re-enrols.
func VerifyBindings(ctx context.Context, st *Store, ledger EnrolLedger) (*BindingReport, error) {
	devices, err := st.ListDevices(ctx)
	if err != nil {
		return nil, err
	}
	var bound []*Device
	needLedger := false
	byNode := map[string]int{}
	for _, d := range devices {
		if d.RasputinNodeID == "" {
			continue
		}
		bound = append(bound, d)
		byNode[d.RasputinNodeID]++
		if d.EnrolJobID == "" || byNode[d.RasputinNodeID] > 1 {
			needLedger = true
		}
	}
	rep := &BindingReport{}
	if !needLedger {
		return rep, st.ensureBindingIndex(ctx)
	}
	var records []EnrolRecord
	if ledger != nil {
		if records, err = ledger.Records(ctx); err != nil {
			// Fail closed: with no readable ledger nothing is proven, so every
			// binding no enrol wrote is cleared and its node re-enrols.
			log.Printf("mesh: cannot read enrol records (%v); treating every binding no enrol recorded as unproven", err)
			records = nil
		}
	}
	// The newest proving record per (node, device).
	proof := map[[2]string]EnrolRecord{}
	for _, r := range records {
		k := [2]string{r.NodeID, r.HSID}
		if _, seen := proof[k]; !seen {
			proof[k] = r
		}
	}
	finished := map[string]time.Time{}
	for _, r := range records {
		if _, seen := finished[r.JobID]; !seen {
			finished[r.JobID] = r.Finished
		}
	}

	// Each binding is either proven (with the time of the enrol that proves
	// it) or cleared.
	type candidate struct {
		d  *Device
		at time.Time
	}
	winners := map[string]candidate{}
	var losers []*Device
	for _, d := range bound {
		jobID := d.EnrolJobID
		at, known := finished[jobID]
		if jobID == "" || !known {
			r, ok := proof[[2]string{d.RasputinNodeID, d.HSID}]
			if !ok && jobID == "" {
				losers = append(losers, d)
				continue
			}
			if ok {
				jobID, at = r.JobID, r.Finished
				if d.EnrolJobID != jobID {
					if err := st.setEnrolJob(ctx, d.HSID, jobID); err != nil {
						return nil, err
					}
					d.EnrolJobID = jobID
				}
			}
		}
		c, ok := winners[d.RasputinNodeID]
		if !ok || at.After(c.at) {
			if ok {
				losers = append(losers, c.d)
			}
			winners[d.RasputinNodeID] = candidate{d: d, at: at}
			continue
		}
		losers = append(losers, d)
	}
	for _, d := range losers {
		if err := st.UnbindDevice(ctx, d.HSID); err != nil {
			return nil, err
		}
		rep.Cleared = append(rep.Cleared, d.RasputinNodeID+"="+d.HSID)
	}
	for node, c := range winners {
		rep.Kept = append(rep.Kept, node+"="+c.d.HSID)
	}
	sort.Strings(rep.Kept)
	sort.Strings(rep.Cleared)
	for _, k := range rep.Kept {
		log.Printf("mesh: binding %s kept (recorded by an enrol)", k)
	}
	for _, c := range rep.Cleared {
		log.Printf("mesh: binding %s cleared (no enrol recorded it, or the node has a newer enrolled device); the node re-enrols on the next reconcile", c)
	}
	return rep, st.ensureBindingIndex(ctx)
}

// ReenrolRoutes is what an automatic re-enrol of nodeID asks its agent to
// advertise. The agent runs `tailscale up --reset`, which drops any route
// the command does not name, so an automatic re-enrol must name the
// routes the node advertises now. In order:
//
//  1. the routes Headscale reports the node's bound device advertising;
//  2. with no bound device (a binding VerifyBindings cleared), the routes
//     the node's newest succeeded enrol sent;
//  3. otherwise the node's enabled subnet_route intents.
//
// Only routes the enrol's validate step would accept are carried; any other
// is logged and left out, so one odd route cannot fail the re-enrol.
func ReenrolRoutes(ctx context.Context, svc *Service, nodeID string, bound *Device, records []EnrolRecord) ([]string, string) {
	var routes []string
	source := "none"
	switch {
	case bound != nil:
		routes, source = bound.AdvertisedRoutes, "device"
	default:
		for _, r := range records {
			if r.NodeID == nodeID {
				routes, source = r.Routes, "last enrol"
				break
			}
		}
		if source == "none" && svc != nil && svc.store != nil {
			intents, err := svc.store.ListIntentsByKind(ctx, string(proto.IntentSubnetRoute))
			if err == nil {
				for _, i := range intents {
					var spec proto.SubnetRouteSpec
					if i.Enabled && json.Unmarshal(i.Spec, &spec) == nil && spec.NodeID == nodeID && spec.CIDR != "" {
						routes = append(routes, spec.CIDR)
						source = "subnet route intents"
					}
				}
			}
		}
	}
	out := make([]string, 0, len(routes))
	seen := map[string]bool{}
	for _, r := range routes {
		if err := ValidateAdvertiseRoutes([]string{r}); err != nil {
			log.Printf("mesh: re-enrol of %s leaves out route %q (%v)", nodeID, r, err)
			continue
		}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out, source
}
