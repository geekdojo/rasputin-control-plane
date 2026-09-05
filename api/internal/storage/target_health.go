package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/releases"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Target health — the gap between runs (design/storage.md §4.4,
// geekdojo/geekdojo-brain#398).
//
// #298 made a RUN that fails loud. This is about the six days between runs at
// the default weekly cadence, during which a target can leave the bus and
// nothing notices: on e3bench (2026-09-02) a USB target threw `device offline
// error` on writes, stopped answering enumeration, and left the machine, and
// the Backups view went on saying CLAIMED the whole time. The claim status was
// not wrong — the operator's intent had not changed — but it was the only
// thing the view said, and "you have a backup target" is precisely the belief
// a backup feature exists to make true.
//
// So the scheduler runs storage.reconcile every five minutes: for each claimed
// target, storage.inspect on the node that holds it WITH A WRITE PROBE, because
// that same stick answered enumeration for some time after it had begun
// failing writes. The verdict is recorded on the target row beside the claim
// status (never in place of it), rendered on the storage page, raised as one
// alert per unhealthy target, and cited by backup.run's refusal so the run's
// failure and the row tell one story.
//
// # What this cannot promise
//
// A 4 KiB probe that passes at 03:55 says nothing about a gigabyte at 04:00.
// The check catches a disk that has LEFT — the bus, the mount table, or the
// set of disks that take writes — between runs. It does not make the next run
// succeed, and the page says so (proto.BackupTargetHealthCaveat).
//
// # Resolved by partition UUID, never by device name
//
// The same e3bench run watched a healthy target move sda → sdb → sda across
// reboots. Inspect resolves by partition UUID (§4.8); the device path recorded
// at claim time is consulted only to answer "then what IS at /dev/sda now?"
// when the UUID is not found, and the answer is the §4.8 fingerprint check: a
// different disk at the old path is reported as a different disk, and health
// stays missing.

// TargetHealthJobKind is the scheduler entry. Named like the other
// drift-prone subsystems' tickers (firewall.reconcile, apps.reconcile,
// mesh.reconcile): this is storage's.
const TargetHealthJobKind = "storage.reconcile"

// Step budget: one inspect (with the probe inside the agent's inspect budget)
// plus, on a missing target, one enumerate to say what is at the old path,
// plus slack. Every RPC inside is bounded on its own; this is the ceiling.
const targetHealthStepTimeout = proto.StorageInspectWork + proto.StorageEnumerateWork + 2*rpcSlack + 10*time.Second

// healthFreshWindow is how old a recorded health may be and still be acted on
// by something OTHER than the poll — backup.run's validate, the restore
// surfaces. Three poll intervals: one for the tick, one for a tick that ran
// long, one for luck. A record older than that (an api that was down) is not
// trusted to refuse anything; the run's own preflight decides, and records.
const healthFreshWindow = 3 * proto.BackupTargetHealthInterval

// TargetHealthWorkflow returns the one-step storage.reconcile saga.
//
//	1 probe_targets  agent  storage.inspect + write probe on every claimed
//	                        target; record each verdict on its row
//
// The step SUCCEEDS on an unhealthy target. The health row and the alert are
// the signal; a job that failed every five minutes would raise a job-failed
// alert per tick (alerts.jobAlerts keeps 24 h of them) and bury the one alert
// that matters. It fails only when the ledger cannot be read or written —
// the case where nothing was recorded and something should say so.
func TargetHealthWorkflow(store *Store, inv *inventory.Store) jobs.Workflow {
	return jobs.Workflow{
		Kind: TargetHealthJobKind,
		Steps: []jobs.WorkflowStep{
			{Name: "probe_targets", Timeout: targetHealthStepTimeout, Do: targetHealthProbe(store, inv)},
		},
	}
}

// TargetHealthDue gates the ticker: fire only when there is a claimed target
// to check. Silent either way — a cluster with no target has nothing to poll,
// and the job's own log lines say what a fired tick found.
func TargetHealthDue(store *Store) func(context.Context) (bool, string) {
	return func(ctx context.Context) (bool, string) {
		claimed, err := store.ListClaimed(ctx)
		if err != nil {
			return false, fmt.Sprintf("could not read claimed targets: %v", err)
		}
		return len(claimed) > 0, ""
	}
}

// targetHealthResult is the step's recorded result: one line per target.
type targetHealthResult struct {
	Targets []targetHealthLine `json:"targets"`
}

type targetHealthLine struct {
	PartUUID string                        `json:"partUuid"`
	Label    string                        `json:"label,omitempty"`
	NodeID   string                        `json:"nodeId"`
	State    proto.BackupTargetHealthState `json:"state"`
	Since    time.Time                     `json:"since"`
	Detail   string                        `json:"detail,omitempty"`
}

func targetHealthProbe(store *Store, inv *inventory.Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		claimed, err := store.ListClaimed(sc.Ctx)
		if err != nil {
			return nil, fmt.Errorf("claimed targets: %w", err)
		}
		res := targetHealthResult{Targets: []targetHealthLine{}}
		var firstErr error
		for _, t := range claimed {
			h, err := CheckTarget(sc.Ctx, sc.NATS, inv, store, t)
			if err != nil {
				// Recorded nothing: say so and keep going — one target's
				// ledger error must not stop the next target's check.
				sc.Log("error", fmt.Sprintf("target %s (partUuid %s): health check not recorded: %v", displayLabel(t.Label), t.PartUUID, err))
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			level := "info"
			if h.State.Unhealthy() {
				level = "error"
			}
			sc.Log(level, fmt.Sprintf("target %s: %s", displayLabel(t.Label), DescribeHealth(h)))
			res.Targets = append(res.Targets, targetHealthLine{
				PartUUID: t.PartUUID, Label: t.Label, NodeID: t.NodeID,
				State: h.State, Since: h.Since, Detail: h.Detail,
			})
		}
		out, merr := json.Marshal(res)
		if merr != nil {
			return nil, merr
		}
		return out, firstErr
	}
}

// CheckTarget probes one target and records what it found. The returned
// health is the row's, with Since resolved against the previous check.
func CheckTarget(ctx context.Context, nc *nats.Conn, inv *inventory.Store, store *Store, target *BackupTarget) (proto.BackupTargetHealth, error) {
	h := ProbeTarget(ctx, nc, inv, target)
	return store.RecordHealth(ctx, target.PartUUID, h)
}

// ProbeTarget runs one health check against target and returns the verdict
// without recording it. Every failure mode maps to a state that is not
// `unknown`: a probe that ran has an answer, even when the answer is "nothing
// answered".
func ProbeTarget(ctx context.Context, nc *nats.Conn, inv *inventory.Store, target *BackupTarget) proto.BackupTargetHealth {
	now := time.Now().UTC()
	h := proto.BackupTargetHealth{CheckedAt: now}
	if target == nil || strings.TrimSpace(target.PartUUID) == "" {
		h.State = proto.BackupTargetHealthMissing
		h.Detail = "the claimed target has no partition UUID recorded, which is the only identifier a target has; nothing can be looked for. Re-claim the disk"
		return h
	}
	if nc == nil {
		h.State = proto.BackupTargetHealthUnreachable
		h.Detail = "this api has no bus connection, so the node holding the target could not be asked"
		return h
	}

	subject := proto.StorageInspectSubject(target.NodeID)
	ack, err := inspectWithProbe(ctx, nc, subject, target.PartUUID)
	if err != nil {
		h.State = proto.BackupTargetHealthUnreachable
		h.Detail = explainSilence(ctx, inv, subject, target.NodeID, err)
		return h
	}

	switch {
	case !ack.Present:
		h.State = proto.BackupTargetHealthMissing
		h.Detail = fmt.Sprintf("nothing attached to %s carries partition UUID %s", target.NodeID, target.PartUUID)
		if ack.Detail != "" && ack.Detail != "no attached disk carries that partition UUID" {
			h.Detail += " (" + ack.Detail + ")"
		}
		h.Detail += "; " + whatIsAtTheOldPath(ctx, nc, target)
		return h
	case !ack.OK:
		h.State = proto.BackupTargetHealthUnmounted
		h.Detail = ack.Detail
		if h.Detail == "" {
			h.Detail = fmt.Sprintf("the partition is attached to %s but could not be mounted", target.NodeID)
		}
		if ack.Refusal != "" {
			h.Detail += " [" + string(ack.Refusal) + "]"
		}
		return h
	}

	// Present and mounted. Before trusting it: is it the disk that was
	// claimed, by its own account? The partition UUID matched, so a mismatch
	// here is nearly impossible — but the marker is the record and the row is
	// the cache (proto.StorageMarkerFile), and a target that has lost its
	// marker is a target restore cannot find.
	where := fmt.Sprintf("attached to %s as %s, mounted at %s", target.NodeID, firstNonEmpty(ack.DevicePath, "?"), firstNonEmpty(ack.MountPath, "?"))
	if ack.TotalBytes > 0 {
		where += fmt.Sprintf(", %s free of %s", humanBytes(ack.FreeBytes), humanBytes(ack.TotalBytes))
	}
	switch {
	case ack.BackupSet == nil:
		h.State = proto.BackupTargetHealthMissing
		h.Detail = where + "; but it carries no readable " + proto.StorageMarkerFile + " marker — by its own account it is not the claimed target, and nothing will be written to it"
		return h
	case strings.TrimSpace(ack.BackupSet.PartUUID) != "" && ack.BackupSet.PartUUID != target.PartUUID:
		h.State = proto.BackupTargetHealthMissing
		h.Detail = fmt.Sprintf("%s; but its marker names partition %s, not %s — a different backup set, and nothing will be written to it",
			where, ack.BackupSet.PartUUID, target.PartUUID)
		return h
	}

	if ack.WriteProbe == nil {
		// Present, mounted, marker intact — and not write-verified, because
		// the agent that answered did not probe. OK, with the gap stated:
		// presence and mount are real findings, and raising a crit alert on
		// every cluster whose agent is one release behind its api would bury
		// the alert that matters.
		h.State = proto.BackupTargetHealthOK
		h.Detail = where + "; write probe NOT performed — " + explainNoProbe(ctx, inv, target.NodeID)
		return h
	}
	h.ProbeDurationMs = ack.WriteProbe.DurationMs
	if !ack.WriteProbe.OK {
		h.State = proto.BackupTargetHealthUnwritable
		h.Detail = where + "; write probe FAILED: " + ack.WriteProbe.Detail
		return h
	}
	h.State = proto.BackupTargetHealthOK
	h.Detail = where + "; " + ack.WriteProbe.Detail
	return h
}

// inspectWithProbe is the RPC, bounded by the agent's inspect budget plus
// slack. An error here is "no answer" in every form — no responder, timeout,
// unreadable reply.
func inspectWithProbe(ctx context.Context, nc *nats.Conn, subject, partUUID string) (*proto.StorageInspectAck, error) {
	ctx, cancel := context.WithTimeout(ctx, proto.StorageInspectWork+rpcSlack)
	defer cancel()
	cmd, err := json.Marshal(proto.StorageInspectCmd{PartUUID: partUUID, Probe: true})
	if err != nil {
		return nil, err
	}
	msg, err := nc.RequestWithContext(ctx, subject, cmd)
	if err != nil {
		return nil, err
	}
	var ack proto.StorageInspectAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		return nil, fmt.Errorf("unreadable reply: %w", err)
	}
	return &ack, nil
}

// explainSilence turns "no answer" into a sentence that says which of the
// three honest readings applies — node offline, agent predates the verb, or a
// real fault — from what inventory already knows (inventory.ExplainNoResponder).
func explainSilence(ctx context.Context, inv *inventory.Store, subject, nodeID string, err error) string {
	budget := (proto.StorageInspectWork + rpcSlack).Truncate(time.Second)
	head := fmt.Sprintf("no answer from the agent on %s to storage.inspect within %s", nodeID, budget)
	if errors.Is(err, nats.ErrNoResponders) || errors.Is(err, context.DeadlineExceeded) {
		if inv != nil {
			return head + ": " + inv.ExplainNoResponder(ctx, subject).String()
		}
		return head
	}
	return head + ": " + err.Error()
}

// explainNoProbe says why an inspect ack came back without a write probe:
// the agent is older than the probe, or it should have probed and did not.
func explainNoProbe(ctx context.Context, inv *inventory.Store, nodeID string) string {
	floor := "v" + proto.StorageInspectProbeMinAgentVersion
	if inv == nil {
		return fmt.Sprintf("the agent on %s answered without one (first probed by agent %s)", nodeID, floor)
	}
	node, err := inv.Get(ctx, nodeID)
	if err != nil || node == nil {
		return fmt.Sprintf("the agent on %s answered without one (first probed by agent %s)", nodeID, floor)
	}
	v := strings.TrimPrefix(strings.TrimSpace(node.AgentVersion), "v")
	if v == "" {
		return fmt.Sprintf("the agent on %s never reported a version and answered without one (first probed by agent %s)", nodeID, floor)
	}
	if c, cerr := releases.Compare(releases.SchemeCalVer, v, proto.StorageInspectProbeMinAgentVersion); cerr == nil && c < 0 {
		return fmt.Sprintf("the agent on %s (v%s) predates the write probe; update the node to ≥ %s", nodeID, v, floor)
	}
	return fmt.Sprintf("the agent on %s (v%s) should have probed and did not", nodeID, v)
}

// whatIsAtTheOldPath answers the question a missing target raises — "then
// what is at /dev/sda now?" — with the §4.8 fingerprint check. A disk at the
// claimed target's old device path with a different fingerprint is a
// DIFFERENT DISK, said in those words, so an operator who swapped sticks is
// told rather than left to infer it from an absence.
func whatIsAtTheOldPath(ctx context.Context, nc *nats.Conn, target *BackupTarget) string {
	path := strings.TrimSpace(target.DevicePath)
	if path == "" {
		return "no device path was recorded at claim time, so nothing was looked for in its place"
	}
	ack, err := Enumerate(ctx, nc, target.NodeID)
	if err != nil {
		return fmt.Sprintf("what is at %s now could not be determined (%v)", path, err)
	}
	for _, c := range ack.Candidates {
		if c.DevicePath != path {
			continue
		}
		desc := describeCandidate(c)
		switch {
		case target.Fingerprint == "":
			return fmt.Sprintf("a disk is at %s now (%s) but the claim recorded no fingerprint to compare it against", path, desc)
		case c.Fingerprint != target.Fingerprint:
			return fmt.Sprintf("a DIFFERENT disk is at %s now (%s; fingerprint %s ≠ the claimed %s) — not the claimed target, and nothing will be written to it",
				path, desc, short(c.Fingerprint), short(target.Fingerprint))
		default:
			return fmt.Sprintf("the disk at %s fingerprints as the claimed one (%s) but no longer carries the partition — its partition table changed underneath the claim",
				path, desc)
		}
	}
	return fmt.Sprintf("nothing is attached at %s either", path)
}

func describeCandidate(c proto.StorageCandidate) string {
	parts := []string{}
	if c.Model != "" {
		parts = append(parts, c.Model)
	}
	if c.Serial != "" {
		parts = append(parts, "serial "+c.Serial)
	}
	if c.SizeBytes > 0 {
		parts = append(parts, humanBytes(c.SizeBytes))
	}
	if len(parts) == 0 {
		return "no model, serial or size reported"
	}
	return strings.Join(parts, ", ")
}

// HealthFresh reports whether h was checked recently enough to act on outside
// the poll — see healthFreshWindow.
func HealthFresh(h *proto.BackupTargetHealth, now time.Time) bool {
	if h == nil || h.State == proto.BackupTargetHealthUnknown || h.CheckedAt.IsZero() {
		return false
	}
	return now.Sub(h.CheckedAt) <= healthFreshWindow
}

// DescribeHealth is the one sentence every surface uses for a health record:
// "MISSING since 2026-09-02 03:12 UTC (3h 40m ago; last probe 03:57 UTC: …)".
// One sentence in one place, so the run's refusal, the row's hover, the
// restore surface and the alert cannot disagree about what was found.
func DescribeHealth(h proto.BackupTargetHealth) string {
	if h.State == "" || h.State == proto.BackupTargetHealthUnknown {
		return "health not checked yet"
	}
	now := time.Now().UTC()
	if h.State == proto.BackupTargetHealthOK {
		return fmt.Sprintf("OK since %s (last probe %s: %s)",
			h.Since.UTC().Format("2006-01-02 15:04 UTC"), h.CheckedAt.UTC().Format("15:04 UTC"), h.Detail)
	}
	return fmt.Sprintf("%s since %s (%s ago; last probe %s: %s)",
		strings.ToUpper(string(h.State)), h.Since.UTC().Format("2006-01-02 15:04 UTC"),
		humanDuration(now.Sub(h.Since)), h.CheckedAt.UTC().Format("15:04 UTC"), h.Detail)
}

// humanDuration is "Nm" / "Nh Nm" / "Nd Nh", clamped at zero.
func humanDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		hrs := int(d.Hours())
		mins := int(d.Minutes()) - hrs*60
		if mins == 0 {
			return fmt.Sprintf("%dh", hrs)
		}
		return fmt.Sprintf("%dh %dm", hrs, mins)
	default:
		days := int(d.Hours() / 24)
		hrs := int(d.Hours()) - days*24
		if hrs == 0 {
			return fmt.Sprintf("%dd", days)
		}
		return fmt.Sprintf("%dd %dh", days, hrs)
	}
}
