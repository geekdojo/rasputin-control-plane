package updater

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"sort"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bytesize"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The control-plane memory floor (geekdojo/geekdojo-brain#1011). A release
// whose signed manifest states a floor is installed on no node of the fleet
// while any control plane reports less memory than the floor, has not reported
// its memory, or cannot have it read. The fleet plan refuses the whole run
// before any child job exists; node.update's validate step refuses a direct
// update of a control plane the same way. A bundle with no floor (0) is
// checked exactly as before the field existed: memory is never read.

// NodeMemory is the one read the floor check makes of the metrics store
// (ARCH-ISP): the newest retained sample of a node's metric, and ok=false when
// the node has none. *metrics.Store satisfies it.
type NodeMemory interface {
	LatestValue(ctx context.Context, nodeID, name string) (float64, bool, error)
}

// floorReason is why a control plane failed the floor; it is the `reason`
// field of the refusal's log record.
type floorReason string

const (
	floorBelow       floorReason = "below"
	floorNotReported floorReason = "not_reported"
	floorUnreadable  floorReason = "unreadable"
)

// errNoMemoryReader is the log record's err when no NodeMemory is wired: the
// memory cannot be read, so the update is refused (ERR-CLOSED).
var errNoMemoryReader = errors.New("updater: no memory reader is wired")

// errMemoryValue is the log record's err when the newest sample is not a
// positive, finite byte count.
var errMemoryValue = errors.New("updater: the reported memory is not a positive finite number")

// floorRefusal is one control plane failing the floor, with what the log
// record carries. NodeID is empty when inventory holds no control plane.
type floorRefusal struct {
	Reason   floorReason
	NodeID   string
	Name     string // hostname, else the node id
	Floor    int64
	MemTotal float64 // the reported value; meaningful for floorBelow and a bad value
	Err      error   // the read error, for the log record only (ERR-BOUNDARY)
	Version  string  // the release the run or bundle carries
}

// sentence is the refusal a person reads, ending in closing (ERR-MESSAGE).
// The raw read error is never part of it.
func (r *floorRefusal) sentence(closing string) string {
	// Floor is > 0 wherever a refusal is built; the guard keeps the unsigned
	// conversion provably in range.
	var floor uint64
	if f := r.Floor; f > 0 {
		floor = uint64(f)
	}
	need := "This update needs at least " + bytesize.Format(floor) + " of memory on the control plane"
	switch {
	case r.NodeID == "":
		return need + ", and this cluster has no control plane that reports its memory, so the update was refused. " + closing
	case r.Reason == floorBelow:
		return need + "; " + r.Name + " has " + bytesize.Format(uint64(r.MemTotal)) + ". " + closing
	case r.Reason == floorNotReported:
		return need + ", and " + r.Name + " has not reported its memory, so the update was refused. " + closing
	default:
		return need + ", and the memory of " + r.Name + " could not be read, so the update was refused. " + closing
	}
}

// planError is the fleet plan's refusal: nothing has run yet.
func (r *floorRefusal) planError() error {
	return &floorError{refusal: r, closing: "No node was updated."}
}

// backstopError is node.update's refusal at validate. It names only the node
// being updated, because a cascade's own control-plane child runs after its
// computes have already installed.
func (r *floorRefusal) backstopError() error {
	return &floorError{refusal: r, closing: "Nothing was installed on " + r.Name + "."}
}

// logAttrs are the refusal record's fields beside component, event and job_id.
func (r *floorRefusal) logAttrs() []any {
	attrs := []any{
		"node_id", r.NodeID, "version", r.Version, "floor_bytes", r.Floor,
		"mem_total_bytes", r.MemTotal, "reason", string(r.Reason),
	}
	if r.Err != nil {
		attrs = append(attrs, "err", r.Err.Error())
	}
	return attrs
}

// log writes the one WARN record for a refusal: handled, and the system stays
// correct (LOG-VERBOSITY). extra carries the caller's own fields.
func (r *floorRefusal) log(ctx context.Context, l *slog.Logger, jobID string, extra ...any) {
	if l == nil {
		return
	}
	args := append([]any{"component", "updater", "event", "updater.memory_floor_refused", "job_id", jobID}, r.logAttrs()...)
	l.WarnContext(ctx, "update refused: a control plane is below the release's memory floor", append(args, extra...)...)
}

// floorError is a floor refusal as a job error; its text is the sentence.
type floorError struct {
	refusal *floorRefusal
	closing string
}

func (e *floorError) Error() string { return e.refusal.sentence(e.closing) }

// checkMemoryFloor judges one control plane against floor (> 0). nil means
// it passes: its newest reported memory is a positive finite number at or
// above the floor.
func checkMemoryFloor(ctx context.Context, mem NodeMemory, cp *proto.Node, floor int64) *floorRefusal {
	name := cp.Hostname
	if name == "" {
		name = cp.ID
	}
	refuse := func(reason floorReason, v float64, err error) *floorRefusal {
		return &floorRefusal{Reason: reason, NodeID: cp.ID, Name: name, Floor: floor, MemTotal: v, Err: err}
	}
	if mem == nil {
		return refuse(floorUnreadable, 0, errNoMemoryReader)
	}
	v, ok, err := mem.LatestValue(ctx, cp.ID, proto.MetricMemTotalBytes)
	switch {
	case err != nil:
		return refuse(floorUnreadable, 0, err)
	case !ok:
		return refuse(floorNotReported, 0, nil)
	case math.IsNaN(v) || math.IsInf(v, 0) || v <= 0:
		return refuse(floorUnreadable, v, errMemoryValue)
	case v < float64(floor):
		return refuse(floorBelow, v, nil)
	}
	return nil
}

// checkFleetMemoryFloor judges every control plane in inventory, whatever the
// run's targeting: an excluded, offline or SKU-mismatched control plane left
// behind is the mixed fleet the floor exists to prevent. floor <= 0 reads
// nothing and passes. The first failure in node-id order is returned.
func checkFleetMemoryFloor(ctx context.Context, mem NodeMemory, nodes []*proto.Node, floor int64, version string) *floorRefusal {
	if floor <= 0 {
		return nil
	}
	var cps []*proto.Node
	for _, n := range nodes {
		if n.Role == proto.RoleControlPlane {
			cps = append(cps, n)
		}
	}
	if len(cps) == 0 {
		return &floorRefusal{Reason: floorNotReported, Floor: floor, Version: version}
	}
	sort.Slice(cps, func(i, j int) bool { return cps[i].ID < cps[j].ID })
	for _, cp := range cps {
		if r := checkMemoryFloor(ctx, mem, cp, floor); r != nil {
			r.Version = version
			return r
		}
	}
	return nil
}

// runMemoryFloor is the largest floor among the bundles a run carries.
func runMemoryFloor(bundles []*Bundle) int64 {
	var floor int64
	for _, b := range bundles {
		floor = max(floor, b.MemoryFloorBytes)
	}
	return floor
}

// floorRefusalOf returns the refusal inside err, if it is one.
func floorRefusalOf(err error) (*floorRefusal, bool) {
	var fe *floorError
	if errors.As(err, &fe) {
		return fe.refusal, true
	}
	return nil, false
}
