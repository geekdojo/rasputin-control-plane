package updater

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// fallbackRows is what the fallback detector needs from the update store.
// *Store satisfies it.
type fallbackRows interface {
	LatestNodeUpdate(ctx context.Context, nodeID string) (*NodeUpdate, error)
	MarkNodeUpdateFallenBack(ctx context.Context, jobID, note string) (bool, error)
}

// publisher is the one bus call a change event needs. *nats.Conn satisfies it.
type publisher interface {
	Publish(subject string, data []byte) error
}

// FallbackDetector relabels a committed update whose node has since come back
// on a different image version (geekdojo/geekdojo-brain#894). COMMITTED is
// declared when the agent accepts mark-good; nothing after that looks at the
// node again, so a node that later falls back to its other slot — or is
// reinstalled — kept a COMMITTED row for an update it is no longer running.
//
// The trigger is a fact, not a timer: every agent registers on every NATS
// connect, including the first after any boot, and the registration carries
// the image version the node is running. The detector compares that with the
// node's LATEST update row only. A newer in-progress row means a rollout is
// mid-flight and the node legitimately reports something else, so an older
// committed row is never considered.
type FallbackDetector struct {
	rows fallbackRows
	pub  publisher
	log  *slog.Logger
	now  func() time.Time
}

// NewFallbackDetector builds the detector. Every collaborator is required.
func NewFallbackDetector(rows fallbackRows, pub publisher, log *slog.Logger, now func() time.Time) (*FallbackDetector, error) {
	switch {
	case rows == nil:
		return nil, errors.New("updater: fallback detector: the update store is nil")
	case pub == nil:
		return nil, errors.New("updater: fallback detector: the publisher is nil")
	case log == nil:
		return nil, errors.New("updater: fallback detector: the logger is nil")
	case now == nil:
		return nil, errors.New("updater: fallback detector: the clock is nil")
	}
	return &FallbackDetector{rows: rows, pub: pub, log: log, now: now}, nil
}

// fallbackNote is the row's note, read by an operator. The api cannot tell a
// slot fallback from a reinstall, so it names both and claims neither
// (F-894-01).
func fallbackNote(reported, target string) string {
	return fmt.Sprintf("After this update committed, the node started reporting version %s, not %s. "+
		"It fell back to its other slot or was reinstalled.", reported, target)
}

// OnRegistered checks one node registration against that node's latest update
// row. It runs on the inventory registration hook, so it must not block: one
// read, and at most once per fallback one write and one publish. A failed read
// or write is logged and retried by the node's next registration.
func (d *FallbackDetector) OnRegistered(ctx context.Context, n *proto.Node) {
	if n == nil {
		return
	}
	row, err := d.rows.LatestNodeUpdate(ctx, n.ID)
	if err != nil {
		d.log.Error("fallback check: could not read the node's latest update",
			"node_id", n.ID, "err", err.Error())
		return
	}
	if row == nil || row.Status != NodeUpdateCommitted {
		return
	}
	if classifyVersion(row.ToVersion, n.ImageVersion, row.BundleSHA256) != versionMismatch {
		return
	}
	note := fallbackNote(n.ImageVersion, row.ToVersion)
	changed, err := d.rows.MarkNodeUpdateFallenBack(ctx, row.JobID, note)
	if err != nil {
		d.log.Error("fallback check: could not mark the update fallen back",
			"node_id", n.ID, "job_id", row.JobID, "err", err.Error())
		return
	}
	if !changed {
		return
	}
	d.log.Warn("committed update fell back: the node reports a different image version",
		"node_id", n.ID, "job_id", row.JobID,
		"target_version", row.ToVersion, "reported_version", n.ImageVersion)
	ev := proto.UpdateChangeEvt{
		NodeID:   n.ID,
		JobID:    row.JobID,
		BundleID: row.BundleSHA256,
		Change:   proto.UpdateFallenBack,
		ToSlot:   row.ToSlot,
		Version:  n.ImageVersion,
		Reason:   note,
		Ts:       d.now().UTC(),
	}
	if err := publishChangeErr(d.pub, ev); err != nil {
		// The record is already correct; only the live feed misses the event,
		// and History shows the row on its next load.
		d.log.Warn("fallback check: the row is fallen back but the live event was not published",
			"node_id", n.ID, "job_id", row.JobID, "err", err.Error())
	}
}
