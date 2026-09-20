package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Convergence on enrolment.
//
// "Nodes that join later receive it" (#558) is not a second mechanism: a
// node that registers and does not already hold the current password gets
// the same console.root_push job, scoped to itself. The trigger is a
// checkable fact — this node's recorded hash id is not the stored one — not
// a timer and not "it is new", so a node that registered before the password
// existed, one that failed its first push, and one that was reflashed all
// converge by the same route.

// Submitter submits a job. Wired to jobs.Runner.Submit in main.
type Submitter func(ctx context.Context, kind string, spec json.RawMessage, createdBy string) error

// Converger pushes the console root password to a node that does not hold
// it, on registration.
type Converger struct {
	store  *Store
	submit Submitter
}

// NewConverger returns the inventory registration hook's backing.
func NewConverger(store *Store, submit Submitter) *Converger {
	return &Converger{store: store, submit: submit}
}

// OnRegistered is the inventory hook. Best-effort and logged: a node that
// could not be converged now is converged on its next registration, and
// nothing here may block a registration.
func (c *Converger) OnRegistered(ctx context.Context, n *proto.Node) {
	if c == nil || c.store == nil || n == nil {
		return
	}
	want, err := c.store.CurrentHashID(ctx)
	if err != nil {
		log.Printf("console: read the current password id for %q: %v", n.ID, err)
		return
	}
	if want == "" {
		return // no password chosen yet; there is nothing to converge to
	}
	status, err := c.store.Status(ctx)
	if err != nil {
		log.Printf("console: read delivery state for %q: %v", n.ID, err)
		return
	}
	for _, st := range status.Nodes {
		if st.NodeID != n.ID {
			continue
		}
		switch st.Status {
		case NodeApplied:
			if st.HashID == want {
				return // already holds it
			}
		case NodePending:
			// A push for this node is already on its way. A registration
			// storm (an agent reconnecting in a loop) must not become a
			// job storm.
			return
		}
		break
	}
	// Claim the node BEFORE submitting, so a second registration arriving
	// while this one is in flight sees pending and stops.
	if err := c.store.RecordNode(ctx, NodeState{
		NodeID: n.ID, Status: NodePending,
		Detail:    "waiting for the console root password to be applied",
		UpdatedAt: time.Now().UTC(),
	}); err != nil {
		log.Printf("console: claim %q for a console root password push: %v", n.ID, err)
		return
	}
	spec, err := json.Marshal(PushSpec{
		NodeIDs: []string{n.ID},
		Reason:  "registration of " + n.ID,
	})
	if err != nil {
		log.Printf("console: build the push spec for %q: %v", n.ID, err)
		return
	}
	if err := c.submit(ctx, PushKind, spec, "system:console-converge"); err != nil {
		// Put the node back where it was, so the next registration retries
		// rather than seeing a pending claim nothing is working on.
		c.fail(ctx, n.ID, "the push job could not be submitted: "+err.Error())
		log.Printf("console: submit a console root password push for %q: %v", n.ID, err)
		return
	}
	log.Printf("console: pushing the console root password (%s) to %q on registration", want, n.ID)
}

func (c *Converger) fail(ctx context.Context, nodeID, detail string) {
	if err := c.store.RecordNode(ctx, NodeState{
		NodeID: nodeID, Status: NodeFailed, Detail: detail, UpdatedAt: time.Now().UTC(),
	}); err != nil {
		log.Printf("console: record %q as failed: %v", nodeID, err)
	}
}

// ClearPendingOnStart fails every node still marked pending.
//
// The same policy the job runner applies to its own in-flight jobs at
// startup (jobs.Runner.Recover: abort, do not resume). Without it a node
// claimed by a push the api restarted out of would stay pending for ever
// and its registration hook would never retry — the node would sit there
// with the image's password and the Settings page would say "waiting".
func ClearPendingOnStart(ctx context.Context, store *Store) error {
	if store == nil {
		return nil
	}
	status, err := store.Status(ctx)
	if err != nil {
		return err
	}
	var errs []error
	n := 0
	for _, st := range status.Nodes {
		if st.Status != NodePending {
			continue
		}
		st.Status = NodeFailed
		st.Detail = "the control plane restarted before this node answered — it is retried when the node next registers, or from Settings"
		st.UpdatedAt = time.Now().UTC()
		if err := store.RecordNode(ctx, st); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", st.NodeID, err))
			continue
		}
		n++
	}
	if n > 0 {
		log.Printf("console: %d node(s) were waiting for a console root password push when the api restarted; they are retried on their next registration", n)
	}
	return errors.Join(errs...)
}
