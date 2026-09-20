package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"sync"
	"syscall"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Handler answers rasputin.node.<id>.cmd.console.root_hash.
type Handler struct {
	nodeID     string
	shadowPath string
	helperPath string
	// mu serializes applies. Two deliveries at once would be a
	// read-modify-write race on the shadow file, and the losing write would
	// silently discard the other's change — including a change to another
	// account made by something else between the read and the rename.
	mu sync.Mutex
}

// NewHandler returns the handler for nodeID. shadowPath is normally
// DefaultShadowPath; RASPUTIN_SHADOW_FILE overrides it (tests, and any
// image that keeps it elsewhere). helperPath is the image's set-root-hash
// helper, normally HelperPath.
func NewHandler(nodeID, shadowPath, helperPath string) *Handler {
	if shadowPath == "" {
		shadowPath = DefaultShadowPath
	}
	if helperPath == "" {
		helperPath = HelperPath
	}
	return &Handler{nodeID: nodeID, shadowPath: shadowPath, helperPath: helperPath}
}

// ShadowPathFromEnv resolves the shadow file the agent should write.
func ShadowPathFromEnv() string {
	if v := os.Getenv("RASPUTIN_SHADOW_FILE"); v != "" {
		return v
	}
	return DefaultShadowPath
}

// Subscriber returns the onConn subscriber for the console.root_hash verb,
// in the shape agent main's subscribe() takes.
func (h *Handler) Subscriber() func(*nats.Conn) error {
	subj := proto.NodeCmdSubject(h.nodeID, proto.ConsoleRootHashVerb)
	return func(nc *nats.Conn) error {
		if _, err := nc.Subscribe(subj, h.handle); err != nil {
			return fmt.Errorf("subscribe %s: %w", subj, err)
		}
		log.Printf("rasputin-agent: subscribed to %s", subj)
		return nil
	}
}

// handle applies one delivery and answers it. Every path answers: a
// control plane left waiting cannot tell a refusal from a node that is
// gone, and #558 says a node that cannot take the hash must say so.
func (h *Handler) handle(m *nats.Msg) {
	var cmd proto.ConsoleRootHashCmd
	if err := json.Unmarshal(m.Data, &cmd); err != nil {
		bus.Respond(m, proto.ConsoleRootHashAck{
			NodeID: h.nodeID,
			Detail: "the console root password command could not be read: " + err.Error(),
		})
		return
	}
	bus.Respond(m, h.apply(cmd))
}

// apply does the work and builds the ack. Split from handle so the
// answers this node gives are tested without a bus.
func (h *Handler) apply(cmd proto.ConsoleRootHashCmd) proto.ConsoleRootHashAck {
	ack := proto.ConsoleRootHashAck{NodeID: h.nodeID}
	// The id travels with the command, but it is derived, so it is
	// recomputed rather than trusted: an ack must name what this node
	// actually holds.
	hashID := proto.ConsoleRootHashID(cmd.Hash)

	// The form check is the agent's own, before anything is exec'd or
	// written: a value that is not a hash must never reach a shadow file or
	// a helper's stdin, whatever either would have done with it.
	if err := proto.ValidConsoleRootHash(cmd.Hash); err != nil {
		ack.Detail = "refusing the delivered console root password: " + err.Error()
		log.Printf("rasputin-agent/console: REFUSED a console root password (%s): %v", hashID, err)
		return ack
	}

	h.mu.Lock()
	changed, via, err := apply(context.Background(), h.shadowPath, h.helperPath, cmd.Hash)
	h.mu.Unlock()
	if err != nil {
		ack.Detail = h.explain(err)
		log.Printf("rasputin-agent/console: could not apply the console root password (%s): %v", hashID, err)
		return ack
	}
	ack.OK, ack.HashID, ack.Changed = true, hashID, changed
	switch {
	case !changed:
		ack.Detail = "this node already held it"
	default:
		ack.Detail = "applied through " + string(via)
		log.Printf("rasputin-agent/console: applied the console root password (%s) to root in %s via %s", hashID, h.shadowPath, via)
	}
	return ack
}

// explain turns a write failure into the sentence an operator reading the
// failed job needs — which node-side thing to go and fix.
func (h *Handler) explain(err error) string {
	switch {
	case errors.Is(err, proto.ErrConsoleRootHashForm):
		return "refusing the delivered console root password: " + err.Error()
	case errors.Is(err, ErrNoRootEntry):
		return fmt.Sprintf("this node's %s has no root entry, so there is no console root account to set a password on", h.shadowPath)
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Sprintf("this node has no %s, so it has no account database to write the console root password into", h.shadowPath)
	// EROFS before EACCES: a read-only squashfs with no writable overlay
	// for /etc is an IMAGE problem (the half #503 and #546 own), and
	// reporting it as "the agent is not root" would send the operator to
	// the wrong place.
	case errors.Is(err, syscall.EROFS):
		return fmt.Sprintf("this node's %s is on a read-only filesystem, so the console root password cannot be changed on this image", h.shadowPath)
	case errors.Is(err, fs.ErrPermission):
		return fmt.Sprintf("this node's %s could not be written (permission denied) — the agent is not running as root here", h.shadowPath)
	}
	return "could not set the console root password on this node: " + err.Error()
}
