package bmc

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// SubmitFn submits a job (matches the runner's Submit shape closed over
// in main).
type SubmitFn func(ctx context.Context, kind string, spec json.RawMessage, createdBy string) error

// BusyFn reports whether a bmc.configure job is queued or running.
type BusyFn func(ctx context.Context) (bool, error)

// StartReconcile subscribes to node registration events and re-pushes
// the desired BMC selection when the configured host re-registers with
// a stale (or missing) config hash — the reflash/missed-push recovery
// path (bmc-settings.md §4). Event-driven only: selection changes flow
// through the bmc.configure saga, so registration is the only moment
// drift can surface; there is no ticker. Env-pinned hosts are skipped —
// the pin is authoritative and visible in Settings.
//
// busy guards a race the bench caught on day one: a configure push
// makes the host re-register BEFORE the job's record step updates
// settings, so mid-job the advertised and desired states legitimately
// disagree — a deconfigure looked like drift and got resurrected.
// While any bmc.configure job is in flight the reconciler stands down;
// the running job is already converging the cluster.
func StartReconcile(nc *nats.Conn, st *setup.Store, busy BusyFn, submit SubmitFn) (unsubscribe func(), err error) {
	r := &reconciler{st: st, busy: busy, submit: submit}
	sub, err := nc.Subscribe("rasputin.node.*.evt.registered", func(m *nats.Msg) { r.onRegistered(m.Data) })
	if err != nil {
		return nil, err
	}
	return func() { _ = sub.Unsubscribe() }, nil
}

type reconciler struct {
	st     *setup.Store
	busy   BusyFn
	submit SubmitFn

	mu            sync.Mutex
	lastHash      string
	lastSubmitted time.Time
}

func (r *reconciler) onRegistered(data []byte) {
	var ev proto.NodeRegisteredEvt
	if err := json.Unmarshal(data, &ev); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	kind, err := r.st.Get(ctx, setup.KeyBMCBackend)
	if err != nil || kind == "" {
		return // BMC off in settings — nothing to converge toward
	}
	hostID, err := r.st.Get(ctx, setup.KeyBMCHostNode)
	if err != nil || hostID == "" || ev.NodeID != hostID {
		return
	}
	if ev.Metadata != nil {
		if pinned, ok := ev.Metadata[proto.MetadataBMCConfigPinned].(bool); ok && pinned {
			return // env pin is authoritative; Settings shows it read-only
		}
	}
	cfg, err := r.st.Get(ctx, setup.KeyBMCConfig)
	if err != nil {
		return
	}
	unlock := ""
	if kind == "bitscope" {
		unlock, _ = r.st.Get(ctx, setup.KeyBMCBitscopeUnlock)
	}
	desired := ConfigHash(kind, json.RawMessage(cfg), unlock)
	var advertised string
	if ev.Metadata != nil {
		advertised, _ = ev.Metadata[proto.MetadataBMCConfigHash].(string)
	}
	if advertised == desired {
		return
	}
	if r.busy != nil {
		if b, berr := r.busy(ctx); berr != nil || b {
			return // an in-flight configure job is already converging
		}
	}

	// Debounce: registration events burst on reconnect storms; one
	// re-push per desired hash per minute is plenty.
	r.mu.Lock()
	if r.lastHash == desired && time.Since(r.lastSubmitted) < time.Minute {
		r.mu.Unlock()
		return
	}
	r.lastHash = desired
	r.lastSubmitted = time.Now()
	r.mu.Unlock()

	spec, _ := json.Marshal(ConfigureSpec{
		Kind: kind, HostNodeID: hostID,
		Config: json.RawMessage(cfg), ConfigHash: desired,
	})
	log.Printf("bmc: host %s registered with config hash %q, want %q — re-pushing", hostID, advertised, desired)
	if err := r.submit(ctx, "bmc.configure", spec, "system:bmc-reconcile"); err != nil {
		log.Printf("bmc: reconcile submit: %v", err)
	}
}
