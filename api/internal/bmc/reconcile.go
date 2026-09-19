package bmc

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/busident"
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
	sub, err := nc.Subscribe("rasputin.node.*.evt.registered", func(m *nats.Msg) { r.onRegistered(m.Subject, m.Data) })
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

func (r *reconciler) onRegistered(subject string, data []byte) {
	// The host id comes from the subject, which the bus scopes to the
	// publisher's credential; a payload naming a different node is dropped.
	ev, err := busident.DecodeRegistered(subject, data)
	if err != nil {
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
	stored, err := r.st.Get(ctx, setup.KeyBMCConfig)
	if err != nil {
		return
	}
	// A config recorded before the credential had its own settings key can
	// still carry it inline. The spec built below goes into the job ledger,
	// and the configure validate step refuses one carrying a credential, so
	// it is moved to its key here first. The job's record step then writes
	// the stripped config back.
	cfg, err := moveLegacyCredential(ctx, r.st, kind, json.RawMessage(stored))
	if err != nil {
		log.Printf("bmc: reconcile: %v", err)
		return
	}
	desired := ConfigHash(kind, cfg, StoredCredential(ctx, r.st, kind))
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
		Config: cfg, ConfigHash: desired,
	})
	log.Printf("bmc: host %s registered with config hash %q, want %q — re-pushing", hostID, advertised, desired)
	if err := r.submit(ctx, "bmc.configure", spec, "system:bmc-reconcile"); err != nil {
		log.Printf("bmc: reconcile submit: %v", err)
	}
}

// moveLegacyCredential returns config without the backend's write-only
// credential field. A non-empty inline value is moved to the credential's
// settings key when that key is still empty; when both are set the settings
// key wins, as it already does at dispatch.
func moveLegacyCredential(ctx context.Context, st *setup.Store, kind string, config json.RawMessage) (json.RawMessage, error) {
	cred, ok := CredentialFor(kind)
	if !ok || len(config) == 0 {
		return config, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(config, &m); err != nil {
		return config, nil // not an object: ValidateSelection refuses it in the job
	}
	raw, present := m[cred.Field]
	if !present {
		return config, nil
	}
	var inline string
	_ = json.Unmarshal(raw, &inline)
	if inline != "" && StoredCredential(ctx, st, kind) == "" {
		if err := st.Set(ctx, cred.SettingsKey, inline); err != nil {
			return nil, fmt.Errorf("move stored %s credential to its own key: %w", kind, err)
		}
	}
	delete(m, cred.Field)
	delete(m, cred.Field+"Set")
	return json.Marshal(m)
}
