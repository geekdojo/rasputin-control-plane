package nodetrust

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/nats-io/nats.go"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/agent/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Reloader is a consumer that caches the bundle and must be told it changed.
// tailscaled is the one: Go reads its cert pool once at process start.
type Reloader interface {
	ReloadTrust(ctx context.Context) error
}

// reloadPendingSuffix names the marker beside the bundle that says a changed
// bundle has not yet reached every Reloader. It is a file, not process state,
// so a pending reload survives an agent restart.
const reloadPendingSuffix = ".reload-pending"

// Handler answers trust.install.
type Handler struct {
	store      *Store
	reloaders  []Reloader
	reregister func()
	log        *slog.Logger

	mu sync.Mutex
}

// NewHandler is the trust.install handler over store. reloaders are called
// after a changed install, and again on any install while a reload is
// pending; reregister re-publishes this node's registration so the api reads
// the new fingerprint without waiting for a reconnect. A nil store, log or
// reregister is refused.
func NewHandler(store *Store, reloaders []Reloader, reregister func(), log *slog.Logger) (*Handler, error) {
	if store == nil || reregister == nil || log == nil {
		return nil, errors.New("nodetrust: NewHandler needs a store, a reregister hook and a logger")
	}
	return &Handler{store: store, reloaders: append([]Reloader(nil), reloaders...), reregister: reregister, log: log}, nil
}

func (h *Handler) markerPath() string { return h.store.Path() + reloadPendingSuffix }

func (h *Handler) reloadPending() bool {
	_, err := os.Stat(h.markerPath())
	return err == nil
}

// ReportedFingerprint is what this node's registration carries under
// proto.MetadataTrustFingerprint: proto.TrustFingerprintReloadPending while a
// changed bundle has not reached tailscaled, so the api reads the node as
// stale and sends again; the bundle's fingerprint otherwise.
func (h *Handler) ReportedFingerprint() string {
	if h.reloadPending() {
		return proto.TrustFingerprintReloadPending
	}
	return h.store.Fingerprint()
}

// Subscribe answers trust.install for nodeID on nc.
func (h *Handler) Subscribe(nc *nats.Conn, nodeID string) (*nats.Subscription, error) {
	subj := proto.TrustInstallSubject(nodeID)
	sub, err := nc.Subscribe(subj, func(m *nats.Msg) {
		// No deadline of its own: the one slow part is restarting tailscaled,
		// which the init system bounds, and the api's request is bounded by
		// its job step.
		bus.Respond(m, h.Handle(context.Background(), nodeID, m.Data))
	})
	if err != nil {
		return nil, fmt.Errorf("subscribe %s: %w", subj, err)
	}
	return sub, nil
}

// Handle runs one trust.install: validate, install, reload when the content
// changed or a reload is pending, re-register when anything changed or a
// reload was attempted, then answer. OK is true only when nothing is left
// pending.
func (h *Handler) Handle(ctx context.Context, nodeID string, data []byte) proto.TrustInstallAck {
	h.mu.Lock()
	defer h.mu.Unlock()
	ack := proto.TrustInstallAck{NodeID: nodeID}
	var cmd proto.TrustInstallCmd
	if err := json.Unmarshal(data, &cmd); err != nil {
		ack.Detail = "bad cmd: " + err.Error()
		ack.Fingerprint = h.ReportedFingerprint()
		return ack
	}
	changed, err := h.store.Install(cmd.BundlePEM)
	if err != nil {
		h.log.WarnContext(ctx, "nodetrust: trust bundle refused", "bundle", h.store.Path(), "err", err.Error())
		ack.Detail = "trust bundle not installed: " + err.Error()
		ack.Fingerprint = h.ReportedFingerprint()
		return ack
	}
	ack.Changed = changed
	if changed {
		// Written before the reload, so a reload that fails — or an agent
		// that dies mid-reload — leaves the fact on disk for the next install.
		if err := atrest.WriteSecretFile(h.markerPath(), []byte(proto.TrustFingerprint(cmd.BundlePEM)+"\n")); err != nil {
			h.log.ErrorContext(ctx, "nodetrust: reload-pending marker not written", "bundle", h.store.Path(), "err", err.Error())
		}
	}
	var reloadErr error
	if changed || h.reloadPending() {
		reloadErr = h.reload(ctx)
		// After the reload and before the ack, so the api reads what this
		// node now reports without waiting for a reconnect.
		h.reregister()
	}
	ack.Fingerprint = h.ReportedFingerprint()
	if reloadErr != nil {
		h.log.ErrorContext(ctx, "nodetrust: trust bundle installed but not reloaded", "bundle", h.store.Path(), "err", reloadErr.Error())
		ack.Detail = "installed; reloading tailscaled failed: " + reloadErr.Error()
		return ack
	}
	ack.OK = true
	return ack
}

// reload calls every Reloader and clears the marker only when all succeed.
func (h *Handler) reload(ctx context.Context) error {
	var errs []error
	for _, r := range h.reloaders {
		if err := r.ReloadTrust(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	if err := os.Remove(h.markerPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clear the reload-pending marker: %w", err)
	}
	return nil
}
