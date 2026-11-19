package storemigrate

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/geekdojo/rasputin-control-plane/api/internal/osoutcome"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// KVStore is the kv session the Hold decorates: secrets.Store's shape, the
// composition root's *storesession.Session.
type KVStore interface {
	Read(ctx context.Context, p secretstore.KVPath, version int) (secretstore.KV, error)
	Write(ctx context.Context, p secretstore.KVPath, data map[string]secret.Value, cas int) (int, error)
	Versions(ctx context.Context, p secretstore.KVPath) (secretstore.Metadata, error)
	Delete(ctx context.Context, p secretstore.KVPath) error
}

// TransitStore is the key session the Hold decorates: secrets.TransitStore's
// shape.
type TransitStore interface {
	TransitCreateKey(ctx context.Context, k secretstore.TransitKey) error
	TransitEncrypt(ctx context.Context, k secretstore.TransitKey, plaintext secret.Value) (secret.Value, error)
	TransitDecrypt(ctx context.Context, k secretstore.TransitKey, ciphertext secret.Value) (secret.Value, error)
	TransitDestroyKey(ctx context.Context, k secretstore.TransitKey) error
}

// presence is the one Files call the Hold makes (ARCH-ISP).
type presence interface {
	Present(name string) (bool, error)
}

// Hold keeps the secrets service's store calls off the store while the
// migration runs (F-1132-03, F-1132-08). It is shaped like a read-write
// lock: each call through KV or Transit takes the shared side for its whole
// duration, and is refused at once with storestate.NotReadyError{Quiesced}
// when it cannot; On takes the exclusive side, so it returns only once every
// call already in flight has returned, and no call that passed the check can
// land in the old tree after it was read.
type Hold struct {
	files presence
	log   *slog.Logger

	rw sync.RWMutex
	// mu serialises On, Off and Stick, and guards on and stuck.
	mu sync.Mutex
	on bool
	// stuck is set when an abort could not establish that the old tree is
	// live, so the Hold stays on until Observe sees that it is; stuckJob is
	// that job, for the release's record.
	stuck    bool
	stuckJob string
}

// NewHold returns a Hold that is off. files is the state directory Observe
// reads.
func NewHold(files presence, log *slog.Logger) (*Hold, error) {
	switch {
	case files == nil:
		return nil, errors.New("storemigrate: the hold's state directory is nil")
	case log == nil:
		return nil, errors.New("storemigrate: the hold's logger is nil")
	}
	return &Hold{files: files, log: log}, nil
}

// refused is every held call's refusal.
var refused = &storestate.NotReadyError{State: storestate.Quiesced}

// On holds every call, waiting for the calls in flight to return. It does
// nothing when the Hold is already on.
func (h *Hold) On() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.on {
		return
	}
	h.rw.Lock()
	h.on = true
}

// Off lets calls through again, and clears stuck. It does nothing when the
// Hold is off.
func (h *Hold) Off() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.off()
}

// off is Off; the caller holds mu.
func (h *Hold) off() {
	if !h.on {
		return
	}
	h.on, h.stuck, h.stuckJob = false, false, ""
	h.rw.Unlock()
}

// Stick leaves an on Hold on until Observe releases it: jobID's abort could
// not show that the old tree is live. It does nothing to a Hold that is off.
func (h *Hold) Stick(jobID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.on {
		h.stuck, h.stuckJob = true, jobID
	}
}

// Held reports whether the Hold is on, and whether it is stuck on.
func (h *Hold) Held() (on, stuck bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.on, h.stuck
}

// Observe takes each parsed os.store_migrate record (osoutcome.Source's
// Observe). A stuck Hold is released on the fact that neither a request nor
// an aside.tar is left: the store start that wrote the record is running
// the old tree, put back (restored) or never moved. Anything else, an
// unreadable directory included, leaves it on (ERR-CLOSED).
func (h *Hold) Observe(ctx context.Context, rec osoutcome.Record) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.stuck {
		return
	}
	for _, name := range []string{NameRequest, NameAside} {
		present, err := h.files.Present(name)
		if err != nil || present {
			return
		}
	}
	jobID := h.stuckJob
	h.off()
	h.log.InfoContext(ctx, "secret store migration hold released: the store runs its old data",
		"component", "secretstore", "event", "secretstore.migrate_hold_released", "job_id", jobID,
		"outcome", rec.Outcome, "run_id", rec.RunID)
}

// enter takes the shared side, or reports that the Hold refuses.
func (h *Hold) enter() bool { return h.rw.TryRLock() }

// KV decorates next.
func (h *Hold) KV(next KVStore) *HeldKV { return &HeldKV{h: h, next: next} }

// Transit decorates next.
func (h *Hold) Transit(next TransitStore) *HeldTransit { return &HeldTransit{h: h, next: next} }

// HeldKV is a kv session behind the Hold.
type HeldKV struct {
	h    *Hold
	next KVStore
}

// Read passes through unless the Hold is on.
func (k *HeldKV) Read(ctx context.Context, p secretstore.KVPath, version int) (secretstore.KV, error) {
	if !k.h.enter() {
		return secretstore.KV{}, refused
	}
	defer k.h.rw.RUnlock()
	return k.next.Read(ctx, p, version)
}

// Write passes through unless the Hold is on.
func (k *HeldKV) Write(ctx context.Context, p secretstore.KVPath, data map[string]secret.Value, cas int) (int, error) {
	if !k.h.enter() {
		return 0, refused
	}
	defer k.h.rw.RUnlock()
	return k.next.Write(ctx, p, data, cas)
}

// Versions passes through unless the Hold is on.
func (k *HeldKV) Versions(ctx context.Context, p secretstore.KVPath) (secretstore.Metadata, error) {
	if !k.h.enter() {
		return secretstore.Metadata{}, refused
	}
	defer k.h.rw.RUnlock()
	return k.next.Versions(ctx, p)
}

// Delete passes through unless the Hold is on.
func (k *HeldKV) Delete(ctx context.Context, p secretstore.KVPath) error {
	if !k.h.enter() {
		return refused
	}
	defer k.h.rw.RUnlock()
	return k.next.Delete(ctx, p)
}

// HeldTransit is a key session behind the Hold.
type HeldTransit struct {
	h    *Hold
	next TransitStore
}

// TransitCreateKey passes through unless the Hold is on.
func (t *HeldTransit) TransitCreateKey(ctx context.Context, k secretstore.TransitKey) error {
	if !t.h.enter() {
		return refused
	}
	defer t.h.rw.RUnlock()
	return t.next.TransitCreateKey(ctx, k)
}

// TransitEncrypt passes through unless the Hold is on.
func (t *HeldTransit) TransitEncrypt(ctx context.Context, k secretstore.TransitKey, plaintext secret.Value) (secret.Value, error) {
	if !t.h.enter() {
		return secret.Value{}, refused
	}
	defer t.h.rw.RUnlock()
	return t.next.TransitEncrypt(ctx, k, plaintext)
}

// TransitDecrypt passes through unless the Hold is on.
func (t *HeldTransit) TransitDecrypt(ctx context.Context, k secretstore.TransitKey, ciphertext secret.Value) (secret.Value, error) {
	if !t.h.enter() {
		return secret.Value{}, refused
	}
	defer t.h.rw.RUnlock()
	return t.next.TransitDecrypt(ctx, k, ciphertext)
}

// TransitDestroyKey passes through unless the Hold is on.
func (t *HeldTransit) TransitDestroyKey(ctx context.Context, k secretstore.TransitKey) error {
	if !t.h.enter() {
		return refused
	}
	defer t.h.rw.RUnlock()
	return t.next.TransitDestroyKey(ctx, k)
}

// LastRecord keeps the last record of one source it observed: the trigger's
// view of this boot's provision record.
type LastRecord struct {
	mu  sync.Mutex
	rec osoutcome.Record
	ok  bool
}

// Observe keeps rec (osoutcome.Source's Observe).
func (l *LastRecord) Observe(_ context.Context, rec osoutcome.Record) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rec, l.ok = rec, true
}

// Last is the last record observed, and whether there was one.
func (l *LastRecord) Last() (osoutcome.Record, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rec, l.ok
}
