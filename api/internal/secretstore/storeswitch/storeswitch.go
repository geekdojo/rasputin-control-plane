// Package storeswitch is the secret store's one-way switch marker, on the
// database side (geekdojo/geekdojo-brain#604).
//
// Until a cluster holds a value nobody can derive, the deploy family may take
// its secrets from the HKDF source when no store is configured: every value
// it would read is the derived one. The first operator-supplied value ends
// that. From then on an unconfigured store must refuse secret-bearing
// deploys, never fall back to deriving, or the app would be handed a random
// value in place of its owner's credential.
//
// The marker is one key in rasputin.db's settings table,
// secretstore.switched_at, written before the first operator value reaches
// the store. A restore puts it back with the database. Nothing clears it, and
// this package exports no way to.
package storeswitch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"
)

// KeySwitchedAt is the settings key, under the secretstore. prefix the
// settings table's convention asks for (setup/schema.go). Its value is the
// time the marker was set, in milliseconds since the epoch.
const KeySwitchedAt = "secretstore.switched_at"

// ErrNoStore is NoStore's refusal: no secret store is configured, so there is
// nowhere an operator value could go.
var ErrNoStore = errors.New("storeswitch: no secret store is configured")

// Settings is the slice of the settings table the marker reads and writes.
// *setup.Store satisfies it.
type Settings interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string) error
}

// Deps are the marker's collaborators. All are required.
type Deps struct {
	Settings Settings
	Now      func() time.Time
	Log      *slog.Logger
}

// Marker reads and writes the switch marker. rasputin.db is its only copy:
// it caches nothing.
type Marker struct {
	d Deps
}

// New checks d and returns a Marker. It does no I/O.
func New(d Deps) (*Marker, error) {
	switch {
	case d.Settings == nil:
		return nil, errors.New("storeswitch: Deps.Settings is nil")
	case d.Now == nil:
		return nil, errors.New("storeswitch: Deps.Now is nil")
	case d.Log == nil:
		return nil, errors.New("storeswitch: Deps.Log is nil")
	}
	return &Marker{d: d}, nil
}

// Switched reports whether the marker is set. Absent reads false:
// setup.Store.Get answers "" when no row exists, and MarkSwitched never
// writes "". Any other value reads true, a malformed one included, so a
// damaged row fails closed. A read error is returned, never read as either
// answer.
func (m *Marker) Switched(ctx context.Context) (bool, error) {
	v, err := m.d.Settings.Get(ctx, KeySwitchedAt)
	if err != nil {
		return false, fmt.Errorf("storeswitch: reading %s: %w", KeySwitchedAt, err)
	}
	return v != "", nil
}

// MarkSwitched sets the marker if it is not set yet, and logs one INFO record
// when it does. A marker already set is left as it is. A read or write that
// fails is returned, and the caller refuses the operator write it guards.
func (m *Marker) MarkSwitched(ctx context.Context) error {
	switched, err := m.Switched(ctx)
	if err != nil {
		return err
	}
	if switched {
		return nil
	}
	at := m.d.Now().UTC()
	if err := m.d.Settings.Set(ctx, KeySwitchedAt, strconv.FormatInt(at.UnixMilli(), 10)); err != nil {
		return fmt.Errorf("storeswitch: writing %s: %w", KeySwitchedAt, err)
	}
	m.d.Log.InfoContext(ctx, "secret store switched: deploys never derive a secret again without a configured store",
		"component", "secretstore", "event", "secretstore.switched", "switched_at", at.Format(time.RFC3339))
	return nil
}

// NoStore is the switch wired when no store backend is requested. Its
// MarkSwitched refuses with ErrNoStore and writes nothing: with no store,
// every write is refused anyway (secretstore.Disabled), so setting the marker
// would only turn the box's deploys into refusals for a value that was never
// stored.
type NoStore struct{}

// MarkSwitched refuses: there is no store to switch to.
func (NoStore) MarkSwitched(context.Context) error { return ErrNoStore }
