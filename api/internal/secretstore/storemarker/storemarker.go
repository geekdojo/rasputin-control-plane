// Package storemarker is the secret store's empty-store marker, on the
// database side (geekdojo/geekdojo-brain#765; ADR-0010 S15 part 7).
//
// The store initialises itself only when its data directory is empty
// (rasputin-store-init, #804), and it records that it did with an
// `initialised` outcome for the boot it ran in. A store that initialises on a
// cluster whose database already says the store was set up has lost its
// data: every secret the database refers to is gone. The marker is two keys
// in the settings table of rasputin.db, which a restore puts back with the
// database and which the store cannot wipe with its own data:
//
//   - secretstore.set_up_boot_id: the boot the store was first seen set up in;
//   - secretstore.blank_boot_id: the boot a blank start was recorded in, or
//     empty.
//
// The readiness monitor reads Blank, raises the crit secret-store:blank
// alert and refuses store-dependent work while it is set. Restoring a backup
// (Rebase) is the recovery.
package storemarker

import (
	"context"
	"errors"
	"log/slog"

	"github.com/geekdojo/rasputin-control-plane/api/internal/osoutcome"
)

// The settings keys, under the secretstore. prefix the settings table's
// convention asks for (setup/schema.go).
const (
	KeySetUpBootID = "secretstore.set_up_boot_id"
	KeyBlankBootID = "secretstore.blank_boot_id"
)

// outcomeInitialised is rasputin-store-init's outcome when it initialised an
// empty store (osoutcome_wiring.go's os.store_init vocabulary).
const outcomeInitialised = "initialised"

// Settings is the slice of the settings table the marker reads and writes.
// *setup.Store satisfies it.
type Settings interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string) error
}

// Deps are the marker's collaborators. All are required.
type Deps struct {
	Settings Settings
	// BootID is this boot's id (/proc/sys/kernel/random/boot_id).
	BootID func() (string, error)
	Log    *slog.Logger
}

// Marker reads and writes the empty-store marker.
type Marker struct {
	d Deps
}

// New checks d and returns a Marker. It does no I/O.
func New(d Deps) (*Marker, error) {
	switch {
	case d.Settings == nil:
		return nil, errors.New("storemarker: Deps.Settings is nil")
	case d.BootID == nil:
		return nil, errors.New("storemarker: Deps.BootID is nil")
	case d.Log == nil:
		return nil, errors.New("storemarker: Deps.Log is nil")
	}
	return &Marker{d: d}, nil
}

// ObserveInit takes one parsed os.store_init record (osoutcome.Source's
// Observe). Only an `initialised` record counts:
//
//   - no marker yet: the store was set up in the record's boot;
//   - the marker names the record's boot: nothing, it is the same start;
//   - the marker names another boot: the store started blank on a set-up
//     cluster, recorded once per blank boot with one ERROR.
func (m *Marker) ObserveInit(ctx context.Context, rec osoutcome.Record) {
	if rec.Outcome != outcomeInitialised || rec.BootID == "" {
		return
	}
	setUp, err := m.d.Settings.Get(ctx, KeySetUpBootID)
	if err != nil {
		m.d.Log.ErrorContext(ctx, "secret store marker unreadable; the store's init is not recorded",
			"component", "secretstore", "event", "secretstore.marker_unreadable", "boot_id", rec.BootID, "err", err.Error())
		return
	}
	switch setUp {
	case "":
		if err := m.d.Settings.Set(ctx, KeySetUpBootID, rec.BootID); err != nil {
			m.d.Log.ErrorContext(ctx, "secret store set-up not recorded",
				"component", "secretstore", "event", "secretstore.marker_write_failed", "boot_id", rec.BootID, "err", err.Error())
			return
		}
		m.d.Log.InfoContext(ctx, "secret store set-up recorded",
			"component", "secretstore", "event", "secretstore.set_up", "boot_id", rec.BootID)
		return
	case rec.BootID:
		return
	}
	blank, err := m.d.Settings.Get(ctx, KeyBlankBootID)
	if err == nil && blank == rec.BootID {
		return // this blank start is already recorded
	}
	if werr := m.d.Settings.Set(ctx, KeyBlankBootID, rec.BootID); werr != nil {
		err = errors.Join(err, werr)
	}
	attrs := []any{"component", "secretstore", "event", "secretstore.blank_store",
		"boot_id", rec.BootID, "set_up_boot_id", setUp}
	if err != nil {
		attrs = append(attrs, "err", err.Error())
	}
	m.d.Log.ErrorContext(ctx, "secret store started blank on a cluster that was set up", attrs...)
}

// Rebase runs on the start that applied a restore carrying the store: the
// restored database's marker names the boot the backed-up cluster was set
// up in, so it is re-based on this boot, and any blank start it recorded is
// cleared. A failed write is one ERROR; it fails toward a false blank alert,
// never toward silence.
func (m *Marker) Rebase(ctx context.Context) {
	boot, err := m.d.BootID()
	if err == nil {
		err = m.d.Settings.Set(ctx, KeySetUpBootID, boot)
	}
	if err == nil {
		err = m.d.Settings.Set(ctx, KeyBlankBootID, "")
	}
	if err != nil {
		m.d.Log.ErrorContext(ctx, "secret store marker not re-based after the restore",
			"component", "secretstore", "event", "secretstore.marker_write_failed", "boot_id", boot, "err", err.Error())
		return
	}
	m.d.Log.InfoContext(ctx, "secret store marker re-based on the restored store",
		"component", "secretstore", "event", "secretstore.marker_rebased", "boot_id", boot)
}

// Arm runs after the start-time outcome read. With no marker and the store's
// data present (or unreadable, read as present), it records this boot as the
// set-up one: a cluster whose store initialised before this build, or a
// pre-store restore onto a store from an earlier boot, is guarded from now
// on (F-765-01). It does nothing when a marker exists or the data is absent.
func (m *Marker) Arm(ctx context.Context, dataPresent bool) {
	if !dataPresent {
		return
	}
	setUp, err := m.d.Settings.Get(ctx, KeySetUpBootID)
	if err != nil {
		m.d.Log.ErrorContext(ctx, "secret store marker unreadable; not armed",
			"component", "secretstore", "event", "secretstore.marker_unreadable", "err", err.Error())
		return
	}
	if setUp != "" {
		return
	}
	boot, err := m.d.BootID()
	if err == nil {
		err = m.d.Settings.Set(ctx, KeySetUpBootID, boot)
	}
	if err != nil {
		m.d.Log.ErrorContext(ctx, "secret store marker not armed",
			"component", "secretstore", "event", "secretstore.marker_write_failed", "err", err.Error())
		return
	}
	m.d.Log.InfoContext(ctx, "secret store marker armed on existing store data",
		"component", "secretstore", "event", "secretstore.marker_armed", "boot_id", boot)
}

// Blank reports whether a blank start has been recorded. The readiness
// monitor reads an error as blank.
func (m *Marker) Blank(ctx context.Context) (bool, error) {
	v, err := m.d.Settings.Get(ctx, KeyBlankBootID)
	if err != nil {
		return false, err
	}
	return v != "", nil
}
