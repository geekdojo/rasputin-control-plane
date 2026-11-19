// Package storemigrate rolls a secret store initialised before rasputin-os
// 2026.11.3 forward without losing its secrets (geekdojo/geekdojo-brain#1132).
//
// Such a store has no rasputin-author role, and no root token and no recovery
// keys to add it with (ADR-0010 S9), so it is re-initialised: the api copies
// every entry it can reach again into memory, asks rasputin-os's root step
// (rasputin-store-migrate.sh, run before every store start) to set the old
// tree aside, lets the store initialise itself afresh, writes every entry
// back, checks each one, and only then commits. Until the commit, any stop,
// crash or failure ends with the old tree back in place on the next store
// start.
//
//   - Hold keeps every secret call of the secrets service, kv and Transit,
//     off the store from the read until the commit.
//   - Migrator is the secretstore.migrate job.
//   - Recover runs at api start and finishes what a dead api left behind.
//   - Trigger submits the job on the fact of this boot's provision record
//     saying the role is absent, and orders the reference check after it.
//
// The contract with rasputin-os is the state directory's file names below,
// the request's boot_id= and job_id= lines, and the os.store_migrate record.
package storemigrate

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
)

// ProductionDir is the state directory rasputin-os creates (tmpfiles.d, root
// 0700).
const ProductionDir = "/var/lib/rasputin/store-migrate"

// The state directory's files: the contract with rasputin-os.
const (
	// NameRequest is written by the api: boot_id= and job_id=. The root step
	// acts on it only in the boot it names.
	NameRequest = "request"
	// NameAttempt is the request, renamed by the root step once the old tree
	// is set aside, so the job id survives beside it.
	NameAttempt = "attempt"
	// NameAside is the old tree, which the root step puts back on every
	// store start until a commit exists.
	NameAside = "aside.tar"
	// NameAsidePartial is the root step's own unfinished aside.tar.
	NameAsidePartial = "aside.tar.partial"
	// NameCommit is written by the api once every entry is written back and
	// checked; the next store start deletes the old tree.
	NameCommit = "commit"
)

// maxStateFile bounds a state file the api reads: request and attempt are
// two short lines.
const maxStateFile = 4096

// StateDir is the state directory. Every write and removal is made durable,
// file and directory, before it returns: the root step acts on these files
// after a power loss too.
type StateDir struct {
	dir  string
	sync func(*os.File) error
}

// NewStateDir returns the state directory at dir. sync makes one open file
// durable; nil is (*os.File).Sync. A test passes a recorder.
func NewStateDir(dir string, sync func(*os.File) error) (*StateDir, error) {
	if dir == "" {
		return nil, errors.New("storemigrate: the state directory is empty")
	}
	if sync == nil {
		sync = (*os.File).Sync
	}
	return &StateDir{dir: dir, sync: sync}, nil
}

// Present reports whether name exists. Only a missing file is false; any
// other error is returned.
func (d *StateDir) Present(name string) (bool, error) {
	var present bool
	err := d.in(func(r *os.Root) error {
		_, err := r.Lstat(name)
		switch {
		case err == nil:
			present = true
			return nil
		case errors.Is(err, fs.ErrNotExist):
			return nil
		}
		return err
	})
	return present, err
}

// Read returns name's bytes, at most maxStateFile of them.
func (d *StateDir) Read(name string) ([]byte, error) {
	var b []byte
	err := d.in(func(r *os.Root) error {
		f, err := r.Open(name)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		b, err = io.ReadAll(io.LimitReader(f, maxStateFile))
		return err
	})
	return b, err
}

// Write replaces name with data, mode 0600, then makes the file and the
// directory durable.
func (d *StateDir) Write(name string, data []byte) error {
	return d.in(func(r *os.Root) error {
		f, err := r.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		_, err = f.Write(data)
		if err == nil {
			err = d.sync(f)
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
		return d.syncDir(r)
	})
}

// Remove removes name, then makes the directory durable. A file that is
// already gone is success.
func (d *StateDir) Remove(name string) error {
	return d.in(func(r *os.Root) error {
		if err := r.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return d.syncDir(r)
	})
}

// in runs fn with the directory opened as an os.Root, so no name can reach
// outside it.
func (d *StateDir) in(fn func(r *os.Root) error) error {
	r, err := os.OpenRoot(d.dir)
	if err != nil {
		return err
	}
	err = fn(r)
	if cerr := r.Close(); err == nil {
		err = cerr
	}
	return err
}

// syncDir makes the directory's entries durable.
func (d *StateDir) syncDir(r *os.Root) error {
	f, err := r.Open(".")
	if err != nil {
		return err
	}
	err = d.sync(f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("sync %s: %w", d.dir, err)
	}
	return nil
}
