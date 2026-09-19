// Package atrest is the one place the api decides the mode of a file it
// writes. Every file that holds secret material (private keys, token seeds,
// bus tokens, tombstones, the database) goes through WriteSecretFile or
// CreateSecretFile, and every directory that holds such files through
// EnsureSecretDir. Files that other processes must read (configs mounted into
// non-root containers) go through WritePublicFile, which sets 0644
// explicitly.
//
// Modes are set with fchmod on the open file, never left to the create mode,
// so the result does not depend on the process umask. That is deliberate:
// the api's unit does NOT set a UMask. A unit-level UMask=0077 would narrow
// the files that are public by design (the observability configs read by
// containers running as fixed non-root uids), and they would stop loading.
//
// Writes are atomic: a temporary file in the same directory, synced, then
// renamed (or linked, for CreateSecretFile) over the target, and the
// directory synced. A crash leaves either the old file or the new one, never
// a partial one, and the rename replaces a symlink at the target rather than
// writing through it.
package atrest

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const (
	// SecretFileMode is the mode of every file holding secret material.
	SecretFileMode fs.FileMode = 0o600
	// SecretDirMode is the mode of every directory holding such files.
	SecretDirMode fs.FileMode = 0o700
	// PublicFileMode is the mode of a file that other uids must read.
	PublicFileMode fs.FileMode = 0o644
)

// WriteSecretFile atomically replaces path with data at mode 0600. The parent
// directory is created 0700 when it does not exist; an existing one keeps its
// mode (EnsureSecretDir is what tightens an existing directory).
func WriteSecretFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), SecretDirMode); err != nil {
		return fmt.Errorf("atrest: mkdir for %s: %w", path, err)
	}
	return replace(path, data, SecretFileMode)
}

// CreateSecretFile writes data to path at mode 0600 only if path does not
// exist yet, atomically: the content is staged in a synced temporary file and
// hard-linked into place, so a concurrent creator loses cleanly with an error
// satisfying errors.Is(err, fs.ErrExist), and a crash never leaves a partial
// file at path. It is for keys that must never be replaced once handed out
// (the bus key, the bus issuer seed).
func CreateSecretFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), SecretDirMode); err != nil {
		return fmt.Errorf("atrest: mkdir for %s: %w", path, err)
	}
	tmp, err := stage(path, data, SecretFileMode)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }()
	if err := os.Link(tmp, path); err != nil {
		return fmt.Errorf("atrest: create %s: %w", path, err)
	}
	syncDir(filepath.Dir(path))
	return nil
}

// WritePublicFile atomically replaces path with data at mode 0644. It exists
// for files that are public by design: read by another uid (a container user),
// and holding nothing secret. Every caller says why at the call site.
func WritePublicFile(path string, data []byte) error {
	return replace(path, data, PublicFileMode)
}

// EnsureSecretDir creates dir (and any missing parents) at 0700 and tightens
// dir itself to 0700 when it already exists with a wider mode, which is how an
// existing install's directories are brought to the rule. Parents that
// already exist are left alone.
func EnsureSecretDir(dir string) error {
	if err := os.MkdirAll(dir, SecretDirMode); err != nil {
		return fmt.Errorf("atrest: mkdir %s: %w", dir, err)
	}
	return tightenDir(dir)
}

// EnsureSecretFile makes path exist at mode 0600 without touching its
// content: it creates an empty file when there is none and tightens an
// existing one. It is how the database is pre-created before SQLite opens it
// (SQLite creates a missing database at 0644 less the umask, and derives the
// mode of its -wal and -shm files from the database's).
func EnsureSecretFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, SecretFileMode)
	switch {
	case err == nil:
		if cerr := f.Chmod(SecretFileMode); cerr != nil {
			_ = f.Close()
			return fmt.Errorf("atrest: chmod %s: %w", path, cerr)
		}
		if cerr := f.Close(); cerr != nil {
			return fmt.Errorf("atrest: close %s: %w", path, cerr)
		}
		syncDir(filepath.Dir(path))
		return nil
	case errors.Is(err, fs.ErrExist):
		return tighten(path, SecretFileMode)
	default:
		return fmt.Errorf("atrest: create %s: %w", path, err)
	}
}

// TightenIfExists sets path to 0600 when it exists at any other mode, and
// does nothing when it does not exist. The database's -wal and -shm
// files are brought to the rule with it.
func TightenIfExists(path string) error {
	err := tighten(path, SecretFileMode)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// tightenDir chmods dir to 0700 when its permission bits differ. A directory
// reached through a symlink (an operator pointing RASPUTIN_TRUST_DIR
// elsewhere) is followed: the directory the api writes into is the one whose
// mode matters.
func tightenDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("atrest: stat %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("atrest: %s is not a directory", dir)
	}
	if info.Mode().Perm() == SecretDirMode {
		return nil
	}
	if err := os.Chmod(dir, SecretDirMode); err != nil {
		return fmt.Errorf("atrest: chmod %s to %#o: %w", dir, SecretDirMode, err)
	}
	return nil
}

// tighten chmods the file at path to mode when its permission bits differ.
// Lstat, not Stat: a symlink is refused rather than followed, so a link
// planted at a secret path cannot redirect the chmod onto another file.
func tighten(path string, mode fs.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("atrest: stat %s: %w", path, err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("atrest: %s is a symlink; refusing to set its mode through it", path)
	}
	if info.Mode().Perm() == mode {
		return nil
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("atrest: chmod %s to %#o: %w", path, mode, err)
	}
	return nil
}

// replace stages data beside path and renames it over path.
func replace(path string, data []byte, mode fs.FileMode) error {
	tmp, err := stage(path, data, mode)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }() // a no-op once renamed
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("atrest: rename onto %s: %w", path, err)
	}
	syncDir(filepath.Dir(path))
	return nil
}

// stage writes data to a new temporary file in path's directory, sets its
// mode with fchmod (independent of the umask), syncs and closes it, and
// returns its name. The caller removes it.
func stage(path string, data []byte, mode fs.FileMode) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return "", fmt.Errorf("atrest: temp file for %s: %w", path, err)
	}
	name := f.Name()
	fail := func(err error) (string, error) {
		_ = f.Close()
		_ = os.Remove(name)
		return "", fmt.Errorf("atrest: write %s: %w", path, err)
	}
	if err := f.Chmod(mode); err != nil {
		return fail(err)
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return "", fmt.Errorf("atrest: close %s: %w", path, err)
	}
	return name, nil
}

// syncDir makes a rename or create in dir durable. Best effort: not every
// platform supports fsync on a directory.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}
