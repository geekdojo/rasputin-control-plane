// Package atrest is the one place the agent decides the mode of a file it
// writes. Everything the agent keeps in its own state tree — app compose
// files, TLS leaf keys, BMC and mesh state, backend manifests — goes through
// WriteSecretFile in a directory made by EnsureSecretDir, so the tree is
// owner-only. The few files that another process must read are written by
// WritePublicFile into EnsurePublicDir directories, and every one of those
// call sites says at the call site why it is public.
//
// Modes are set with fchmod on the open file, never left to the create mode,
// so the result does not depend on the process umask. That is deliberate: the
// agent's unit does NOT set a UMask. A unit-level UMask=0077 would narrow the
// files that are public by design — the systemd-resolved drop-in and the
// dnsmasq hosts file, both read by unprivileged daemons — and they would stop
// working, silently in resolved's case.
//
// Writes are atomic: a temporary file in the same directory, synced, then
// renamed over the target, and the directory synced. A crash leaves either the
// old file or the new one, never a partial one, and the rename replaces a
// symlink at the target rather than writing through it.
//
// This is the agent-side twin of api/internal/atrest, with the same semantics
// for the names both packages carry. It is a copy rather than an import
// because the api's package is `internal` to a different Go module (see
// go.work); the agent binary cannot import it at all. The twin carries only
// what the agent uses — the api's CreateSecretFile and EnsureSecretFile have
// no agent-side caller (the agent creates no database and no never-replaced
// key) — and adds EnsurePublicDir, which the agent needs for the two
// directories whose contents other daemons read.
package atrest

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const (
	// SecretFileMode is the mode of every file in the agent's state tree.
	SecretFileMode fs.FileMode = 0o600
	// SecretDirMode is the mode of every directory holding such files.
	SecretDirMode fs.FileMode = 0o700
	// PublicFileMode is the mode of a file another uid must read.
	PublicFileMode fs.FileMode = 0o644
	// PublicDirMode is the mode of a directory another uid must traverse.
	PublicDirMode fs.FileMode = 0o755
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

// WritePublicFile atomically replaces path with data at mode 0644. It exists
// for files that are public by design: read by another uid, and holding
// nothing secret. Every caller says why at the call site.
func WritePublicFile(path string, data []byte) error {
	return replace(path, data, PublicFileMode)
}

// EnsureSecretDir creates dir (and any missing parents) at 0700 and tightens
// dir itself to 0700 when it already exists with a wider mode, which is how an
// existing install's directories are brought to the rule at agent start.
// Parents that already exist are left alone.
func EnsureSecretDir(dir string) error {
	if err := os.MkdirAll(dir, SecretDirMode); err != nil {
		return fmt.Errorf("atrest: mkdir %s: %w", dir, err)
	}
	return ensureDirMode(dir, SecretDirMode)
}

// EnsurePublicDir creates dir (and any missing parents) at 0755 and sets dir
// itself to 0755 when it exists at another mode. It is for the directories
// another daemon must traverse — nothing secret is written into one, and each
// caller says which daemon reads it.
func EnsurePublicDir(dir string) error {
	if err := os.MkdirAll(dir, PublicDirMode); err != nil {
		return fmt.Errorf("atrest: mkdir %s: %w", dir, err)
	}
	return ensureDirMode(dir, PublicDirMode)
}

// TightenIfExists sets path to 0600 when it exists at any other mode, and does
// nothing when it does not exist. It brings the files an older agent left
// behind to the rule without rewriting their contents.
func TightenIfExists(path string) error {
	err := tighten(path, SecretFileMode)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// ensureDirMode chmods dir to mode when its permission bits differ. A
// directory reached through a symlink (an operator pointing
// RASPUTIN_AGENT_STATE_DIR elsewhere) is followed: the directory the agent
// writes into is the one whose mode matters.
func ensureDirMode(dir string, mode fs.FileMode) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("atrest: stat %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("atrest: %s is not a directory", dir)
	}
	if info.Mode().Perm() == mode {
		return nil
	}
	if err := os.Chmod(dir, mode); err != nil {
		return fmt.Errorf("atrest: chmod %s to %#o: %w", dir, mode, err)
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

// stage writes data to a new temporary file in path's directory, sets its mode
// with fchmod (independent of the umask), syncs and closes it, and returns its
// name. The caller removes it.
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
