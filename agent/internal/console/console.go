// Package console applies the console root password hash the control plane
// delivers (geekdojo/geekdojo-brain#587, decision #558).
//
// No image ships a console password any more. The operator chooses one in
// the control plane's first-run wizard; the api hashes it and sends the
// HASH — never the password — to each node over that node's own command
// lane. This package is what receives it: it rewrites root's entry in
// /etc/shadow and answers.
//
// Three rules the handler keeps, because the control plane's report is only
// as honest as this end:
//
//   - It never answers OK for a node it did not change and did not already
//     match. A node that cannot take the hash — a read-only /etc, no root
//     entry, a hash it cannot parse — answers OK=false with the reason, and
//     the control plane FAILS that node. Silence and success are both worse
//     than a refusal an operator can read.
//   - It never logs, echoes or writes the hash anywhere but root's shadow
//     field. Everything that names the password names it by its id.
//   - It writes atomically and keeps the file's existing mode and owner, so
//     an interrupted write leaves the old shadow file rather than a
//     truncated one, and a node whose root account was reachable stays
//     reachable.
package console

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// DefaultShadowPath is where both images keep it.
const DefaultShadowPath = "/etc/shadow"

// shadowMode is the fallback when the existing file's mode cannot be read.
// Owner-only: /etc/shadow is the file the whole account model rests on.
const shadowMode fs.FileMode = 0o600

// rootUser is the only account this package will touch. The control plane
// delivers one password, for one account, and a verb that could name any
// account would be a verb that could rewrite any account.
const rootUser = "root"

// ErrNoRootEntry is returned when the shadow file has no root line.
var ErrNoRootEntry = errors.New("the shadow file has no root entry")

// ApplyRootHash puts hash into root's shadow entry at path.
//
// Returns changed=false when root already holds exactly this hash: the
// delivery is idempotent, and a re-run of the control plane's job must not
// rewrite a file it has nothing to say about.
func ApplyRootHash(path, hash string) (changed bool, err error) {
	if err := proto.ValidConsoleRootHash(hash); err != nil {
		return false, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", path, err)
	}
	lines := strings.Split(string(raw), "\n")
	idx := -1
	for i, line := range lines {
		if strings.HasPrefix(line, rootUser+":") {
			idx = i
			break
		}
	}
	if idx < 0 {
		return false, fmt.Errorf("%s: %w", path, ErrNoRootEntry)
	}
	updated, changed, err := setShadowPassword(lines[idx], hash)
	if err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}
	if !changed {
		return false, nil
	}
	lines[idx] = updated
	if err := replaceFile(path, []byte(strings.Join(lines, "\n"))); err != nil {
		return false, err
	}
	return true, nil
}

// setShadowPassword replaces field 2 of a shadow line and stamps field 3
// (last change, in days since the epoch) the way passwd(1) does. Every other
// field — the ageing policy the image chose — is left exactly as it was.
func setShadowPassword(line, hash string) (string, bool, error) {
	fields := strings.Split(line, ":")
	if len(fields) < 2 {
		return "", false, fmt.Errorf("root entry has %d field(s), want at least 2", len(fields))
	}
	if fields[1] == hash {
		return line, false, nil
	}
	fields[1] = hash
	if len(fields) > 2 {
		fields[2] = strconv.FormatInt(time.Now().UTC().Unix()/86400, 10)
	}
	return strings.Join(fields, ":"), true, nil
}

// replaceFile writes data over path atomically, keeping path's mode, owner
// and group. A temporary file in the same directory, synced, then renamed:
// a crash leaves the old shadow file intact, and the rename replaces a
// symlink at the target rather than writing through it. Same shape as the
// api's atrest helper, which the agent cannot import (separate module).
func replaceFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	mode, uid, gid := statOrDefault(path)
	tmp, err := os.CreateTemp(dir, ".rasputin-shadow-*")
	if err != nil {
		return fmt.Errorf("stage a replacement for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	// Mode before content: the window in which the file exists with the
	// hash in it must never be a window in which it is world-readable.
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set the mode on a replacement for %s: %w", path, err)
	}
	if uid >= 0 && gid >= 0 {
		// Best-effort: an unprivileged dev run cannot chown, and a shadow
		// file it owns is already the right owner.
		_ = tmp.Chown(uid, gid)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write a replacement for %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync a replacement for %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close a replacement for %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	syncDir(dir)
	return nil
}

// statOrDefault reports path's mode, uid and gid, falling back to 0600 and
// "leave the owner alone" (-1) when it cannot be read.
func statOrDefault(path string) (fs.FileMode, int, int) {
	info, err := os.Stat(path)
	if err != nil {
		return shadowMode, -1, -1
	}
	mode := info.Mode().Perm()
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return mode, int(st.Uid), int(st.Gid)
	}
	return mode, -1, -1
}

// syncDir fsyncs a directory so the rename is durable. Best-effort: a
// filesystem that refuses it has already taken the rename.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer func() { _ = d.Close() }()
	_ = d.Sync()
}
