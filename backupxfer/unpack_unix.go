//go:build unix

package backupxfer

import (
	"archive/tar"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// applyMeta puts the header's mode, ownership and modification time onto an
// fd this function's caller just created — every call is fd-based (fchmod,
// fchown, futimes), so no path is ever re-resolved after the create.
//
// Ownership is applied only when the caller said it could (a root agent);
// a chown that fails when it was asked for is an error, because a volume
// whose files the app cannot open is not a restored volume. Times are best
// effort on a directory (a later entry inside it moves them anyway) and
// required on a file.
func applyMeta(f *os.File, hdr *tar.Header, chown, isFile bool) error {
	if err := f.Chmod(os.FileMode(hdr.Mode & 0o7777)); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	if chown {
		if err := f.Chown(hdr.Uid, hdr.Gid); err != nil {
			return fmt.Errorf("chown %d:%d: %w", hdr.Uid, hdr.Gid, err)
		}
	}
	if hdr.ModTime.IsZero() {
		return nil
	}
	tv := unix.NsecToTimeval(hdr.ModTime.UnixNano())
	if err := unix.Futimes(int(f.Fd()), []unix.Timeval{tv, tv}); err != nil && isFile {
		return fmt.Errorf("set mtime: %w", err)
	}
	return nil
}
