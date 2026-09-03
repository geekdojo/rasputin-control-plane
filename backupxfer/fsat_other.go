//go:build !unix

package backupxfer

import (
	"errors"
	"os"
)

// The ingest endpoint needs openat(2) with O_NOFOLLOW to write beneath a
// directory without ever following a symlink somebody put there. There is no
// equivalent here, so the package builds and the endpoint refuses.

var errUnsupportedOS = errors.New("backupxfer: ingest is only supported on unix (needs openat with O_NOFOLLOW)")

func openDirNoFollow(*os.File, string) (*os.File, error) { return nil, errUnsupportedOS }
func mkdirOpen(*os.File, string) (*os.File, error)       { return nil, errUnsupportedOS }
func existsAt(*os.File, string) (bool, error)            { return false, errUnsupportedOS }
func createExclusive(*os.File, string) (*os.File, error) { return nil, errUnsupportedOS }
func unlinkAt(*os.File, string) error                    { return errUnsupportedOS }
func renameAt(*os.File, string, string) error            { return errUnsupportedOS }
func openRootDir(string) (*os.File, error)               { return nil, errUnsupportedOS }

const ingestSupported = false
