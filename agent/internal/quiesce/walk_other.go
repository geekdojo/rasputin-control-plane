//go:build !unix

package quiesce

import (
	"archive/tar"
	"errors"
	"os"
)

// The agent's quiesce drivers need openat(2)/O_NOFOLLOW to copy a volume
// without ever following a symlink a container planted. There is no
// equivalent here, so the package builds and every copy refuses.

var errUnsupportedOS = errors.New("quiesce: volume copy is only supported on unix (needs openat with O_NOFOLLOW)")

var errSkipDir = errors.New("skip this directory")

type entryStat struct{}

func (e *entryStat) isDir() bool                                 { return false }
func (e *entryStat) isRegular() bool                             { return false }
func (e *entryStat) isSymlink() bool                             { return false }
func (e *entryStat) size() uint64                                { return 0 }
func (e *entryStat) sizeInt64() int64                            { return 0 }
func (e *entryStat) header(string, byte, string) *tar.Header     { return &tar.Header{} }
func openRoot(string) (*os.File, error)                          { return nil, errUnsupportedOS }
func openFileAt(*os.File, string) (*os.File, *entryStat, error)  { return nil, nil, errUnsupportedOS }
func openBeneath(*os.File, string) (*os.File, *entryStat, error) { return nil, nil, errUnsupportedOS }
func readlinkAt(*os.File, string) (string, error)                { return "", errUnsupportedOS }
func walk(*os.File, string, func(*os.File, string, string, *entryStat) error) error {
	return errUnsupportedOS
}
