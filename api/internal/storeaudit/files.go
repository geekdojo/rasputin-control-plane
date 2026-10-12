package storeaudit

import (
	"io/fs"
	"os"
)

// Files is the filesystem the rotator works on: the four calls it makes and
// nothing else (ARCH-ISP). Production passes OSFiles; a test wraps OSFiles to
// force one call to fail.
type Files interface {
	// Stat describes the file at path, following no special rules: a missing
	// file is an error satisfying errors.Is(err, fs.ErrNotExist).
	Stat(path string) (fs.FileInfo, error)
	// Link makes newname a second name for oldname's inode. It fails with an
	// error satisfying errors.Is(err, fs.ErrExist) when newname exists, which
	// is what makes it a rename that never replaces anything.
	Link(oldname, newname string) error
	// Remove removes one name.
	Remove(path string) error
	// ReadDir lists dir.
	ReadDir(dir string) ([]fs.DirEntry, error)
}

// OSFiles is Files over package os.
type OSFiles struct{}

// Stat is os.Stat.
func (OSFiles) Stat(path string) (fs.FileInfo, error) { return os.Stat(path) }

// Link is os.Link.
func (OSFiles) Link(oldname, newname string) error { return os.Link(oldname, newname) }

// Remove is os.Remove.
func (OSFiles) Remove(path string) error { return os.Remove(path) }

// ReadDir is os.ReadDir.
func (OSFiles) ReadDir(dir string) ([]fs.DirEntry, error) { return os.ReadDir(dir) }
