//go:build !unix

package fsat

import (
	"errors"
	"os"
)

// There is no openat(2) with O_NOFOLLOW here, so the package builds and every
// primitive refuses. Callers check Supported and say so in their own words.

// Supported is false: the primitives cannot be provided on this platform.
const Supported = false

// ErrUnsupported is what every primitive returns here.
var ErrUnsupported = errors.New("fsat: no-follow filesystem primitives are only supported on unix (needs openat with O_NOFOLLOW)")

func OpenRoot(string) (*os.File, error)                  { return nil, ErrUnsupported }
func OpenDir(*os.File, string) (*os.File, error)         { return nil, ErrUnsupported }
func MkdirOpen(*os.File, string) (*os.File, error)       { return nil, ErrUnsupported }
func OpenFile(*os.File, string) (*os.File, error)        { return nil, ErrUnsupported }
func Exists(*os.File, string) (bool, error)              { return false, ErrUnsupported }
func CreateExclusive(*os.File, string) (*os.File, error) { return nil, ErrUnsupported }
func Unlink(*os.File, string) error                      { return ErrUnsupported }
func Rename(*os.File, string, string) error              { return ErrUnsupported }
