package secretstore

import (
	"errors"
	"fmt"
	"strings"
)

// KVPath is a kv-v2 mount and a path under it, both checked by NewKVPath. The
// zero value names nothing and every method refuses it.
type KVPath struct {
	mount string
	path  string
}

// NewKVPath checks mount and path and returns them as a KVPath (SEC-INPUT).
//
// Each is one or more '/'-separated segments. It refuses empty input, a
// leading or trailing '/', an empty segment, a "." or ".." segment, and any
// character outside [A-Za-z0-9._-]. A path built only from those can carry no
// URL syntax, so it is placed in a request URL without escaping.
func NewKVPath(mount, path string) (KVPath, error) {
	if err := checkSegments(mount); err != nil {
		return KVPath{}, fmt.Errorf("secretstore: mount %q: %w", mount, err)
	}
	if err := checkSegments(path); err != nil {
		return KVPath{}, fmt.Errorf("secretstore: path %q: %w", path, err)
	}
	return KVPath{mount: mount, path: path}, nil
}

// Mount is the kv-v2 mount.
func (p KVPath) Mount() string { return p.mount }

// Path is the path under the mount.
func (p KVPath) Path() string { return p.path }

// String is mount/path.
func (p KVPath) String() string { return p.mount + "/" + p.path }

func (p KVPath) valid() bool { return p.mount != "" && p.path != "" }

func checkSegments(s string) error {
	if s == "" {
		return errors.New("is empty")
	}
	for _, seg := range strings.Split(s, "/") {
		switch seg {
		case "":
			return errors.New("has an empty segment, or a leading or trailing '/'")
		case ".", "..":
			return fmt.Errorf("has a %q segment", seg)
		}
		for _, r := range seg {
			if !allowedRune(r) {
				return fmt.Errorf("has the character %q, outside [A-Za-z0-9._-]", r)
			}
		}
	}
	return nil
}

func allowedRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
		r == '.' || r == '_' || r == '-'
}
