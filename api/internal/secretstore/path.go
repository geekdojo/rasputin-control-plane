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

// TransitKey is a Transit mount and one key's name in it, both checked by
// NewTransitKey (geekdojo/geekdojo-brain#1084). The zero value names nothing
// and every method refuses it.
type TransitKey struct {
	mount string
	name  string
}

// NewTransitKey checks mount and name and returns them as a TransitKey
// (SEC-INPUT). mount follows NewKVPath's rules. name is exactly one segment
// of [A-Za-z0-9._-], so it can carry no URL syntax and no key sub-path.
func NewTransitKey(mount, name string) (TransitKey, error) {
	if err := checkSegments(mount); err != nil {
		return TransitKey{}, fmt.Errorf("secretstore: mount %q: %w", mount, err)
	}
	if err := checkSegments(name); err != nil {
		return TransitKey{}, fmt.Errorf("secretstore: key %q: %w", name, err)
	}
	if strings.Contains(name, "/") {
		return TransitKey{}, fmt.Errorf("secretstore: key %q: is more than one segment", name)
	}
	return TransitKey{mount: mount, name: name}, nil
}

// Mount is the Transit mount.
func (k TransitKey) Mount() string { return k.mount }

// Name is the key's name.
func (k TransitKey) Name() string { return k.name }

// String is mount/keys/name.
func (k TransitKey) String() string { return k.mount + "/keys/" + k.name }

func (k TransitKey) valid() bool { return k.mount != "" && k.name != "" }

// kvPath is k as the KVPath an *Error names: the mount and keys/<name>.
func (k TransitKey) kvPath() KVPath { return KVPath{mount: k.mount, path: "keys/" + k.name} }
