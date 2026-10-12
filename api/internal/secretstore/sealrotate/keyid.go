package sealrotate

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
)

// KeyID is a seal key's id: rasputin-<kernel uuid>, the format
// rasputin-seal-key.sh writes (geekdojo/geekdojo-brain#803). It is not
// secret, and it names a file under rotation/, so only ParseKeyID makes one.
type KeyID string

// keyIDRE is the only shape a key id may take. It admits no '/' and no '.',
// so an id can never name a path outside rotation/.
var keyIDRE = regexp.MustCompile(`^rasputin-[0-9a-f-]{36}$`)

// ParseKeyID returns s as a KeyID, or an error when s is not rasputin-
// followed by 36 lowercase hex digits and hyphens. The error quotes only s.
func ParseKeyID(s string) (KeyID, error) {
	if !keyIDRE.MatchString(s) {
		return "", fmt.Errorf("sealrotate: key id %q is not rasputin-<uuid>", s)
	}
	return KeyID(s), nil
}

// String is the id.
func (k KeyID) String() string { return string(k) }

// KernelKeyID returns the key-id source #803 uses: a new id from the kernel
// uuid file at path (/proc/sys/kernel/random/uuid) on each call.
func KernelKeyID(path string) func() (KeyID, error) {
	return func() (KeyID, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("sealrotate: read the kernel uuid: %w", err)
		}
		uuid := string(bytes.TrimSpace(b))
		if uuid == "" {
			return "", errors.New("sealrotate: the kernel uuid is empty")
		}
		return ParseKeyID("rasputin-" + uuid)
	}
}
