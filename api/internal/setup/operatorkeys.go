package setup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Operator SSH key — the ONE public key the Add-node wizard fills in for the
// operator, persisted as a cluster setting so they aren't re-asked on every
// enrollment (backlog: nodes.md "reuse the operator SSH key").
//
// What the setting does, and what it does not (geekdojo/geekdojo-brain#246):
//   - It is the key the wizard prefills, so it is written into the seed of
//     each node enrolled FROM NOW ON. That is all it does.
//   - It never changes an already-enrolled node. Each node's authorized_keys
//     is operator-owned and was written once, from its seed; replacing or
//     revoking a key there is a manual step on that node. The fleet re-key
//     saga that would have changed this (#244) was closed as not planned.
//
// It is ONE key, not a list. The setting shipped as a list with add/remove,
// but a second key was inert (the seed carries one line and the wizard only
// ever prefilled the first) and "remove" revoked nothing — the UI promised
// more than the setting did.
//
// Semantics:
//   - UNSET (no row) means "never captured" — the api seeds it once at
//     startup from the control plane's own authorized_keys (the bootstrap
//     seed put the operator's key there), so a bootstrap-flashed cluster
//     prefills before the wizard is ever opened.
//   - An explicit clear is a valid operator choice ("don't prefill") and is
//     never re-seeded over at startup.
//
// Storage keeps the original shape — a JSON string array under
// KeyOperatorSSHKeys — so no migration is needed and a stored value stays
// readable by an older api. Writes store zero or one element.
//
// Legacy lists with more than one key (written by the list UI): the
// effective key is the FIRST element, which is exactly the key the wizard
// has always prefilled, so enrollment behaviour does not change. The extras
// are not deleted on read — reads never write — and are reported as
// IgnoredKeys so Settings can say so; the operator's next save or clear
// writes a single-key value and they are gone.
//
// Public-key material only — never store private keys or secrets here.
const KeyOperatorSSHKeys = "enroll.operator_ssh_keys"

// ErrInvalidSSHKey rejects a key line that doesn't look like an OpenSSH
// public key. Mirrors the UI's validateSSHKey and rasputin-provision's
// resolveSSHKey rules.
var ErrInvalidSSHKey = errors.New("not an OpenSSH public key line (expected e.g. \"ssh-ed25519 AAAA… you@laptop\")")

var sshKeyRe = regexp.MustCompile(`^(ssh-ed25519|ssh-rsa|ecdsa-sha2-[a-z0-9-]+|sk-[a-z0-9-]+(@[a-z0-9.-]+)?) [A-Za-z0-9+/=]+( \S.*)?$`)

// ValidOperatorSSHKey reports whether one trimmed line parses as an OpenSSH
// public key. Beyond the shape check it rejects the characters that would
// break the sh-sourced seed's double-quoted RASPUTIN_SSH_AUTHORIZED_KEY line
// — same rules as the UI's validateSSHKey and rasputin-provision's
// resolveSSHKey (keep all three in sync).
func ValidOperatorSSHKey(key string) bool {
	if strings.ContainsAny(key, "\"$\\`\n\r") {
		return false
	}
	return sshKeyRe.MatchString(key)
}

// OperatorKey is the operator SSH key setting as read.
type OperatorKey struct {
	// Key is the key the Add-node wizard prefills; "" when none is saved.
	Key string
	// Captured is false only while the setting has never been set. A
	// cleared setting is captured with an empty Key.
	Captured bool
	// IgnoredKeys counts extra keys in a legacy multi-key value. They have
	// no effect and are dropped by the next SetOperatorSSHKey.
	IgnoredKeys int
}

// OperatorSSHKey returns the stored operator key (see KeyOperatorSSHKeys for
// the legacy multi-key rule).
func (s *Service) OperatorSSHKey(ctx context.Context) (OperatorKey, error) {
	raw, err := s.store.Get(ctx, KeyOperatorSSHKeys)
	if err != nil {
		return OperatorKey{}, err
	}
	if raw == "" {
		return OperatorKey{}, nil // never captured
	}
	var keys []string
	if err := json.Unmarshal([]byte(raw), &keys); err != nil {
		return OperatorKey{}, fmt.Errorf("setup: corrupt %s value: %w", KeyOperatorSSHKeys, err)
	}
	out := OperatorKey{Captured: true}
	if len(keys) > 0 {
		out.Key = keys[0]
		out.IgnoredKeys = len(keys) - 1
	}
	return out, nil
}

// SetOperatorSSHKey replaces the stored value with exactly one key, or
// clears it when key is blank. A clear is an explicit "no prefill" and
// sticks — the startup capture never overwrites it. Either way any legacy
// extra keys are dropped. Returns the trimmed key that was stored.
func (s *Service) SetOperatorSSHKey(ctx context.Context, key string) (string, error) {
	key = strings.TrimSpace(key)
	keys := []string{}
	if key != "" {
		if !ValidOperatorSSHKey(key) {
			return "", fmt.Errorf("%w: %q", ErrInvalidSSHKey, truncateKey(key))
		}
		keys = append(keys, key)
	}
	raw, err := json.Marshal(keys)
	if err != nil {
		return "", err
	}
	if err := s.store.Set(ctx, KeyOperatorSSHKeys, string(raw)); err != nil {
		return "", err
	}
	return key, nil
}

// SeedOperatorSSHKeyFromFile captures the operator key from the control
// plane's own authorized_keys — but only when the setting has NEVER been set
// (an explicit clear sticks). On a bootstrap-flashed control plane the first
// key line is the seed's key: firstboot creates the file from the seed, and
// anything added by hand is appended after it. So the first valid line is
// captured and any further valid lines are counted and left alone — they
// were never the wizard's key. Comment and invalid lines are skipped; a
// missing file is not an error (dev api, no seed).
//
// Returns the captured key ("" if nothing was done) and how many other
// valid key lines the file held.
func (s *Service) SeedOperatorSSHKeyFromFile(ctx context.Context, path string) (string, int, error) {
	raw, err := s.store.Get(ctx, KeyOperatorSSHKeys)
	if err != nil {
		return "", 0, err
	}
	if raw != "" {
		return "", 0, nil // already captured (possibly an explicit clear)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", 0, nil
		}
		return "", 0, err
	}
	var keys []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !ValidOperatorSSHKey(line) {
			continue
		}
		keys = append(keys, line)
	}
	if len(keys) == 0 {
		return "", 0, nil // nothing usable; stay unset so a later boot can seed
	}
	key, err := s.SetOperatorSSHKey(ctx, keys[0])
	if err != nil {
		return "", 0, err
	}
	return key, len(keys) - 1, nil
}

// truncateKey keeps error messages readable (keys are ~100s of chars).
func truncateKey(k string) string {
	if len(k) > 40 {
		return k[:40] + "…"
	}
	return k
}
