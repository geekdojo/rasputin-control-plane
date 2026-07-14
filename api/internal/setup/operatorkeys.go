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

// Operator SSH keys — the public key(s) the operator uses for SSH access to
// nodes, persisted as a cluster setting so the Add-node wizard can prefill
// instead of re-asking on every enrollment (backlog: nodes.md "reuse the
// operator SSH key"). The cluster has seen the key on every seed it ever
// minted; this makes it first-class.
//
// Semantics:
//   - UNSET (no row) means "never captured" — the api seeds it once at
//     startup from the control plane's own authorized_keys (the bootstrap
//     seed put the operator's key there), so a bootstrap-flashed cluster
//     prefills before the wizard is ever opened.
//   - An explicit empty list is a valid operator choice ("don't prefill")
//     and is never re-seeded over.
//   - Rotation is forward-only: editing the list changes future seeds; it
//     does not re-key already-enrolled nodes (that's a separate job kind).
//
// Stored as a JSON string array under KeyOperatorSSHKeys. Public-key
// material only — never store private keys or secrets here.
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

// OperatorSSHKeys returns the stored operator keys. nil means the setting
// has never been captured; an empty non-nil slice is an explicit "none".
func (s *Service) OperatorSSHKeys(ctx context.Context) ([]string, error) {
	raw, err := s.store.Get(ctx, KeyOperatorSSHKeys)
	if err != nil {
		return nil, err
	}
	if raw == "" {
		return nil, nil // never captured
	}
	var keys []string
	if err := json.Unmarshal([]byte(raw), &keys); err != nil {
		return nil, fmt.Errorf("setup: corrupt %s value: %w", KeyOperatorSSHKeys, err)
	}
	if keys == nil {
		keys = []string{}
	}
	return keys, nil
}

// SetOperatorSSHKeys validates and replaces the stored list. Keys are
// trimmed and de-duplicated preserving order; an empty list is allowed
// (explicit "no prefill") and sticks — the startup seed never overwrites it.
func (s *Service) SetOperatorSSHKeys(ctx context.Context, keys []string) ([]string, error) {
	clean := make([]string, 0, len(keys))
	seen := map[string]bool{}
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" || seen[k] {
			continue
		}
		if !ValidOperatorSSHKey(k) {
			return nil, fmt.Errorf("%w: %q", ErrInvalidSSHKey, truncateKey(k))
		}
		seen[k] = true
		clean = append(clean, k)
	}
	raw, err := json.Marshal(clean)
	if err != nil {
		return nil, err
	}
	if err := s.store.Set(ctx, KeyOperatorSSHKeys, string(raw)); err != nil {
		return nil, err
	}
	return clean, nil
}

// RememberOperatorSSHKey appends a key if it isn't already stored. Used by
// the wizard's persist-on-mint path; a no-op (not an error) for duplicates.
func (s *Service) RememberOperatorSSHKey(ctx context.Context, key string) ([]string, error) {
	key = strings.TrimSpace(key)
	if !ValidOperatorSSHKey(key) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidSSHKey, truncateKey(key))
	}
	keys, err := s.OperatorSSHKeys(ctx)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		if k == key {
			return keys, nil
		}
	}
	return s.SetOperatorSSHKeys(ctx, append(keys, key))
}

// SeedOperatorSSHKeysFromFile captures the control plane's own
// authorized_keys as the initial operator-key list — but only when the
// setting has NEVER been set (an explicit empty list sticks). On a
// bootstrap-flashed control plane that file holds exactly the seed's key,
// so the wizard prefills without ever having been run. Invalid or comment
// lines are skipped; a missing file is not an error (dev api, no seed).
// Returns the seeded keys, or nil if nothing was done.
func (s *Service) SeedOperatorSSHKeysFromFile(ctx context.Context, path string) ([]string, error) {
	raw, err := s.store.Get(ctx, KeyOperatorSSHKeys)
	if err != nil {
		return nil, err
	}
	if raw != "" {
		return nil, nil // already captured (possibly an explicit empty list)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
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
		return nil, nil // nothing usable; stay unset so a later boot can seed
	}
	return s.SetOperatorSSHKeys(ctx, keys)
}

// truncateKey keeps error messages readable (keys are ~100s of chars).
func truncateKey(k string) string {
	if len(k) > 40 {
		return k[:40] + "…"
	}
	return k
}
