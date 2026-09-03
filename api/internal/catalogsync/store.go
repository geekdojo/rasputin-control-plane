// Package catalogsync holds the effective app catalog and the rules for
// replacing it.
//
// ADR-0006 Decision 6 states resolution once: the effective catalog is the
// most recent VERIFIED fetch, or the embedded floor if no fetch has ever
// succeeded. Not a union, not a merge — a union would make "which tile is
// live" depend on two sources with no obvious precedence.
//
// Everything here is deliberately offline. Fetching is a separate concern; this
// package decides whether a bundle that has already been obtained is allowed to
// become the catalog, and makes the replacement survivable across a crash.
package catalogsync

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// Verifier checks a detached signature over a bundle file. It exists as an
// interface so this package's rules can be tested without crypto, and so the
// one production implementation can be the shared artifactsig — bound to the
// CATALOG purpose, never a generic "is this signed" check.
type Verifier interface {
	VerifyForPurpose(artifactPath, sigPath string) error
}

const (
	bundleName  = "catalog-%d.json"
	sigSuffix   = ".sig"
	pointerName = "current"
	dirName     = "catalog"

	// The catalog is not secret, but it is api-owned state and nothing else
	// on the box reads it. 0700/0600 keeps the blast radius of a compromised
	// unprivileged process to what it already had, and costs nothing.
	dirPerm  = 0o700
	filePerm = 0o600
)

// Store is the live catalog and the state directory behind it.
type Store struct {
	mu      sync.RWMutex
	current tileschema.Bundle
	// fetched is false while the floor is in effect. The UI needs to
	// distinguish "no fetch has succeeded yet" from "fetched and it happens to
	// match" — otherwise a cluster that has never reached the internet looks
	// identical to one that is up to date (#163's failure mode).
	fetched bool

	floor    tileschema.Bundle
	dir      string
	verify   Verifier
	lastErr  error
	lastNote string

	// rejected is the per-tile refusals from the catalog CURRENTLY in effect
	// (ADR-0006 Decision 7, #162). Held rather than only logged because a
	// catalog that quietly loses tiles is a worse failure than one that fails
	// loudly: the operator's symptom is an app that simply is not there, with
	// nothing to search for. Empty whenever the floor is in effect — the floor
	// is validated strictly, so it cannot have any.
	rejected []tileschema.TileRejection
}

// New builds the store, adopting any previously verified bundle from disk.
//
// A persisted bundle is RE-VERIFIED on load rather than trusted because it is
// on our disk. The signature travels with it precisely so that trust does not
// have to be re-established by provenance, and re-checking costs milliseconds
// once per boot. A persisted bundle that fails falls back to the floor loudly
// rather than refusing to start — a cluster with a corrupt cache should still
// serve apps.
func New(stateDir string, v Verifier, floor tileschema.Bundle) (*Store, error) {
	if v == nil {
		return nil, errors.New("catalogsync: a verifier is required; there is no unverified mode")
	}
	if err := floor.Validate(); err != nil {
		return nil, fmt.Errorf("catalogsync: the embedded floor is not a valid bundle: %w", err)
	}
	s := &Store{
		current: floor,
		floor:   floor,
		dir:     filepath.Join(stateDir, dirName),
		verify:  v,
	}
	if err := os.MkdirAll(s.dir, dirPerm); err != nil {
		return nil, fmt.Errorf("catalogsync: %w", err)
	}

	b, rejected, err := s.loadPersisted()
	switch {
	case err != nil:
		s.lastNote = "using the embedded floor: " + err.Error()
	case b.Version > floor.Version:
		s.current, s.fetched, s.rejected = b, true, rejected
		for _, r := range rejected {
			log.Printf("catalog: cached v%d tile %q refused, serving the rest: %s", b.Version, r.ID, r.Reason)
		}
	default:
		// A persisted bundle no newer than the floor means the image was
		// updated past it. The floor wins; the stale file is left for the next
		// successful fetch to supersede rather than deleted on a guess.
		s.lastNote = fmt.Sprintf("embedded floor v%d supersedes the cached catalog v%d", floor.Version, b.Version)
	}
	return s, nil
}

// Current returns the effective catalog.
func (s *Store) Current() tileschema.Bundle {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

// Get returns one tile from the catalog in effect, with its compose attached.
//
// This is the lookup /api/catalog/{id} performs and the one the backup
// fan-out joins installed apps against — the SAME lookup, deliberately. The
// 2026-09-03 e3bench run had the fan-out reading the tile set embedded in the
// binary while /api/catalog served a verified v17 whose tiles carried the
// volume classifications the fan-out needed; the two disagreed, and a
// `critical` volume vanished from a manifest stamped complete. A lookup that
// lives here cannot be wired to the wrong object.
func (s *Store) Get(id string) (tileschema.Tile, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, bt := range s.current.Tiles {
		if bt.Tile.ID == id {
			t := bt.Tile
			t.ComposeYAML = bt.Compose
			return t, true
		}
	}
	return tileschema.Tile{}, false
}

// Source names the catalog in effect for a record that has to say which one
// answered: "v17 (verified fetch)" while a fetched bundle is live, or
// "v14 (embedded floor — no verified catalog has been fetched)" before one is.
//
// The provenance travels with the version on purpose. A backup manifest that
// says a tile "declares no volumes" is read weeks later, and whether that was
// the published catalog or the floor a fresh cluster boots on is the
// difference between "the tile needs classifying" and "this cluster has never
// reached the catalog".
func (s *Store) Source() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.fetched {
		return fmt.Sprintf("v%d (verified fetch)", s.current.Version)
	}
	return fmt.Sprintf("v%d (embedded floor — no verified catalog has been fetched)", s.current.Version)
}

// State reports what the operator needs to answer "which catalog am I on, and
// is that because a fetch worked or because nothing ever has".
func (s *Store) State() (version int, fromFetch bool, note string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := s.lastNote
	if s.lastErr != nil {
		n = s.lastErr.Error()
	}
	return s.current.Version, s.fetched, n
}

// Apply verifies a downloaded bundle and, if it supersedes the current one,
// makes it the catalog and persists it.
//
// Every refusal leaves the current catalog untouched — that is the whole
// contract. A cluster that rejects an update keeps serving the last good
// catalog rather than falling to empty, because an empty catalog is
// indistinguishable to a user from a broken product.
func (s *Store) Apply(bundlePath, sigPath string) error {
	// Verify BEFORE reading the content into anything that parses it
	// (Decision 4). The signature is checked against the catalog purpose, so a
	// release leaf — equally valid, equally chained to our root — is refused.
	if err := s.verify.VerifyForPurpose(bundlePath, sigPath); err != nil {
		return s.fail(fmt.Errorf("signature: %w", err))
	}
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		return s.fail(err)
	}
	// Tolerant here, strict for the floor and the publisher: a tile this build
	// cannot accept costs that tile, not the catalog (Decision 7, #162). The
	// bundle still fails whole if its envelope is untrustworthy or if EVERY
	// tile is refused.
	b, rejected, err := tileschema.ParseFetchedBundle(raw)
	if err != nil {
		return s.fail(err)
	}

	s.mu.Lock()
	have := s.current.Version
	s.mu.Unlock()

	// Decision 5. A validly-signed OLD bundle is a rollback to image digests
	// with known CVEs, and a signature check cannot tell that from an update.
	if !b.SupersedesVersion(have) {
		return s.fail(fmt.Errorf("catalog v%d does not supersede the v%d already in effect", b.Version, have))
	}

	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return s.fail(err)
	}
	// `raw`, deliberately — the bytes as published, NOT a re-marshalling of the
	// filtered corpus. The detached signature covers exactly these bytes, so
	// writing the survivors instead would produce a pair that fails its own
	// re-verification on the next boot and drop the cluster to the floor. The
	// filtering is a decision this reader makes about content it keeps intact.
	if err := s.persist(b.Version, raw, sig); err != nil {
		return s.fail(err)
	}

	if len(rejected) > 0 {
		// Once per adopt, not once per poll: the poller re-reads the same
		// bundle every 24h and a line per tile per day would bury it.
		for _, r := range rejected {
			log.Printf("catalog: v%d tile %q refused, serving the rest: %s", b.Version, r.ID, r.Reason)
		}
	}

	s.mu.Lock()
	s.current, s.fetched, s.lastErr = b, true, nil
	s.rejected = rejected
	s.lastNote = ""
	s.mu.Unlock()
	return nil
}

// Rejected returns the per-tile refusals behind the catalog in effect.
func (s *Store) Rejected() []tileschema.TileRejection {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.rejected) == 0 {
		return nil
	}
	out := make([]tileschema.TileRejection, len(s.rejected))
	copy(out, s.rejected)
	return out
}

func (s *Store) fail(err error) error {
	s.mu.Lock()
	s.lastErr = err
	s.mu.Unlock()
	return err
}

// persist writes the pair, then flips a pointer file.
//
// Two renames are not atomic TOGETHER, so a crash between them could leave a
// bundle paired with the previous signature — which would then fail
// verification on the next boot and silently drop the cluster to the floor.
// Writing version-suffixed files and renaming a single small pointer LAST
// makes the switch one atomic operation: until the pointer moves, the old pair
// is still what loads.
func (s *Store) persist(version int, bundle, sig []byte) error {
	base := fmt.Sprintf(bundleName, version)
	if err := writeSync(filepath.Join(s.dir, base), bundle); err != nil {
		return err
	}
	if err := writeSync(filepath.Join(s.dir, base+sigSuffix), sig); err != nil {
		return err
	}
	return writeSyncRename(filepath.Join(s.dir, pointerName), []byte(strconv.Itoa(version)+"\n"))
}

func (s *Store) loadPersisted() (tileschema.Bundle, []tileschema.TileRejection, error) {
	ptr, err := os.ReadFile(filepath.Join(s.dir, pointerName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return tileschema.Bundle{}, nil, errors.New("no catalog has been fetched yet")
		}
		return tileschema.Bundle{}, nil, err
	}
	version, err := strconv.Atoi(strings.TrimSpace(string(ptr)))
	if err != nil {
		return tileschema.Bundle{}, nil, fmt.Errorf("unreadable catalog pointer: %w", err)
	}
	base := filepath.Join(s.dir, fmt.Sprintf(bundleName, version))
	if err := s.verify.VerifyForPurpose(base, base+sigSuffix); err != nil {
		return tileschema.Bundle{}, nil, fmt.Errorf("cached catalog v%d failed verification: %w", version, err)
	}
	raw, err := os.ReadFile(base)
	if err != nil {
		return tileschema.Bundle{}, nil, err
	}
	// Same disposition as Apply, and it must be: this re-parses the very bytes
	// Apply adopted, so a stricter reading here would make a cluster lose
	// tiles across a reboot with nothing having been published.
	b, rejected, err := tileschema.ParseFetchedBundle(raw)
	if err != nil {
		return tileschema.Bundle{}, nil, fmt.Errorf("cached catalog v%d: %w", version, err)
	}
	if b.Version != version {
		return tileschema.Bundle{}, nil, fmt.Errorf("cached catalog claims v%d but the pointer says v%d", b.Version, version)
	}
	return b, rejected, nil
}

// writeSync writes and fsyncs. The Sync matters: without it the rename below
// can be durable while the bytes it points at are not, which on a power cut
// leaves a pointer to a truncated bundle — the exact state the pointer scheme
// exists to prevent.
//
// Close is checked on every path, including the error paths. On a filesystem
// that reports write errors late, Close is where a failed write surfaces, and
// discarding it turns a lost catalog into a silent success.
func writeSync(path string, data []byte) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, filePerm)
	if err != nil {
		return err
	}
	defer func() {
		cerr := f.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}

// writeSyncRename writes to a sibling temp file and renames over the target,
// which is atomic within a directory on every filesystem we run on.
func writeSyncRename(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := writeSync(tmp, data); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		// Report the rename failure, but say so if the temp file also could
		// not be cleaned up — a stray .tmp is harmless, silently swallowing
		// the reason a directory is unwritable is not.
		if rmErr := os.Remove(tmp); rmErr != nil {
			return fmt.Errorf("rename %s: %w (and the temp file could not be removed: %v)", path, err, rmErr)
		}
		return err
	}
	return nil
}

// marshal renders a bundle the way the publisher does. Used by tests and by
// any caller that needs the canonical bytes.
func marshal(b tileschema.Bundle) ([]byte, error) {
	tileschema.SortTiles(b.Tiles)
	return json.MarshalIndent(b, "", "  ")
}
