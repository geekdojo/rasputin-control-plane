package busauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"sort"
	"time"
)

// Revocation tombstones (auth consolidation 1A.10).
//
// A revoke lives in rasputin.db, and two things replace that file wholesale: a
// lost database, and an identity restore, which swaps in the database the
// archive holds. Either one would otherwise bring back every token revoked
// since: a matched-set token because the preseed is reloaded on every boot
// (INSERT OR IGNORE finds no row to ignore), and any other token because the
// restored database never saw its revoke.
//
// So every revocation — operator revoke, node removal, and the api's own
// rotation of its agent token — also writes a tombstone to TombstoneFileName in
// the bus directory, beside preseed.json and bus.key and outside the database.
// At start, UseTombstoneFile unions that file with every revoked row in the
// database and re-applies the whole set to the database, and PreloadHashes
// skips every tombstoned hash. The identity archive carries the file, and a
// restore unions the archive's tombstones into the live file
// (MergeTombstoneFiles) rather than replacing it, so restoring an older archive
// cannot revert a later revocation.
//
// What this does not cover: a controlplane reflashed from its original seed
// and started WITHOUT a restore has a fresh persistent partition, so the file
// is gone too.

// TombstoneFileName is the tombstone file's name in the bus directory, and its
// path inside the identity archive is "bus/" + TombstoneFileName.
const TombstoneFileName = "revoked.json"

// tombstoneFileVersion is the only version this build reads and writes.
const tombstoneFileVersion = 1

// maxTombstoneFileBytes bounds a read. A tombstone is ~150 bytes; this holds
// tens of thousands of revocations.
const maxTombstoneFileBytes = 8 << 20

// Tombstone records that one token hash was revoked. It holds no secret: the
// hash is the stored verifier, never the plaintext.
type Tombstone struct {
	Hash      string    `json:"hash"`
	NodeID    string    `json:"nodeId,omitempty"`
	RevokedAt time.Time `json:"revokedAt"`
}

type tombstoneFile struct {
	Version    int         `json:"version"`
	Tombstones []Tombstone `json:"tombstones"`
}

// tombstones is the Store's view of the file. path is "" until
// UseTombstoneFile succeeds; while it is "", revocations are recorded in the
// database only.
type tombstones struct {
	path string
	set  map[string]Tombstone
}

// ReadTombstoneFile reads a tombstone file. A missing file is an empty set,
// not an error; an unreadable or malformed one is an error.
func ReadTombstoneFile(path string) (map[string]Tombstone, error) {
	out := map[string]Tombstone{}
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("busauth: read tombstones %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxTombstoneFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("busauth: read tombstones %s: %w", path, err)
	}
	if len(data) > maxTombstoneFileBytes {
		return nil, fmt.Errorf("busauth: tombstones %s: larger than %d bytes", path, maxTombstoneFileBytes)
	}
	var tf tombstoneFile
	if err := json.Unmarshal(data, &tf); err != nil {
		return nil, fmt.Errorf("busauth: tombstones %s: not readable JSON: %w", path, err)
	}
	if tf.Version != tombstoneFileVersion {
		return nil, fmt.Errorf("busauth: tombstones %s: version %d; this build reads %d", path, tf.Version, tombstoneFileVersion)
	}
	for i, t := range tf.Tombstones {
		if t.Hash == "" {
			return nil, fmt.Errorf("busauth: tombstones %s: entry %d names no hash", path, i)
		}
		out[t.Hash] = earlier(out[t.Hash], t)
	}
	return out, nil
}

// earlier keeps the first revocation of a hash, so a union is stable whichever
// side it is read from.
func earlier(have, t Tombstone) Tombstone {
	if have.Hash == "" || (!t.RevokedAt.IsZero() && t.RevokedAt.Before(have.RevokedAt)) {
		if t.NodeID == "" {
			t.NodeID = have.NodeID
		}
		return t
	}
	if have.NodeID == "" {
		have.NodeID = t.NodeID
	}
	return have
}

// writeTombstoneFile replaces path with set, sorted by hash, atomically and
// owner-only.
func writeTombstoneFile(path string, set map[string]Tombstone) error {
	tf := tombstoneFile{Version: tombstoneFileVersion, Tombstones: make([]Tombstone, 0, len(set))}
	for _, t := range set {
		tf.Tombstones = append(tf.Tombstones, t)
	}
	sort.Slice(tf.Tombstones, func(i, j int) bool { return tf.Tombstones[i].Hash < tf.Tombstones[j].Hash })
	data, err := json.MarshalIndent(tf, "", "  ")
	if err != nil {
		return err
	}
	if err := writeOwnerOnlyFile(path, append(data, '\n')); err != nil {
		return fmt.Errorf("busauth: write tombstones %s: %w", path, err)
	}
	return nil
}

// MergeTombstoneFiles unions the tombstones in from into the file at into,
// which it creates if missing. The restore uses it to fold an archive's
// tombstones into the live file instead of replacing it. It returns how many
// hashes into did not already hold.
func MergeTombstoneFiles(into, from string) (added int, err error) {
	live, err := ReadTombstoneFile(into)
	if err != nil {
		return 0, err
	}
	other, err := ReadTombstoneFile(from)
	if err != nil {
		return 0, err
	}
	for h, t := range other {
		if _, ok := live[h]; !ok {
			added++
		}
		live[h] = earlier(live[h], t)
	}
	if added == 0 {
		return 0, nil
	}
	return added, writeTombstoneFile(into, live)
}

// UseTombstoneFile makes path the store's tombstone file and reconciles it with
// the database, in both directions:
//
//   - every row the database holds as revoked is added to the file, and
//   - every tombstoned hash still live in the database is revoked there.
//
// It returns how many tombstones it added to the file and how many rows it
// revoked. Call it at start, after OpenStore and before PreloadHashes and the
// auth-callout responder.
//
// A file that cannot be read or parsed is an error, and the store is left
// without a tombstone file: nothing overwrites what might be the only record of
// a revocation. The caller must then not preload the preseed, whose tokens the
// unreadable file may have revoked.
func (s *Store) UseTombstoneFile(ctx context.Context, path string) (addedToFile, revokedInDB int, err error) {
	set, err := ReadTombstoneFile(path)
	if err != nil {
		return 0, 0, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT token_hash, COALESCE(node_id, ''), revoked_at FROM bus_tokens WHERE revoked_at IS NOT NULL`)
	if err != nil {
		return 0, 0, fmt.Errorf("busauth: read revoked tokens: %w", err)
	}
	for rows.Next() {
		var (
			t  Tombstone
			at int64
		)
		if err := rows.Scan(&t.Hash, &t.NodeID, &at); err != nil {
			_ = rows.Close()
			return 0, 0, fmt.Errorf("busauth: read revoked tokens: %w", err)
		}
		t.RevokedAt = fromMs(at)
		if _, ok := set[t.Hash]; !ok {
			addedToFile++
		}
		set[t.Hash] = earlier(set[t.Hash], t)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, 0, fmt.Errorf("busauth: read revoked tokens: %w", err)
	}
	_ = rows.Close()

	if addedToFile > 0 {
		// A failed write is logged, not returned: the set in memory is
		// complete (the file's entries plus every revoked row), so preload and
		// the re-apply below are still right, and the next revoke or start
		// writes the file again.
		if err := writeTombstoneFile(path, set); err != nil {
			log.Printf("%v — the tombstones are in effect for this run and are written again at the next revoke or start", err)
		}
	}

	now := ms(time.Now().UTC())
	for h := range set {
		res, err := s.db.ExecContext(ctx,
			`UPDATE bus_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL`, now, h)
		if err != nil {
			return addedToFile, revokedInDB, fmt.Errorf("busauth: re-apply tombstone: %w", err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			revokedInDB++
		}
	}

	s.tombMu.Lock()
	s.tomb = tombstones{path: path, set: set}
	s.tombMu.Unlock()
	return addedToFile, revokedInDB, nil
}

// tombstoned reports whether hash has a tombstone.
func (s *Store) tombstoned(hash string) bool {
	s.tombMu.Lock()
	defer s.tombMu.Unlock()
	_, ok := s.tomb.set[hash]
	return ok
}

// recordTombstones adds a tombstone for each revoked token and rewrites the
// file. The revoke has already happened in the database, so a failure here is
// logged, not returned: the next start's UseTombstoneFile adds every revoked
// row to the file again.
func (s *Store) recordTombstones(revoked []Tombstone) {
	if len(revoked) == 0 {
		return
	}
	s.tombMu.Lock()
	defer s.tombMu.Unlock()
	if s.tomb.path == "" {
		// No file in use: the api said so loudly at start (UseTombstoneFile
		// failed), and a store in a test never asked for one.
		return
	}
	for _, t := range revoked {
		s.tomb.set[t.Hash] = earlier(s.tomb.set[t.Hash], t)
	}
	if err := writeTombstoneFile(s.tomb.path, s.tomb.set); err != nil {
		log.Printf("busauth: %v — the revocation stands in the database, and the next api start adds it to the file", err)
	}
}

// revokeReturning runs an UPDATE ... RETURNING that revokes rows and returns
// them as tombstones. query must set revoked_at to its first argument and
// return token_hash and node_id.
func (s *Store) revokeReturning(ctx context.Context, at time.Time, query string, args ...any) ([]Tombstone, error) {
	rows, err := s.db.QueryContext(ctx, query, append([]any{ms(at)}, args...)...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Tombstone
	for rows.Next() {
		t := Tombstone{RevokedAt: at.UTC().Truncate(time.Millisecond)}
		if err := rows.Scan(&t.Hash, &t.NodeID); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
