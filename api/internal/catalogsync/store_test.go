package catalogsync

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// fakeVerifier lets the STORE's rules be tested without crypto. The real
// verifier has its own cross-purpose matrix in artifactsig; conflating the two
// would make a version-gate bug look like a signature bug.
type fakeVerifier struct {
	err   error
	calls int
	// seenFirst records whether verification happened before the content was
	// read. Decision 4 is an ordering requirement, not just a presence one.
	seenFirst bool
	readYet   *bool
}

func (f *fakeVerifier) VerifyForPurpose(artifactPath, sigPath string) error {
	f.calls++
	if f.readYet != nil && !*f.readYet {
		f.seenFirst = true
	}
	return f.err
}

func bundle(version int, id string) tileschema.Bundle {
	return tileschema.Bundle{
		SchemaVersion: tileschema.BundleSchemaVersion,
		Version:       version,
		PublishedAt:   "2026-08-21T00:00:00Z",
		Tiles: []tileschema.BundleTile{{
			Tile: tileschema.Tile{
				ID: id, Name: "N", Tagline: "t", Description: "d",
				Collection: tileschema.CollectionEssentials, Arch: "both",
				ExposureDefault: "lan-only", RAMFloorMB: 256,
				Status: tileschema.StatusPreview,
			},
		}},
	}
}

// write emits a bundle + a placeholder signature and returns both paths.
func write(t *testing.T, dir string, b tileschema.Bundle) (string, string) {
	t.Helper()
	raw, err := marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	bp := filepath.Join(dir, "in.json")
	sp := bp + ".sig"
	if err := os.WriteFile(bp, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sp, []byte("signature"), 0o644); err != nil {
		t.Fatal(err)
	}
	return bp, sp
}

func newStore(t *testing.T, v Verifier, floor tileschema.Bundle) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := New(dir, v, floor)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, dir
}

func TestNew_StartsOnTheEmbeddedFloor(t *testing.T) {
	s, _ := newStore(t, &fakeVerifier{}, bundle(3, "floor"))
	if got := s.Current().Version; got != 3 {
		t.Fatalf("current = v%d, want the floor v3", got)
	}
	v, fetched, _ := s.State()
	if v != 3 || fetched {
		t.Errorf("State = (v%d, fetched=%v); a cluster that has never fetched must not look fetched", v, fetched)
	}
}

func TestNew_RefusesWithoutAVerifier(t *testing.T) {
	if _, err := New(t.TempDir(), nil, bundle(1, "a")); err == nil {
		t.Fatal("a nil verifier must be refused; there is no unverified mode")
	}
}

func TestApply_AdoptsANewerBundle(t *testing.T) {
	s, _ := newStore(t, &fakeVerifier{}, bundle(1, "floor"))
	bp, sp := write(t, t.TempDir(), bundle(2, "fetched"))
	if err := s.Apply(bp, sp); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := s.Current().Version; got != 2 {
		t.Fatalf("current = v%d, want v2", got)
	}
	if _, fetched, _ := s.State(); !fetched {
		t.Error("a successful Apply must mark the catalog as fetched")
	}
}

// The contract: every refusal leaves the current catalog untouched. An empty
// catalog is indistinguishable to a user from a broken product.
func TestApply_RefusalsKeepTheLastGoodCatalog(t *testing.T) {
	cases := map[string]struct {
		verifyErr error
		incoming  tileschema.Bundle
		corrupt   bool
		wantErr   string
	}{
		"bad signature":       {verifyErr: errors.New("wrong purpose"), incoming: bundle(9, "x"), wantErr: "signature"},
		"same version":        {incoming: bundle(5, "x"), wantErr: "does not supersede"},
		"older version":       {incoming: bundle(4, "x"), wantErr: "does not supersede"},
		"unparseable content": {incoming: bundle(9, "x"), corrupt: true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s, _ := newStore(t, &fakeVerifier{err: c.verifyErr}, bundle(5, "floor"))
			dir := t.TempDir()
			bp, sp := write(t, dir, c.incoming)
			if c.corrupt {
				if err := os.WriteFile(bp, []byte("{not json"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			err := s.Apply(bp, sp)
			if err == nil {
				t.Fatal("want refusal")
			}
			if c.wantErr != "" && !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("error %q should mention %q so an operator can tell why", err, c.wantErr)
			}
			if got := s.Current().Version; got != 5 {
				t.Fatalf("a refusal changed the catalog to v%d; it must stay v5", got)
			}
			if _, fetched, _ := s.State(); fetched {
				t.Error("a refused fetch must not mark the catalog as fetched")
			}
		})
	}
}

// Decision 4 is an ORDERING requirement. Parsing first and verifying second
// would still "verify every bundle" while having already fed attacker-supplied
// bytes to a parser.
func TestApply_VerifiesBeforeReadingContent(t *testing.T) {
	read := false
	v := &fakeVerifier{err: errors.New("nope"), readYet: &read}
	s, _ := newStore(t, v, bundle(1, "floor"))
	bp, sp := write(t, t.TempDir(), bundle(2, "x"))
	_ = s.Apply(bp, sp)
	if v.calls != 1 || !v.seenFirst {
		t.Fatalf("verification must run before the bundle is read (calls=%d first=%v)", v.calls, v.seenFirst)
	}
}

// Survives a restart, and re-verifies rather than trusting its own disk.
func TestNew_AdoptsAPersistedBundleAndReVerifiesIt(t *testing.T) {
	dir := t.TempDir()
	v := &fakeVerifier{}
	s, err := New(dir, v, bundle(1, "floor"))
	if err != nil {
		t.Fatal(err)
	}
	bp, sp := write(t, t.TempDir(), bundle(7, "fetched"))
	if err := s.Apply(bp, sp); err != nil {
		t.Fatal(err)
	}

	v2 := &fakeVerifier{}
	s2, err := New(dir, v2, bundle(1, "floor"))
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.Current().Version; got != 7 {
		t.Fatalf("restart lost the fetched catalog: v%d", got)
	}
	if v2.calls == 0 {
		t.Error("a cached bundle must be re-verified on load, not trusted for being on our disk")
	}
}

func TestNew_CorruptCacheFallsBackToTheFloorRatherThanFailing(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir, &fakeVerifier{}, bundle(1, "floor"))
	if err != nil {
		t.Fatal(err)
	}
	bp, sp := write(t, t.TempDir(), bundle(7, "fetched"))
	if err := s.Apply(bp, sp); err != nil {
		t.Fatal(err)
	}

	// Now the cached bundle fails verification, as a tampered one would.
	s2, err := New(dir, &fakeVerifier{err: errors.New("tampered")}, bundle(1, "floor"))
	if err != nil {
		t.Fatalf("a corrupt cache must not stop the api starting: %v", err)
	}
	if got := s2.Current().Version; got != 1 {
		t.Fatalf("want the floor v1 after a failed cache load, got v%d", got)
	}
	_, _, note := s2.State()
	if !strings.Contains(note, "floor") {
		t.Errorf("the operator should be told why they are on the floor; note = %q", note)
	}
	_ = s
}

// A crash between writing the pair and flipping the pointer must leave the
// PREVIOUS catalog loadable, not a bundle paired with the wrong signature.
func TestPersist_PointerIsTheAtomicSwitch(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir, &fakeVerifier{}, bundle(1, "floor"))
	if err != nil {
		t.Fatal(err)
	}
	bp, sp := write(t, t.TempDir(), bundle(2, "two"))
	if err := s.Apply(bp, sp); err != nil {
		t.Fatal(err)
	}
	// Simulate the crash: v3's files land, the pointer never moves.
	raw, _ := marshal(bundle(3, "three"))
	if err := os.WriteFile(filepath.Join(dir, dirName, "catalog-3.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, dirName, "catalog-3.json.sig"), []byte("sig"), 0o644); err != nil {
		t.Fatal(err)
	}

	s2, err := New(dir, &fakeVerifier{}, bundle(1, "floor"))
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.Current().Version; got != 2 {
		t.Fatalf("an interrupted write was adopted: v%d, want the last committed v2", got)
	}
}
