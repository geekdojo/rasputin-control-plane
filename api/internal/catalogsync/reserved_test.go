package catalogsync

import (
	"testing"
)

func assertReservedRejected(t *testing.T, s *Store, ids ...string) {
	t.Helper()
	for _, bt := range s.Current().Tiles {
		for _, id := range ids {
			if bt.Tile.ID == id {
				t.Errorf("reserved tile %q is in the catalog in effect", id)
			}
		}
	}
	got := map[string]string{}
	for _, r := range s.Rejected() {
		got[r.ID] = r.Reason
	}
	for _, id := range ids {
		if want := "Tile id " + id + " is kept for the cluster's sign-in addresses."; got[id] != want {
			t.Errorf("Rejected()[%q] = %q, want %q", id, got[id], want)
		}
		if _, ok := s.Get(id); ok {
			t.Errorf("Get(%q) found a reserved tile", id)
		}
	}
}

// TC-983-14: a verified fetched bundle with jellyfin, signin and radius
// adopts jellyfin and refuses the reserved ids with a sentence, and the
// persisted bundle refuses them again after a restart.
func TestApply_RefusesReservedTileIDs(t *testing.T) {
	s, dir := newStore(t, &fakeVerifier{}, bundle(1, "floor"))
	bp, sp := write(t, dir, withTiles(2, okTileNamed("jellyfin"), okTileNamed("signin"), okTileNamed("radius")))
	if err := s.Apply(bp, sp); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, ok := s.Get("jellyfin"); !ok || s.Current().Version != 2 {
		t.Fatalf("jellyfin not adopted at v2: %+v", s.Current())
	}
	assertReservedRejected(t, s, "signin", "radius")

	reloaded, err := New(dir, &fakeVerifier{}, bundle(1, "floor"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reloaded.Get("jellyfin"); !ok {
		t.Fatal("restart lost jellyfin")
	}
	assertReservedRejected(t, reloaded, "signin", "radius")
}

// TC-983-14: the embedded floor is held to the same refusal.
func TestNew_RefusesReservedTileIDsOnTheFloor(t *testing.T) {
	s, _ := newStore(t, &fakeVerifier{}, withTiles(1, okTileNamed("jellyfin"), okTileNamed("signin")))
	if _, ok := s.Get("jellyfin"); !ok {
		t.Fatal("floor lost jellyfin")
	}
	assertReservedRejected(t, s, "signin")
}
