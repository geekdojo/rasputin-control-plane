package proto

import (
	"strings"
	"testing"
)

// The name rule is the whole of what keeps the remove verb away from anything
// that is not a Rasputin-managed compose volume, so it is pinned here: the api
// and the agent both read it from this package and this is the one place its
// edges are stated.
func TestParseAppVolumeName(t *testing.T) {
	const ulid = "01J6ZK3Q9V8XKX2M5TQ7R4A9BE"
	cases := []struct {
		name       string
		in         string
		wantID     string
		wantVolume string
		ok         bool
	}{
		{"lower-cased project as compose writes it", "rasp_01j6zk3q9v8xkx2m5tq7r4a9be_immich-db", ulid, "immich-db", true},
		{"upper-cased ulid also parses", "rasp_" + ulid + "_data", ulid, "data", true},
		{"volume name may itself carry underscores", "rasp_01j6zk3q9v8xkx2m5tq7r4a9be_model_cache", ulid, "model_cache", true},
		{"outside the prefix", "immich_db", "", "", false},
		{"prefix only", "rasp_", "", "", false},
		{"project segment too short", "rasp_abc_data", "", "", false},
		{"project segment not crockford (contains I, L, O, U)", "rasp_01J6ZK3Q9V8XKX2M5TQ7R4A9BI_data", "", "", false},
		{"no separator after the ulid", "rasp_" + ulid + "data", "", "", false},
		{"empty volume segment", "rasp_" + ulid + "_", "", "", false},
		{"another project's volume", "myproj_data", "", "", false},
		{"a bare docker volume id", "3f1a9b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, vol, ok := ParseAppVolumeName(tc.in)
			if ok != tc.ok || id != tc.wantID || vol != tc.wantVolume {
				t.Fatalf("ParseAppVolumeName(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tc.in, id, vol, ok, tc.wantID, tc.wantVolume, tc.ok)
			}
		})
	}
}

// AppVolumeName and ParseAppVolumeName are inverses, and the project name they
// share is the one the agent hands `docker compose -p`.
func TestAppVolumeNameRoundTrips(t *testing.T) {
	const ulid = "01J6ZK3Q9V8XKX2M5TQ7R4A9BE"
	name := AppVolumeName(ulid, "immich-upload")
	if name != "rasp_01j6zk3q9v8xkx2m5tq7r4a9be_immich-upload" {
		t.Fatalf("AppVolumeName: %q", name)
	}
	id, vol, ok := ParseAppVolumeName(name)
	if !ok || id != ulid || vol != "immich-upload" {
		t.Fatalf("round trip: (%q, %q, %v)", id, vol, ok)
	}
	if AppProjectName(ulid) != "rasp_01j6zk3q9v8xkx2m5tq7r4a9be" {
		t.Fatalf("AppProjectName: %q", AppProjectName(ulid))
	}
}

// RefuseAppVolumeName is the two daemon-free rules the api and the agent both
// apply; its wording is what an operator sees, so it is pinned here.
func TestRefuseAppVolumeName(t *testing.T) {
	const live = "01J6ZK3Q9V8XKX2M5TQ7R4A9BF"
	liveSet := map[string]bool{live: true}
	if r := RefuseAppVolumeName(AppVolumeName("01J6ZK3Q9V8XKX2M5TQ7R4A9BE", "immich-db"), liveSet); r != "" {
		t.Errorf("clean orphan refused: %q", r)
	}
	if r := RefuseAppVolumeName(AppVolumeName(live, "data"), liveSet); !strings.Contains(r, live) || !strings.Contains(r, "still installed") {
		t.Errorf("live app: %q", r)
	}
	if r := RefuseAppVolumeName("myproj_data", liveSet); !strings.Contains(r, "does not start with") {
		t.Errorf("outside prefix: %q", r)
	}
	if r := RefuseAppVolumeName("rasp_not-a-ulid_data", liveSet); !strings.Contains(r, "not of the form") {
		t.Errorf("malformed: %q", r)
	}
}
