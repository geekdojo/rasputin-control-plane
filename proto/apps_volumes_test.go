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

// An anonymous volume's name is docker's 64-hex id. The shape admits nothing
// else — in particular no rasp_ name, and nothing that could begin with `-` —
// and it confers no ownership: that is the agent record's to say (#413).
func TestIsAnonymousVolumeName(t *testing.T) {
	hex := "0e86382a2c39722bcd8f0edc143841aafa446e025e27f76e8fbbe0f0c374ed8f"
	cases := []struct {
		in   string
		want bool
	}{
		{hex, true},
		{strings.ToUpper(hex), false},
		{hex[:63], false},
		{hex + "0", false},
		{"-" + hex[1:], false},
		{"g" + hex[1:], false},
		{"rasp_01j6zk3q9v8xkx2m5tq7r4a9be_immich-db", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := IsAnonymousVolumeName(tc.in); got != tc.want {
			t.Errorf("IsAnonymousVolumeName(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestValidAppID(t *testing.T) {
	for in, want := range map[string]bool{
		"01J6ZK3Q9V8XKX2M5TQ7R4A9BE":  true,
		"01j6zk3q9v8xkx2m5tq7r4a9be":  true,
		"01J6ZK3Q9V8XKX2M5TQ7R4A9BI":  false, // I is not Crockford
		"01J6ZK3Q9V8XKX2M5TQ7R4A9B":   false,
		"01J6ZK3Q9V8XKX2M5TQ7R4A9BEE": false,
		"..":                          false,
		"":                            false,
	} {
		if got := ValidAppID(in); got != want {
			t.Errorf("ValidAppID(%q) = %v, want %v", in, got, want)
		}
	}
}

// The ledger rule reads the same whether the app id came off a volume's name
// or out of the agent's record for an anonymous volume.
func TestRefuseAppVolumeOwner(t *testing.T) {
	const ulid = "01J6ZK3Q9V8XKX2M5TQ7R4A9BE"
	live := map[string]bool{ulid: true}
	if r := RefuseAppVolumeOwner(strings.ToLower(ulid), live); !strings.Contains(r, ulid) || !strings.Contains(r, "still installed") {
		t.Errorf("live owner: %q", r)
	}
	if r := RefuseAppVolumeOwner("01J6ZK3Q9V8XKX2M5TQ7R4A9BF", live); r != "" {
		t.Errorf("gone owner refused: %q", r)
	}
	if RefuseAppVolumeName(AppVolumeName(ulid, "db"), live) != RefuseAppVolumeOwner(ulid, live) {
		t.Error("the named-volume rule and the owner rule word the refusal differently")
	}
}
