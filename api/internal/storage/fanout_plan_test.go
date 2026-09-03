package storage

import (
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// The join, on its own. Every case is about what the plan does with one shape
// of input, and the invariant that runs through all of them: a classified
// volume is either in the stage list or in the skipped list, never in neither.

func TestPlanAppVolumesOrdersCriticalFirst(t *testing.T) {
	stage, skipped := PlanAppVolumes([]*apps.App{
		testApp("a2", "zulu", runNodeID, "zulu"),
		testApp("a1", "alpha", runNodeID, "alpha"),
	}, fakeTiles{
		"zulu": testTile("zulu",
			vol("zulu-state", tileschema.BackupState, tileschema.QuiesceNone),
			vol("zulu-critical", tileschema.BackupCritical, tileschema.QuiesceStop)),
		"alpha": testTile("alpha",
			vol("alpha-state", tileschema.BackupState, tileschema.QuiesceNone)),
	}, runNodeID)

	if len(skipped) != 0 {
		t.Fatalf("nothing here is off-node or bulk: %+v", skipped)
	}
	got := make([]string, 0, len(stage))
	for _, p := range stage {
		got = append(got, p.Volume)
	}
	want := []string{"zulu-critical", "alpha-state", "zulu-state"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("order = %v, want %v — `critical` first because a run that dies part-way should already hold "+
			"what costs most to lose, then alphabetical so two runs over an unchanged cluster agree", got, want)
	}
}

// TestPlanAppVolumesIsDeterministicWithinAnApp covers the last tie-break, which
// is the one the PR's "two runs over an unchanged cluster agree" claim rests on.
//
// Two volumes of the same class belonging to the same app have nothing left to
// order them by but their names, and a comparator that returned a constant
// there would leave the sequence up to the sort's internals — so a diff between
// two generations would stop meaning anything.
func TestPlanAppVolumesIsDeterministicWithinAnApp(t *testing.T) {
	tiles := fakeTiles{
		"t": testTile("t",
			vol("zzz-data", tileschema.BackupState, tileschema.QuiesceNone),
			vol("aaa-data", tileschema.BackupState, tileschema.QuiesceNone)),
		"off": testTile("off",
			vol("zzz-remote", tileschema.BackupState, tileschema.QuiesceNone),
			vol("aaa-remote", tileschema.BackupState, tileschema.QuiesceNone)),
	}
	stage, skipped := PlanAppVolumes([]*apps.App{
		testApp("a", "app", runNodeID, "t"),
		testApp("b", "app", "n-other", "off"),
	}, tiles, runNodeID)

	if len(stage) != 2 || stage[0].Volume != "aaa-data" || stage[1].Volume != "zzz-data" {
		t.Errorf("stage order = %v; two volumes of one app and one class order by name or by nothing", volumeNames(stage))
	}
	if len(skipped) != 2 || skipped[0].Volume != "aaa-remote" || skipped[1].Volume != "zzz-remote" {
		t.Errorf("skipped order = %+v; the record list is read by a human and must be stable too", skipped)
	}
}

func volumeNames(v []PlannedVolume) []string {
	out := make([]string, 0, len(v))
	for _, p := range v {
		out = append(out, p.Volume)
	}
	return out
}

func TestPlanAppVolumesClassifiesEveryOutcome(t *testing.T) {
	stage, skipped := PlanAppVolumes([]*apps.App{
		testApp("a-local", "local", runNodeID, "t"),
		testApp("a-remote", "remote", "n-other", "t"),
		testApp("a-custom", "custom", runNodeID, ""),
		testApp("a-gone", "gone", runNodeID, "withdrawn"),
	}, fakeTiles{
		"t": testTile("t",
			vol("v-critical", tileschema.BackupCritical, tileschema.QuiesceStop),
			vol("v-state", tileschema.BackupState, tileschema.QuiesceSQLite),
			vol("v-cache", tileschema.BackupCache, tileschema.QuiesceNone),
			vol("v-bulk", tileschema.BackupBulk, tileschema.QuiesceNone)),
	}, runNodeID)

	if len(stage) != 2 {
		t.Fatalf("stage = %+v, want the local critical and state volumes only", stage)
	}
	byReason := map[string]string{}
	for _, s := range skipped {
		byReason[s.App+"/"+s.Volume] = s.Reason
		if s.Captured {
			t.Errorf("%s is in the skipped list and marked captured", s.Volume)
		}
		if strings.TrimSpace(s.Reason) == "" {
			t.Errorf("%s/%s was skipped with no reason", s.App, s.Volume)
		}
	}
	// `cache` is excluded by design and is not a gap: counting it would mean no
	// archive on any cluster could ever be complete.
	for k := range byReason {
		if strings.HasSuffix(k, "v-cache") {
			t.Errorf("%s is recorded as a gap; §4.2 says `cache` is never copied", k)
		}
	}
	if r := byReason["remote/v-critical"]; !strings.Contains(r, "#295") {
		t.Errorf("off-node reason = %q", r)
	}
	if r := byReason["local/v-bulk"]; !strings.Contains(r, "bulk") {
		t.Errorf("bulk reason = %q", r)
	}
	if r := byReason["custom/(unknown — no tile)"]; !strings.Contains(r, "custom compose") {
		t.Errorf("unclassified reason = %q", r)
	}
	if r := byReason["gone/(unknown — tile withdrawn)"]; !strings.Contains(r, "no longer ships") {
		t.Errorf("withdrawn reason = %q", r)
	}
}

// TestPlanAppVolumesStagesNothingWithoutASelfNode is the fail-safe direction.
// An api that does not know which node it is cannot know which volumes are
// local, and guessing would mean sending a stage command — which STOPS AN APP —
// to a node on the strength of an assumption.
func TestPlanAppVolumesStagesNothingWithoutASelfNode(t *testing.T) {
	stage, skipped := PlanAppVolumes([]*apps.App{testApp("a", "app", runNodeID, "t")},
		fakeTiles{"t": testTile("t", vol("v", tileschema.BackupCritical, tileschema.QuiesceStop))}, "")
	if len(stage) != 0 {
		t.Error("volumes were planned by an api that does not know which node it runs on")
	}
	if len(skipped) != 1 || skipped[0].Captured {
		t.Errorf("skipped = %+v; the volume must still be recorded", skipped)
	}
}

// TestArchivePathCarriesAppAndVolume is the restore side's contract (#291,
// unbuilt). A flattened tree would make a restore guess which file belonged to
// which app.
func TestArchivePathCarriesAppAndVolume(t *testing.T) {
	p := PlannedVolume{AppName: "vaultwarden", Volume: "vaultwarden-data"}
	if got := p.ArchivePath(); got != "app-volumes/vaultwarden/vaultwarden-data.tar" {
		t.Errorf("archive path = %q", got)
	}
	// The member path is written into an archive a restore later expands, and a
	// member path is the classic way a tar becomes a write outside its
	// destination. Nothing that is not [A-Za-z0-9._-] survives, and no member
	// can start with a dot or climb out of the prefix.
	for _, bad := range []struct{ app, vol string }{
		{"../etc", "passwd"},
		{"app", "../../etc/shadow"},
		{"..", ".."},
		{"", ""},
		{"a/b", "c:d"},
	} {
		got := (PlannedVolume{AppName: bad.app, Volume: bad.vol}).ArchivePath()
		if !strings.HasPrefix(got, AppVolumeStagePrefix+"/") {
			t.Errorf("%q/%q produced %q, which is not under the app-volume prefix", bad.app, bad.vol, got)
		}
		if strings.Contains(got, "..") {
			t.Errorf("%q/%q produced %q, which climbs out of the archive", bad.app, bad.vol, got)
		}
	}
}
