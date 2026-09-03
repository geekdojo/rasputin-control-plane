package storage

import (
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// The join, on its own. Every case is about what the plan does with one shape
// of input, and the invariant that runs through all of them: a classified
// volume is either in the stage list or in the skipped list, never in neither.

func TestPlanAppVolumesOrdersCriticalFirst(t *testing.T) {
	plan := PlanAppVolumes([]*apps.App{
		testApp("a2", "zulu", runNodeID, "zulu"),
		testApp("a1", "alpha", runNodeID, "alpha"),
	}, fakeTiles{
		"zulu": testTile("zulu",
			vol("zulu-state", tileschema.BackupState, tileschema.QuiesceNone),
			vol("zulu-critical", tileschema.BackupCritical, tileschema.QuiesceStop)),
		"alpha": testTile("alpha",
			vol("alpha-state", tileschema.BackupState, tileschema.QuiesceNone)),
	})
	stage, skipped := plan.Stage, plan.Skipped

	if len(skipped) != 0 {
		t.Fatalf("nothing here is bulk or unclassified: %+v", skipped)
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
		"b": testTile("b",
			vol("zzz-bulk", tileschema.BackupBulk, tileschema.QuiesceNone),
			vol("aaa-bulk", tileschema.BackupBulk, tileschema.QuiesceNone)),
	}
	plan := PlanAppVolumes([]*apps.App{
		testApp("a", "app", runNodeID, "t"),
		testApp("b", "app", "n-other", "b"),
	}, tiles)
	stage, skipped := plan.Stage, plan.Skipped

	if len(stage) != 2 || stage[0].Volume != "aaa-data" || stage[1].Volume != "zzz-data" {
		t.Errorf("stage order = %v; two volumes of one app and one class order by name or by nothing", volumeNames(stage))
	}
	if len(skipped) != 2 || skipped[0].Volume != "aaa-bulk" || skipped[1].Volume != "zzz-bulk" {
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
	plan := PlanAppVolumes([]*apps.App{
		testApp("a-local", "local", runNodeID, "t"),
		testApp("a-remote", "remote", "n-other", "t"),
		testApp("a-custom", "custom", runNodeID, ""),
		testApp("a-gone", "gone", runNodeID, "withdrawn"),
		testApp("a-nowhere", "nowhere", "", "t"),
	}, fakeTiles{
		"t": testTile("t",
			vol("v-critical", tileschema.BackupCritical, tileschema.QuiesceStop),
			vol("v-state", tileschema.BackupState, tileschema.QuiesceSQLite),
			vol("v-cache", tileschema.BackupCache, tileschema.QuiesceNone),
			vol("v-bulk", tileschema.BackupBulk, tileschema.QuiesceNone)),
	})
	stage, skipped := plan.Stage, plan.Skipped

	// The controlplane's volumes and the compute node's are planned alike:
	// there is one transport and it runs everywhere. Critical first.
	if len(stage) != 4 || stage[0].Class != tileschema.BackupCritical || stage[1].Class != tileschema.BackupCritical {
		t.Fatalf("stage = %+v, want the critical and state volumes of both the local and the remote app", stage)
	}
	for _, pv := range stage {
		if pv.NodeID != runNodeID && pv.NodeID != "n-other" {
			t.Errorf("planned %s/%s on node %q", pv.AppName, pv.Volume, pv.NodeID)
		}
	}
	byReason := map[string]string{}
	failed := map[string]bool{}
	for _, s := range skipped {
		byReason[s.App+"/"+s.Volume] = s.Reason
		failed[s.App+"/"+s.Volume] = s.Failed
		if s.Captured {
			t.Errorf("%s is in the skipped list and marked captured", s.Volume)
		}
		if strings.TrimSpace(s.Reason) == "" {
			t.Errorf("%s/%s was skipped with no reason", s.App, s.Volume)
		}
	}
	for k := range byReason {
		if strings.HasSuffix(k, "v-cache") {
			t.Errorf("%s is recorded as a gap; §4.2 says `cache` is never copied", k)
		}
	}
	if r := byReason["local/v-bulk"]; !strings.Contains(r, "bulk") || failed["local/v-bulk"] {
		t.Errorf("bulk reason = %q failed=%v; a bulk volume is a different lane, not a failure", r, failed["local/v-bulk"])
	}
	if r := byReason["custom/(unknown — no tile)"]; !strings.Contains(r, "custom compose") {
		t.Errorf("unclassified reason = %q", r)
	}
	if r := byReason["gone/(unknown — tile withdrawn)"]; !strings.Contains(r, "no longer ships") {
		t.Errorf("withdrawn reason = %q", r)
	}
	// An app deployed nowhere has no agent to stage on: a FAILURE of the
	// run, because the app is installed, classified, and not backed up.
	if !failed["nowhere/v-critical"] || !failed["nowhere/v-state"] {
		t.Errorf("an app on no node is not recorded as failed: %v", failed)
	}
	// Five installed; three resolved to a tile that classifies its volumes.
	if plan.AppsInstalled != 5 || plan.AppsResolved != 3 {
		t.Errorf("enumeration = %d installed / %d resolved, want 5/3", plan.AppsInstalled, plan.AppsResolved)
	}
	if plan.Catalog != "v0 (test tiles)" {
		t.Errorf("plan.Catalog = %q; the plan must say which catalog answered", plan.Catalog)
	}
}

// TestPlanAppVolumesRecordsATileThatDeclaresNoVolumes is the 2026-09-03 e3bench
// gap, at the join. The tile is THERE and says nothing, and before this the app
// fell straight through the inner loop — not staged, not skipped, not
// mentioned — and the manifest said complete.
func TestPlanAppVolumesRecordsATileThatDeclaresNoVolumes(t *testing.T) {
	plan := PlanAppVolumes([]*apps.App{testApp("app-vw", "vaultwarden", runNodeID, "vaultwarden")},
		fakeTiles{"vaultwarden": testTile("vaultwarden")})

	if len(plan.Stage) != 0 {
		t.Errorf("stage = %+v; nothing is classified, so nothing can be staged", plan.Stage)
	}
	if len(plan.Skipped) != 1 {
		t.Fatalf("skipped = %+v, want exactly one record for the app — an installed app must never vanish from the plan", plan.Skipped)
	}
	rec := plan.Skipped[0]
	if rec.Captured || rec.App != "vaultwarden" || rec.AppID != "app-vw" || rec.TileID != "vaultwarden" || rec.Node != runNodeID {
		t.Errorf("record = %+v", rec)
	}
	if rec.Class != "unclassified" {
		t.Errorf("class = %q, want unclassified — no class was declared, and inventing one would be the default §4.2 refuses", rec.Class)
	}
	for _, want := range []string{"declares no volumes", "`vaultwarden`", "v0 (test tiles)", "CHECK NOW"} {
		if !strings.Contains(rec.Reason, want) {
			t.Errorf("reason does not say %q: %q", want, rec.Reason)
		}
	}
	if plan.AppsInstalled != 1 || plan.AppsResolved != 0 {
		t.Errorf("enumeration = %d installed / %d resolved, want 1/0", plan.AppsInstalled, plan.AppsResolved)
	}
}

// TestPlanAppVolumesNeverLosesAnInstalledApp is the invariant the bench broke,
// stated over every shape a tile can take: an installed app is in the stage
// list, or in the skipped list, or resolved to a tile whose only volumes are
// `cache` — and in every case it is COUNTED. There is no fourth outcome.
func TestPlanAppVolumesNeverLosesAnInstalledApp(t *testing.T) {
	tiles := fakeTiles{
		"empty":      testTile("empty"),
		"cache-only": testTile("cache-only", vol("c", tileschema.BackupCache, tileschema.QuiesceNone)),
		"local":      testTile("local", vol("v", tileschema.BackupCritical, tileschema.QuiesceStop)),
		"bulk":       testTile("bulk", vol("b", tileschema.BackupBulk, tileschema.QuiesceNone)),
	}
	cases := []struct {
		name                   string
		app                    *apps.App
		wantStage              int
		wantSkipped            int
		wantResolved           int
		wantCompleteIfCaptured bool
	}{
		{"custom compose, no tile", testApp("a", "custom", runNodeID, ""), 0, 1, 0, false},
		{"tile withdrawn", testApp("a", "gone", runNodeID, "withdrawn"), 0, 1, 0, false},
		{"tile declares no volumes", testApp("a", "empty", runNodeID, "empty"), 0, 1, 0, false},
		{"tile declares only cache", testApp("a", "cache", runNodeID, "cache-only"), 0, 0, 1, true},
		{"critical volume, local", testApp("a", "local", runNodeID, "local"), 1, 0, 1, true},
		{"critical volume, off-node", testApp("a", "remote", "n-other", "local"), 1, 0, 1, true},
		{"critical volume, deployed nowhere", testApp("a", "nowhere", "", "local"), 0, 1, 1, false},
		{"bulk volume", testApp("a", "bulk", runNodeID, "bulk"), 0, 1, 1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			plan := PlanAppVolumes([]*apps.App{c.app}, tiles)
			if len(plan.Stage) != c.wantStage || len(plan.Skipped) != c.wantSkipped {
				t.Errorf("stage=%d skipped=%d, want %d/%d", len(plan.Stage), len(plan.Skipped), c.wantStage, c.wantSkipped)
			}
			if plan.AppsInstalled != 1 || plan.AppsResolved != c.wantResolved {
				t.Errorf("enumeration = %d installed / %d resolved, want 1/%d", plan.AppsInstalled, plan.AppsResolved, c.wantResolved)
			}
			// What the report would say if every staged volume were captured.
			// Only a resolved app with nothing missed can earn `complete`.
			records := append([]VolumeRecord(nil), plan.Skipped...)
			for _, pv := range plan.Stage {
				rec := notCaptured(pv, "")
				rec.Captured = true
				records = append(records, rec)
			}
			if got := NewAppVolumeReport(plan.AppEnumeration, records, len(plan.Stage)).Complete(); got != c.wantCompleteIfCaptured {
				t.Errorf("complete = %v, want %v", got, c.wantCompleteIfCaptured)
			}
		})
	}
}

// TestMemberPathCarriesAppAndVolume is the restore side's contract (#291): one
// sealed member per volume, named for the app and the volume, in the
// generation directory. A flattened tree would make a restore guess which
// file belonged to which app.
func TestMemberPathCarriesAppAndVolume(t *testing.T) {
	p := PlannedVolume{AppName: "vaultwarden", Volume: "vaultwarden-data"}
	if got := p.Member(); got != "volumes/vaultwarden/vaultwarden-data.rasputin-archive" {
		t.Errorf("member = %q", got)
	}
	// The member name is written onto removable media and later expanded by
	// a restore, and it is also what the ingest endpoint's containment check
	// accepts: whatever the app and volume are called, the result must pass
	// that check and must not climb.
	for _, bad := range []struct{ app, vol string }{
		{"../etc", "passwd"},
		{"app", "../../etc/shadow"},
		{"..", ".."},
		{"", ""},
		{"a/b", "c:d"},
		{".hidden", ".also"},
	} {
		got := (PlannedVolume{AppName: bad.app, Volume: bad.vol}).Member()
		if !proto.BackupValidMemberPath(got) {
			t.Errorf("%q/%q produced %q, which the ingest endpoint would refuse", bad.app, bad.vol, got)
		}
		if strings.Contains(got, "..") {
			t.Errorf("%q/%q produced %q, which climbs out of the generation", bad.app, bad.vol, got)
		}
	}
}
