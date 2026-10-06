package storage

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bustls"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// THE RESTORE COVERAGE GATE (geekdojo/geekdojo-brain#694).
//
// Getting a file back from an identity archive takes two lists to agree:
// identityRestorePath (restore.go) decides what PrepareRestore stages and
// reports as restored, and identityApplyRules (restore_apply.go) decides where
// ApplyPendingRestore puts it. A member Assemble writes that either list
// forgets is a file that ships out and never comes back. This test assembles a
// real archive from a fixture that fills every IdentitySources field and every
// trustFiles path, and fails on any member that is not both mapped and matched,
// unless the allowlist below names it with a reviewed reason. It also fails on
// a rule or allowlist entry that matches nothing, so neither list can rot.

// allowEntry is an archive member the restore deliberately does not put back.
type allowEntry struct {
	member string
	reason string
}

// restoreAllowlist is every identity-archive member restore does not put back,
// and why. An entry here is a reviewed decision; a blank reason fails the gate.
var restoreAllowlist = []allowEntry{
	{
		member: proto.BackupManifestFile,
		reason: "PrepareRestore reads manifest.json as the archive's index and never restores it as a file",
	},
	{
		member: appSecretSeedArchivePath,
		reason: "KNOWN DEFECT geekdojo/geekdojo-brain#751: must be restored; identityRestorePath does not map it. #751's fix deletes this entry; check (e) fails until it does.",
	},
}

// checkRestoreCoverage returns one problem for each gap between the archive's
// members, the two restore lists and the allowlist. mapped is
// identityRestorePath in the real run; rules are matched through matchRule,
// the same lookup ApplyPendingRestore uses.
func checkRestoreCoverage(members []string, mapped func(string) (string, bool), rules []applyRule, allow []allowEntry) []string {
	var problems []string
	allowed := map[string]bool{}
	for _, a := range allow {
		allowed[a.member] = true
	}
	present := map[string]bool{}
	for _, m := range members {
		present[m] = true
		if allowed[m] {
			continue
		}
		_, isMapped := mapped(m)
		_, isMatched := matchRule(rules, m)
		switch {
		case !isMapped && !isMatched:
			problems = append(problems, fmt.Sprintf("%s: identityRestorePath does not map it and no restore_apply rule matches it; restore it in both, or allowlist it with a reason", m))
		case !isMapped:
			problems = append(problems, fmt.Sprintf("%s: identityRestorePath does not map it, so PrepareRestore never stages it", m))
		case !isMatched:
			problems = append(problems, fmt.Sprintf("%s: no restore_apply rule matches it (identityApplyRules), so ApplyPendingRestore refuses it", m))
		}
	}
	for _, r := range rules {
		hit := false
		for _, m := range members {
			if r.matches(m) {
				hit = true
				break
			}
		}
		if !hit {
			problems = append(problems, fmt.Sprintf("restore_apply rule %q matches no archive member; delete it or add the member", r.archive))
		}
	}
	for _, a := range allow {
		if !present[a.member] {
			problems = append(problems, fmt.Sprintf("allowlist entry %q matches no archive member; delete it", a.member))
		}
		if strings.TrimSpace(a.reason) == "" {
			problems = append(problems, fmt.Sprintf("allowlist entry %q has a blank reason", a.member))
		}
		if _, ok := mapped(a.member); ok {
			problems = append(problems, fmt.Sprintf("allowlist entry %q is stale: identityRestorePath maps it, so restore now reaches it; delete the entry", a.member))
		}
	}
	return problems
}

// assembledMembers writes a fixture source tree with a file at every place
// Assemble reads, assembles it with the real Assemble, and returns the sources
// and every tar member name in archive order, manifest.json included.
func assembledMembers(t *testing.T) (IdentitySources, []string) {
	t.Helper()
	dir := t.TempDir()
	src := IdentitySources{
		TrustDir:     filepath.Join(dir, "trust"),
		MeshStateDir: filepath.Join(dir, "mesh"),
		BusDir:       filepath.Join(dir, "bus"),
	}
	if src.TrustDir != "" {
		appSecretFixtureSeed(t, src.TrustDir)
	}
	// Every trust file the production list names, not a list of our own.
	for _, f := range trustFiles(src) {
		if _, err := os.Stat(f.abs); err == nil {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(f.abs), 0o700); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, f.abs, "FIXTURE "+f.arc)
	}
	if hs := headscaleDir(src); hs != "" {
		if err := os.MkdirAll(hs, 0o700); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(hs, "db.sqlite"), "FIXTURE-HEADSCALE")
	}
	snap := filepath.Join(dir, "snapshot.db")
	writeTestFile(t, snap, "FIXTURE-SNAPSHOT")

	var buf bytes.Buffer
	if _, err := Assemble(&buf, AssembleOptions{
		Sources:      src,
		SnapshotPath: snap,
		GenerationID: "20261006T000000Z-coverage-full",
		ClusterID:    "home1",
		KeyID:        "key-1",
		Scope:        proto.BackupScopeFull,
	}); err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	var members []string
	tr := tar.NewReader(&buf)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read archive: %v", err)
		}
		members = append(members, h.Name)
	}
	return src, members
}

// TC-694-01: every member of a real archive is mapped and matched, or
// allowlisted with a reason, and the allowlist is exactly the two reviewed
// entries.
func TestEveryIdentityMemberHasARestorePath(t *testing.T) {
	_, members := assembledMembers(t)
	problems := checkRestoreCoverage(members, identityRestorePath, identityApplyRules(), restoreAllowlist)
	for _, p := range problems {
		t.Error(p)
	}
	if len(problems) != 0 {
		t.Fatalf("%d restore coverage problem(s) above; members: %v", len(problems), members)
	}

	if len(restoreAllowlist) != 2 {
		t.Fatalf("restoreAllowlist has %d entries, want exactly 2 (manifest.json and the #751 seed): %+v", len(restoreAllowlist), restoreAllowlist)
	}
	m, s := restoreAllowlist[0], restoreAllowlist[1]
	if m.member != proto.BackupManifestFile || !strings.Contains(m.reason, "PrepareRestore") || !strings.Contains(m.reason, "index") || !strings.Contains(m.reason, "never restores") {
		t.Errorf("allowlist[0] = %+v, want manifest.json read by PrepareRestore as the index and never restored", m)
	}
	if s.member != appSecretSeedArchivePath || !strings.HasPrefix(s.reason, "KNOWN DEFECT geekdojo/geekdojo-brain#751") {
		t.Errorf("allowlist[1] = %+v, want %s marked KNOWN DEFECT geekdojo/geekdojo-brain#751", s, appSecretSeedArchivePath)
	}
}

// TC-694-02: the fixture really fills every source the archive reads, so the
// gate is not passing over an archive with members missing.
func TestRestoreCoverageFixtureIsComplete(t *testing.T) {
	src, members := assembledMembers(t)

	v := reflect.ValueOf(src)
	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Name
		dir := v.Field(i).String()
		if strings.TrimSpace(dir) == "" {
			t.Errorf("IdentitySources.%s is empty in the coverage fixture; fill it and write a file beneath it", name)
			continue
		}
		files := 0
		_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				files++
			}
			return nil
		})
		if files == 0 {
			t.Errorf("IdentitySources.%s (%s) has no file beneath it in the coverage fixture", name, dir)
		}
	}

	set := map[string]bool{}
	for _, m := range members {
		set[m] = true
	}
	for _, f := range trustFiles(src) {
		if !set[f.arc] {
			t.Errorf("trust file %s is not a member of the fixture archive", f.arc)
		}
	}
	hs := false
	for _, m := range members {
		hs = hs || strings.HasPrefix(m, "mesh/headscale/")
	}
	if !hs {
		t.Error("no mesh/headscale/ member in the fixture archive")
	}
	if !set["rasputin.db"] {
		t.Error("rasputin.db is not a member of the fixture archive")
	}
	if len(members) == 0 || members[0] != proto.BackupManifestFile {
		t.Errorf("first member is not %s: %v", proto.BackupManifestFile, members)
	}
}

// fakeMapped maps exactly the named paths.
func fakeMapped(paths ...string) func(string) (string, bool) {
	set := map[string]bool{}
	for _, p := range paths {
		set[p] = true
	}
	return func(p string) (string, bool) { return "", set[p] }
}

func exactRules(paths ...string) []applyRule {
	var out []applyRule
	for _, p := range paths {
		out = append(out, applyRule{archive: p, kind: applyReplace})
	}
	return out
}

func wantOneProblem(t *testing.T, problems []string, contains ...string) {
	t.Helper()
	if len(problems) != 1 {
		t.Fatalf("got %d problems, want 1: %q", len(problems), problems)
	}
	for _, c := range contains {
		if !strings.Contains(problems[0], c) {
			t.Errorf("problem %q does not contain %q", problems[0], c)
		}
	}
}

// TC-694-03: a mapped member with no restore_apply rule.
func TestRestoreCoverageFlagsAMemberWithNoApplyRule(t *testing.T) {
	problems := checkRestoreCoverage(
		[]string{"rasputin.db", "x/new.key"},
		fakeMapped("rasputin.db", "x/new.key"),
		exactRules("rasputin.db"),
		nil,
	)
	wantOneProblem(t, problems, "x/new.key", "no restore_apply rule")
}

// TC-694-04: the #751 shape — a rule exists but identityRestorePath does not map it.
func TestRestoreCoverageFlagsAMemberRestorePathDoesNotMap(t *testing.T) {
	problems := checkRestoreCoverage(
		[]string{"rasputin.db", "x/seed"},
		fakeMapped("rasputin.db"),
		exactRules("rasputin.db", "x/seed"),
		nil,
	)
	wantOneProblem(t, problems, "x/seed", "identityRestorePath does not map it")
}

// TC-694-05: a member neither mapped nor matched, and not allowlisted.
func TestRestoreCoverageFlagsAnUnhandledMember(t *testing.T) {
	problems := checkRestoreCoverage(
		[]string{"rasputin.db", "x/orphan"},
		fakeMapped("rasputin.db"),
		exactRules("rasputin.db"),
		nil,
	)
	wantOneProblem(t, problems, "x/orphan", "does not map it and no restore_apply rule matches it")
}

// TC-694-06: an allowlist entry with a blank reason.
func TestRestoreCoverageFlagsABlankAllowlistReason(t *testing.T) {
	for _, reason := range []string{"", "  \t"} {
		t.Run(fmt.Sprintf("%q", reason), func(t *testing.T) {
			problems := checkRestoreCoverage(
				[]string{"rasputin.db", "x/skip"},
				fakeMapped("rasputin.db"),
				exactRules("rasputin.db"),
				[]allowEntry{{member: "x/skip", reason: reason}},
			)
			wantOneProblem(t, problems, `"x/skip"`, "blank reason")
		})
	}
}

// TC-694-07: an allowlist entry that matches no member.
func TestRestoreCoverageFlagsAnAllowlistEntryMatchingNothing(t *testing.T) {
	problems := checkRestoreCoverage(
		[]string{"rasputin.db"},
		fakeMapped("rasputin.db"),
		exactRules("rasputin.db"),
		[]allowEntry{{member: "nope/absent", reason: "a reason"}},
	)
	wantOneProblem(t, problems, `"nope/absent"`, "matches no archive member")
}

// TC-694-08: an exact rule and a prefix rule that each match no member.
func TestRestoreCoverageFlagsRulesMatchingNothing(t *testing.T) {
	rules := append(exactRules("rasputin.db", "x/ghost"), applyRule{archive: "ghost/dir/", kind: applyReplaceTree})
	problems := checkRestoreCoverage([]string{"rasputin.db"}, fakeMapped("rasputin.db"), rules, nil)
	want := []string{
		`restore_apply rule "x/ghost" matches no archive member; delete it or add the member`,
		`restore_apply rule "ghost/dir/" matches no archive member; delete it or add the member`,
	}
	if !reflect.DeepEqual(problems, want) {
		t.Fatalf("problems = %q\nwant %q", problems, want)
	}
}

// TC-694-09: an allowlisted member that restore now reaches is a stale entry.
func TestRestoreCoverageFlagsAStaleAllowlistEntry(t *testing.T) {
	problems := checkRestoreCoverage(
		[]string{"rasputin.db", "x/now-mapped"},
		fakeMapped("rasputin.db", "x/now-mapped"),
		exactRules("rasputin.db", "x/now-mapped"),
		[]allowEntry{{member: "x/now-mapped", reason: "was not restored"}},
	)
	wantOneProblem(t, problems, `"x/now-mapped"`, "stale", "restore now reaches it")
}

// TC-694-10: the real code fails without the seed's allowlist entry, which is
// the gate catching #751 on main. When #751 maps the seed this case finds zero
// problems and fails, and check (e) fails TC-694-01, until #751's PR deletes
// both this case and the entry.
func TestRestoreCoverageCatchesTheUnmappedSeedWithoutItsAllowlistEntry(t *testing.T) {
	_, members := assembledMembers(t)
	var allow []allowEntry
	for _, a := range restoreAllowlist {
		if a.member != appSecretSeedArchivePath {
			allow = append(allow, a)
		}
	}
	problems := checkRestoreCoverage(members, identityRestorePath, identityApplyRules(), allow)
	wantOneProblem(t, problems, appSecretSeedArchivePath, "identityRestorePath does not map it")
}

// stagePending writes a pending restore whose report lists the given staged
// files, as PrepareRestore leaves it.
func stagePending(t *testing.T, dataDir string, staged map[string]string, order []string) {
	t.Helper()
	pending := filepath.Join(dataDir, restorePendingDirName)
	report := RestoreReport{ID: "r-coverage", Phase: RestorePhase, GenerationID: "g1", PreparedAt: time.Now().UTC()}
	for _, p := range order {
		abs := filepath.Join(pending, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, abs, staged[p])
		report.Restored = append(report.Restored, RestoredEntry{Path: p, SizeBytes: int64(len(staged[p])), SHA256: mustSHA([]byte(staged[p]))})
	}
	writeReportFile(t, filepath.Join(pending, restoreReportFile), report)
}

// assertRefusedWithNoResidue checks that a refused apply left the data dir as
// it found it: the pending restore whole, nothing applied, nothing replaced.
func assertRefusedWithNoResidue(t *testing.T, dataDir string, staged map[string]string) {
	t.Helper()
	pending := filepath.Join(dataDir, restorePendingDirName)
	for p, body := range staged {
		got, err := os.ReadFile(filepath.Join(pending, filepath.FromSlash(p)))
		if err != nil || string(got) != body {
			t.Errorf("staged %s after the refusal: %q, %v; want %q", p, got, err, body)
		}
	}
	if _, err := os.Stat(filepath.Join(pending, restoreReportFile)); err != nil {
		t.Errorf("the pending report is gone after the refusal: %v", err)
	}
	for _, e := range dataDirEntries(t, dataDir) {
		if e == restoreAppliedDirName || strings.HasPrefix(e, restoreReplacedPrefix) {
			t.Errorf("a refused apply left %s in the data dir", e)
		}
	}
}

func readString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// TC-694-11: a restored entry no rule matches is refused before any move, not
// skipped and reported green.
func TestApplyPendingRestoreRefusesAnEntryWithNoRule(t *testing.T) {
	dataDir := t.TempDir()
	writeTestFile(t, filepath.Join(dataDir, "rasputin.db"), "FRESH-DB")
	staged := map[string]string{"rasputin.db": "ARCHIVED-DB", "trust/unknown.key": "ARCHIVED-UNKNOWN"}
	stagePending(t, dataDir, staged, []string{"rasputin.db", "trust/unknown.key"})

	report, applied, err := ApplyPendingRestore(RestoreLayout{DataDir: dataDir})
	if !errors.Is(err, ErrRestoreApplyFailed) || !strings.Contains(err.Error(), "trust/unknown.key") {
		t.Fatalf("err = %v, want ErrRestoreApplyFailed naming trust/unknown.key", err)
	}
	if applied || report != nil {
		t.Errorf("applied = %v, report = %+v; want false, nil", applied, report)
	}
	if got := readString(t, filepath.Join(dataDir, "rasputin.db")); got != "FRESH-DB" {
		t.Errorf("live rasputin.db = %q after the refusal, want FRESH-DB", got)
	}
	assertRefusedWithNoResidue(t, dataDir, staged)
}

// TC-694-12: the bus-cert row puts the cert in the configured BusDir, where
// the bus reads it, and nowhere under <DataDir>/bus.
func TestApplyPendingRestorePlacesTheBusCertInTheConfiguredBusDir(t *testing.T) {
	dataDir := t.TempDir()
	busDir := filepath.Join(t.TempDir(), "elsewhere-bus")
	if err := os.MkdirAll(busDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(busDir, bustls.CertFileName), "FRESH-CERT")
	stagePending(t, dataDir, map[string]string{busCertArchivePath: "ARCHIVED-CERT"}, []string{busCertArchivePath})

	if _, applied, err := ApplyPendingRestore(RestoreLayout{DataDir: dataDir, BusDir: busDir}); err != nil || !applied {
		t.Fatalf("ApplyPendingRestore: applied=%v err=%v", applied, err)
	}
	if got := readString(t, filepath.Join(busDir, bustls.CertFileName)); got != "ARCHIVED-CERT" {
		t.Errorf("live bus cert = %q, want ARCHIVED-CERT", got)
	}
	var replaced string
	for _, e := range dataDirEntries(t, dataDir) {
		if strings.HasPrefix(e, restoreReplacedPrefix) {
			replaced = filepath.Join(dataDir, e)
		}
	}
	if replaced == "" {
		t.Fatal("no restore-replaced directory was created")
	}
	if got := readString(t, filepath.Join(replaced, "bus", bustls.CertFileName)); got != "FRESH-CERT" {
		t.Errorf("set-aside bus cert = %q, want FRESH-CERT", got)
	}
	if _, err := os.Lstat(filepath.Join(dataDir, "bus")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("<DataDir>/bus exists after a restore configured with BusDir %s: %v", busDir, err)
	}
}

// TC-694-16: the mesh-CA pair-check refusal leaves no residue either — the
// replaced directory is created only after the check passes (F-694-09).
func TestApplyPendingRestoreHalfACARefusalLeavesNoResidue(t *testing.T) {
	dataDir := t.TempDir()
	writeTestFile(t, filepath.Join(dataDir, "rasputin.db"), "FRESH-DB")
	if err := os.MkdirAll(filepath.Join(dataDir, "trust"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dataDir, "trust", "mesh-ca.key"), "FRESH-CA-KEY")
	staged := map[string]string{"rasputin.db": "ARCHIVED-DB", "trust/mesh-ca.key": "ARCHIVED-CA-KEY"}
	stagePending(t, dataDir, staged, []string{"rasputin.db", "trust/mesh-ca.key"})

	report, applied, err := ApplyPendingRestore(RestoreLayout{DataDir: dataDir})
	if !errors.Is(err, ErrRestoreApplyFailed) || !strings.Contains(err.Error(), "one half of the mesh CA") {
		t.Fatalf("err = %v, want ErrRestoreApplyFailed saying the restore holds one half of the mesh CA", err)
	}
	if applied || report != nil {
		t.Errorf("applied = %v, report = %+v; want false, nil", applied, report)
	}
	if got := readString(t, filepath.Join(dataDir, "rasputin.db")); got != "FRESH-DB" {
		t.Errorf("live rasputin.db = %q, want FRESH-DB", got)
	}
	if got := readString(t, filepath.Join(dataDir, "trust", "mesh-ca.key")); got != "FRESH-CA-KEY" {
		t.Errorf("live mesh-ca.key = %q, want FRESH-CA-KEY", got)
	}
	assertRefusedWithNoResidue(t, dataDir, staged)
}
