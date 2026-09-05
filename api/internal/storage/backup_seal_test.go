package storage

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// timeNow is a one-word alias so the schedule cases read as prose.
func timeNow() time.Time { return time.Now().UTC() }

// §4.6's write path itself — the seal — is tested in backupxfer, beside the
// code, with the opener in backupxfer/sealtest. What is tested HERE is the
// api's use of it: that nothing key-shaped reaches the ledger, and that the
// manifest the api assembles says the truth about the generation.

// TestNoKeyMaterialReachesTheLedger is the assertion the whole slice hangs on.
//
// A step result, a job event and a job error are all PERSISTED and RENDERED —
// the Tasks view shows them. So the surface under test is the ledger as the
// store hands it back, not anything the saga returned in memory.
//
// It scans for four things: the recipient's private key in both encodings a
// leak would plausibly take, and both §4.6 wrappings. The private key is the
// catastrophic one; the wrappings are ciphertext, but they are still the
// narrowest-surface rule the claim saga follows and there is no reason for
// either to be in a job feed.
func TestNoKeyMaterialReachesTheLedger(t *testing.T) {
	h := newRunHarness(t, nil, runHarnessOpts{})
	jobID := h.submit(t, RunSpec{Reason: ReasonScheduled})
	j := h.waitTerminal(t, jobID)
	if j.Status != jobs.StatusSucceeded {
		t.Fatalf("job status = %s (%s)", j.Status, j.Error)
	}

	ledger := h.ledgerText(t, jobID)
	forbidden := map[string]string{
		"the recipient's private key (base64url)": h.key.privateB64(),
		"the recipient's private key (hex)":       h.key.privateHex(),
		"the passphrase-wrapped private key":      testWrappedPass,
		"the recovery-code-wrapped private key":   testWrappedRecovery,
	}
	for what, needle := range forbidden {
		if needle == "" {
			t.Fatalf("nothing to look for: %s", what)
		}
		if strings.Contains(ledger, needle) {
			t.Errorf("%s appears in the job ledger — a step result, an event or the job error", what)
		}
	}

	// The PUBLIC key is allowed to be there, and asserting it IS present keeps
	// the scan honest: a test that found nothing because the ledger was empty
	// would pass for the wrong reason.
	if !strings.Contains(ledger, h.key.publicB64) {
		t.Error("the ledger does not contain the target's public key, so this scan may have been looking at nothing")
	}
	if !strings.Contains(ledger, proto.BackupScopeFull) {
		t.Error("the ledger never mentions the scope; the run's own output must say what it captured")
	}
	// And no upload credential: the fan-out mints one per member and it must
	// live in the command and nowhere else.
	for _, rec := range h.agent.transferRecords() {
		if rec.cmd.Credential == "" {
			t.Fatal("a transfer command carried no credential")
		}
		if strings.Contains(ledger, rec.cmd.Credential) {
			t.Error("an upload credential appears in the job ledger")
		}
	}
}

// TestAssembleWritesTheManifestFirst is the streaming property: a reader learns
// the scope before it reads a byte of anything else, so a restore can refuse an
// identity-only archive it was told was complete without buffering the lot.
func TestAssembleWritesTheManifestFirst(t *testing.T) {
	h := newRunHarness(t, nil, runHarnessOpts{})
	snap := t.TempDir() + "/snapshot.db"
	writeTestFile(t, snap, "SQLITE-SNAPSHOT-BYTES")

	var buf bytes.Buffer
	m, err := Assemble(&buf, AssembleOptions{
		Sources:      IdentitySources{TrustDir: h.trustDir, MeshStateDir: h.meshDir},
		SnapshotPath: snap,
		GenerationID: "20260902T000000Z-test-full",
		JobID:        "job-1",
		ClusterID:    "home1",
		KeyID:        "key-1",
		Scope:        proto.BackupScopeFull,
	})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	// No fan-out report was supplied, so nobody enumerated the installed apps:
	// the scope is this build's reach, and complete is FALSE — an archive
	// nobody looked at cannot claim nothing was missed. The section is still
	// present, and says so.
	if m.Scope != proto.BackupScopeFull || m.Complete {
		t.Errorf("manifest scope=%q complete=%v", m.Scope, m.Complete)
	}
	if m.ManifestVersion != 2 || m.Layout == "" {
		t.Errorf("manifest version %d layout %q; a restore reading this needs both", m.ManifestVersion, m.Layout)
	}
	if m.AppVolumes.Enumerated || m.AppVolumes.Volumes == nil || !strings.Contains(m.AppVolumes.Summary, "did not run") {
		t.Errorf("appVolumes = %+v; a manifest with no fan-out must say the fan-out did not run", m.AppVolumes)
	}

	tr := tar.NewReader(&buf)
	first, err := tr.Next()
	if err != nil {
		t.Fatalf("read first tar entry: %v", err)
	}
	if first.Name != proto.BackupManifestFile {
		t.Fatalf("first archive entry is %q, want the manifest — a reader must learn the scope before the payload", first.Name)
	}
	body, err := io.ReadAll(tr)
	if err != nil {
		t.Fatalf("read manifest entry: %v", err)
	}
	var inner Manifest
	if err := json.Unmarshal(body, &inner); err != nil {
		t.Fatalf("manifest inside the archive is not JSON: %v", err)
	}
	if inner.Scope != proto.BackupScopeFull {
		t.Errorf("the manifest inside the archive says scope=%q", inner.Scope)
	}
	if inner.AppVolumes.CapturedCount != 0 || inner.AppVolumes.Reason == "" || inner.AppVolumes.Volumes == nil {
		t.Error("the archive's own manifest does not carry the fan-out's report")
	}

	// Every remaining entry is listed, in order, with the digest the manifest
	// promised.
	seen := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("tar read %s: %v", hdr.Name, err)
		}
		sum := sha256.Sum256(data)
		found := false
		for _, e := range m.Entries {
			if e.Path == hdr.Name {
				found = true
				if e.SHA256 != hex.EncodeToString(sum[:]) {
					t.Errorf("%s: manifest digest %s, archive contains %s", hdr.Name, e.SHA256, hex.EncodeToString(sum[:]))
				}
			}
		}
		if !found {
			t.Errorf("the archive holds %s, which the manifest does not list", hdr.Name)
		}
		seen[hdr.Name] = true
	}
	for _, e := range m.Entries {
		if !seen[e.Path] {
			t.Errorf("the manifest lists %s, which is not in the archive", e.Path)
		}
	}
}

// TestAssembleRefusesWithoutASnapshot: an archive with no rasputin.db restores
// as an appliance with no users, no nodes and no apps.
func TestAssembleRefusesWithoutASnapshot(t *testing.T) {
	h := newRunHarness(t, nil, runHarnessOpts{})
	var buf bytes.Buffer
	_, err := Assemble(&buf, AssembleOptions{
		Sources:      IdentitySources{TrustDir: h.trustDir, MeshStateDir: h.meshDir},
		GenerationID: "g",
		Scope:        proto.BackupScopeFull,
	})
	if err == nil {
		t.Fatal("Assemble produced an archive with no database in it")
	}
	if !strings.Contains(err.Error(), "no users, no nodes and no apps") {
		t.Errorf("error = %q", err)
	}
}

// TestFanOutReportIsHonest pins the shape of the report an operator reads on
// the day they discover an app is not in their archive.
//
// Every assertion here is about a way the report could be quietly weaker than
// the truth: a nil slice rendering as `null`, a count that disagrees with the
// records, a not-captured volume with no reason, a `complete` that is true
// while something was missed.
func TestFanOutReportIsHonest(t *testing.T) {
	empty := NewAppVolumeReport(AppEnumeration{}, nil, 0)
	if empty.Captured == nil || empty.Volumes == nil {
		t.Error("nil slices render as `null`, and `null` is not the answer `[]` is")
	}
	if !empty.Complete() {
		t.Error("a cluster with no apps installed has had every classified volume captured, and the manifest says appsInstalled: 0")
	}
	if !strings.Contains(empty.Summary, "No app is installed") {
		t.Errorf("summary = %q; zero apps must be stated as zero apps, not as zero volumes", empty.Summary)
	}
	if empty.Reason == "" {
		t.Fatal("the report does not carry the standing caveat")
	}
	if AppVolumeFanOutReason() != empty.Reason {
		t.Error("the exported reason and the report's reason have drifted apart; every surface must say the same words")
	}

	r := NewAppVolumeReport(AppEnumeration{AppsInstalled: 4, AppsResolved: 4}, []VolumeRecord{
		{App: "vaultwarden", Volume: "vaultwarden-data", Class: "critical", Captured: true, SizeBytes: 10, AppRestored: true, Member: "volumes/vaultwarden/vaultwarden-data.rasputin-archive", SealedSHA256: "ab"},
		{App: "immich", Volume: "immich-upload", Class: "state", Captured: false, Failed: true, Reason: "node n-compute is OFFLINE", AppRestored: true},
		{App: "immich", Volume: "immich-library", Class: "bulk", Captured: false, Reason: ReasonBulkStreamsDirect, AppRestored: true},
		{App: "paperless", Volume: "paperless-data", Class: "state", Captured: false, Failed: true, Reason: "refused", AppRestored: false},
	}, 2)
	if r.CapturedCount != 1 || r.SkippedCount != 3 || r.FailedCount != 2 {
		t.Errorf("counts = %d captured / %d skipped / %d failed, want 1/3/2", r.CapturedCount, r.SkippedCount, r.FailedCount)
	}
	if len(r.Captured) != 1 || r.Captured[0] != "vaultwarden/vaultwarden-data" {
		t.Errorf("captured = %v", r.Captured)
	}
	if len(r.Failed) != 2 || r.Failed[0] != "immich/immich-upload" || r.Failed[1] != "paperless/paperless-data" {
		t.Errorf("failed = %v; §4.4's failed volumes must be a field, not a scan", r.Failed)
	}
	if r.Complete() {
		t.Error("complete is true with three volumes missing — the one field a hurried reader trusts is lying")
	}
	if len(r.AppsLeftDown) != 1 || r.AppsLeftDown[0] != "paperless" {
		t.Errorf("appsLeftDown = %v, want [paperless] — an app the backup left down must be a field, not a scan", r.AppsLeftDown)
	}
	if !strings.Contains(r.Summary, "1 of 4") || !strings.Contains(r.Summary, "2 FAILED") {
		t.Errorf("summary = %q; it must say how many of how many, and how many failed", r.Summary)
	}
	// The only blocker a report may name is the `bulk` lane, which is a
	// missing BUILD; #292–#296 shipped and naming a closed issue would send
	// an operator looking in the wrong place.
	if !strings.Contains(strings.Join(r.BlockedBy, " "), "bulk") {
		t.Errorf("blockedBy = %v; a report with an uncaptured bulk volume names the missing lane", r.BlockedBy)
	}
	for _, done := range []string{"#292", "#293", "#294", "#295", "#296"} {
		if strings.Contains(strings.Join(r.BlockedBy, " "), done) {
			t.Errorf("blockedBy still names %s, which shipped", done)
		}
	}
	noBulk := NewAppVolumeReport(AppEnumeration{AppsInstalled: 1, AppsResolved: 1}, []VolumeRecord{
		{App: "immich", Volume: "immich-upload", Class: "state", Captured: false, Failed: true, Reason: "offline", AppRestored: true},
	}, 1)
	if len(noBulk.BlockedBy) != 0 {
		t.Errorf("a failed run names a blocker: %v — a failure is not a missing build", noBulk.BlockedBy)
	}
	if !strings.Contains(r.Reason, proto.BackupScopeFull) || !strings.Contains(r.Reason, "EVERY NODE") {
		t.Error("the standing caveat does not name the scope, so a reader cannot connect it to the generation on the platter")
	}
	// Every not-captured record carries a sentence. This is the invariant the
	// whole structure exists for.
	for _, v := range r.Volumes {
		if !v.Captured && strings.TrimSpace(v.Reason) == "" {
			t.Errorf("%s/%s is recorded as not captured with no reason", v.App, v.Volume)
		}
	}
}

// TestBackupScheduleDefaultsAndBounds covers §4.1's cadence: weekly by default,
// overridable, and bounded.
func TestBackupScheduleDefaultsAndBounds(t *testing.T) {
	ctx := context.Background()
	st := newMemorySettings()

	got, err := GetBackupSchedule(ctx, st, true)
	if err != nil {
		t.Fatalf("GetBackupSchedule: %v", err)
	}
	if !got.Enabled {
		t.Error("scheduled backups default to OFF; §4.1 makes the weekly run the product's behaviour, not an opt-in")
	}
	if got.Interval() != DefaultBackupCadence {
		t.Errorf("default cadence = %s, want %s", got.Interval(), DefaultBackupCadence)
	}

	if _, err := SetBackupSchedule(ctx, st, BackupSchedule{Enabled: true, Every: "1m"}); err == nil {
		t.Error("a one-minute cadence was accepted; every run is a FULL and stages a copy of the identity set")
	}
	if _, err := SetBackupSchedule(ctx, st, BackupSchedule{Enabled: true, Every: "10000h"}); err == nil {
		t.Error("a cadence beyond the ceiling was accepted")
	}
	saved, err := SetBackupSchedule(ctx, st, BackupSchedule{Enabled: true, Every: "24h"})
	if err != nil {
		t.Fatalf("SetBackupSchedule: %v", err)
	}
	if saved.Interval() != 24*time.Hour {
		t.Errorf("saved cadence = %s", saved.Interval())
	}

	// A corrupt stored value must not be able to turn backups off.
	_ = st.Set(ctx, KeyBackupSchedule, `{"enabled":true,"every":"not a duration"}`)
	got, err = GetBackupSchedule(ctx, st, true)
	if err != nil {
		t.Fatalf("GetBackupSchedule: %v", err)
	}
	if got.Interval() != DefaultBackupCadence {
		t.Errorf("a corrupt cadence resolved to %s rather than falling back to the default — a bad value that read as `never` would be an outage nobody sees until they need a restore", got.Interval())
	}
}

// TestBackupRetainDefaultsAndBounds covers §4.4's retention depth beside the
// cadence (#297): four by default, overridable, floored at one — a prune that
// keeps nothing is not a retention policy — and ceilinged at a year of weekly
// fulls.
func TestBackupRetainDefaultsAndBounds(t *testing.T) {
	ctx := context.Background()
	st := newMemorySettings()

	got, err := GetBackupSchedule(ctx, st, true)
	if err != nil {
		t.Fatalf("GetBackupSchedule: %v", err)
	}
	if got.Retain != proto.BackupRetainGenerations || got.Generations() != 4 {
		t.Errorf("default retain = %d (resolved %d), want §4.4's 4", got.Retain, got.Generations())
	}

	// A schedule saved before the field existed — cadence only — keeps the
	// default depth, and is SERVED with it resolved rather than as zero.
	if _, err := SetBackupSchedule(ctx, st, BackupSchedule{Enabled: true, Every: "24h"}); err != nil {
		t.Fatalf("SetBackupSchedule: %v", err)
	}
	got, _ = GetBackupSchedule(ctx, st, true)
	if got.Retain != 4 {
		t.Errorf("a schedule set without a depth is served with retain = %d, want 4", got.Retain)
	}

	for _, bad := range []int{-1, 53, 1000} {
		if _, err := SetBackupSchedule(ctx, st, BackupSchedule{Enabled: true, Retain: bad}); err == nil {
			t.Errorf("retain %d was accepted", bad)
		} else if !errors.Is(err, ErrInvalidRetain) {
			t.Errorf("retain %d refused with %v, want ErrInvalidRetain", bad, err)
		}
	}
	for _, ok := range []int{1, 2, 52} {
		saved, err := SetBackupSchedule(ctx, st, BackupSchedule{Enabled: true, Retain: ok})
		if err != nil {
			t.Errorf("retain %d refused: %v", ok, err)
			continue
		}
		if saved.Generations() != ok {
			t.Errorf("retain %d saved as %d", ok, saved.Generations())
		}
	}

	// A depth persisted out of range — by hand, or by a build with different
	// bounds — resolves to the default rather than reaching the agent as a
	// Keep it would refuse (which would fail every run) or as zero.
	_ = st.Set(ctx, KeyBackupSchedule, `{"enabled":true,"every":"168h","retain":0}`)
	got, err = GetBackupSchedule(ctx, st, true)
	if err != nil {
		t.Fatalf("GetBackupSchedule: %v", err)
	}
	if got.Generations() != 4 || got.Retain != 4 {
		t.Errorf("a stored zero depth resolved to %d, want the default 4", got.Generations())
	}
	_ = st.Set(ctx, KeyBackupSchedule, `{"enabled":true,"every":"168h","retain":999}`)
	got, _ = GetBackupSchedule(ctx, st, true)
	if got.Generations() != 4 {
		t.Errorf("a stored out-of-range depth resolved to %d, want the default 4", got.Generations())
	}
}

// TestDueFuncGatesTheSchedule covers each branch of the scheduler gate.
func TestDueFuncGatesTheSchedule(t *testing.T) {
	h := newRunHarness(t, nil, runHarnessOpts{})
	ctx := context.Background()
	due := DueFunc(h.store, h.settings, true)

	// A fresh installation with a claimed target: due now, not in a week.
	if ok, reason := due(ctx); !ok {
		t.Errorf("a never-backed-up installation is not due: %s", reason)
	}

	// Schedule off.
	if _, err := SetBackupSchedule(ctx, h.settings, BackupSchedule{Enabled: false}); err != nil {
		t.Fatalf("SetBackupSchedule: %v", err)
	}
	ok, reason := due(ctx)
	if ok {
		t.Error("a disabled schedule fired anyway")
	}
	if !strings.Contains(reason, "turned off") {
		t.Errorf("the skip reason is %q, which does not distinguish a disabled schedule from a broken one", reason)
	}

	// A run in flight.
	if _, err := SetBackupSchedule(ctx, h.settings, BackupSchedule{Enabled: true, Every: "1h"}); err != nil {
		t.Fatalf("SetBackupSchedule: %v", err)
	}
	if err := h.store.StartRun(ctx, "job-inflight", ReasonManual, proto.BackupScopeIdentityOnly, timeNow()); err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	if ok, reason := due(ctx); ok {
		t.Error("the schedule fired while a run was already in flight")
	} else if !strings.Contains(reason, "already running") {
		t.Errorf("the skip reason is %q", reason)
	}

	// Finished, and inside the cadence.
	if err := h.store.FinishRun(ctx, "job-inflight", RunResult{
		GenerationID: "g", Digest: "d", SizeBytes: 1, GenerationsKept: 1, At: timeNow(),
	}); err != nil {
		t.Fatalf("FinishRun: %v", err)
	}
	if ok, _ := due(ctx); ok {
		t.Error("the schedule fired again immediately after a success, inside the cadence")
	}
}

// TestFanOutCompleteIsAPositiveAssertion pins what earns `complete: true`: the
// fan-out enumerated the installed apps, every one resolved to a tile that
// classifies its volumes, and every classified volume was captured. An empty
// record list on its own earns nothing — that was the 2026-09-03 e3bench
// manifest, `complete: true` over one installed app nobody had classified.
func TestFanOutCompleteIsAPositiveAssertion(t *testing.T) {
	var nobodyLooked AppVolumeReport
	if nobodyLooked.Complete() {
		t.Error("the zero-value report — one nobody built — is complete")
	}
	if unenumeratedReport().Complete() {
		t.Error("the section an archive gets when no fan-out ran is complete")
	}

	// One installed app, none resolved, no records: the shape the bench
	// produced. It cannot arise from PlanAppVolumes any more (the unresolved
	// app leaves a record), and even hand-built it earns nothing.
	if NewAppVolumeReport(AppEnumeration{AppsInstalled: 1}, nil, 0).Complete() {
		t.Error("an empty plan over an installed app is complete — this is the bench's exact lie")
	}

	// Zero apps installed, stated as such: complete, because nothing was
	// classified and nothing was missed, and appsInstalled: 0 says why.
	none := NewAppVolumeReport(AppEnumeration{}, nil, 0)
	if !none.Complete() || !none.Enumerated || none.AppsInstalled != 0 {
		t.Errorf("a cluster with no apps: complete=%v enumerated=%v installed=%d", none.Complete(), none.Enumerated, none.AppsInstalled)
	}

	// One app resolved to a tile that declares only `cache`: complete, and
	// the summary says why there are no records rather than implying nobody
	// declared anything.
	cacheOnly := NewAppVolumeReport(AppEnumeration{AppsInstalled: 1, AppsResolved: 1}, nil, 0)
	if !cacheOnly.Complete() || !strings.Contains(cacheOnly.Summary, "`cache`") {
		t.Errorf("cache-only cluster: complete=%v summary=%q", cacheOnly.Complete(), cacheOnly.Summary)
	}

	// The positive case: resolved, captured, consulted.
	captured := NewAppVolumeReport(AppEnumeration{AppsInstalled: 1, AppsResolved: 1}, []VolumeRecord{
		{App: "vaultwarden", Volume: "vaultwarden-data", Class: "critical", Captured: true, AppRestored: true},
	}, 1)
	if !captured.Complete() {
		t.Error("one app, one volume, captured — and not complete")
	}
	// JSON carries every part of the assertion, so a reader can check it.
	raw, err := json.Marshal(captured)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"appsInstalled":1`, `"appsResolved":1`, `"enumerated":true`} {
		if !strings.Contains(string(raw), key) {
			t.Errorf("manifest JSON lacks %s: %s", key, raw)
		}
	}
}
