package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// The app-volume restore (design/storage.md §4.5 phase 2, #291): the plan's
// decisions, the session's custody of the key, the restore-stream endpoint,
// and the saga end to end over the fake agents on real NATS against the
// real ingest and egress on one real socket.

// ----- the plan --------------------------------------------------------------

func vwApp() *apps.App { return testApp("app-vw", "vaultwarden", computeNodeID, "vaultwarden") }

func vwTile(vols ...tileschema.Volume) tileschema.Tile {
	if len(vols) == 0 {
		vols = []tileschema.Volume{vol("vaultwarden-data", tileschema.BackupCritical, tileschema.QuiesceStop)}
	}
	return testTile("vaultwarden", vols...)
}

func captured(appID, app, volume, class, node string) VolumeRecord {
	r := capturedVolume(app, volume, class)
	r.AppID, r.Node, r.TileID = appID, node, "vaultwarden"
	r.SHA256, r.SizeBytes, r.FileCount = strings.Repeat("cd", 32), 4096, 3
	return r
}

func TestPlanAppRestoreRestoresToWhereTheAppIsNow(t *testing.T) {
	// Captured on n-old; the app is on n-compute today.
	rec := captured("app-vw", "vaultwarden", "vaultwarden-data", "critical", "n-old")
	plan := PlanAppRestore(vwApp(), vwTile(), true, []VolumeRecord{rec}, nil)
	if len(plan.Restore) != 1 || len(plan.Skipped) != 0 {
		t.Fatalf("plan: %+v", plan)
	}
	p := plan.Restore[0]
	if p.Volume != "vaultwarden-data" || p.Class != "critical" || p.CapturedFrom != "n-old" || p.Member != rec.Member || p.SHA256 != rec.SHA256 || p.SizeBytes != 4096 {
		t.Fatalf("plan entry: %+v", p)
	}
}

func TestPlanAppRestoreSkipsWhatItMustAndSaysWhy(t *testing.T) {
	app := vwApp()
	tile := vwTile(
		vol("vaultwarden-data", tileschema.BackupCritical, tileschema.QuiesceStop),
		vol("vaultwarden-state", tileschema.BackupState, tileschema.QuiesceStop),
		vol("vaultwarden-cache", tileschema.BackupCache, tileschema.QuiesceNone),
		vol("vaultwarden-media", tileschema.BackupBulk, tileschema.QuiesceNone),
		vol("vaultwarden-new", tileschema.BackupState, tileschema.QuiesceStop),
	)
	records := []VolumeRecord{
		captured("app-vw", "vaultwarden", "vaultwarden-state", "state", computeNodeID),
		captured("app-vw", "vaultwarden", "vaultwarden-data", "critical", computeNodeID),
		// In the generation, but the tile classes it cache/bulk today.
		captured("app-vw", "vaultwarden", "vaultwarden-cache", "state", computeNodeID),
		captured("app-vw", "vaultwarden", "vaultwarden-media", "state", computeNodeID),
		// In the generation, and the tile no longer declares it.
		captured("app-vw", "vaultwarden", "vaultwarden-legacy", "state", computeNodeID),
		// Classified then, and not captured — the run's own reason.
		func() VolumeRecord {
			r := skippedVolume("vaultwarden", "vaultwarden-attachments", "state", "node n-compute is OFFLINE: no agent answered. §4.4 says failed")
			r.AppID = "app-vw"
			return r
		}(),
	}
	plan := PlanAppRestore(app, tile, true, records, nil)
	got := map[string]string{}
	for _, s := range plan.Skipped {
		got[s.Volume] = s.Reason
	}
	want := map[string]string{
		"vaultwarden-cache":       "classed `cache`",
		"vaultwarden-media":       "classed `bulk`",
		"vaultwarden-legacy":      "no longer declares",
		"vaultwarden-attachments": "not in this generation: node n-compute is OFFLINE",
		"vaultwarden-new":         "no record of this volume",
	}
	for v, frag := range want {
		if !strings.Contains(got[v], frag) {
			t.Errorf("%s: reason %q, want it to mention %q", v, got[v], frag)
		}
	}
	if len(plan.Skipped) != len(want) {
		t.Errorf("skipped %d, want %d: %+v", len(plan.Skipped), len(want), plan.Skipped)
	}
	// Critical first, then state — the order the backup took them in.
	if len(plan.Restore) != 2 || plan.Restore[0].Volume != "vaultwarden-data" || plan.Restore[1].Volume != "vaultwarden-state" {
		t.Fatalf("restore order: %+v", plan.Restore)
	}
	for _, s := range plan.Skipped {
		if s.Failed {
			t.Errorf("%s: a skip the plan chose is marked failed", s.Volume)
		}
	}
}

func TestPlanAppRestoreHonoursASelection(t *testing.T) {
	records := []VolumeRecord{
		captured("app-vw", "vaultwarden", "vaultwarden-data", "critical", computeNodeID),
		captured("app-vw", "vaultwarden", "vaultwarden-state", "state", computeNodeID),
	}
	tile := vwTile(vol("vaultwarden-data", "critical", "stop"), vol("vaultwarden-state", "state", "stop"))
	plan := PlanAppRestore(vwApp(), tile, true, records, []string{"vaultwarden-state"})
	if len(plan.Restore) != 1 || plan.Restore[0].Volume != "vaultwarden-state" || len(plan.Skipped) != 1 || !strings.Contains(plan.Skipped[0].Reason, "not selected") {
		t.Fatalf("plan: %+v", plan)
	}
}

func TestPlanAppRestoreWithoutATileRestoresNothing(t *testing.T) {
	records := []VolumeRecord{captured("app-vw", "vaultwarden", "vaultwarden-data", "critical", computeNodeID)}
	plan := PlanAppRestore(vwApp(), tileschema.Tile{}, false, records, nil)
	if len(plan.Restore) != 0 || len(plan.Skipped) != 1 || !strings.Contains(plan.Skipped[0].Reason, "not in the catalog") {
		t.Fatalf("plan: %+v", plan)
	}
}

func TestPlanAppRestoreRefusesAnUnverifiableMember(t *testing.T) {
	rec := captured("app-vw", "vaultwarden", "vaultwarden-data", "critical", computeNodeID)
	rec.SHA256 = ""
	plan := PlanAppRestore(vwApp(), vwTile(), true, []VolumeRecord{rec}, nil)
	if len(plan.Restore) != 0 || len(plan.Skipped) != 1 || !strings.Contains(plan.Skipped[0].Reason, "nothing can verify") {
		t.Fatalf("plan: %+v", plan)
	}
}

// A reinstalled app has a new id; its records are found by tile and name,
// and the listing says so.
func TestManifestRecordsForMatchesAReinstalledAppByTileAndName(t *testing.T) {
	m := &Manifest{AppVolumes: AppVolumeReport{Volumes: []VolumeRecord{
		captured("app-old", "vaultwarden", "vaultwarden-data", "critical", computeNodeID),
		captured("app-other", "paperless", "paperless-data", "state", computeNodeID),
	}}}
	recs, by := manifestRecordsFor(m, vwApp())
	if len(recs) != 1 || by != "tile+name" || recs[0].Volume != "vaultwarden-data" {
		t.Fatalf("%v %q", recs, by)
	}
	m.AppVolumes.Volumes[0].AppID = "app-vw"
	recs, by = manifestRecordsFor(m, vwApp())
	if len(recs) != 1 || by != "appId" {
		t.Fatalf("%v %q", recs, by)
	}
	custom := testApp("app-c", "vaultwarden", computeNodeID, "")
	if recs, _ := manifestRecordsFor(m, custom); len(recs) != 0 {
		t.Fatalf("a custom app with no tile matched by name alone: %v", recs)
	}
}

// ----- the session -----------------------------------------------------------

func TestRestoreSessionsHoldOneKeyForOneJobAndZeroIt(t *testing.T) {
	r := NewRestoreSessions()
	key := bytes.Repeat([]byte{7}, 32)
	id, err := r.Open(key)
	if err != nil {
		t.Fatal(err)
	}
	// The session has its own copy: zeroing the caller's does not touch it.
	for i := range key {
		key[i] = 0
	}
	s := r.Get(id)
	if s == nil || !bytes.Equal(s.key, bytes.Repeat([]byte{7}, 32)) {
		t.Fatal("the session does not hold the key")
	}
	if _, active := r.Active(); !active {
		t.Fatal("an open session is not active")
	}
	if _, err := r.Open(bytes.Repeat([]byte{8}, 32)); !errors.Is(err, ErrRestoreActive) {
		t.Fatalf("a second session opened: %v", err)
	}
	if err := r.Bind(id, "job-1"); err != nil {
		t.Fatal(err)
	}
	if err := r.Bind(id, "job-2"); err == nil {
		t.Fatal("bound to a second job")
	}
	if err := r.Bind(id, "job-1"); err != nil {
		t.Fatalf("binding the same job again is not a no-op: %v", err)
	}
	if r.ByJob("job-1") != s || r.ByJob("job-9") != nil {
		t.Fatal("ByJob")
	}
	if err := r.Arm(id, "/mnt/x", "part", "gen", "n1", map[string]restoreMemberFacts{"volumes/a/b.rasputin-archive": {}}); err != nil {
		t.Fatal(err)
	}
	held := s.key
	r.CloseJob("job-1")
	if !allZero(held) || r.Get(id) != nil || r.ByJob("job-1") != nil {
		t.Fatal("close did not zero and forget the key")
	}
	if _, active := r.Active(); active {
		t.Fatal("still active after close")
	}
	if err := r.Bind(id, "job-1"); !errors.Is(err, ErrRestoreSessionGone) {
		t.Fatalf("bind after close: %v", err)
	}
	if _, err := r.Open(make([]byte, 32)); err == nil {
		t.Fatal("an all-zero key opened a session")
	}
	if _, err := r.Open([]byte("short")); err == nil {
		t.Fatal("a short key opened a session")
	}
}

func TestRestoreSessionsDropAnUnboundSessionAfterItsTTL(t *testing.T) {
	r := NewRestoreSessions()
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }
	id, err := r.Open(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s := r.Get(id)
	now = now.Add(unboundSessionTTL + time.Second)
	if r.Get(id) != nil {
		t.Fatal("an unbound session outlived its TTL")
	}
	if !allZero(s.key) {
		t.Fatal("the swept session's key was not zeroed")
	}
	if _, err := r.Open(bytes.Repeat([]byte{2}, 32)); err != nil {
		t.Fatalf("a new session after the sweep: %v", err)
	}
}

// ----- the trusted manifest ------------------------------------------------

func TestReadSealedManifestTrustsTheArchiveNotTheSidecar(t *testing.T) {
	key := newTestKeypair(t)
	mount := filepath.Join(t.TempDir(), "mnt")
	m := buildGeneration(t, mount, key, newIdentityFixture(), generationOpts{
		complete: true, volumes: []VolumeRecord{capturedVolume("vaultwarden", "vaultwarden-data", "critical")},
	})
	gen := filepath.Join(mount, proto.BackupGenerationsDir, m.GenerationID)
	// Edit the sidecar: an attacker holding the disk says the volume was
	// never captured.
	if err := os.WriteFile(filepath.Join(gen, proto.BackupManifestFile), []byte(`{"manifestVersion":2,"appVolumes":{"volumes":[]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(gen, proto.BackupArchiveFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	got, err := readSealedManifest(f, key.priv.Bytes())
	if err != nil {
		t.Fatalf("readSealedManifest: %v", err)
	}
	if got.GenerationID != m.GenerationID || len(got.AppVolumes.Volumes) != 1 || got.AppVolumes.Volumes[0].Volume != "vaultwarden-data" {
		t.Fatalf("inner manifest: %+v", got)
	}
	// The wrong key opens nothing.
	other := newTestKeypair(t)
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := readSealedManifest(f, other.priv.Bytes()); !errors.Is(err, ErrRestoreArchive) {
		t.Fatalf("wrong key: %v", err)
	}
}

// ----- the restore-stream endpoint ------------------------------------------

type egressRig struct {
	t        *testing.T
	auth     *backupxfer.Authority
	sessions *RestoreSessions
	egress   *RestoreEgress
	srv      *httptest.Server
	mount    string
	key      testKeypair
	genID    string
	member   string
	plain    []byte
	sealed   []byte
	logs     *syncLog
}

// syncLog is a log sink the handler goroutine writes and the test reads.
type syncLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *syncLog) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(&l.buf, format+"\n", args...)
}

func (l *syncLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func newEgressRig(t *testing.T) *egressRig {
	t.Helper()
	auth, err := backupxfer.NewAuthority()
	if err != nil {
		t.Fatal(err)
	}
	sessions := NewRestoreSessions()
	egress := NewRestoreEgress(auth, sessions)
	logs := &syncLog{}
	egress.logf = logs.Printf
	mux := http.NewServeMux()
	mux.Handle("GET "+backupxfer.EgressPathPrefix, egress)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	key := newTestKeypair(t)
	mount := filepath.Join(t.TempDir(), "mnt")
	genID := proto.BackupGenerationID(time.Now(), "job-1", proto.BackupScopeFull)
	member := proto.BackupMemberPath("vaultwarden", "vaultwarden-data")
	plain := []byte(strings.Repeat("TAR BYTES OF A VOLUME ", 5000))
	var sealed bytes.Buffer
	if _, err := backupxfer.Seal(&sealed, bytes.NewReader(plain), key.publicB64, "key-1", proto.BackupScopeFull); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(mount, proto.BackupGenerationsDir, genID, filepath.FromSlash(member))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, sealed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return &egressRig{t: t, auth: auth, sessions: sessions, egress: egress, srv: srv, mount: mount, key: key,
		genID: genID, member: member, plain: plain, sealed: sealed.Bytes(), logs: logs}
}

// arm opens, binds and arms a session for the member with the manifest's
// facts, and returns the session id.
func (r *egressRig) arm(sealedDigest string) string {
	r.t.Helper()
	id, err := r.sessions.Open(r.key.priv.Bytes())
	if err != nil {
		r.t.Fatal(err)
	}
	if err := r.sessions.Bind(id, "job-restore"); err != nil {
		r.t.Fatal(err)
	}
	if err := r.sessions.Arm(id, r.mount, "part", r.genID, "n-compute", map[string]restoreMemberFacts{
		r.member: {sealedSHA256: sealedDigest, sealedBytes: uint64(len(r.sealed)), plaintextSHA256: mustSHA(r.plain), plaintextBytes: uint64(len(r.plain))},
	}); err != nil {
		r.t.Fatal(err)
	}
	return id
}

func (r *egressRig) fetch(cred string) ([]byte, *backupxfer.Stream, error) {
	r.t.Helper()
	source, _ := backupxfer.EgressDestination(r.srv.URL)
	f, _ := backupxfer.FetcherFor(source, backupxfer.HTTPOptions{})
	st, err := f.Get(context.Background(), backupxfer.GetRequest{Source: source, Generation: r.genID, Member: r.member, Credential: cred})
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = st.Body.Close() }()
	b, err := io.ReadAll(st.Body)
	return b, st, err
}

func TestRestoreEgressStreamsAPlannedMemberUnsealed(t *testing.T) {
	r := newEgressRig(t)
	r.arm(mustSHA(r.sealed))
	cred, err := r.egress.Mint(backupxfer.Grant{Generation: r.genID, Member: r.member, NodeID: "n-compute", JobID: "job-restore", MaxBytes: uint64(len(r.plain)), Use: backupxfer.UseRestore}, backupxfer.RestoreCredentialTTL)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	got, st, err := r.fetch(cred)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !bytes.Equal(got, r.plain) {
		t.Fatalf("the stream is not the plaintext (%d bytes vs %d)", len(got), len(r.plain))
	}
	if st.DeclaredDigest != mustSHA(r.plain) || st.DeclaredBytes != uint64(len(r.plain)) {
		t.Fatalf("declared: %+v", st)
	}
	if strings.Contains(r.logs.String(), cred) {
		t.Fatal("the credential reached a log line")
	}
	if !strings.Contains(r.logs.String(), "streamed") {
		t.Fatalf("no record of the stream: %s", r.logs.String())
	}
}

func TestRestoreEgressRefusesWhatItMust(t *testing.T) {
	r := newEgressRig(t)
	grant := backupxfer.Grant{Generation: r.genID, Member: r.member, NodeID: "n-compute", JobID: "job-restore", MaxBytes: 1 << 20, Use: backupxfer.UseRestore}
	code := func(err error) string {
		var refused *backupxfer.RefusedError
		if errors.As(err, &refused) {
			return refused.Problem.Code
		}
		return "no refusal: " + fmt.Sprint(err)
	}
	// No session at all: the endpoint will not mint, and a credential from
	// the bare authority is refused as no-restore.
	if _, err := r.egress.Mint(grant, time.Minute); err == nil {
		t.Fatal("minted for a job with no session")
	}
	bare, _ := r.auth.Mint(grant, time.Minute)
	if _, _, err := r.fetch(bare); code(err) != backupxfer.CodeNoRestore {
		t.Fatalf("no session: %v", err)
	}
	r.arm(mustSHA(r.sealed))
	// An UPLOAD credential for the very member: refused by use.
	up := grant
	up.Use = ""
	upTok, _ := r.auth.Mint(up, time.Minute)
	if _, _, err := r.fetch(upTok); code(err) != backupxfer.CodeCredentialScope {
		t.Fatalf("upload credential: %v", err)
	}
	// A restore credential for another member: not minted here, and refused
	// by scope when minted elsewhere.
	other := grant
	other.Member = proto.BackupMemberPath("paperless", "paperless-data")
	if _, err := r.egress.Mint(other, time.Minute); err == nil {
		t.Fatal("minted a member the plan does not name")
	}
	otherTok, _ := r.auth.Mint(other, time.Minute)
	if _, _, err := r.fetch(otherTok); code(err) != backupxfer.CodeCredentialScope {
		t.Fatalf("other member: %v", err)
	}
	// Another node: not minted.
	elsewhere := grant
	elsewhere.NodeID = "n-other"
	if _, err := r.egress.Mint(elsewhere, time.Minute); err == nil {
		t.Fatal("minted for a node the app is not on")
	}
	// A forged credential.
	if _, _, err := r.fetch("rbx1.forged.forged"); code(err) != backupxfer.CodeCredentialInvalid {
		t.Fatalf("forged: %v", err)
	}
	// After the session closes, a still-valid credential is dead.
	cred, _ := r.egress.Mint(grant, time.Minute)
	r.sessions.CloseJob("job-restore")
	if _, _, err := r.fetch(cred); code(err) != backupxfer.CodeNoRestore {
		t.Fatalf("after close: %v", err)
	}
}

// A member edited on the platter is refused before the key is spent on it.
func TestRestoreEgressRefusesAMemberTheManifestDoesNotVouchFor(t *testing.T) {
	r := newEgressRig(t)
	r.arm(strings.Repeat("00", 32))
	cred, _ := r.egress.Mint(backupxfer.Grant{Generation: r.genID, Member: r.member, NodeID: "n-compute", JobID: "job-restore", MaxBytes: 1 << 20, Use: backupxfer.UseRestore}, time.Minute)
	_, _, err := r.fetch(cred)
	var refused *backupxfer.RefusedError
	if !errors.As(err, &refused) || refused.Problem.Code != backupxfer.CodeDigestMismatch {
		t.Fatalf("err = %v", err)
	}
}

// The wrong key in the session: the status is already 200 when the unseal
// fails, so the connection is aborted and the client sees a cut stream —
// never a clean EOF on a truncated tar.
func TestRestoreEgressAbortsTheStreamWhenTheKeyDoesNotOpenTheMember(t *testing.T) {
	r := newEgressRig(t)
	other := newTestKeypair(t)
	id, _ := r.sessions.Open(other.priv.Bytes())
	_ = r.sessions.Bind(id, "job-restore")
	_ = r.sessions.Arm(id, r.mount, "part", r.genID, "n-compute", map[string]restoreMemberFacts{
		r.member: {sealedSHA256: mustSHA(r.sealed), plaintextSHA256: mustSHA(r.plain), plaintextBytes: uint64(len(r.plain))},
	})
	cred, _ := r.egress.Mint(backupxfer.Grant{Generation: r.genID, Member: r.member, NodeID: "n-compute", JobID: "job-restore", MaxBytes: 1 << 20, Use: backupxfer.UseRestore}, time.Minute)
	got, _, err := r.fetch(cred)
	if err == nil {
		t.Fatalf("a stream under the wrong key ended cleanly with %d bytes", len(got))
	}
	if !strings.Contains(r.logs.String(), "ABORTED") {
		t.Fatalf("the abort was not logged: %s", r.logs.String())
	}
}

// ----- the saga, end to end --------------------------------------------------

// restoreCase is one app with one real volume on the controlplane node,
// backed up for real by the fake agents through the real transport, then
// corrupted.
type restoreCase struct {
	h      *runHarness
	app    *apps.App
	volDir string
	want   map[string]string
	genID  string
}

func writeMarker(t *testing.T, h *runHarness, keyID string) {
	t.Helper()
	marker := proto.StorageBackupSet{
		MarkerVersion: proto.StorageMarkerVersion, ClusterID: "home1", PartUUID: runPartUUID,
		KeyID: keyID, KeyAlg: "X25519;wrap=AES-256-GCM", PublicKey: h.key.publicB64,
		WrappedByPassphrase: testWrappedPass, WrappedByRecoveryCode: testWrappedRecovery,
		Label: "the archive disk", CreatedAt: time.Now().UTC(),
	}
	mb, _ := json.Marshal(marker)
	if err := os.WriteFile(filepath.Join(h.mountDir, proto.StorageMarkerFile), mb, 0o600); err != nil {
		t.Fatal(err)
	}
}

func dirSnapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			b, _ := os.ReadFile(p) //nolint:gosec // G304: the test's own temp dir
			rel, _ := filepath.Rel(dir, p)
			out[filepath.ToSlash(rel)] = string(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func newRestoreCase(t *testing.T, opts runHarnessOpts) *restoreCase {
	t.Helper()
	volDir := filepath.Join(t.TempDir(), "vaultwarden-data")
	if err := os.MkdirAll(filepath.Join(volDir, "attachments"), 0o750); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(volDir, "db.sqlite3"), "SQLite format 3\x00 the vault "+strings.Repeat("row ", 3000))
	writeTestFile(t, filepath.Join(volDir, "rsa_key.pem"), "-----BEGIN RSA PRIVATE KEY-----\nVAULT\n")
	writeTestFile(t, filepath.Join(volDir, "attachments", "note.txt"), "an attachment")
	app := testApp("app-vw", "vaultwarden", runNodeID, "vaultwarden")
	opts.apps = []*apps.App{app}
	opts.tiles = fakeTiles{"vaultwarden": vwTile()}
	opts.stageOutcomes = map[string]stageOutcome{"vaultwarden-data": {dir: volDir, interrupting: true, consistency: proto.BackupConsistencyCleanShutdown}}
	opts.restore = true
	h := newRunHarness(t, nil, opts)
	h.agent.registerVolume(app.ID, "vaultwarden-data", volDir)
	writeMarker(t, h, "key-1")
	// The mount verb answers with the harness's mount.
	sub, err := h.nc.Subscribe(proto.StorageMountSubject(runNodeID), func(m *nats.Msg) {
		b, _ := json.Marshal(proto.StorageMountAck{OK: true, PartUUID: runPartUUID, MountPath: h.mountDir})
		_ = m.Respond(b)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })

	c := &restoreCase{h: h, app: app, volDir: volDir, want: dirSnapshot(t, volDir)}
	jobID := h.submit(t, RunSpec{Reason: ReasonManual})
	if j := h.waitTerminal(t, jobID); j.Status != jobs.StatusSucceeded {
		t.Fatalf("backup.run: %s %s", j.Status, j.Error)
	}
	c.genID = h.run(t, jobID).GenerationID
	if c.genID == "" {
		t.Fatal("no generation")
	}
	return c
}

func (c *restoreCase) corrupt(t *testing.T) {
	t.Helper()
	writeTestFile(t, filepath.Join(c.volDir, "db.sqlite3"), "")
	if err := os.Remove(filepath.Join(c.volDir, "rsa_key.pem")); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(c.volDir, "ransom.txt"), "your files")
}

func (c *restoreCase) spec() RestoreAppSpec {
	return RestoreAppSpec{AppID: c.app.ID, PartUUID: runPartUUID, GenerationID: c.genID, KeyID: "key-1"}
}

func (c *restoreCase) restore(t *testing.T, spec RestoreAppSpec) (*jobs.Job, string) {
	t.Helper()
	jobID := c.h.submitRestore(t, spec)
	return c.h.waitTerminal(t, jobID), jobID
}

func TestRestoreAppPutsTheVolumeBackAndRecordsIt(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	c := newRestoreCase(t, runHarnessOpts{})
	c.corrupt(t)
	if fmt.Sprint(dirSnapshot(t, c.volDir)) == fmt.Sprint(c.want) {
		t.Fatal("the corruption did nothing")
	}

	j, jobID := c.restore(t, c.spec())
	if j.Status != jobs.StatusSucceeded {
		t.Fatalf("restore job %s: %s", j.Status, j.Error)
	}
	if got := dirSnapshot(t, c.volDir); fmt.Sprint(got) != fmt.Sprint(c.want) {
		t.Fatalf("the volume is not the backup:\n got  %v\n want %v", got, c.want)
	}
	calls := c.h.agent.restoreCalls()
	if len(calls) != 1 || !calls[0].ack.OK || !calls[0].ack.Replaced || !calls[0].ack.Stopped || !calls[0].ack.AppRestored {
		t.Fatalf("restore calls: %+v", calls)
	}
	if stops, starts := c.h.agent.quiesceCounts(); stops != 1 || starts != 1 {
		t.Fatalf("stops=%d starts=%d", stops, starts)
	}
	cmd := calls[0].cmd
	if cmd.AppID != c.app.ID || cmd.Volume != "vaultwarden-data" || cmd.Class != "critical" || cmd.GenerationID != c.genID || cmd.PlaintextDigest == "" || cmd.PlaintextBytes == 0 {
		t.Fatalf("command: %+v", cmd)
	}
	// The record, per volume, in the same table phase 1 writes.
	rep, err := c.h.store.LatestRestore(context.Background())
	if err != nil || rep == nil {
		t.Fatalf("LatestRestore: %v %+v", err, rep)
	}
	if rep.Phase != RestorePhaseAppVolumes || rep.JobID != jobID || rep.AppID != c.app.ID || rep.GenerationID != c.genID || rep.AppliedAt == nil {
		t.Fatalf("report: %+v", rep)
	}
	if len(rep.AppVolumes) != 1 || !rep.AppVolumes[0].Restored || rep.AppVolumes[0].Volume != "vaultwarden-data" || rep.AppVolumes[0].Node != runNodeID || rep.AppVolumes[0].PreviousKept == "" || !rep.AppVolumes[0].Stopped {
		t.Fatalf("report volumes: %+v", rep.AppVolumes)
	}
	if !strings.Contains(rep.Warning, "REPLACING") {
		t.Fatalf("warning: %q", rep.Warning)
	}
	// The session died with the job.
	if _, active := c.h.sessions.Active(); active {
		t.Fatal("the session is still open after the job ended")
	}
	// The key and the credential are nowhere: not in the ledger, not in a
	// log line, not in the record.
	ledger := c.h.ledgerText(t, jobID)
	cred := c.h.agent.credentials.get("restore:vaultwarden-data")
	if cred == "" {
		t.Fatal("the fake never saw a credential")
	}
	rj, _ := json.Marshal(rep)
	for name, text := range map[string]string{"job ledger": ledger, "log": logs.String(), "restore record": string(rj)} {
		if strings.Contains(text, c.h.key.privateB64()) || strings.Contains(text, c.h.key.privateHex()) {
			t.Fatalf("the private key reached the %s", name)
		}
		if strings.Contains(text, cred) {
			t.Fatalf("the restore credential reached the %s", name)
		}
	}
	if !strings.Contains(ledger, "REPLACED") {
		t.Fatal("the job feed did not say the data would be replaced")
	}
}

func TestRestoreAppRefusesAnAppThatIsNotInstalled(t *testing.T) {
	c := newRestoreCase(t, runHarnessOpts{})
	spec := c.spec()
	spec.AppID = "app-ghost"
	j, _ := c.restore(t, spec)
	if j.Status != jobs.StatusFailed || !strings.Contains(j.Error, "not installed") || !strings.Contains(j.Error, "install the app first") {
		t.Fatalf("job: %s %s", j.Status, j.Error)
	}
	if len(c.h.agent.restoreCalls()) != 0 {
		t.Fatal("an agent was asked")
	}
	if fmt.Sprint(dirSnapshot(t, c.volDir)) != fmt.Sprint(c.want) {
		t.Fatal("the volume changed")
	}
	if _, active := c.h.sessions.Active(); active {
		t.Fatal("the session outlived the refused job")
	}
}

func TestRestoreAppRefusesAnOfflineNodeByName(t *testing.T) {
	stale := &proto.Node{ID: runNodeID, Role: proto.RoleControlPlane, Hostname: runNodeID + ".test",
		FirstSeen: time.Now().Add(-time.Hour), LastSeen: time.Now().Add(-time.Hour), AgentVersion: "2026.08.5-dev.140"}
	c := newRestoreCase(t, runHarnessOpts{nodes: []*proto.Node{stale}})
	j, _ := c.restore(t, c.spec())
	if j.Status != jobs.StatusFailed || !strings.Contains(j.Error, "node "+runNodeID) || !strings.Contains(j.Error, "OFFLINE") || !strings.Contains(j.Error, "not queued") {
		t.Fatalf("job: %s %s", j.Status, j.Error)
	}
	if len(c.h.agent.restoreCalls()) != 0 {
		t.Fatal("an offline node was asked")
	}
}

// A key that does not belong to the disk: refused at step 1 with nothing
// stopped — and the handler refuses it even earlier, before a job exists.
func TestRestoreAppRefusesTheWrongKeyBeforeAnythingIsStopped(t *testing.T) {
	c := newRestoreCase(t, runHarnessOpts{})
	other := newTestKeypair(t)
	sid, err := c.h.sessions.Open(other.priv.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	spec := c.spec()
	spec.SessionID = sid
	body, _ := json.Marshal(spec)
	jb, err := c.h.runner.Submit(context.Background(), RestoreAppJobKind, body, "test")
	if err != nil {
		t.Fatal(err)
	}
	_ = c.h.sessions.Bind(sid, jb.ID)
	j := c.h.waitTerminal(t, jb.ID)
	if j.Status != jobs.StatusFailed || !strings.Contains(j.Error, "does not belong to this disk") {
		t.Fatalf("job: %s %s", j.Status, j.Error)
	}
	if stops, _ := c.h.agent.quiesceCounts(); len(c.h.agent.restoreCalls()) != 0 || stops != 0 {
		t.Fatal("something was stopped for a key that did not open the disk")
	}
	// And the synchronous check the handler runs says the same, with no job.
	if _, _, err := CheckRestoreCustody(context.Background(), c.h.restoreCfg, runPartUUID, "key-1", other.priv.Bytes()); !errors.Is(err, ErrRestoreKeyMismatch) {
		t.Fatalf("CheckRestoreCustody: %v", err)
	}
}

func TestRestoreAppRefusesWhileABackupRuns(t *testing.T) {
	c := newRestoreCase(t, runHarnessOpts{})
	if err := c.h.store.StartRun(context.Background(), "job-live", ReasonManual, proto.BackupScopeFull, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	j, _ := c.restore(t, c.spec())
	if j.Status != jobs.StatusFailed || !strings.Contains(j.Error, "a backup is running") {
		t.Fatalf("job: %s %s", j.Status, j.Error)
	}
	if len(c.h.agent.restoreCalls()) != 0 {
		t.Fatal("an agent was asked during a run")
	}
}

// And the other direction: a run refuses to start while a restore holds a
// session.
func TestBackupRunRefusesWhileARestoreIsActive(t *testing.T) {
	c := newRestoreCase(t, runHarnessOpts{})
	sid, err := c.h.sessions.Open(c.h.key.priv.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.h.sessions.Bind(sid, "job-restore-live")
	jobID := c.h.submit(t, RunSpec{Reason: ReasonManual})
	j := c.h.waitTerminal(t, jobID)
	if j.Status != jobs.StatusFailed || !strings.Contains(j.Error, "restore is in progress") {
		t.Fatalf("job: %s %s", j.Status, j.Error)
	}
}

// The agent refuses one volume: the volume is recorded failed with the
// agent's reason, the report is written, and the job ends failed naming it.
func TestRestoreAppRecordsAnAgentRefusalAndFails(t *testing.T) {
	c := newRestoreCase(t, runHarnessOpts{restoreOutcomes: map[string]restoreOutcome{
		"vaultwarden-data": {refusal: proto.BackupRefusalDigestMismatch, detail: "the stream is not what the manifest recorded"},
	}})
	c.corrupt(t)
	corrupted := dirSnapshot(t, c.volDir)
	j, _ := c.restore(t, c.spec())
	if j.Status != jobs.StatusFailed || !strings.Contains(j.Error, "did NOT go back") || !strings.Contains(j.Error, "vaultwarden-data") {
		t.Fatalf("job: %s %s", j.Status, j.Error)
	}
	if fmt.Sprint(dirSnapshot(t, c.volDir)) != fmt.Sprint(corrupted) {
		t.Fatal("the volume changed under a refusal")
	}
	rep, _ := c.h.store.LatestRestore(context.Background())
	if rep == nil || len(rep.AppVolumes) != 1 || rep.AppVolumes[0].Restored || !rep.AppVolumes[0].Failed || !strings.Contains(rep.AppVolumes[0].Reason, "digest-mismatch") {
		t.Fatalf("report: %+v", rep)
	}
}

// An app left down is the loudest outcome: the volumes are back, and the
// job is failed for the app.
func TestRestoreAppFailsForAnAppLeftDown(t *testing.T) {
	down := false
	c := newRestoreCase(t, runHarnessOpts{restoreOutcomes: map[string]restoreOutcome{"vaultwarden-data": {appRestored: &down}}})
	c.corrupt(t)
	j, jobID := c.restore(t, c.spec())
	if j.Status != jobs.StatusFailed || !strings.Contains(j.Error, "NOT RUNNING") {
		t.Fatalf("job: %s %s", j.Status, j.Error)
	}
	if got := dirSnapshot(t, c.volDir); fmt.Sprint(got) != fmt.Sprint(c.want) {
		t.Fatal("the volume did not go back")
	}
	if !strings.Contains(c.h.ledgerText(t, jobID), "APP LEFT DOWN") {
		t.Fatal("the job feed did not say the app is down")
	}
}

// The listing: the generation that holds the app's volume is offered, with
// the marker the browser unwraps and the facts the confirmation shows.
func TestListAppRestoreSourcesOffersTheGenerationThatHoldsTheApp(t *testing.T) {
	c := newRestoreCase(t, runHarnessOpts{})
	out, err := ListAppRestoreSources(context.Background(), c.h.restoreCfg, c.app)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Installed || out.NodeID != runNodeID || out.Marker == nil || out.Marker.WrappedByRecoveryCode != testWrappedRecovery || out.Target == nil || out.Target.PartUUID != runPartUUID {
		t.Fatalf("sources: %+v", out)
	}
	if len(out.Generations) != 1 || out.Generations[0].ID != c.genID || !out.Generations[0].Restorable || out.Generations[0].MatchedBy != "appId" {
		t.Fatalf("generations: %+v", out.Generations)
	}
	g := out.Generations[0]
	if len(g.Volumes) != 1 || g.Volumes[0].Volume != "vaultwarden-data" || !g.Volumes[0].Restorable || g.Volumes[0].SizeBytes == 0 || g.Volumes[0].CapturedFrom != runNodeID || g.AgeHuman == "" {
		t.Fatalf("volumes: %+v", g.Volumes)
	}
	if len(out.DeclaredVolumes) != 1 {
		t.Fatalf("declared: %+v", out.DeclaredVolumes)
	}
	// An app the generation does not hold is offered nothing, and says so.
	other := testApp("app-pl", "paperless", runNodeID, "paperless")
	out, err = ListAppRestoreSources(context.Background(), c.h.restoreCfg, other)
	if err != nil || len(out.Generations) != 0 || !strings.Contains(out.Problem, "no retained generation") {
		t.Fatalf("other app: %v %+v", err, out)
	}
}

// The trusted manifest is the sealed one: a sidecar edited to claim a
// member the archive does not vouch for changes nothing.
func TestRestoreAppTrustsTheSealedManifestOverTheSidecar(t *testing.T) {
	c := newRestoreCase(t, runHarnessOpts{})
	c.corrupt(t)
	side := filepath.Join(c.h.generationDir(c.genID), proto.BackupManifestFile)
	raw, _ := os.ReadFile(side) //nolint:gosec // G304: the test's own temp dir
	// The sidecar now says the volume was never captured.
	edited := strings.Replace(string(raw), `"captured": true`, `"captured": false`, 1)
	if edited == string(raw) {
		edited = strings.Replace(string(raw), `"captured":true`, `"captured":false`, 1)
	}
	if err := os.WriteFile(side, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	j, _ := c.restore(t, c.spec())
	if j.Status != jobs.StatusSucceeded {
		t.Fatalf("restore job %s: %s", j.Status, j.Error)
	}
	if got := dirSnapshot(t, c.volDir); fmt.Sprint(got) != fmt.Sprint(c.want) {
		t.Fatal("the volume did not go back")
	}
}
