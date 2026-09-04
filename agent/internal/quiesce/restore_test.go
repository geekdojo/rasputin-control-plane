package quiesce

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// The restore verb against the fake runtime and a stand-in for the api's
// restore-stream endpoint. The tar the stand-in serves is the tar THIS
// package's own walk would have staged from the volume (writeTar), so what
// goes back is what a backup would have taken.
//
// Every case is the same question from a different angle: is the live volume
// untouched unless the whole stream arrived, verified and swapped — and is
// the app running afterwards whatever happened?

const (
	rsGen    = "20260904T041601Z-1WF3849B-full"
	rsMember = "volumes/vaultwarden/vaultwarden-data.rasputin-archive"
	rsCred   = "rbx1.RESTORE-CREDENTIAL-NEVER-IN-A-LOG-LINE.sig"
)

// egress is the stand-in source: it serves `tar` for the member, on the
// credential, and lets a case interfere with the stream.
type egress struct {
	srv   *httptest.Server
	tar   []byte
	mu    sync.Mutex
	auth  []string
	paths []string
	// cutAt, when > 0, ends the response after that many body bytes as if
	// the source went away. refuse, when set, answers with that problem.
	cutAt  int
	refuse *backupxfer.Problem
	status int
}

func newEgress(t *testing.T, tarBytes []byte) *egress {
	t.Helper()
	e := &egress{tar: tarBytes, status: http.StatusConflict}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+backupxfer.EgressPathPrefix, func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.auth = append(e.auth, r.Header.Get("Authorization"))
		e.paths = append(e.paths, r.URL.Path)
		refuse, cutAt, status, body := e.refuse, e.cutAt, e.status, e.tar
		e.mu.Unlock()
		if refuse != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = fmt.Fprintf(w, `{"code":%q,"detail":%q}`, refuse.Code, refuse.Detail)
			return
		}
		sum := sha256.Sum256(body)
		w.Header().Set("Content-Type", backupxfer.EgressContentType)
		w.Header().Set(backupxfer.HeaderPlaintextDigest, hex.EncodeToString(sum[:]))
		w.Header().Set(backupxfer.HeaderPlaintextBytes, strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		if cutAt > 0 && cutAt < len(body) {
			_, _ = w.Write(body[:cutAt])
			http.NewResponseController(w).Flush()
			// The source dies: the connection is torn down mid-body.
			panic(http.ErrAbortHandler)
		}
		_, _ = w.Write(body)
	})
	e.srv = httptest.NewServer(mux)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *egress) source(t *testing.T) string {
	t.Helper()
	src, err := backupxfer.EgressDestination(e.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return src
}

func (e *egress) requests() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.paths)
}

// restoreRig is one app, one volume, one source.
type restoreRig struct {
	rt      *fakeRuntime
	s       *Stager
	e       *egress
	volRoot string
	logs    *bytes.Buffer
	// backup is the tar as the stage verb would have written it, taken from
	// the volume BEFORE the case mutates it.
	backup []byte
	digest string
}

// newRestoreRig deploys a running app whose volume holds fixtureVolume,
// takes the backup tar of it with the package's own walk, then lets the
// case corrupt the live volume before restoring.
func newRestoreRig(t *testing.T) *restoreRig {
	t.Helper()
	rt := newFake(t)
	volRoot := rt.volDir("vw", "vaultwarden-data")
	if err := os.MkdirAll(volRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	writeVolFile(t, filepath.Join(volRoot, "db.sqlite3"), "SQLite format 3\x00 ORIGINAL ROWS")
	writeVolFile(t, filepath.Join(volRoot, "rsa_key.pem"), "-----BEGIN RSA PRIVATE KEY-----\nORIGINAL\n")
	if err := os.MkdirAll(filepath.Join(volRoot, "attachments", "2026"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeVolFile(t, filepath.Join(volRoot, "attachments", "2026", "cat.jpg"), strings.Repeat("J", 70000))
	rt.running["vw"] = true

	tarPath := filepath.Join(t.TempDir(), "staged.tar")
	if _, err := writeTar(context.Background(), volRoot, tarPath, nil, nil, nil); err != nil {
		t.Fatalf("writeTar: %v", err)
	}
	backup, err := os.ReadFile(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(backup)

	var logs bytes.Buffer
	var lmu sync.Mutex
	s := newStager(t, rt)
	s.logf = func(format string, args ...any) {
		lmu.Lock()
		defer lmu.Unlock()
		fmt.Fprintf(&logs, format+"\n", args...)
	}
	s.SetRestoreRecordDir(filepath.Join(t.TempDir(), "restore-staging"))
	e := newEgress(t, backup)
	return &restoreRig{rt: rt, s: s, e: e, volRoot: volRoot, logs: &logs, backup: backup, digest: hex.EncodeToString(sum[:])}
}

func writeVolFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// corrupt is what a case does to the live volume before restoring: the
// database is emptied, the key is gone, a stray file appears.
func (r *restoreRig) corrupt(t *testing.T) {
	t.Helper()
	writeVolFile(t, filepath.Join(r.volRoot, "db.sqlite3"), "")
	if err := os.Remove(filepath.Join(r.volRoot, "rsa_key.pem")); err != nil {
		t.Fatal(err)
	}
	writeVolFile(t, filepath.Join(r.volRoot, "ransom.txt"), "your files")
}

func (r *restoreRig) cmd(t *testing.T) proto.BackupRestoreVolumeCmd {
	t.Helper()
	return proto.BackupRestoreVolumeCmd{
		AppID: "vw", AppName: "vaultwarden", Volume: "vaultwarden-data", Class: tileschema.BackupCritical,
		Source: r.e.source(t), Credential: rsCred, GenerationID: rsGen, Member: rsMember, RestoreID: "rs-1",
		PlaintextDigest: r.digest, PlaintextBytes: uint64(len(r.backup)), FileCount: 3,
	}
}

// snapshot reads every regular file beneath the live volume.
func (r *restoreRig) snapshot(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(r.volRoot, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			b, rerr := os.ReadFile(p) //nolint:gosec // G304: test walks its own temp dir
			if rerr != nil {
				return rerr
			}
			rel, _ := filepath.Rel(r.volRoot, p)
			out[filepath.ToSlash(rel)] = string(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// beside lists the entries beside the volume with the given prefix.
func (r *restoreRig) beside(t *testing.T, prefix string) []string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Dir(r.volRoot))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), prefix) {
			out = append(out, e.Name())
		}
	}
	return out
}

func (r *restoreRig) records(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir(r.s.restoreRecordDir)
	if err != nil {
		return 0
	}
	return len(ents)
}

func (r *restoreRig) assertUntouched(t *testing.T, want map[string]string, ack *proto.BackupRestoreVolumeAck) {
	t.Helper()
	got := r.snapshot(t)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("the live volume changed:\n got  %v\n want %v", got, want)
	}
	if ack.Replaced {
		t.Fatal("the ack claims the volume was replaced")
	}
	if n := r.beside(t, restoreStagingPrefix); len(n) != 0 {
		t.Fatalf("staging left beside the volume: %v", n)
	}
	if r.records(t) != 0 {
		t.Fatal("a staging record was left behind")
	}
	if !r.rt.isRunning("vw") || !ack.AppRestored {
		t.Fatalf("the app is not running afterwards (running=%v ack.AppRestored=%v)", r.rt.isRunning("vw"), ack.AppRestored)
	}
}

func (r *restoreRig) assertNoSecretInLogs(t *testing.T, ack *proto.BackupRestoreVolumeAck) {
	t.Helper()
	if strings.Contains(r.logs.String(), rsCred) || strings.Contains(ack.Detail, rsCred) {
		t.Fatal("the restore credential reached a log line or the ack")
	}
}

func TestRestoreVolumePutsTheBackupBackAtomically(t *testing.T) {
	r := newRestoreRig(t)
	want := r.snapshot(t)
	r.corrupt(t)
	if got := r.snapshot(t); fmt.Sprint(got) == fmt.Sprint(want) {
		t.Fatal("the corruption did nothing; the test proves nothing")
	}

	ack := r.s.RestoreVolume(context.Background(), r.cmd(t))
	if !ack.OK || !ack.Replaced {
		t.Fatalf("ack: %+v", ack)
	}
	if got := r.snapshot(t); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("the restored volume is not the backup:\n got  %v\n want %v", got, want)
	}
	if ack.FileCount != 3 || ack.DirCount != 2 || ack.ReceivedBytes != uint64(len(r.backup)) || ack.Digest != r.digest {
		t.Fatalf("counts: %+v", ack)
	}
	// The app was stopped once, started once, and is running; the outage is
	// bracketed and measured.
	stops, starts := r.rt.counts()
	if stops != 1 || starts != 1 || !r.rt.isRunning("vw") {
		t.Fatalf("stops=%d starts=%d running=%v", stops, starts, r.rt.isRunning("vw"))
	}
	if !ack.WasRunning || !ack.Stopped || !ack.AppRestored || ack.RestoredBy != "driver" || ack.RestartedAt.Before(ack.StoppedAt) || ack.DowntimeMillis < 0 {
		t.Fatalf("restart facts: %+v", ack)
	}
	// The previous contents are beside the volume, complete, never deleted;
	// the staging name is gone; the record is gone.
	kept := r.beside(t, restoreReplacedPrefix)
	if len(kept) != 1 || ack.PreviousKept != filepath.Join(filepath.Dir(r.volRoot), kept[0]) {
		t.Fatalf("previous contents: beside=%v ack=%q", kept, ack.PreviousKept)
	}
	if b, err := os.ReadFile(filepath.Join(ack.PreviousKept, "ransom.txt")); err != nil || string(b) != "your files" {
		t.Fatalf("the previous contents are not intact under %s: %q %v", ack.PreviousKept, b, err)
	}
	if n := r.beside(t, restoreStagingPrefix); len(n) != 0 || r.records(t) != 0 {
		t.Fatalf("staging left: %v records=%d", n, r.records(t))
	}
	// The volume root kept its own mode.
	if st, err := os.Stat(r.volRoot); err != nil || st.Mode().Perm() != 0o750 {
		t.Fatalf("volume root mode %v %v", st, err)
	}
	// The source saw exactly one fetch, on the credential, at the member.
	if r.e.requests() != 1 || r.e.auth[0] != "Bearer "+rsCred || !strings.HasSuffix(r.e.paths[0], rsGen+"/"+rsMember) {
		t.Fatalf("source saw %v %v", r.e.auth, r.e.paths)
	}
	r.assertNoSecretInLogs(t, ack)
	if !strings.Contains(r.logs.String(), "STOPPING app vw") {
		t.Fatal("the stop was not said out loud")
	}
}

// A second restore keeps only the newest previous copy.
func TestRestoreVolumeKeepsOnePreviousCopy(t *testing.T) {
	r := newRestoreRig(t)
	for i := 0; i < 2; i++ {
		r.corrupt(t)
		if ack := r.s.RestoreVolume(context.Background(), r.cmd(t)); !ack.OK {
			t.Fatalf("restore %d: %+v", i, ack)
		}
		time.Sleep(1100 * time.Millisecond) // the kept name carries a second-resolution timestamp
	}
	if kept := r.beside(t, restoreReplacedPrefix); len(kept) != 1 {
		t.Fatalf("kept copies: %v", kept)
	}
}

// An app that was not running is not started: restoring service means
// restoring the state the app was found in.
func TestRestoreVolumeLeavesAStoppedAppStopped(t *testing.T) {
	r := newRestoreRig(t)
	want := r.snapshot(t)
	r.corrupt(t)
	r.rt.running["vw"] = false
	ack := r.s.RestoreVolume(context.Background(), r.cmd(t))
	if !ack.OK || !ack.Replaced || ack.WasRunning || ack.Stopped {
		t.Fatalf("ack: %+v", ack)
	}
	if stops, starts := r.rt.counts(); stops != 0 || starts != 0 || r.rt.isRunning("vw") {
		t.Fatalf("stops=%d starts=%d running=%v", stops, starts, r.rt.isRunning("vw"))
	}
	if got := r.snapshot(t); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("restored: %v", got)
	}
}

func TestRestoreVolumeRefusesAnAppNotDeployedHere(t *testing.T) {
	r := newRestoreRig(t)
	want := r.snapshot(t)
	cmd := r.cmd(t)
	cmd.AppID = "not-installed"
	ack := r.s.RestoreVolume(context.Background(), cmd)
	if ack.OK || ack.Refusal != proto.BackupRefusalVolumeNotFound || !strings.Contains(ack.Detail, "install it first") {
		t.Fatalf("ack: %+v", ack)
	}
	if r.e.requests() != 0 {
		t.Fatal("the source was asked for a volume of an app that is not here")
	}
	if stops, _ := r.rt.counts(); stops != 0 {
		t.Fatal("an app was stopped")
	}
	r.assertUntouched(t, want, ack)
}

func TestRestoreVolumeRefusesCacheAndBulkBeforeFetching(t *testing.T) {
	r := newRestoreRig(t)
	want := r.snapshot(t)
	for _, class := range []string{tileschema.BackupCache, tileschema.BackupBulk} {
		cmd := r.cmd(t)
		cmd.Class = class
		ack := r.s.RestoreVolume(context.Background(), cmd)
		if ack.OK || ack.Refusal != proto.BackupRefusalClassNotRestored || !strings.Contains(ack.Detail, class) {
			t.Fatalf("%s: %+v", class, ack)
		}
	}
	if r.e.requests() != 0 {
		t.Fatal("the source was asked")
	}
	r.assertUntouched(t, want, r.s.RestoreVolume(context.Background(), func() proto.BackupRestoreVolumeCmd { c := r.cmd(t); c.Class = "cache"; return c }()))
}

func TestRestoreVolumeRefusesByShapeBeforeTouchingAnything(t *testing.T) {
	r := newRestoreRig(t)
	want := r.snapshot(t)
	edits := map[string]func(c *proto.BackupRestoreVolumeCmd){
		"no credential":      func(c *proto.BackupRestoreVolumeCmd) { c.Credential = "" },
		"no digest":          func(c *proto.BackupRestoreVolumeCmd) { c.PlaintextDigest = "" },
		"short digest":       func(c *proto.BackupRestoreVolumeCmd) { c.PlaintextDigest = "abcd" },
		"zero length":        func(c *proto.BackupRestoreVolumeCmd) { c.PlaintextBytes = 0 },
		"bad member":         func(c *proto.BackupRestoreVolumeCmd) { c.Member = "../../etc/passwd" },
		"bad generation":     func(c *proto.BackupRestoreVolumeCmd) { c.GenerationID = "gen/../x" },
		"no source":          func(c *proto.BackupRestoreVolumeCmd) { c.Source = "" },
		"unknown class":      func(c *proto.BackupRestoreVolumeCmd) { c.Class = "precious" },
		"no app":             func(c *proto.BackupRestoreVolumeCmd) { c.AppID = "" },
		"unsupported scheme": func(c *proto.BackupRestoreVolumeCmd) { c.Source = "s3://bucket/x" },
	}
	for name, edit := range edits {
		cmd := r.cmd(t)
		edit(&cmd)
		ack := r.s.RestoreVolume(context.Background(), cmd)
		if ack.OK || ack.Refusal == "" {
			t.Fatalf("%s: accepted: %+v", name, ack)
		}
		r.assertUntouched(t, want, ack)
		r.assertNoSecretInLogs(t, ack)
	}
	if r.e.requests() != 0 {
		t.Fatal("a malformed command reached the source")
	}
	if stops, _ := r.rt.counts(); stops != 0 {
		t.Fatal("an app was stopped")
	}
	// No record directory configured: refused, nothing staged.
	r.s.restoreRecordDir = ""
	if ack := r.s.RestoreVolume(context.Background(), r.cmd(t)); ack.OK || !strings.Contains(ack.Detail, "record directory") {
		t.Fatalf("no record dir: %+v", ack)
	}
}

// The stream's bytes are not the manifest's: refused, and the app was never
// stopped — the check runs before the stop.
func TestRestoreVolumeRefusesADigestTheManifestDoesNotVouchFor(t *testing.T) {
	r := newRestoreRig(t)
	r.corrupt(t)
	want := r.snapshot(t)
	cmd := r.cmd(t)
	cmd.PlaintextDigest = strings.Repeat("0", 64)
	ack := r.s.RestoreVolume(context.Background(), cmd)
	if ack.OK || ack.Refusal != proto.BackupRefusalDigestMismatch || !strings.Contains(ack.Detail, "not touched") {
		t.Fatalf("ack: %+v", ack)
	}
	if stops, _ := r.rt.counts(); stops != 0 || ack.Stopped {
		t.Fatal("the app was stopped for a stream that did not verify")
	}
	r.assertUntouched(t, want, ack)

	// A length that disagrees is refused the same way, before a byte of the
	// body is read.
	cmd = r.cmd(t)
	cmd.PlaintextBytes = uint64(len(r.backup)) + 7
	ack = r.s.RestoreVolume(context.Background(), cmd)
	if ack.OK || ack.Refusal != proto.BackupRefusalDigestMismatch {
		t.Fatalf("length: %+v", ack)
	}
	r.assertUntouched(t, want, ack)
}

// The source goes away mid-stream: the live volume is untouched, the staging
// tree is gone, the app was never stopped.
func TestRestoreVolumeMidTransferDisconnectLeavesTheVolumeUntouched(t *testing.T) {
	r := newRestoreRig(t)
	r.corrupt(t)
	want := r.snapshot(t)
	r.e.cutAt = len(r.backup) / 2
	ack := r.s.RestoreVolume(context.Background(), r.cmd(t))
	if ack.OK || ack.Refusal != proto.BackupRefusalTransferFailed {
		t.Fatalf("ack: %+v", ack)
	}
	if stops, _ := r.rt.counts(); stops != 0 || ack.Stopped {
		t.Fatal("the app was stopped for a stream that never finished")
	}
	r.assertUntouched(t, want, ack)
	r.assertNoSecretInLogs(t, ack)
}

func TestRestoreVolumeCarriesTheSourcesRefusal(t *testing.T) {
	r := newRestoreRig(t)
	want := r.snapshot(t)
	r.e.refuse = &backupxfer.Problem{Code: backupxfer.CodeCredentialExpired, Detail: "expired"}
	r.e.status = http.StatusUnauthorized
	ack := r.s.RestoreVolume(context.Background(), r.cmd(t))
	if ack.OK || ack.Refusal != proto.BackupRefusalSourceRefused || ack.SourceCode != backupxfer.CodeCredentialExpired {
		t.Fatalf("ack: %+v", ack)
	}
	r.assertUntouched(t, want, ack)
	r.assertNoSecretInLogs(t, ack)
}

// A tar carrying a symlink — the stager archives a volume's own symlinks as
// symlinks — is refused whole rather than recreated without it.
func TestRestoreVolumeRefusesATarWithASymlink(t *testing.T) {
	r := newRestoreRig(t)
	if err := os.Symlink("/etc/shadow", filepath.Join(r.volRoot, "planted")); err != nil {
		t.Fatal(err)
	}
	tarPath := filepath.Join(t.TempDir(), "with-link.tar")
	if _, err := writeTar(context.Background(), r.volRoot, tarPath, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	withLink, _ := os.ReadFile(tarPath)
	_ = os.Remove(filepath.Join(r.volRoot, "planted"))
	want := r.snapshot(t)
	sum := sha256.Sum256(withLink)
	r.e.tar = withLink
	cmd := r.cmd(t)
	cmd.PlaintextDigest, cmd.PlaintextBytes = hex.EncodeToString(sum[:]), uint64(len(withLink))
	ack := r.s.RestoreVolume(context.Background(), cmd)
	if ack.OK || ack.Refusal != proto.BackupRefusalArchiveInvalid || !strings.Contains(ack.Detail, "planted") || !strings.Contains(ack.Detail, "symlink") {
		t.Fatalf("ack: %+v", ack)
	}
	r.assertUntouched(t, want, ack)
}

// A stop that fails leaves the volume untouched and the app running — there
// is nothing to restart, because nothing was stopped.
func TestRestoreVolumeStopFailureTouchesNothing(t *testing.T) {
	r := newRestoreRig(t)
	r.corrupt(t)
	want := r.snapshot(t)
	r.rt.stopErr = errors.New("injected: the daemon is busy")
	ack := r.s.RestoreVolume(context.Background(), r.cmd(t))
	if ack.OK || ack.Refusal != proto.BackupRefusalQuiesceFailed || !ack.Stopped || !ack.AppRestored {
		t.Fatalf("ack: %+v", ack)
	}
	r.assertUntouched(t, want, ack)
	if r.beside(t, restoreReplacedPrefix) != nil {
		t.Fatal("something was moved aside for a swap that never happened")
	}
}

// The exchange fails with the app stopped: the live volume is as it was, the
// staged tree is removed, and the guard restarted the app.
func TestRestoreVolumeSwapFailureLeavesTheVolumeAndRestartsTheApp(t *testing.T) {
	r := newRestoreRig(t)
	r.corrupt(t)
	want := r.snapshot(t)
	r.s.swapFn = func(live, staging string) error { return errors.New("injected: EXDEV") }
	ack := r.s.RestoreVolume(context.Background(), r.cmd(t))
	if ack.OK || ack.Refusal != proto.BackupRefusalSwapFailed || !ack.Stopped {
		t.Fatalf("ack: %+v", ack)
	}
	if stops, starts := r.rt.counts(); stops != 1 || starts != 1 {
		t.Fatalf("stops=%d starts=%d", stops, starts)
	}
	r.assertUntouched(t, want, ack)
	if r.beside(t, restoreReplacedPrefix) != nil {
		t.Fatal("something was moved aside for a swap that failed")
	}
}

// The restart fails twice and succeeds on the third try: the ack reports the
// app restored, by the driver, after retries — and the swap stands.
func TestRestoreVolumeGuardRetriesTheRestart(t *testing.T) {
	r := newRestoreRig(t)
	want := r.snapshot(t)
	r.corrupt(t)
	r.rt.startFail = 2
	ack := r.s.RestoreVolume(context.Background(), r.cmd(t))
	if !ack.OK || !ack.Replaced || !ack.AppRestored || ack.RestoredBy != "driver" || !strings.Contains(ack.RestoreDetail, "attempt 3") {
		t.Fatalf("ack: %+v", ack)
	}
	if got := r.snapshot(t); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("restored: %v", got)
	}
	if !r.rt.isRunning("vw") {
		t.Fatal("the app is not running")
	}
}

// The restart never succeeds inside the ack's wait: the ack says so —
// AppRestored false is the alert — and the marker survives for the boot
// sweep, which then starts it.
func TestRestoreVolumeAppLeftDownIsSaidAndSweptLater(t *testing.T) {
	r := newRestoreRig(t)
	r.corrupt(t)
	r.rt.startFail = 100
	r.s.releaseWait = 200 * time.Millisecond
	ack := r.s.RestoreVolume(context.Background(), r.cmd(t))
	if !ack.OK || !ack.Replaced || ack.AppRestored {
		t.Fatalf("ack: %+v", ack)
	}
	markers, _ := os.ReadDir(r.s.markerDir)
	if len(markers) != 1 {
		t.Fatalf("markers: %v", markers)
	}
	r.rt.mu.Lock()
	r.rt.startFail = 0
	r.rt.mu.Unlock()
	// Let the background retries wind down before the sweep re-enters.
	time.Sleep(100 * time.Millisecond)
	if n := r.s.SweepArmedStops(); n != 1 && !r.rt.isRunning("vw") {
		t.Fatalf("sweep=%d running=%v", n, r.rt.isRunning("vw"))
	}
	deadline := time.Now().Add(2 * time.Second)
	for !r.rt.isRunning("vw") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !r.rt.isRunning("vw") {
		t.Fatal("the app never came back")
	}
}

// A staging tree a dying process left beside a volume is swept at the next
// start through its record; a kept previous copy is not.
func TestSweepRestoreStagingRemovesOnlyRecordedStagingTrees(t *testing.T) {
	r := newRestoreRig(t)
	parent := filepath.Dir(r.volRoot)
	stale := filepath.Join(parent, restoreStagingPrefix+"vaultwarden-data-deadbeef")
	kept := filepath.Join(parent, restoreReplacedPrefix+"vaultwarden-data-20260904T000000Z")
	for _, d := range []string{stale, kept} {
		if err := os.MkdirAll(filepath.Join(d, "x"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.s.writeRestoreRecord(restoreRecord{Staging: stale, AppID: "vw", Volume: "vaultwarden-data"}); err != nil {
		t.Fatal(err)
	}
	// A record naming something that is not a staging tree by name is left
	// alone, and so is what it names.
	if _, err := r.s.writeRestoreRecord(restoreRecord{Staging: kept}); err != nil {
		t.Fatal(err)
	}
	if n := r.s.SweepRestoreStaging(); n != 1 {
		t.Fatalf("swept %d", n)
	}
	if _, err := os.Lstat(stale); err == nil {
		t.Fatal("the stale staging tree survived")
	}
	if _, err := os.Lstat(kept); err != nil {
		t.Fatal("the kept previous copy was removed")
	}
	if r.records(t) != 1 {
		t.Fatalf("records left: %d", r.records(t))
	}
}

// A stale staging tree beside the volume from a run nobody recorded is
// removed before this run sizes itself — and nothing else beside it is.
func TestRestoreVolumeRemovesAStaleStagingTreeFirst(t *testing.T) {
	r := newRestoreRig(t)
	parent := filepath.Dir(r.volRoot)
	stale := filepath.Join(parent, restoreStagingPrefix+"vaultwarden-data-00000000")
	other := filepath.Join(parent, "other-volume")
	for _, d := range []string{stale, other} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	r.corrupt(t)
	if ack := r.s.RestoreVolume(context.Background(), r.cmd(t)); !ack.OK {
		t.Fatalf("ack: %+v", ack)
	}
	if _, err := os.Lstat(stale); err == nil {
		t.Fatal("the stale staging tree survived")
	}
	if _, err := os.Lstat(other); err != nil {
		t.Fatal("a sibling volume was removed")
	}
}

// Not enough room beside the volume: refused before a byte is fetched.
func TestRestoreVolumeRefusesWithoutRoomBesideTheVolume(t *testing.T) {
	r := newRestoreRig(t)
	want := r.snapshot(t)
	r.s.freeBytes = func(string) (uint64, error) { return 1 << 20, nil }
	ack := r.s.RestoreVolume(context.Background(), r.cmd(t))
	if ack.OK || ack.Refusal != proto.BackupRefusalInsufficientSpace || !strings.Contains(ack.Detail, "not stopped") {
		t.Fatalf("ack: %+v", ack)
	}
	if r.e.requests() != 0 {
		t.Fatal("the source was asked")
	}
	r.assertUntouched(t, want, ack)
}

// The stream is a tar, verified, but the fetch's reader is cut exactly at a
// member boundary by the limit — an over-long stream is refused by count.
func TestRestoreVolumeRefusesAnOverLongStream(t *testing.T) {
	r := newRestoreRig(t)
	want := r.snapshot(t)
	longer := append(append([]byte{}, r.backup...), make([]byte, 512)...)
	sum := sha256.Sum256(longer)
	r.e.tar = longer
	cmd := r.cmd(t)
	// The command carries the manifest's numbers for the SHORTER tar; the
	// source serves more.
	cmd.PlaintextDigest = hex.EncodeToString(sum[:])
	ack := r.s.RestoreVolume(context.Background(), cmd)
	if ack.OK || ack.Refusal != proto.BackupRefusalDigestMismatch {
		t.Fatalf("ack: %+v", ack)
	}
	r.assertUntouched(t, want, ack)
	_ = io.EOF
}
