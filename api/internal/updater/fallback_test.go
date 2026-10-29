package updater

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/geekdojo/rasputin-control-plane/api/internal/dbutil"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Tests for geekdojo/geekdojo-brain#894: a committed update whose node later
// registers on a different image version is relabelled fallen_back, once.

const (
	fbNode     = "cp-firewall1"
	fbTarget   = "2026.10.3"
	fbFallback = "2026.10.3-dev.168"
)

var fbNow = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

type fallbackFixture struct {
	ctx   context.Context
	store *Store
	nc    *nats.Conn
	sub   *nats.Subscription
	log   *slog.Logger
	rec   *logkittest.Recorder
	det   *FallbackDetector
}

// newFallbackFixture builds a detector over a real SQLite store and a real NATS
// server, with a subscriber on every update change subject. rows and pub
// override the real store and connection for the failure-path cases.
func newFallbackFixture(t *testing.T, rows fallbackRows, pub publisher) *fallbackFixture {
	t.Helper()
	f := &fallbackFixture{ctx: context.Background(), store: newStoreFixture(t).store, nc: startNATS(t)}
	sub, err := f.nc.SubscribeSync("rasputin.updates.>")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	f.sub = sub
	f.log, f.rec = logkittest.New()
	if rows == nil {
		rows = f.store
	}
	if pub == nil {
		pub = f.nc
	}
	det, err := NewFallbackDetector(rows, pub, f.log, func() time.Time { return fbNow })
	if err != nil {
		t.Fatalf("NewFallbackDetector: %v", err)
	}
	f.det = det
	return f
}

// seed writes a node_updates row with the given status and versions.
func (f *fallbackFixture) seed(t *testing.T, jobID string, status NodeUpdateStatus, from, to string, started time.Time) *NodeUpdate {
	t.Helper()
	u := &NodeUpdate{
		JobID: jobID, NodeID: fbNode, BundleSHA256: "sha-" + jobID,
		FromSlot: proto.SlotA, ToSlot: proto.SlotB,
		FromVersion: from, ToVersion: to,
		Status: NodeUpdateInProgress, StartedAt: started.UTC().Truncate(time.Millisecond),
	}
	if err := f.store.CreateNodeUpdate(f.ctx, u); err != nil {
		t.Fatalf("CreateNodeUpdate: %v", err)
	}
	if status != NodeUpdateInProgress {
		if err := f.store.UpdateNodeUpdate(f.ctx, jobID, status, proto.SlotB, to, "", started.Add(time.Minute)); err != nil {
			t.Fatalf("UpdateNodeUpdate: %v", err)
		}
	}
	return f.row(t, jobID)
}

func (f *fallbackFixture) row(t *testing.T, jobID string) *NodeUpdate {
	t.Helper()
	r, err := f.store.GetNodeUpdate(f.ctx, jobID)
	if err != nil || r == nil {
		t.Fatalf("GetNodeUpdate(%s) = %+v, %v", jobID, r, err)
	}
	return r
}

func (f *fallbackFixture) register(version string) {
	f.det.OnRegistered(f.ctx, &proto.Node{ID: fbNode, ImageVersion: version})
}

// published drains every change event delivered so far. Publisher and
// subscriber share one connection, so after Flush's round trip every event
// the server routed is already queued on the subscription.
func (f *fallbackFixture) published(t *testing.T) []*nats.Msg {
	t.Helper()
	if err := f.nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	var out []*nats.Msg
	for {
		m, err := f.sub.NextMsg(0)
		if err != nil {
			return out
		}
		out = append(out, m)
	}
}

func wantNothingPublished(t *testing.T, f *fallbackFixture) {
	t.Helper()
	if msgs := f.published(t); len(msgs) != 0 {
		t.Fatalf("published %d event(s), want none: first on %s", len(msgs), msgs[0].Subject)
	}
}

func wantStatus(t *testing.T, f *fallbackFixture, jobID string, want NodeUpdateStatus) *NodeUpdate {
	t.Helper()
	r := f.row(t, jobID)
	if r.Status != want {
		t.Fatalf("row %s status = %q, want %q", jobID, r.Status, want)
	}
	return r
}

func wantAttrs(t *testing.T, rec slog.Record, want map[string]string) {
	t.Helper()
	for k, v := range want {
		got, ok := logkittest.Attr(rec, k)
		if !ok {
			t.Errorf("record %q has no %s field", rec.Message, k)
			continue
		}
		if v != "" && got != v {
			t.Errorf("record %q field %s = %q, want %q", rec.Message, k, got, v)
		}
	}
}

func TestNewFallbackDetector_RequiresEveryCollaborator(t *testing.T) {
	st := newStoreFixture(t).store
	nc := startNATS(t)
	lg, _ := logkittest.New()
	now := time.Now
	cases := map[string]func() (*FallbackDetector, error){
		"rows":   func() (*FallbackDetector, error) { return NewFallbackDetector(nil, nc, lg, now) },
		"pub":    func() (*FallbackDetector, error) { return NewFallbackDetector(st, nil, lg, now) },
		"logger": func() (*FallbackDetector, error) { return NewFallbackDetector(st, nc, nil, now) },
		"clock":  func() (*FallbackDetector, error) { return NewFallbackDetector(st, nc, lg, nil) },
	}
	for name, build := range cases {
		if d, err := build(); err == nil || d != nil {
			t.Errorf("nil %s: got (%v, %v), want an error and no detector", name, d, err)
		}
	}
}

// TC-894-01: a committed update whose node registers a different version
// reads fallen_back; to_slot, to_version and finished_at are unchanged, and
// the note names both versions.
func TestFallback_FlipsCommittedRowOnMismatch(t *testing.T) {
	f := newFallbackFixture(t, nil, nil)
	before := f.seed(t, "j1", NodeUpdateCommitted, fbFallback, fbTarget, fbNow.Add(-time.Hour))

	f.register(fbFallback)

	after := wantStatus(t, f, "j1", NodeUpdateFallenBack)
	if after.ToSlot != before.ToSlot || after.ToVersion != before.ToVersion {
		t.Errorf("to_slot/to_version changed: before %s/%s, after %s/%s", before.ToSlot, before.ToVersion, after.ToSlot, after.ToVersion)
	}
	if before.FinishedAt == nil || after.FinishedAt == nil || !after.FinishedAt.Equal(*before.FinishedAt) {
		t.Errorf("finished_at changed: before %v, after %v", before.FinishedAt, after.FinishedAt)
	}
	if !strings.Contains(after.Error, fbFallback) || !strings.Contains(after.Error, fbTarget) {
		t.Errorf("note %q must name both %s and %s", after.Error, fbFallback, fbTarget)
	}
}

// TC-894-02: exactly one fallen_back event, carrying the row's identity, the
// reported version and the injected clock's time.
func TestFallback_PublishesOneEvent(t *testing.T) {
	f := newFallbackFixture(t, nil, nil)
	f.seed(t, "j1", NodeUpdateCommitted, fbFallback, fbTarget, fbNow.Add(-time.Hour))

	f.register(fbFallback)

	msgs := f.published(t)
	if len(msgs) != 1 {
		t.Fatalf("published %d events, want exactly 1", len(msgs))
	}
	if want := "rasputin.updates." + fbNode + ".fallen_back"; msgs[0].Subject != want {
		t.Errorf("subject = %q, want %q", msgs[0].Subject, want)
	}
	var ev proto.UpdateChangeEvt
	if err := json.Unmarshal(msgs[0].Data, &ev); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ev.Change != proto.UpdateFallenBack || ev.JobID != "j1" || ev.NodeID != fbNode ||
		ev.BundleID != "sha-j1" || ev.ToSlot != proto.SlotB || ev.Version != fbFallback {
		t.Errorf("event = %+v, want fallen_back for j1/%s, bundle sha-j1, to_slot b, version %s", ev, fbNode, fbFallback)
	}
	if !ev.Ts.Equal(fbNow) {
		t.Errorf("Ts = %v, want the injected clock's %v", ev.Ts, fbNow)
	}
}

// TC-894-03: a node on its committed version is never relabelled.
func TestFallback_MatchingVersionLeavesRowCommitted(t *testing.T) {
	f := newFallbackFixture(t, nil, nil)
	f.seed(t, "j1", NodeUpdateCommitted, fbFallback, fbTarget, fbNow.Add(-time.Hour))

	f.register(fbTarget)

	wantStatus(t, f, "j1", NodeUpdateCommitted)
	wantNothingPublished(t, f)
}

// TC-894-04: an unknown version is never a mismatch — an empty reported
// version, or a pre-#111 row whose to_version is its bundle SHA.
func TestFallback_UnknownIsNeverAMismatch(t *testing.T) {
	t.Run("empty reported version", func(t *testing.T) {
		f := newFallbackFixture(t, nil, nil)
		f.seed(t, "j1", NodeUpdateCommitted, fbFallback, fbTarget, fbNow.Add(-time.Hour))
		f.register("")
		wantStatus(t, f, "j1", NodeUpdateCommitted)
		wantNothingPublished(t, f)
	})
	t.Run("pre-#111 row: to_version is the bundle SHA", func(t *testing.T) {
		f := newFallbackFixture(t, nil, nil)
		// seed names the bundle "sha-<job>"; make to_version that SHA.
		f.seed(t, "j1", NodeUpdateCommitted, "", "sha-j1", fbNow.Add(-time.Hour))
		f.register(fbFallback)
		wantStatus(t, f, "j1", NodeUpdateCommitted)
		wantNothingPublished(t, f)
	})
}

// TC-894-05: while a newer update is in progress, the older committed row is
// not considered, even though the node reports something other than the newer
// row's target.
func TestFallback_MidSagaOlderCommittedRowIsNotFlipped(t *testing.T) {
	f := newFallbackFixture(t, nil, nil)
	f.seed(t, "old", NodeUpdateCommitted, "2026.10.2", fbFallback, fbNow.Add(-2*time.Hour))
	f.seed(t, "new", NodeUpdateInProgress, fbFallback, fbTarget, fbNow.Add(-time.Minute))

	f.register(fbFallback) // the pre-reboot agent, still on the older target

	wantStatus(t, f, "old", NodeUpdateCommitted)
	wantStatus(t, f, "new", NodeUpdateInProgress)
	wantNothingPublished(t, f)
}

// TC-894-06: only a committed latest row is considered.
func TestFallback_OnlyCommittedLatestRowIsConsidered(t *testing.T) {
	for _, st := range []NodeUpdateStatus{NodeUpdateRolledBack, NodeUpdateFailed, NodeUpdateFallenBack} {
		t.Run(string(st), func(t *testing.T) {
			f := newFallbackFixture(t, nil, nil)
			if st == NodeUpdateFallenBack {
				f.seed(t, "j1", NodeUpdateCommitted, fbFallback, fbTarget, fbNow.Add(-time.Hour))
				if ok, err := f.store.MarkNodeUpdateFallenBack(f.ctx, "j1", "earlier note"); err != nil || !ok {
					t.Fatalf("seed fallen_back: %v, %v", ok, err)
				}
			} else {
				f.seed(t, "j1", st, fbFallback, fbTarget, fbNow.Add(-time.Hour))
			}
			before := f.row(t, "j1")

			f.register("2026.11.0")

			after := wantStatus(t, f, "j1", st)
			if after.Error != before.Error {
				t.Errorf("note changed: %q -> %q", before.Error, after.Error)
			}
			wantNothingPublished(t, f)
		})
	}
}

// TC-894-07: a fallback onto a third version — neither from nor to — flips.
func TestFallback_ThirdVersionFlips(t *testing.T) {
	f := newFallbackFixture(t, nil, nil)
	f.seed(t, "j1", NodeUpdateCommitted, "A", "B", fbNow.Add(-time.Hour))

	f.register("C")

	wantStatus(t, f, "j1", NodeUpdateFallenBack)
	msgs := f.published(t)
	if len(msgs) != 1 {
		t.Fatalf("published %d events, want 1", len(msgs))
	}
	var ev proto.UpdateChangeEvt
	if err := json.Unmarshal(msgs[0].Data, &ev); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ev.Version != "C" {
		t.Errorf("event Version = %q, want C", ev.Version)
	}
}

// TC-894-08: the flip is one-shot. Later registrations — the same version,
// then yet another — publish nothing and leave the note byte for byte.
func TestFallback_FlipIsOneShot(t *testing.T) {
	f := newFallbackFixture(t, nil, nil)
	f.seed(t, "j1", NodeUpdateCommitted, fbFallback, fbTarget, fbNow.Add(-time.Hour))

	f.register(fbFallback)
	first := wantStatus(t, f, "j1", NodeUpdateFallenBack).Error
	f.register(fbFallback)
	f.register("2026.11.0")

	if n := len(f.published(t)); n != 1 {
		t.Errorf("published %d events across three registrations, want 1", n)
	}
	if got := f.row(t, "j1").Error; got != first {
		t.Errorf("note changed after the first flip:\n got %q\nwant %q", got, first)
	}
}

// TC-894-09: a node with no update history: nothing written, nothing
// published, nothing logged at WARN or ERROR.
func TestFallback_NoHistoryIsSilent(t *testing.T) {
	f := newFallbackFixture(t, nil, nil)

	f.register(fbFallback)

	rows, err := f.store.ListNodeUpdates(f.ctx, fbNode, 10)
	if err != nil || len(rows) != 0 {
		t.Errorf("rows = %d (%v), want none", len(rows), err)
	}
	wantNothingPublished(t, f)
	if n := len(f.rec.AtLevel(slog.LevelWarn)) + len(f.rec.AtLevel(slog.LevelError)); n != 0 {
		t.Errorf("%d WARN/ERROR records, want none: %s", n, f.rec.Text())
	}
}

// flakyRows wraps the real store and fails the named call while failRead or
// failWrite is set.
type flakyRows struct {
	*Store
	failRead, failWrite bool
}

func (r *flakyRows) LatestNodeUpdate(ctx context.Context, nodeID string) (*NodeUpdate, error) {
	if r.failRead {
		return nil, errors.New("database is locked")
	}
	return r.Store.LatestNodeUpdate(ctx, nodeID)
}

func (r *flakyRows) MarkNodeUpdateFallenBack(ctx context.Context, jobID, note string) (bool, error) {
	if r.failWrite {
		return false, errors.New("disk I/O error")
	}
	return r.Store.MarkNodeUpdateFallenBack(ctx, jobID, note)
}

// TC-894-10: a read failure logs one ERROR with node_id and err and publishes
// nothing; the next registration, with the store working, flips the row.
func TestFallback_ReadFailureThenRetry(t *testing.T) {
	rows := &flakyRows{failRead: true}
	f := newFallbackFixture(t, rows, nil)
	rows.Store = f.store
	f.seed(t, "j1", NodeUpdateCommitted, fbFallback, fbTarget, fbNow.Add(-time.Hour))

	f.register(fbFallback)

	errs := f.rec.AtLevel(slog.LevelError)
	if len(errs) != 1 {
		t.Fatalf("%d ERROR records, want 1: %s", len(errs), f.rec.Text())
	}
	wantAttrs(t, errs[0], map[string]string{"node_id": fbNode, "err": "database is locked"})
	wantNothingPublished(t, f)
	wantStatus(t, f, "j1", NodeUpdateCommitted)

	rows.failRead = false
	f.register(fbFallback)
	wantStatus(t, f, "j1", NodeUpdateFallenBack)
}

// TC-894-11: a write failure logs one ERROR with node_id, job_id and err, and
// publishes nothing.
func TestFallback_WriteFailureLogsAndPublishesNothing(t *testing.T) {
	rows := &flakyRows{failWrite: true}
	f := newFallbackFixture(t, rows, nil)
	rows.Store = f.store
	f.seed(t, "j1", NodeUpdateCommitted, fbFallback, fbTarget, fbNow.Add(-time.Hour))

	f.register(fbFallback)

	errs := f.rec.AtLevel(slog.LevelError)
	if len(errs) != 1 {
		t.Fatalf("%d ERROR records, want 1: %s", len(errs), f.rec.Text())
	}
	wantAttrs(t, errs[0], map[string]string{"node_id": fbNode, "job_id": "j1", "err": "disk I/O error"})
	wantNothingPublished(t, f)
}

type failingPublisher struct{}

func (failingPublisher) Publish(string, []byte) error { return errors.New("nats: connection closed") }

// TC-894-12 (F-894-02): a publish failure leaves the row fallen_back and logs
// one WARN through the injected logger with node_id, job_id and err.
func TestFallback_PublishFailureIsLoggedWithFields(t *testing.T) {
	f := newFallbackFixture(t, nil, failingPublisher{})
	f.seed(t, "j1", NodeUpdateCommitted, fbFallback, fbTarget, fbNow.Add(-time.Hour))

	f.register(fbFallback)

	wantStatus(t, f, "j1", NodeUpdateFallenBack)
	recs := f.rec.Matching(slog.LevelWarn, "not published")
	if len(recs) != 1 {
		t.Fatalf("%d publish-failure WARN records, want 1: %s", len(recs), f.rec.Text())
	}
	wantAttrs(t, recs[0], map[string]string{"node_id": fbNode, "job_id": "j1", "err": ""})
	if e, _ := logkittest.Attr(recs[0], "err"); !strings.Contains(e, "connection closed") {
		t.Errorf("err field = %q, want the publisher's error", e)
	}
}

// TC-894-13: the flip logs exactly one WARN with node_id, job_id,
// target_version and reported_version.
func TestFallback_FlipIsLoggedForTheOperator(t *testing.T) {
	f := newFallbackFixture(t, nil, nil)
	f.seed(t, "j1", NodeUpdateCommitted, fbFallback, fbTarget, fbNow.Add(-time.Hour))

	f.register(fbFallback)

	warns := f.rec.AtLevel(slog.LevelWarn)
	if len(warns) != 1 {
		t.Fatalf("%d WARN records, want 1: %s", len(warns), f.rec.Text())
	}
	wantAttrs(t, warns[0], map[string]string{
		"node_id": fbNode, "job_id": "j1", "target_version": fbTarget, "reported_version": fbFallback,
	})
}

// TC-894-14: the store's guarded flip changes only a committed row.
func TestStore_MarkNodeUpdateFallenBack(t *testing.T) {
	f := newFallbackFixture(t, nil, nil)
	t0 := fbNow.Add(-time.Hour)
	f.seed(t, "committed", NodeUpdateCommitted, "A", "B", t0)
	for _, st := range []NodeUpdateStatus{NodeUpdateInProgress, NodeUpdateRolledBack, NodeUpdateFailed} {
		f.seed(t, string(st), st, "A", "B", t0)
	}
	f.seed(t, "already", NodeUpdateCommitted, "A", "B", t0)
	if ok, err := f.store.MarkNodeUpdateFallenBack(f.ctx, "already", "first note"); err != nil || !ok {
		t.Fatalf("seed already-fallen-back row: %v, %v", ok, err)
	}

	ok, err := f.store.MarkNodeUpdateFallenBack(f.ctx, "committed", "the note")
	if err != nil || !ok {
		t.Fatalf("committed row: got (%v, %v), want (true, nil)", ok, err)
	}
	r := wantStatus(t, f, "committed", NodeUpdateFallenBack)
	if r.Error != "the note" {
		t.Errorf("note = %q, want %q", r.Error, "the note")
	}

	for _, id := range []string{"in_progress", "rolled_back", "failed", "already"} {
		before := f.row(t, id)
		ok, err := f.store.MarkNodeUpdateFallenBack(f.ctx, id, "should not land")
		if err != nil || ok {
			t.Errorf("%s: got (%v, %v), want (false, nil)", id, ok, err)
		}
		after := f.row(t, id)
		if after.Status != before.Status || after.Error != before.Error {
			t.Errorf("%s changed: %s/%q -> %s/%q", id, before.Status, before.Error, after.Status, after.Error)
		}
	}
	if ok, err := f.store.MarkNodeUpdateFallenBack(f.ctx, "no-such-job", "x"); err != nil || ok {
		t.Errorf("unknown job: got (%v, %v), want (false, nil)", ok, err)
	}
}

// TC-894-15 (F-894-01): the note starts with a capital, ends with a full stop,
// names both versions, and names both causes rather than asserting a fallback.
func TestFallback_NoteWording(t *testing.T) {
	f := newFallbackFixture(t, nil, nil)
	f.seed(t, "j1", NodeUpdateCommitted, fbFallback, fbTarget, fbNow.Add(-time.Hour))

	f.register(fbFallback)

	note := f.row(t, "j1").Error
	want := "After this update committed, the node started reporting version 2026.10.3-dev.168, not 2026.10.3. " +
		"It fell back to its other slot or was reinstalled."
	if note != want {
		t.Errorf("note:\n got %q\nwant %q", note, want)
	}
	if note == "" || !unicode.IsUpper([]rune(note)[0]) || !strings.HasSuffix(note, ".") {
		t.Errorf("note %q must start with a capital and end with a full stop", note)
	}
	for _, s := range []string{fbFallback, fbTarget, "fell back", "reinstalled"} {
		if !strings.Contains(note, s) {
			t.Errorf("note %q must mention %q", note, s)
		}
	}
}

// previousReleaseNodeUpdates is node_updates exactly as the release before
// #894 created it.
const previousReleaseNodeUpdates = `
CREATE TABLE node_updates (
    job_id          TEXT PRIMARY KEY,
    node_id         TEXT NOT NULL,
    bundle_sha256   TEXT NOT NULL,
    from_slot       TEXT NOT NULL DEFAULT 'unknown',
    to_slot         TEXT NOT NULL DEFAULT 'unknown',
    from_version    TEXT NOT NULL DEFAULT '',
    to_version      TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL,  -- 'in_progress' | 'committed' | 'rolled_back' | 'failed'
    started_at      INTEGER NOT NULL,
    finished_at     INTEGER,
    error           TEXT NOT NULL DEFAULT '',
    unverified_boot    INTEGER NOT NULL DEFAULT 0,
    unverified_version INTEGER NOT NULL DEFAULT 0
);`

// TC-894-18: a database written by the previous release opens with its
// node_updates table unchanged, a mismatching registration flips its committed
// row, and a matching one leaves its row committed.
func TestFallback_PreviousReleaseDatabase(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "prev.db")
	db, err := dbutil.Open(ctx, path, previousReleaseNodeUpdates, "updater-prev")
	if err != nil {
		t.Fatalf("open previous-release db: %v", err)
	}
	started := fbNow.Add(-time.Hour).UnixMilli()
	for _, r := range []struct{ job, node string }{{"fell", "fw"}, {"stayed", "c01"}} {
		if _, err := db.ExecContext(ctx, `
            INSERT INTO node_updates (job_id, node_id, bundle_sha256, to_slot, to_version, status, started_at, finished_at, error)
            VALUES (?, ?, 'sha', 'b', ?, 'committed', ?, ?, '')`,
			r.job, r.node, fbTarget, started, started+60000); err != nil {
			t.Fatalf("seed %s: %v", r.job, err)
		}
	}
	colsBefore := tableColumns(t, db)
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatalf("OpenStore on the previous release's database: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if got := tableColumns(t, s.db); strings.Join(got, ",") != strings.Join(colsBefore, ",") {
		t.Errorf("node_updates columns changed on open:\n before %v\n after  %v", colsBefore, got)
	}

	lg, _ := logkittest.New()
	det, err := NewFallbackDetector(s, startNATS(t), lg, func() time.Time { return fbNow })
	if err != nil {
		t.Fatalf("NewFallbackDetector: %v", err)
	}
	det.OnRegistered(ctx, &proto.Node{ID: "fw", ImageVersion: fbFallback})
	det.OnRegistered(ctx, &proto.Node{ID: "c01", ImageVersion: fbTarget})

	if r, _ := s.GetNodeUpdate(ctx, "fell"); r == nil || r.Status != NodeUpdateFallenBack {
		t.Errorf("fell = %+v, want fallen_back", r)
	}
	if r, _ := s.GetNodeUpdate(ctx, "stayed"); r == nil || r.Status != NodeUpdateCommitted {
		t.Errorf("stayed = %+v, want committed", r)
	}
}

func tableColumns(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), `SELECT name FROM pragma_table_info('node_updates') ORDER BY cid`)
	if err != nil {
		t.Fatalf("table_info: %v", err)
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		cols = append(cols, n)
	}
	return cols
}
