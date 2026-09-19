package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// changeRecorder collects the AlertChangeEvts the service publishes.
type changeRecorder struct {
	mu       sync.Mutex
	evs      []proto.AlertChangeEvt
	sentinel chan struct{}
	nc       *nats.Conn
}

const sentinelChange proto.AlertChangeType = "test-sentinel"

// changes returns every event published so far. It publishes a sentinel on
// the same connection and waits for it: NATS delivers one publisher's
// messages to a subscription in order, so once the sentinel arrives every
// earlier event has too.
func (r *changeRecorder) changes(t *testing.T) []proto.AlertChangeType {
	t.Helper()
	body, _ := json.Marshal(proto.AlertChangeEvt{Change: sentinelChange})
	if err := r.nc.Publish(proto.AlertsChangesSubject, body); err != nil {
		t.Fatalf("publish sentinel: %v", err)
	}
	select {
	case <-r.sentinel:
	case <-time.After(5 * time.Second):
		t.Fatal("sentinel never delivered")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]proto.AlertChangeType, 0, len(r.evs))
	for _, e := range r.evs {
		out = append(out, e.Change)
	}
	return out
}

func embeddedNATS(t *testing.T) (*nats.Conn, *changeRecorder) {
	t.Helper()
	ns, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatalf("nats server: %v", err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(2 * time.Second) {
		t.Fatal("nats not ready")
	}
	t.Cleanup(func() { ns.Shutdown(); ns.WaitForShutdown() })
	nc, err := nats.Connect("", nats.InProcessServer(ns))
	if err != nil {
		t.Fatalf("nats connect: %v", err)
	}
	t.Cleanup(nc.Close)
	rec := &changeRecorder{nc: nc, sentinel: make(chan struct{}, 16)}
	if _, err := nc.Subscribe(proto.AlertsChangesSubject, func(m *nats.Msg) {
		var ev proto.AlertChangeEvt
		if err := json.Unmarshal(m.Data, &ev); err != nil {
			return
		}
		if ev.Change == sentinelChange {
			rec.sentinel <- struct{}{}
			return
		}
		rec.mu.Lock()
		rec.evs = append(rec.evs, ev)
		rec.mu.Unlock()
	}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	return nc, rec
}

func highCPU(node string) FiringRule {
	return FiringRule{
		Labels: map[string]string{
			"alertname":  "HighCPU",
			"alertgroup": "rasputin-default",
			"severity":   "warning",
			"source":     "vmalert",
			"nodeId":     node,
		},
		ActiveAt: time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC),
		Summary:  "Sustained CPU > 90% on " + node,
	}
}

func newSyncService(t *testing.T) (*Service, *Store, *changeRecorder, *time.Time) {
	t.Helper()
	store := openTestStore(t)
	nc, rec := embeddedNATS(t)
	svc := New(nil, nil, nil, nil, store, nc, false)
	now := time.Date(2026, 9, 19, 12, 10, 0, 0, time.UTC)
	svc.SetNow(func() time.Time { return now })
	return svc, store, rec, &now
}

func TestSyncRuleAlerts_FiringAlertPersistsAndSurfaces(t *testing.T) {
	ctx := context.Background()
	svc, _, rec, _ := newSyncService(t)

	if err := svc.SyncRuleAlerts(ctx, []FiringRule{highCPU("node-dev")}); err != nil {
		t.Fatalf("SyncRuleAlerts: %v", err)
	}
	alerts, err := svc.ruleAlerts(ctx)
	if err != nil {
		t.Fatalf("ruleAlerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("ruleAlerts returned %d, want 1", len(alerts))
	}
	a := alerts[0]
	if a.Title != "HighCPU" || a.Source != proto.AlertSourceRule || a.Severity != proto.AlertWarn {
		t.Errorf("alert = %+v, want HighCPU / rule / warn", a)
	}
	if a.Detail != "Sustained CPU > 90% on node-dev" {
		t.Errorf("detail = %q", a.Detail)
	}
	if a.RelatedKind != "node" || a.RelatedID != "node-dev" {
		t.Errorf("related = %s/%s, want node/node-dev", a.RelatedKind, a.RelatedID)
	}
	if !a.Since.Equal(highCPU("").ActiveAt) {
		t.Errorf("since = %v, want the alert's activation time %v", a.Since, highCPU("").ActiveAt)
	}
	if got := rec.changes(t); len(got) != 1 || got[0] != proto.AlertFired {
		t.Errorf("published %v, want one fired", got)
	}
}

func TestSyncRuleAlerts_CriticalSeverityMappedToCrit(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := newSyncService(t)
	f := highCPU("n1")
	f.Labels["alertname"] = "NodeDown"
	f.Labels["severity"] = "critical"
	if err := svc.SyncRuleAlerts(ctx, []FiringRule{f}); err != nil {
		t.Fatal(err)
	}
	alerts, _ := svc.ruleAlerts(ctx)
	if len(alerts) != 1 || alerts[0].Severity != proto.AlertCrit {
		t.Fatalf("got %+v, want one crit alert", alerts)
	}
}

// Every tick re-reads the same firing set; a continuing alert must neither
// duplicate, re-announce, nor be rewritten.
func TestSyncRuleAlerts_ContinuingAlertIsNotRewritten(t *testing.T) {
	ctx := context.Background()
	svc, store, rec, now := newSyncService(t)
	set := []FiringRule{highCPU("n1")}
	if err := svc.SyncRuleAlerts(ctx, set); err != nil {
		t.Fatal(err)
	}
	first, _ := store.ListFiring(ctx)
	*now = now.Add(30 * time.Second)
	time.Sleep(5 * time.Millisecond) // Upsert stamps updated_at from the wall clock
	if err := svc.SyncRuleAlerts(ctx, set); err != nil {
		t.Fatal(err)
	}
	second, _ := store.ListFiring(ctx)
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("rows = %d then %d, want 1 and 1", len(first), len(second))
	}
	if !second[0].UpdatedAt.Equal(first[0].UpdatedAt) {
		t.Errorf("unchanged alert was rewritten (updated_at %v -> %v)", first[0].UpdatedAt, second[0].UpdatedAt)
	}
	if got := rec.changes(t); len(got) != 1 {
		t.Errorf("published %v, want exactly one fired", got)
	}
}

func TestSyncRuleAlerts_AbsentAlertResolves(t *testing.T) {
	ctx := context.Background()
	svc, store, rec, now := newSyncService(t)
	if err := svc.SyncRuleAlerts(ctx, []FiringRule{highCPU("n1"), highCPU("n2")}); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Minute)
	if err := svc.SyncRuleAlerts(ctx, []FiringRule{highCPU("n2")}); err != nil {
		t.Fatal(err)
	}
	firing, _ := store.ListFiring(ctx)
	if len(firing) != 1 || firing[0].Labels["nodeId"] != "n2" {
		t.Fatalf("still firing = %+v, want only n2", firing)
	}
	resolved, _ := store.Get(ctx, "rule:"+fingerprintFromLabels(highCPU("n1").Labels))
	if resolved == nil || resolved.Status != "resolved" || resolved.EndsAt == nil || !resolved.EndsAt.Equal(*now) {
		t.Fatalf("n1 row = %+v, want resolved at %v", resolved, *now)
	}
	alerts, _ := svc.ruleAlerts(ctx)
	if len(alerts) != 1 {
		t.Errorf("live rule alerts = %d, want 1 (a resolved, unacked alert drops out)", len(alerts))
	}
	want := []proto.AlertChangeType{proto.AlertFired, proto.AlertFired, proto.AlertResolved}
	if got := rec.changes(t); len(got) != 3 || got[2] != want[2] {
		t.Errorf("published %v, want %v", got, want)
	}

	// Firing again after resolving re-opens the same row and re-announces it.
	if err := svc.SyncRuleAlerts(ctx, []FiringRule{highCPU("n1"), highCPU("n2")}); err != nil {
		t.Fatal(err)
	}
	again, _ := store.Get(ctx, resolved.ID)
	if again.Status != "firing" {
		t.Errorf("re-fired row status = %q, want firing", again.Status)
	}
	if got := rec.changes(t); len(got) != 4 || got[3] != proto.AlertFired {
		t.Errorf("published %v, want a fourth event, fired", got)
	}
}

// Rows written before the read-back loop carry the same label-hash
// fingerprint, so a continuing alert keeps its row (and its ack), and one
// that is no longer firing is resolved rather than left stuck.
func TestSyncRuleAlerts_AdoptsExistingRowsByFingerprint(t *testing.T) {
	ctx := context.Background()
	svc, store, _, _ := newSyncService(t)
	cont, gone := highCPU("n1"), highCPU("n2")
	for _, f := range []FiringRule{cont, gone} {
		if _, _, err := store.Upsert(ctx, &PersistedAlert{
			Fingerprint: fingerprintFromLabels(f.Labels), Status: "firing",
			Severity: proto.AlertWarn, Title: "HighCPU", Detail: f.Summary,
			Labels: f.Labels, StartsAt: f.ActiveAt,
		}); err != nil {
			t.Fatal(err)
		}
	}
	contID := "rule:" + fingerprintFromLabels(cont.Labels)
	if _, err := store.Ack(ctx, contID); err != nil {
		t.Fatal(err)
	}
	if err := svc.SyncRuleAlerts(ctx, []FiringRule{cont}); err != nil {
		t.Fatal(err)
	}
	got, _ := store.Get(ctx, contID)
	if got.Status != "firing" || got.AckedAt == nil {
		t.Errorf("continuing row = %+v, want firing and still acked", got)
	}
	g, _ := store.Get(ctx, "rule:"+fingerprintFromLabels(gone.Labels))
	if g.Status != "resolved" {
		t.Errorf("no-longer-firing row status = %q, want resolved", g.Status)
	}
}

func TestSyncRuleAlerts_DismissedFiringRowStillResolves(t *testing.T) {
	ctx := context.Background()
	svc, store, _, _ := newSyncService(t)
	if err := svc.SyncRuleAlerts(ctx, []FiringRule{highCPU("n1")}); err != nil {
		t.Fatal(err)
	}
	id := "rule:" + fingerprintFromLabels(highCPU("n1").Labels)
	if _, err := store.Dismiss(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := svc.SyncRuleAlerts(ctx, nil); err != nil {
		t.Fatal(err)
	}
	got, _ := store.Get(ctx, id)
	if got.Status != "resolved" || got.DismissedAt == nil {
		t.Errorf("row = %+v, want resolved and still dismissed", got)
	}
}

func TestSyncRuleAlerts_UnknownActivationTime(t *testing.T) {
	ctx := context.Background()
	svc, store, _, now := newSyncService(t)
	f := highCPU("n1")
	f.ActiveAt = time.Time{}
	if err := svc.SyncRuleAlerts(ctx, []FiringRule{f}); err != nil {
		t.Fatal(err)
	}
	first := *now
	*now = now.Add(time.Minute)
	if err := svc.SyncRuleAlerts(ctx, []FiringRule{f}); err != nil {
		t.Fatal(err)
	}
	rows, _ := store.ListFiring(ctx)
	if len(rows) != 1 || !rows[0].StartsAt.Equal(first) {
		t.Fatalf("rows = %+v, want one starting at first sighting %v", rows, first)
	}
}

func TestSyncRuleAlerts_NoStoreErrors(t *testing.T) {
	svc := New(nil, nil, nil, nil, nil, nil, false)
	if err := svc.SyncRuleAlerts(context.Background(), nil); err == nil {
		t.Fatal("want error with no store")
	}
}

// A failed read must change nothing: not knowing what is firing is not the
// same as nothing firing.
func TestRunRuleSync_ReadErrorLeavesAlertsFiring(t *testing.T) {
	svc, store, _, _ := newSyncService(t)
	ctx, cancel := context.WithCancel(context.Background())
	if err := svc.SyncRuleAlerts(ctx, []FiringRule{highCPU("n1")}); err != nil {
		t.Fatal(err)
	}
	reads := make(chan struct{}, 8)
	read := func(context.Context) ([]FiringRule, error) {
		reads <- struct{}{}
		return nil, errors.New("vm unreachable")
	}
	done := make(chan struct{})
	go func() { svc.RunRuleSync(ctx, read, time.Millisecond); close(done) }()
	for i := 0; i < 3; i++ {
		select {
		case <-reads:
		case <-time.After(5 * time.Second):
			t.Fatal("RunRuleSync never read")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunRuleSync did not stop on cancel")
	}
	rows, _ := store.ListFiring(context.Background())
	if len(rows) != 1 {
		t.Fatalf("firing rows = %d after failed reads, want 1", len(rows))
	}
}

func TestRunRuleSync_AppliesWhatItReads(t *testing.T) {
	svc, store, _, _ := newSyncService(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	applied := make(chan struct{})
	var once sync.Once
	read := func(context.Context) ([]FiringRule, error) {
		defer once.Do(func() { close(applied) })
		return []FiringRule{highCPU("n1")}, nil
	}
	// A period far longer than the test: only the start-up read runs.
	go svc.RunRuleSync(ctx, read, time.Hour)
	select {
	case <-applied:
	case <-time.After(5 * time.Second):
		t.Fatal("RunRuleSync never read at start")
	}
	// The read returned; SyncRuleAlerts runs right after it. Wait on the
	// store for that fact rather than for a duration.
	deadline := time.Now().Add(5 * time.Second)
	for {
		rows, _ := store.ListFiring(context.Background())
		if len(rows) == 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("firing rows = %d, want 1 after the start-up sync", len(rows))
		}
		time.Sleep(5 * time.Millisecond)
	}
}
