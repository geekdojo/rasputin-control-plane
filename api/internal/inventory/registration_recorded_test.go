package inventory

// The one INFO record a written registration leaves, "inventory: registration
// recorded" (geekdojo/geekdojo-brain#623): emitted once per registration the
// store accepted, with node_id, role and first, and never for one it rejected
// or failed to write.

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

const recordedMsg = "inventory: registration recorded"

// capturedRecord is one log record, with its attributes flattened.
type capturedRecord struct {
	level slog.Level
	msg   string
	attrs map[string]any
}

// captureHandler is a slog.Handler that keeps every record. onRecord, when
// set, runs inside Handle, so a test can check what was true at the moment
// the record was written.
type captureHandler struct {
	mu       sync.Mutex
	records  []capturedRecord
	onRecord func(capturedRecord)
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *captureHandler) WithGroup(string) slog.Handler            { return h }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	rec := capturedRecord{level: r.Level, msg: r.Message, attrs: map[string]any{}}
	r.Attrs(func(a slog.Attr) bool {
		rec.attrs[a.Key] = a.Value.Any()
		return true
	})
	if h.onRecord != nil {
		h.onRecord(rec)
	}
	h.mu.Lock()
	h.records = append(h.records, rec)
	h.mu.Unlock()
	return nil
}

// recorded returns the "registration recorded" records captured so far.
func (h *captureHandler) recorded() []capturedRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []capturedRecord
	for _, r := range h.records {
		if r.msg == recordedMsg {
			out = append(out, r)
		}
	}
	return out
}

// newRecordingService is an inventory Service on a real store and a real
// in-process bus, logging into a capture handler.
func newRecordingService(t *testing.T) (*Service, *Store, *captureHandler) {
	t.Helper()
	nc := startNATS(t)
	store := newStore(t)
	h := &captureHandler{}
	svc := NewService(store, nc, slog.New(h))
	svc.ctx = context.Background()
	return svc, store, h
}

func computeReg(id string) proto.NodeRegisteredEvt {
	return proto.NodeRegisteredEvt{NodeID: id, Role: proto.RoleCompute, Hostname: id + ".test", AgentVersion: "v1"}
}

func assertNoneRecorded(t *testing.T, h *captureHandler) {
	t.Helper()
	if got := h.recorded(); len(got) != 0 {
		t.Fatalf("%d %q record(s) for a registration that was not written: %+v", len(got), recordedMsg, got)
	}
}

// failNodeWrites makes every write of op ("INSERT" or "UPDATE") to the nodes
// table fail, in the real database, while reads keep working.
func failNodeWrites(t *testing.T, s *Store, op string) {
	t.Helper()
	stmt := fmt.Sprintf(`CREATE TRIGGER fail_nodes_%s BEFORE %s ON nodes BEGIN SELECT RAISE(ABORT, 'injected %s failure'); END`, op, op, op)
	if _, err := s.db.ExecContext(context.Background(), stmt); err != nil {
		t.Fatalf("install the %s failure: %v", op, err)
	}
}

// TC-623-01: a first registration emits exactly one INFO record carrying
// node_id, role and first=true, written after the row exists.
func TestRegistrationRecorded_FirstRegistration(t *testing.T) {
	svc, store, h := newRecordingService(t)
	rowAtRecord := make(chan bool, 1)
	h.onRecord = func(r capturedRecord) {
		if r.msg == recordedMsg {
			n, err := store.Get(context.Background(), "n1")
			rowAtRecord <- err == nil && n != nil
		}
	}

	register(t, svc, computeReg("n1"))

	got := h.recorded()
	if len(got) != 1 {
		t.Fatalf("%d %q records, want 1: %+v", len(got), recordedMsg, got)
	}
	r := got[0]
	if r.level != slog.LevelInfo {
		t.Errorf("level %v, want INFO", r.level)
	}
	if r.attrs["node_id"] != "n1" || r.attrs["role"] != string(proto.RoleCompute) || r.attrs["first"] != true {
		t.Errorf("attrs %v, want node_id=n1 role=compute first=true", r.attrs)
	}
	if !<-rowAtRecord {
		t.Error("the record was written before the node's row existed")
	}
}

// TC-623-02: a re-registration emits one more record, with first=false.
func TestRegistrationRecorded_ReRegistration(t *testing.T) {
	svc, _, h := newRecordingService(t)

	register(t, svc, computeReg("n1"))
	register(t, svc, computeReg("n1"))

	got := h.recorded()
	if len(got) != 2 {
		t.Fatalf("%d %q records after two registrations, want 2: %+v", len(got), recordedMsg, got)
	}
	if got[0].attrs["first"] != true || got[1].attrs["first"] != false {
		t.Fatalf("first flags %v then %v, want true then false", got[0].attrs["first"], got[1].attrs["first"])
	}
	if got[1].attrs["node_id"] != "n1" || got[1].level != slog.LevelInfo {
		t.Fatalf("second record %+v, want INFO with node_id=n1", got[1])
	}
}

// TC-623-03: a registration that does not decode — a payload naming another
// node than its subject, or malformed JSON — records nothing and writes no row.
func TestRegistrationRecorded_NoneWhenUndecodable(t *testing.T) {
	for _, tc := range []struct {
		name string
		data func(t *testing.T) []byte
	}{
		{"payload names another node", func(t *testing.T) []byte { return mustJSON(t, computeReg("n2")) }},
		{"malformed JSON", func(*testing.T) []byte { return []byte("{not json") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, store, h := newRecordingService(t)
			svc.handleRegistered(&nats.Msg{Subject: proto.NodeRegisteredSubject("n1"), Data: tc.data(t)})
			assertNoneRecorded(t, h)
			for _, id := range []string{"n1", "n2"} {
				if n, _ := store.Get(context.Background(), id); n != nil {
					t.Fatalf("a row was written for %s: %+v", id, n)
				}
			}
		})
	}
}

// TC-623-04: an invalid role records nothing and writes no row.
func TestRegistrationRecorded_NoneOnInvalidRole(t *testing.T) {
	svc, store, h := newRecordingService(t)
	ev := computeReg("n1")
	ev.Role = proto.NodeRole("bogus")

	register(t, svc, ev)

	assertNoneRecorded(t, h)
	if n, _ := store.Get(context.Background(), "n1"); n != nil {
		t.Fatalf("a row was written for an invalid role: %+v", n)
	}
}

// TC-623-05: a node enrolled as compute registering as storage records
// nothing, and its row keeps its role and last_seen.
func TestRegistrationRecorded_NoneOnRoleChange(t *testing.T) {
	ctx := context.Background()
	svc, store, h := newRecordingService(t)
	if err := store.Insert(ctx, makeNode("n1", proto.RoleCompute, time.Minute)); err != nil {
		t.Fatal(err)
	}
	before, err := store.Get(ctx, "n1")
	if err != nil || before == nil {
		t.Fatalf("Get before: (%v, %v)", before, err)
	}

	ev := computeReg("n1")
	ev.Role = proto.RoleStorage
	register(t, svc, ev)

	assertNoneRecorded(t, h)
	after, err := store.Get(ctx, "n1")
	if err != nil || after == nil {
		t.Fatalf("Get after: (%v, %v)", after, err)
	}
	if after.Role != proto.RoleCompute || !after.LastSeen.Equal(before.LastSeen) {
		t.Fatalf("row changed: role %q last_seen %v, want %q and %v", after.Role, after.LastSeen, proto.RoleCompute, before.LastSeen)
	}
}

// TC-623-06: at the cluster cap a new node records nothing and no row is
// inserted.
func TestRegistrationRecorded_NoneAtClusterCap(t *testing.T) {
	ctx := context.Background()
	svc, store, h := newRecordingService(t)
	for i := 0; i < proto.MaxClusterNodes; i++ {
		if err := store.Insert(ctx, makeNode(fmt.Sprintf("n-%02d", i), proto.RoleCompute, time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	members := store.Registry().MemberCount()

	register(t, svc, computeReg("over-cap"))

	assertNoneRecorded(t, h)
	if got := store.Registry().MemberCount(); got != members {
		t.Fatalf("member count %d → %d", members, got)
	}
	if n, _ := store.Get(ctx, "over-cap"); n != nil {
		t.Fatalf("a row was inserted past the cap: %+v", n)
	}
}

// TC-623-07: a failed write records nothing, on the insert path (new node)
// and on the update path (known node).
func TestRegistrationRecorded_NoneOnStoreWriteError(t *testing.T) {
	t.Run("insert fails for a new node", func(t *testing.T) {
		svc, store, h := newRecordingService(t)
		failNodeWrites(t, store, "INSERT")

		register(t, svc, computeReg("n1"))

		assertNoneRecorded(t, h)
		if n, _ := store.Get(context.Background(), "n1"); n != nil {
			t.Fatalf("the failing insert left a row: %+v", n)
		}
	})
	t.Run("update fails for a known node", func(t *testing.T) {
		svc, store, h := newRecordingService(t)
		if err := store.Insert(context.Background(), makeNode("n1", proto.RoleCompute, time.Minute)); err != nil {
			t.Fatal(err)
		}
		failNodeWrites(t, store, "UPDATE")

		register(t, svc, computeReg("n1"))

		assertNoneRecorded(t, h)
	})
}
