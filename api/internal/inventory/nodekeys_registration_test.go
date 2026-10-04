package inventory

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// registerWithKeys drives the real registration handler with a metadata map,
// after a JSON round-trip, so the accept rules are exercised on exactly the
// shape that arrives off the bus.
func registerWithKeys(t *testing.T, svc *Service, nodeID string, keys proto.NodeKeys) {
	t.Helper()
	meta := map[string]any{}
	if keys != nil {
		meta[proto.MetadataNodeKeys] = keys
	}
	blob, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(blob, &wire); err != nil {
		t.Fatal(err)
	}
	register(t, svc, proto.NodeRegisteredEvt{
		NodeID: nodeID, Role: proto.RoleCompute, Hostname: nodeID + ".test", Metadata: wire,
	})
}

func keyChangeRecorder(svc *Service) func() []NodeKeyChange {
	var mu sync.Mutex
	var got []NodeKeyChange
	svc.SetOnNodeKeyChanged(func(_ context.Context, c NodeKeyChange) {
		mu.Lock()
		got = append(got, c)
		mu.Unlock()
	})
	return func() []NodeKeyChange { mu.Lock(); defer mu.Unlock(); return append([]NodeKeyChange(nil), got...) }
}

// TC-517-13: a registration carrying node keys and no busTls is recorded —
// the bus accepts only pinned TLS, so there is no transport flag to wait for
// (geekdojo/geekdojo-brain#517).
func TestRecordNodeKeys_RecordedWithoutBusTLS(t *testing.T) {
	ctx := context.Background()
	svc, store, _ := newRoleTestService(t)
	agentKey := spki(t)

	registerWithKeys(t, svc, "c1", proto.NodeKeys{proto.NodeKeyAgent: agentKey})
	got, err := store.NodeKeys(ctx, "c1")
	if err != nil || got[proto.NodeKeyAgent] != agentKey {
		t.Fatalf("a key reported with no busTls was not recorded: %v, %v", got, err)
	}
	if o, ok := store.Registry().KeyOwner(agentKey); !ok || o.NodeID != "c1" {
		t.Fatalf("KeyOwner = %+v, %v", o, ok)
	}
}

// TC-517-13: the same node presenting a different key: recorded, audited in
// the log, and the change handed to the alert hook. A FIRST registration is
// not a change and must not raise the alert, or every new node would raise one.
func TestRecordNodeKeys_ReplacementRaisesTheChangeHook(t *testing.T) {
	var audit strings.Builder
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&audit)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })

	svc, store, _ := newRoleTestService(t)
	changes := keyChangeRecorder(svc)
	first, second := spki(t), spki(t)

	registerWithKeys(t, svc, "c1", proto.NodeKeys{proto.NodeKeyAgent: first})
	if got := changes(); len(got) != 0 {
		t.Fatalf("a first registration raised a key change: %+v", got)
	}

	// A reconnect with the same key is not a change either.
	registerWithKeys(t, svc, "c1", proto.NodeKeys{proto.NodeKeyAgent: first})
	if got := changes(); len(got) != 0 {
		t.Fatalf("re-reporting the same key raised a change: %+v", got)
	}

	registerWithKeys(t, svc, "c1", proto.NodeKeys{proto.NodeKeyAgent: second})
	got := changes()
	if len(got) != 1 {
		t.Fatalf("a replacement raised %d change(s), want 1", len(got))
	}
	if got[0].NodeID != "c1" || got[0].Previous[proto.NodeKeyAgent] != first || got[0].Current[proto.NodeKeyAgent] != second {
		t.Errorf("change = %+v", got[0])
	}
	if recorded, _ := store.NodeKeys(context.Background(), "c1"); recorded[proto.NodeKeyAgent] != second {
		t.Errorf("the replacement was not recorded: %v", recorded)
	}
	if line := audit.String(); !strings.Contains(line, "node key CHANGED for c1") || !strings.Contains(line, first) || !strings.Contains(line, second) {
		t.Errorf("the key change was not audited with both hashes: %q", line)
	}
}

// TC-517-13: a malformed report is refused whole and leaves the node's
// recorded keys alone — and does not take the node out of inventory.
func TestRecordNodeKeys_MalformedReportIsIgnored(t *testing.T) {
	ctx := context.Background()
	svc, store, _ := newRoleTestService(t)
	good := spki(t)
	registerWithKeys(t, svc, "c1", proto.NodeKeys{proto.NodeKeyAgent: good})

	register(t, svc, proto.NodeRegisteredEvt{
		NodeID: "c1", Role: proto.RoleCompute, Hostname: "c1.test",
		Metadata: map[string]any{
			proto.MetadataNodeKeys:     map[string]any{"agent": "sha256/not-a-hash", "collector": spki(t)},
			"primaryLanCidr":           "192.168.1.0/24",
			proto.MetadataConfigFaults: nil,
		},
	})
	if n, _ := store.Get(ctx, "c1"); n == nil || n.Hostname != "c1.test" {
		t.Fatal("a malformed key report rejected the registration")
	}
	recorded, err := store.NodeKeys(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	if recorded[proto.NodeKeyAgent] != good || len(recorded) != 1 {
		t.Errorf("a malformed report changed the record: %v", recorded)
	}
}

// A node that reports no keys at all — a pre-key agent — keeps whatever was
// recorded and is not disturbed.
func TestRecordNodeKeys_SilentAgentKeepsItsRecord(t *testing.T) {
	ctx := context.Background()
	svc, store, _ := newRoleTestService(t)
	key := spki(t)
	registerWithKeys(t, svc, "c1", proto.NodeKeys{proto.NodeKeyAgent: key})
	registerWithKeys(t, svc, "c1", nil)
	if recorded, _ := store.NodeKeys(ctx, "c1"); recorded[proto.NodeKeyAgent] != key {
		t.Errorf("a silent registration cleared the record: %v", recorded)
	}
	if _, ok := store.Registry().KeyOwner(key); !ok {
		t.Error("a silent registration retired the key")
	}
}

// Two nodes presenting the same key: the second is refused and the first
// keeps it, and neither registration is rejected.
func TestRecordNodeKeys_SharedKeyRefused(t *testing.T) {
	ctx := context.Background()
	svc, store, _ := newRoleTestService(t)
	shared := spki(t)
	registerWithKeys(t, svc, "c1", proto.NodeKeys{proto.NodeKeyAgent: shared})
	registerWithKeys(t, svc, "c2", proto.NodeKeys{proto.NodeKeyAgent: shared})

	if n, _ := store.Get(ctx, "c2"); n == nil {
		t.Fatal("the second node was kept out of inventory")
	}
	if got, _ := store.NodeKeys(ctx, "c2"); len(got) != 0 {
		t.Errorf("c2 recorded a key another node holds: %v", got)
	}
	if o, ok := store.Registry().KeyOwner(shared); !ok || o.NodeID != "c1" {
		t.Errorf("KeyOwner = %+v, %v; want c1 to keep it", o, ok)
	}
}
