package inventory

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// registerWithKeys drives the real registration handler with a metadata map,
// after a JSON round-trip, so the accept rules are exercised on exactly the
// shape that arrives off the bus.
func registerWithKeys(t *testing.T, svc *Service, nodeID string, busTLS bool, keys proto.NodeKeys) {
	t.Helper()
	meta := map[string]any{proto.MetadataBusTLS: busTLS}
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

// A key is recorded only over a pinned TLS bus connection. On a plaintext one
// the registration still succeeds — the node stays in inventory and on the bus
// — but its key is refused, so it stays on the legacy path.
func TestRecordNodeKeys_OnlyOverAPinnedConnection(t *testing.T) {
	ctx := context.Background()
	svc, store, _ := newRoleTestService(t)
	agentKey := spki(t)

	registerWithKeys(t, svc, "plain", false, proto.NodeKeys{proto.NodeKeyAgent: agentKey})
	if n, _ := store.Get(ctx, "plain"); n == nil {
		t.Fatal("a plaintext registration carrying keys was rejected outright")
	}
	if got, err := store.NodeKeys(ctx, "plain"); err != nil || len(got) != 0 {
		t.Fatalf("a key was recorded over a plaintext connection: %v, %v", got, err)
	}
	if _, ok := store.Registry().KeyOwner(agentKey); ok {
		t.Fatal("a key registered over a plaintext connection is in the registry")
	}

	registerWithKeys(t, svc, "pinned", true, proto.NodeKeys{proto.NodeKeyAgent: agentKey})
	got, err := store.NodeKeys(ctx, "pinned")
	if err != nil || got[proto.NodeKeyAgent] != agentKey {
		t.Fatalf("a key reported over a pinned connection was not recorded: %v, %v", got, err)
	}
	if o, ok := store.Registry().KeyOwner(agentKey); !ok || o.NodeID != "pinned" {
		t.Fatalf("KeyOwner = %+v, %v", o, ok)
	}
}

// The same node, pinned, presenting a different key: recorded, and the change
// handed to the alert hook. A FIRST registration is not a change and must not
// raise the alert, or every new node would raise one.
func TestRecordNodeKeys_ReplacementRaisesTheChangeHook(t *testing.T) {
	svc, store, _ := newRoleTestService(t)
	changes := keyChangeRecorder(svc)
	first, second := spki(t), spki(t)

	registerWithKeys(t, svc, "c1", true, proto.NodeKeys{proto.NodeKeyAgent: first})
	if got := changes(); len(got) != 0 {
		t.Fatalf("a first registration raised a key change: %+v", got)
	}

	// A reconnect with the same key is not a change either.
	registerWithKeys(t, svc, "c1", true, proto.NodeKeys{proto.NodeKeyAgent: first})
	if got := changes(); len(got) != 0 {
		t.Fatalf("re-reporting the same key raised a change: %+v", got)
	}

	registerWithKeys(t, svc, "c1", true, proto.NodeKeys{proto.NodeKeyAgent: second})
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
	// And the replacement is only accepted over a pinned connection: a
	// plaintext registration presenting a third key changes nothing.
	third := spki(t)
	registerWithKeys(t, svc, "c1", false, proto.NodeKeys{proto.NodeKeyAgent: third})
	if recorded, _ := store.NodeKeys(context.Background(), "c1"); recorded[proto.NodeKeyAgent] != second {
		t.Errorf("a plaintext registration replaced a recorded key: %v", recorded)
	}
	if len(changes()) != 1 {
		t.Errorf("a refused replacement raised a change: %+v", changes())
	}
}

// A malformed report is refused whole and leaves the node's recorded keys
// alone — and does not take the node out of inventory.
func TestRecordNodeKeys_MalformedReportIsIgnored(t *testing.T) {
	ctx := context.Background()
	svc, store, _ := newRoleTestService(t)
	good := spki(t)
	registerWithKeys(t, svc, "c1", true, proto.NodeKeys{proto.NodeKeyAgent: good})

	register(t, svc, proto.NodeRegisteredEvt{
		NodeID: "c1", Role: proto.RoleCompute, Hostname: "c1.test",
		Metadata: map[string]any{
			proto.MetadataBusTLS:       true,
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
	registerWithKeys(t, svc, "c1", true, proto.NodeKeys{proto.NodeKeyAgent: key})
	registerWithKeys(t, svc, "c1", true, nil)
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
	registerWithKeys(t, svc, "c1", true, proto.NodeKeys{proto.NodeKeyAgent: shared})
	registerWithKeys(t, svc, "c2", true, proto.NodeKeys{proto.NodeKeyAgent: shared})

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
