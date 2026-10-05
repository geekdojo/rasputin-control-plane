package console

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// deliverStep runs pushDeliver alone, so the test reaches its own read of the
// hash rather than the plan step's refusal ahead of it.
func (f *fleet) deliverStep(t *testing.T) (json.RawMessage, error) {
	t.Helper()
	raw, _ := json.Marshal(PushSpec{Reason: "test"})
	return pushDeliver(f.store, f.list, discardLog)(&jobs.StepCtx{
		Ctx: context.Background(), JobID: "job-1", Spec: raw, NATS: f.nc,
		Log: func(string, string) {},
	})
}

// TC-825-34: both agents, the accepting one and the refusing one, receive the
// stored hash; the step's result carries the hash id and not the hash; the
// held secret.Value is destroyed when the step returns.
func TestPushDeliver_HashIsAValueDestroyedWhenTheStepReturns(t *testing.T) {
	ctx := context.Background()
	f := newFleet(t)
	f.add("ok", proto.RoleCompute, proto.StatusOnline, "2026.09.4-dev.172")
	f.add("no", proto.RoleCompute, proto.StatusOnline, "2026.09.4-dev.172")
	f.agent("ok", applying("ok"))
	f.agent("no", refusing("no", "read-only"))
	hashID, err := f.store.SetPassword(ctx, goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	stored, _, err := f.store.HashForDispatch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := string(stored.Reveal())
	stored.Destroy()

	var held secret.Value
	var heldBytes string
	f.store.heldHash = func(v secret.Value) {
		held = v
		heldBytes = string(v.Reveal())
	}
	res, err := f.deliverStep(t)
	if err != nil {
		t.Fatalf("deliver: %v", err)
	}
	f.mu.Lock()
	for _, id := range []string{"ok", "no"} {
		if f.seen[id] != want {
			t.Errorf("%s was sent %q, want the stored hash", id, f.seen[id])
		}
	}
	f.mu.Unlock()
	if !bytes.Contains(res, []byte(hashID)) {
		t.Errorf("the deliver result lacks the hash id: %s", res)
	}
	if bytes.Contains(res, []byte(want)) {
		t.Errorf("the deliver result carries the hash: %s", res)
	}
	if heldBytes != want {
		t.Errorf("held hash = %q, want the stored hash", heldBytes)
	}
	if held.Len() != 0 {
		t.Errorf("the held hash has %d bytes after the step returned, want it destroyed", held.Len())
	}
}

// TC-825-34: with no password set the deliver step fails with ErrNoPassword,
// and with an unusable stored hash it fails with "stored hash is unusable";
// in both cases no RPC is sent.
func TestPushDeliver_RefusesWithoutAUsableHash(t *testing.T) {
	t.Run("no password", func(t *testing.T) {
		f := newFleet(t)
		f.add("cp", proto.RoleControlPlane, proto.StatusOnline, "2026.09.4-dev.172")
		f.agent("cp", applying("cp"))
		if _, err := f.deliverStep(t); !errors.Is(err, ErrNoPassword) {
			t.Errorf("err = %v, want ErrNoPassword", err)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(f.seen) != 0 {
			t.Errorf("a command was sent: %v", f.seen)
		}
	})
	t.Run("unusable hash", func(t *testing.T) {
		f := newFleet(t)
		f.add("cp", proto.RoleControlPlane, proto.StatusOnline, "2026.09.4-dev.172")
		f.agent("cp", applying("cp"))
		if _, err := f.store.db.Exec(`INSERT INTO console_root_secret (id, hash, hash_id, set_at) VALUES (1, 'not-a-crypt-hash', 'id', 0)`); err != nil {
			t.Fatal(err)
		}
		if _, err := f.deliverStep(t); err == nil || !strings.Contains(err.Error(), "stored hash is unusable") {
			t.Errorf("err = %v, want stored hash is unusable", err)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(f.seen) != 0 {
			t.Errorf("a command was sent: %v", f.seen)
		}
	})
}
