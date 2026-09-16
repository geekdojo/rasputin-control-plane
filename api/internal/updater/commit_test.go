package updater

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// answerPrecheck makes id's "agent" answer update.precheck with ack.
func answerPrecheck(t *testing.T, nc *nats.Conn, id string, ack proto.UpdatePrecheckAck) {
	t.Helper()
	b, err := json.Marshal(ack)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nc.Subscribe(proto.UpdatePrecheckSubject(id), func(m *nats.Msg) { _ = m.Respond(b) }); err != nil {
		t.Fatal(err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
}

func boolp(b bool) *bool { return &b }

func TestSelfBuildCommitted(t *testing.T) {
	ctx := context.Background()

	t.Run("no self node: a dev api is committed", func(t *testing.T) {
		ok, why, err := SelfBuildCommitted(ctx, newJobStore(t), startNATS(t), "", time.Second)
		if err != nil || !ok || !strings.Contains(why, "RASPUTIN_SELF_NODE_ID") {
			t.Fatalf("= (%t, %q, %v)", ok, why, err)
		}
	})

	t.Run("the agent's report decides", func(t *testing.T) {
		nc := startNATS(t)
		answerPrecheck(t, nc, "cp-yes", proto.UpdatePrecheckAck{OK: true, BootCommitted: boolp(true), BootCommittedDetail: "good"})
		answerPrecheck(t, nc, "cp-no", proto.UpdatePrecheckAck{OK: true, BootCommitted: boolp(false), BootCommittedDetail: "trial pending"})
		answerPrecheck(t, nc, "cp-old", proto.UpdatePrecheckAck{OK: true})
		store := newJobStore(t)
		for id, want := range map[string]struct {
			ok  bool
			why string
		}{
			"cp-yes":    {true, "good"},
			"cp-no":     {false, "trial pending"},
			"cp-old":    {false, "update it"},
			"cp-absent": {false, "did not answer"},
		} {
			ok, why, err := SelfBuildCommitted(ctx, store, nc, id, 2*time.Second)
			if err != nil || ok != want.ok || !strings.Contains(why, want.why) {
				t.Errorf("%s: = (%t, %q, %v), want (%t, containing %q)", id, ok, why, err, want.ok, want.why)
			}
		}
	})

	t.Run("an update in flight holds it back whatever the agent says", func(t *testing.T) {
		nc := startNATS(t)
		answerPrecheck(t, nc, "cp1", proto.UpdatePrecheckAck{OK: true, BootCommitted: boolp(true)})
		now := time.Now().UTC()
		for _, tc := range []struct {
			kind, spec string
			blocks     bool
		}{
			{"node.update", `{"nodeId":"cp1"}`, true},
			{"node.update", `{"nodeId":"n7"}`, false},
			{"system.update", `{}`, true},
			{"mesh.reconcile", `{}`, false},
		} {
			store := newJobStore(t)
			j := &jobs.Job{ID: "j1", Kind: tc.kind, Spec: json.RawMessage(tc.spec), Status: jobs.StatusQueued, CreatedAt: now}
			if err := store.CreateJob(ctx, j); err != nil {
				t.Fatal(err)
			}
			ok, why, err := SelfBuildCommitted(ctx, store, nc, "cp1", 2*time.Second)
			if err != nil || ok == tc.blocks {
				t.Errorf("%s %s: = (%t, %q, %v), want committed=%t", tc.kind, tc.spec, ok, why, err, !tc.blocks)
			}
		}
	})
}
