package updater

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// probeHealth prefers diag.health (role-aware), falls back to diag.ping for
// agents that don't answer it, and treats an unhealthy ack or no responder as a
// rollback signal. Distinct node ids per case avoid unsubscribe races.
func TestProbeHealth(t *testing.T) {
	nc := startNATS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	respondHealth := func(node string, ack proto.DiagHealthAck) {
		_, err := nc.Subscribe(proto.NodeCmdSubject(node, "diag.health"), func(m *nats.Msg) {
			b, _ := json.Marshal(ack)
			_ = m.Respond(b)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	respondPing := func(node string) {
		_, err := nc.Subscribe(proto.NodeCmdSubject(node, "diag.ping"), func(m *nats.Msg) {
			_ = m.Respond([]byte(`{"ok":true}`))
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	_ = nc.Flush()

	// 1. diag.health OK=true → healthy.
	respondHealth("healthy", proto.DiagHealthAck{OK: true})
	// 2. diag.health OK=false → unhealthy, detail surfaced.
	respondHealth("broken", proto.DiagHealthAck{OK: false, Detail: "failed critical checks: nft-ruleset"})
	// 3. no diag.health, diag.ping answers → fallback healthy.
	respondPing("oldagent")
	// 4. "dead" node: no subscribers at all.
	_ = nc.Flush()

	if ok, _ := probeHealth(ctx, nc, "healthy", "j"); !ok {
		t.Error("healthy node should pass")
	}
	if ok, detail := probeHealth(ctx, nc, "broken", "j"); ok || detail != "failed critical checks: nft-ruleset" {
		t.Errorf("broken node: got (%v, %q)", ok, detail)
	}
	if ok, _ := probeHealth(ctx, nc, "oldagent", "j"); !ok {
		t.Error("old agent (diag.ping only) should pass via fallback")
	}
	if ok, _ := probeHealth(ctx, nc, "dead", "j"); ok {
		t.Error("dead node (no responder) should fail")
	}
}
