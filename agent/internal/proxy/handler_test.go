package proxy

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

func startNATS(t *testing.T) *nats.Conn {
	t.Helper()
	ns, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatalf("nats new server: %v", err)
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
	return nc
}

func requestLeaf(t *testing.T, nc *nats.Conn, nodeID string, cmd proto.AppLeafCmd) proto.AppLeafAck {
	t.Helper()
	payload, _ := json.Marshal(cmd)
	msg, err := nc.Request(proto.AppLeafSubject(nodeID), payload, 3*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	var ack proto.AppLeafAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	return ack
}

func TestHandler_DeliverThenRemove(t *testing.T) {
	nc := startNATS(t)
	store := NewLeafStore(t.TempDir())
	sub, err := RegisterHandlers(nc, "node-1", store, nil)
	if err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	defer sub.Unsubscribe()

	// Deliver a leaf over the wire → files land, ack OK.
	if ack := requestLeaf(t, nc, "node-1", proto.AppLeafCmd{
		AppID: "app-1", Name: "jellyfin", CertPEM: []byte("CERT"), KeyPEM: []byte("KEY"), TailnetFQDN: "jellyfin.home1.internal", UpstreamPort: 8096,
	}); !ack.OK {
		t.Fatalf("deliver ack not OK: %+v", ack)
	}
	if b, _ := os.ReadFile(store.CertPath("app-1")); string(b) != "CERT" {
		t.Errorf("cert not written: %q", b)
	}

	// Teardown over the wire → files gone, ack OK.
	if ack := requestLeaf(t, nc, "node-1", proto.AppLeafCmd{AppID: "app-1", Remove: true}); !ack.OK {
		t.Fatalf("remove ack not OK: %+v", ack)
	}
	if _, err := os.Stat(store.CertPath("app-1")); !os.IsNotExist(err) {
		t.Errorf("cert still present after remove")
	}

	// A bad cmd (empty appId) → ack not OK, no crash.
	if ack := requestLeaf(t, nc, "node-1", proto.AppLeafCmd{CertPEM: []byte("c"), KeyPEM: []byte("k")}); ack.OK {
		t.Errorf("empty appId should not be OK")
	}
}
