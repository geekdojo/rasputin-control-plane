package ids

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

func startNATS(t *testing.T) *nats.Conn {
	t.Helper()
	opts := &natsserver.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true}
	ns, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("nats new server: %v", err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(2 * time.Second) {
		t.Fatal("nats not ready in 2s")
	}
	t.Cleanup(func() { ns.Shutdown(); ns.WaitForShutdown() })
	nc, err := nats.Connect("", nats.InProcessServer(ns))
	if err != nil {
		t.Fatalf("nats connect: %v", err)
	}
	t.Cleanup(nc.Close)
	return nc
}

func TestRun_AppendedAlertPublishedOnBus(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alert_fast.txt")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	prev := PollInterval
	PollInterval = 10 * time.Millisecond
	t.Cleanup(func() { PollInterval = prev })

	nc := startNATS(t)
	sub, err := nc.SubscribeSync(proto.IDSAlertSubject("fw-1"))
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go Run(ctx, nc, "fw-1", path)

	time.Sleep(20 * time.Millisecond) // let initial seek-to-end land

	const line = `06/08-14:23:45.123456 [**] [1:2009582:5] ET POLICY HTTP traffic on port 443 (POST) [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 192.168.1.50:54321 -> 8.8.8.8:443
`
	if err := os.WriteFile(path, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}

	msg, err := sub.NextMsg(2 * time.Second)
	if err != nil {
		t.Fatalf("waiting for IDS alert on bus: %v", err)
	}

	var ev proto.IDSAlertEvt
	if err := json.Unmarshal(msg.Data, &ev); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ev.NodeID != "fw-1" {
		t.Errorf("NodeID %q want fw-1", ev.NodeID)
	}
	if ev.SID != 2009582 {
		t.Errorf("SID %d want 2009582", ev.SID)
	}
	if ev.SrcAddr != "192.168.1.50" || ev.DstAddr != "8.8.8.8" {
		t.Errorf("addr parse degraded: %+v", ev)
	}
}

func TestRun_UnparseableLineIsSkippedNotFatal(t *testing.T) {
	// A header/junk line lands first, then a real alert. The header must
	// NOT show up on the bus AND must NOT prevent the real alert that
	// follows from being published.
	dir := t.TempDir()
	path := filepath.Join(dir, "alert_fast.txt")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	prev := PollInterval
	PollInterval = 10 * time.Millisecond
	t.Cleanup(func() { PollInterval = prev })

	nc := startNATS(t)
	sub, err := nc.SubscribeSync(proto.IDSAlertSubject("fw-2"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go Run(ctx, nc, "fw-2", path)
	time.Sleep(20 * time.Millisecond)

	const mixed = `-- snort 3.10 started --
06/08-14:23:45.123456 [**] [1:1:1] real alert [**] [Classification: Misc] [Priority: 3] {TCP} 1.1.1.1:1 -> 2.2.2.2:2
`
	if err := os.WriteFile(path, []byte(mixed), 0o644); err != nil {
		t.Fatal(err)
	}

	msg, err := sub.NextMsg(2 * time.Second)
	if err != nil {
		t.Fatalf("waiting for IDS alert: %v", err)
	}
	var ev proto.IDSAlertEvt
	if err := json.Unmarshal(msg.Data, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.SID != 1 || ev.Message != "real alert" {
		t.Errorf("expected the real alert to come through; got %+v", ev)
	}
	// Make sure no second message is lurking (the header line shouldn't
	// have produced one).
	if _, err := sub.NextMsg(150 * time.Millisecond); err == nil {
		t.Error("got an unexpected second message — header line should not have published")
	}
}
