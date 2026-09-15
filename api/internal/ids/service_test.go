package ids

import (
	"bufio"
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

// readJSONLines reads the entire JSONL file and decodes each line.
// Used to assert the writer-side state after the subscriber runs.
func readJSONLines(t *testing.T, path string) []proto.IDSAlertEvt {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	var out []proto.IDSAlertEvt
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var ev proto.IDSAlertEvt
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Errorf("decode line: %v", err)
			continue
		}
		out = append(out, ev)
	}
	return out
}

func TestService_PublishedAlertLandsInJSONLFile(t *testing.T) {
	nc := startNATS(t)
	path := filepath.Join(t.TempDir(), "ids.jsonl")
	w, err := NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })

	svc := NewService(w, nc)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(svc.Stop)

	ev := sampleEvt()
	payload, _ := json.Marshal(ev)
	if err := nc.Publish(proto.IDSAlertSubject(ev.NodeID), payload); err != nil {
		t.Fatal(err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}

	// Brief wait for the subscriber callback + file append. handle() is
	// synchronous on the NATS msg-delivery goroutine, so Flush + a few ms
	// is enough.
	deadline := time.Now().Add(500 * time.Millisecond)
	var lines []proto.IDSAlertEvt
	for time.Now().Before(deadline) {
		lines = readJSONLines(t, path)
		if len(lines) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(lines) != 1 {
		t.Fatalf("expected 1 line in JSONL file, got %d", len(lines))
	}
	if lines[0].SID != ev.SID || lines[0].NodeID != ev.NodeID {
		t.Errorf("round-trip mismatch: got %+v", lines[0])
	}
}

// An empty payload nodeId is filled from the subject (the bus-scoped identity);
// a payload naming a different node than its subject is dropped.
func TestService_BindsNodeIDToSubject(t *testing.T) {
	nc := startNATS(t)
	path := filepath.Join(t.TempDir(), "ids.jsonl")
	w, err := NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })

	svc := NewService(w, nc)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Stop)

	mismatched := *sampleEvt()
	mismatched.NodeID = "beta"
	mismatched.SID = 1
	empty := *sampleEvt()
	empty.NodeID = ""
	empty.SID = 2
	// One subscription delivers in order, so once the second message's line
	// is written the first has already been handled.
	for _, ev := range []proto.IDSAlertEvt{mismatched, empty} {
		payload, _ := json.Marshal(&ev)
		if err := nc.Publish(proto.IDSAlertSubject("alpha"), payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	var lines []proto.IDSAlertEvt
	for {
		lines = readJSONLines(t, path)
		if len(lines) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no alert written within 5s")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(lines) != 1 || lines[0].SID != 2 || lines[0].NodeID != "alpha" {
		t.Errorf("got %+v, want only the empty-nodeId alert (sid 2), attributed to alpha", lines)
	}
}

func TestService_InvalidJSONIsSkipped(t *testing.T) {
	nc := startNATS(t)
	path := filepath.Join(t.TempDir(), "ids.jsonl")
	w, err := NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })

	svc := NewService(w, nc)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Stop)

	if err := nc.Publish("rasputin.node.x.evt.ids.alert", []byte("not json")); err != nil {
		t.Fatal(err)
	}
	// Then a good one — the bad message must not have wedged the subscriber.
	good, _ := json.Marshal(sampleEvt())
	_ = nc.Publish("rasputin.node.fw-1.evt.ids.alert", good)
	_ = nc.Flush()

	deadline := time.Now().Add(500 * time.Millisecond)
	var lines []proto.IDSAlertEvt
	for time.Now().Before(deadline) {
		lines = readJSONLines(t, path)
		if len(lines) >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(lines) != 1 {
		t.Errorf("expected 1 line (only the good event), got %d", len(lines))
	}
}
