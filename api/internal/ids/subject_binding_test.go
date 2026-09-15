package ids

// A node's identity comes from the subject it publishes on
// (rasputin.node.<id>.evt.ids.alert), which the bus scopes to the node's
// credential — never from the nodeId field in the payload. An alert whose
// payload names a different node is dropped; one with the matching id is kept.

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

func TestService_Handle_PayloadNodeIDMustMatchSubject(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ids.jsonl")
	w, err := NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	svc := NewService(w, nil) // handle never touches the bus

	mismatched := sampleEvt()
	mismatched.NodeID = "beta"
	payload, _ := json.Marshal(mismatched)
	svc.handle(&nats.Msg{Subject: proto.IDSAlertSubject("alpha"), Data: payload})

	matching := sampleEvt()
	matching.NodeID = "alpha"
	payload, _ = json.Marshal(matching)
	svc.handle(&nats.Msg{Subject: proto.IDSAlertSubject("alpha"), Data: payload})

	lines := readJSONLines(t, path)
	for _, line := range lines {
		if line.NodeID != "alpha" {
			t.Errorf("alert published on %s was recorded as nodeId %q — a mismatched payload node id "+
				"must be dropped", proto.IDSAlertSubject("alpha"), line.NodeID)
		}
	}
	if len(lines) != 1 {
		t.Errorf("recorded %d alerts, want exactly the 1 whose payload matches its subject", len(lines))
	}
}

func TestService_Handle_EmptyPayloadNodeIDTakesSubject(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ids.jsonl")
	w, err := NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	svc := NewService(w, nil)

	ev := sampleEvt()
	ev.NodeID = ""
	payload, _ := json.Marshal(ev)
	svc.handle(&nats.Msg{Subject: proto.IDSAlertSubject("alpha"), Data: payload})

	lines := readJSONLines(t, path)
	if len(lines) != 1 || lines[0].NodeID != "alpha" {
		t.Fatalf("got %+v, want one alert attributed to the subject's node id %q", lines, "alpha")
	}
}
