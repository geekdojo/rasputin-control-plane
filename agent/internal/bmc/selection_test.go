package bmc

import (
	"encoding/json"
	"strings"
	"testing"
)

// A turingpi selection whose target carries an empty node_id must be rejected
// with a specific error, because an empty node id can't be advertised or
// addressed. Guards the `e.NodeID == ""` check (selection.go:67): the negated
// form (`!=`) skips the guard, admits the blank id, and — since the rest of the
// selection here is otherwise valid — would construct a backend successfully.
// Asserting the "empty node_id" error kills that mutant.
func TestNewFromSelection_TuringPiRejectsEmptyNodeID(t *testing.T) {
	raw := json.RawMessage(`{
		"endpoint": "https://turingpi.local",
		"user": "admin",
		"pin": "sha256/epr81hmPYzpdyR6LUQ2gb+spADtZSHpXfIQ5fF+AHqs=",
		"targets": [{"node_id": "", "slot": 1}]
	}`)
	_, err := NewFromSelection("turingpi", raw, t.TempDir())
	if err == nil {
		t.Fatal("expected an error for a target with empty node_id, got nil")
	}
	if !strings.Contains(err.Error(), "empty node_id") {
		t.Errorf("error = %q, want it to mention %q", err.Error(), "empty node_id")
	}
}

// A stored selection that predates the pinned-TLS rule must not build a
// client on the node either. The api refuses to push one, but the agent is
// the last line: a hand-built selection, or one delivered by an api that
// somehow still holds the old shape, gets no client and no credential goes
// anywhere (geekdojo/geekdojo-brain#548).
func TestNewFromSelection_TuringPiRefusesRetiredTLSShapes(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{"insecure_skip_verify", `{"endpoint":"https://turingpi.local","user":"admin","insecure_skip_verify":true,"targets":[{"node_id":"a","slot":1}]}`},
		{"cert fingerprint", `{"endpoint":"https://turingpi.local","user":"admin","fingerprint":"41:7C:1E:EA","targets":[{"node_id":"a","slot":1}]}`},
		{"no pin", `{"endpoint":"https://turingpi.local","user":"admin","targets":[{"node_id":"a","slot":1}]}`},
		{"http endpoint", `{"endpoint":"http://turingpi.local","user":"admin","pin":"sha256/epr81hmPYzpdyR6LUQ2gb+spADtZSHpXfIQ5fF+AHqs=","targets":[{"node_id":"a","slot":1}]}`},
	} {
		if _, err := NewFromSelection("turingpi", json.RawMessage(tc.raw), t.TempDir()); err == nil {
			t.Errorf("%s: expected a refusal, got a working backend", tc.name)
		}
	}
}
