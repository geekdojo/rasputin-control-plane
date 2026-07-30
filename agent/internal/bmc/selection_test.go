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
		"insecure_skip_verify": true,
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
