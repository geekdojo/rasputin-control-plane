package busident

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// These decoders are where a node's authenticated identity is established: the
// subject is the only trustworthy source, the payload is attacker-chosen bytes.
// The invariant is therefore not "no panic" but "a decoded event is always
// attributed to the node whose subject carried it" — the property whose absence
// let one node rewrite another's inventory row.

// assertBoundToSubject checks the identity invariant for a decoded event:
// gotID came from the subject, is a valid node id, and matches any node id the
// raw payload claimed.
func assertBoundToSubject(t *testing.T, kind, subject string, data []byte, gotID string) {
	t.Helper()
	subjID, ok := NodeIDFromSubject(subject)
	if !ok {
		t.Fatalf("%s: decoded %q but its subject has no valid node id", kind, subject)
	}
	if gotID != subjID {
		t.Fatalf("%s: decoded node id %q, but subject %q names %q", kind, gotID, subject, subjID)
	}
	if !tileschema.ValidDNSLabel(gotID) {
		t.Fatalf("%s: decoded node id %q is not a valid node id", kind, gotID)
	}
	// Whatever the payload claimed, it must not have disagreed: a mismatch is
	// required to be an error, never a silent rewrite in either direction.
	var claim struct {
		NodeID *string `json:"nodeId"`
	}
	if err := json.Unmarshal(data, &claim); err == nil && claim.NodeID != nil {
		if *claim.NodeID != "" && *claim.NodeID != gotID {
			t.Fatalf("%s: payload claimed node id %q and decode accepted it as %q", kind, *claim.NodeID, gotID)
		}
	}
}

func seedSubjectsAndPayloads(f *testing.F, subjects []string) {
	payloads := []string{
		`{}`,
		`{"nodeId":"cp-1"}`,
		`{"nodeId":"cp-compute5"}`,
		`{"nodeId":""}`,
		`{"nodeId":"cp-1","role":"controlplane","imageVersion":"../../../x"}`,
		`{"nodeId":123}`,
		`{"metrics":{"cpu":1.5},"nodeId":"cp-1"}`,
		``,
		`null`,
	}
	for _, s := range subjects {
		for _, p := range payloads {
			f.Add(s, []byte(p))
		}
	}
}

func FuzzDecodeRegistered(f *testing.F) {
	seedSubjectsAndPayloads(f, []string{
		proto.NodeRegisteredSubject("cp-1"),
		proto.NodeRegisteredSubject("cp-compute4"),
		"rasputin.node.*.evt.registered",
		"rasputin.node.cp-1.evt.registered.extra",
		"rasputin.node..evt.registered",
		"rasputin.node.CP-1.evt.registered",
		"rasputin.node.cp-1.metrics",
		"rasputin.node.cp-1",
		"",
	})
	f.Fuzz(func(t *testing.T, subject string, data []byte) {
		ev, err := DecodeRegistered(subject, data)
		if err != nil {
			return
		}
		assertBoundToSubject(t, "registered", subject, data, ev.NodeID)
		if subject != proto.NodeRegisteredSubject(ev.NodeID) {
			t.Fatalf("registered: accepted subject %q, which is not the registration subject for %q",
				subject, ev.NodeID)
		}
	})
}

func FuzzDecodeIDSAlert(f *testing.F) {
	seedSubjectsAndPayloads(f, []string{
		proto.IDSAlertSubject("cp-firewall1"),
		proto.NodeEvtSubject("cp-1", "ids.alert"),
		proto.NodeEvtSubject("cp-1", "ids."),
		"rasputin.node.cp-1.evt.ids",
		"rasputin.node.*.evt.ids.alert",
		"rasputin.node.cp-1.evt.registered",
		"",
	})
	f.Fuzz(func(t *testing.T, subject string, data []byte) {
		ev, err := DecodeIDSAlert(subject, data)
		if err != nil {
			return
		}
		assertBoundToSubject(t, "ids", subject, data, ev.NodeID)
		prefix := proto.NodeEvtSubject(ev.NodeID, "ids.")
		if !strings.HasPrefix(subject, prefix) || len(subject) == len(prefix) {
			t.Fatalf("ids: accepted subject %q, which is not an ids event subject for %q", subject, ev.NodeID)
		}
	})
}

func FuzzDecodeMetrics(f *testing.F) {
	seedSubjectsAndPayloads(f, []string{
		proto.NodeMetricsSubject("cp-1"),
		proto.NodeMetricsSubject("cp-compute5"),
		"rasputin.node.*.metrics",
		"rasputin.node.cp-1.metrics.extra",
		"rasputin.node.cp-1.evt.registered",
		"",
	})
	f.Fuzz(func(t *testing.T, subject string, data []byte) {
		ev, err := DecodeMetrics(subject, data)
		if err != nil {
			return
		}
		assertBoundToSubject(t, "metrics", subject, data, ev.NodeID)
		if subject != proto.NodeMetricsSubject(ev.NodeID) {
			t.Fatalf("metrics: accepted subject %q, which is not the metrics subject for %q", subject, ev.NodeID)
		}
	})
}

// FuzzNodeIDFromSubject pins the extractor every consumer builds on: an accepted
// subject is exactly "rasputin.node.<valid id>.<non-empty rest>", and the id it
// returns reconstructs that prefix byte for byte.
func FuzzNodeIDFromSubject(f *testing.F) {
	for _, s := range []string{
		"rasputin.node.cp-1.metrics",
		"rasputin.node.cp-1.evt.registered",
		"rasputin.node.*.metrics",
		"rasputin.node.>.metrics",
		"rasputin.node.cp-1.",
		"rasputin.node.cp-1",
		"rasputin.node..metrics",
		"rasputin.NODE.cp-1.metrics",
		"rasputin.node.CP-1.metrics",
		"other.node.cp-1.metrics",
		"",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, subject string) {
		id, ok := NodeIDFromSubject(subject)
		if !ok {
			if id != "" {
				t.Fatalf("NodeIDFromSubject(%q) refused but returned id %q", subject, id)
			}
			return
		}
		if !tileschema.ValidDNSLabel(id) {
			t.Fatalf("NodeIDFromSubject(%q) returned %q, which is not a valid node id", subject, id)
		}
		want := "rasputin.node." + id + "."
		if !strings.HasPrefix(subject, want) || len(subject) == len(want) {
			t.Fatalf("NodeIDFromSubject(%q) returned %q, which does not reconstruct the subject prefix", subject, id)
		}
	})
}
