package proto

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestNodeBMCTargets_Nil(t *testing.T) {
	if got := NodeBMCTargets(nil); got != nil {
		t.Errorf("nil node: %v, want nil", got)
	}
	if got := NodeBMCTargets(&Node{}); got != nil {
		t.Errorf("no metadata: %v, want nil", got)
	}
	if got := NodeBMCTargets(&Node{Metadata: map[string]any{"other": 1}}); got != nil {
		t.Errorf("unrelated metadata: %v, want nil", got)
	}
}

func TestNodeBMCTargets_StringSlice(t *testing.T) {
	n := &Node{Metadata: map[string]any{MetadataBMCTargets: []string{"a", "b"}}}
	if got := NodeBMCTargets(n); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("[]string shape: %v", got)
	}
}

func TestNodeBMCTargets_JSONRoundTrip(t *testing.T) {
	// The api decodes registration events from JSON, so the metadata
	// value arrives as []any — the shape the store then persists.
	n := &Node{Metadata: map[string]any{MetadataBMCTargets: []string{"a", "b"}}}
	buf, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	var back Node
	if err := json.Unmarshal(buf, &back); err != nil {
		t.Fatal(err)
	}
	if got := NodeBMCTargets(&back); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("post-JSON shape: %v, want [a b]", got)
	}
}

func TestNodeBMCTargets_DropsNonStrings(t *testing.T) {
	n := &Node{Metadata: map[string]any{MetadataBMCTargets: []any{"a", 7, "b"}}}
	if got := NodeBMCTargets(n); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("mixed entries: %v, want [a b]", got)
	}
}

func TestAvailableBMCBackend(t *testing.T) {
	// turingpi became selectable once per-target capabilities existed: it
	// can advertise power+reset without claiming a console it cannot serve.
	for _, kind := range []string{"bitscope", "mock", "turingpi"} {
		if !AvailableBMCBackend(kind) {
			t.Errorf("%q should be available", kind)
		}
	}
	// planned, unknown, and the off states are not selectable
	for _, kind := range []string{"rasputin", "none", "", "bogus"} {
		if AvailableBMCBackend(kind) {
			t.Errorf("%q should not be available", kind)
		}
	}
}

func TestSupportedBMCBackends_Shape(t *testing.T) {
	seen := map[string]bool{}
	for _, b := range SupportedBMCBackends {
		if b.Kind == "" || b.Label == "" {
			t.Errorf("entry %+v missing kind/label", b)
		}
		if b.Status != BMCBackendAvailable && b.Status != BMCBackendPlanned {
			t.Errorf("entry %q has bad status %q", b.Kind, b.Status)
		}
		if seen[b.Kind] {
			t.Errorf("duplicate kind %q", b.Kind)
		}
		seen[b.Kind] = true
	}
}

func TestBMCConfigureRoundTrip(t *testing.T) {
	in := BMCConfigureCmd{
		Kind:       "mock",
		Config:     json.RawMessage(`{"targets":["a"]}`),
		ConfigHash: "abc123",
	}
	buf, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out BMCConfigureCmd
	if err := json.Unmarshal(buf, &out); err != nil {
		t.Fatal(err)
	}
	if out.Kind != in.Kind || out.ConfigHash != in.ConfigHash || string(out.Config) != string(in.Config) {
		t.Errorf("round trip: %+v", out)
	}
	if got, want := BMCConfigureSubject("host-1"), "rasputin.node.host-1.cmd.bmc.configure"; got != want {
		t.Errorf("subject: %q, want %q", got, want)
	}
}

// An agent older than per-target capabilities advertises only the node-id
// list. Those backends really could do all three, so a bare listing must
// decode as fully capable — otherwise a rolling update would silently
// strip controls from a working BitScope rack.
func TestNodeBMCCapabilities_LegacyFallback(t *testing.T) {
	n := &Node{Metadata: map[string]any{MetadataBMCTargets: []string{"c02", "c03"}}}
	got := NodeBMCCapabilities(n)
	if len(got) != 2 {
		t.Fatalf("NodeBMCCapabilities = %v, want 2 entries", got)
	}
	for _, tgt := range got {
		for _, cap := range LegacyBMCCaps {
			if !tgt.HasCap(cap) {
				t.Errorf("%s: legacy target should advertise %q, caps=%v", tgt.NodeID, cap, tgt.Caps)
			}
		}
		if tgt.Console == nil || tgt.Console.Mode != BMCConsoleCharacter {
			t.Errorf("%s: legacy console should be character-mode, got %+v", tgt.NodeID, tgt.Console)
		}
	}
}

// The rich shape wins when present, and must survive the JSON round-trip
// the api's store path puts it through ([]any of map[string]any).
func TestNodeBMCCapabilities_RichShape(t *testing.T) {
	for name, meta := range map[string]any{
		"in-process": []BMCTarget{
			{NodeID: "tp-n1", Caps: []string{BMCCapPower, BMCCapReset}},
		},
		"json-round-trip": []any{
			map[string]any{
				"nodeId": "tp-n1",
				"caps":   []any{BMCCapPower, BMCCapReset},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			n := &Node{Metadata: map[string]any{
				MetadataBMCTargets:      []string{"tp-n1"},
				MetadataBMCCapabilities: meta,
			}}
			got := NodeBMCCapabilities(n)
			if len(got) != 1 {
				t.Fatalf("NodeBMCCapabilities = %v", got)
			}
			if !got[0].HasCap(BMCCapPower) || !got[0].HasCap(BMCCapReset) {
				t.Errorf("caps = %v, want power+reset", got[0].Caps)
			}
			// The rich shape must NOT be widened by the legacy list that
			// ships alongside it — that would resurrect the console button.
			if got[0].HasCap(BMCCapConsole) {
				t.Error("console must not leak in from the legacy list")
			}
		})
	}
}

func TestNodeBMCCapabilities_ConsoleFidelity(t *testing.T) {
	n := &Node{Metadata: map[string]any{
		MetadataBMCCapabilities: []any{
			map[string]any{
				"nodeId":  "x",
				"caps":    []any{BMCCapConsole},
				"console": map[string]any{"mode": BMCConsoleLine, "lossy": true},
			},
		},
	}}
	got := NodeBMCCapabilities(n)
	if len(got) != 1 || got[0].Console == nil {
		t.Fatalf("NodeBMCCapabilities = %+v", got)
	}
	if got[0].Console.Mode != BMCConsoleLine || !got[0].Console.Lossy {
		t.Errorf("console = %+v, want line-mode and lossy", got[0].Console)
	}
}

func TestNodeBMCTargetFor(t *testing.T) {
	n := &Node{Metadata: map[string]any{MetadataBMCTargets: []string{"a"}}}
	if _, ok := NodeBMCTargetFor(n, "a"); !ok {
		t.Error("NodeBMCTargetFor should find an advertised target")
	}
	if _, ok := NodeBMCTargetFor(n, "b"); ok {
		t.Error("NodeBMCTargetFor should not invent an unadvertised target")
	}
}

func TestBMCTargetIDs(t *testing.T) {
	got := BMCTargetIDs([]BMCTarget{{NodeID: "b"}, {NodeID: "a"}})
	if len(got) != 2 || got[0] != "b" || got[1] != "a" {
		t.Errorf("BMCTargetIDs = %v, want order preserved [b a]", got)
	}
}
