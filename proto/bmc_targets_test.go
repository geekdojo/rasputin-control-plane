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
	for _, kind := range []string{"bitscope", "mock"} {
		if !AvailableBMCBackend(kind) {
			t.Errorf("%q should be available", kind)
		}
	}
	// planned, unknown, and the off states are not selectable
	for _, kind := range []string{"turingpi", "rasputin", "none", "", "bogus"} {
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
