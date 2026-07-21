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
