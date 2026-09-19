package busauth

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestValidNodeID(t *testing.T) {
	cases := []struct {
		id   string
		want bool
	}{
		{"alpha", true},
		{"e3bench-controlplane1", true},
		{"node-9bbaa24a", true},
		{"a", true},
		{"0", true},
		{"a-b", true},
		{strings.Repeat("a", 63), true},

		{"", false},
		{"*", false},
		{">", false},
		{"a.b", false},
		{"a b", false},
		{"a\tb", false},
		{" alpha", false},
		{"alpha\n", false},
		{"Alpha", false},
		{"ALPHA", false},
		{"node_1", false},
		{"a/b", false},
		{"-alpha", false},
		{"alpha-", false},
		{"-", false},
		{"ålpha", false},
		{strings.Repeat("a", 64), false},
	}
	for _, tc := range cases {
		if got := ValidNodeID(tc.id); got != tc.want {
			t.Errorf("ValidNodeID(%q) = %v, want %v", tc.id, got, tc.want)
		}
	}
}

// Store and minter errors wrap ErrInvalidNodeID so callers can tell a bad id
// from an internal failure.
func TestInvalidNodeIDErrorsAreTyped(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	if _, _, err := s.MintBound(ctx, "t", "a.b", "compute"); !errors.Is(err, ErrInvalidNodeID) {
		t.Errorf("MintBound error = %v, want ErrInvalidNodeID", err)
	}
	_, h, _ := GenerateToken()
	if _, err := s.PreloadHashes(ctx, []PreseedToken{{Hash: h, NodeID: "*"}}); !errors.Is(err, ErrInvalidNodeID) {
		t.Errorf("PreloadHashes error = %v, want ErrInvalidNodeID", err)
	}
	// An entry with no node id is refused with its own error: every token is
	// bound (geekdojo-brain#423).
	if n, err := s.PreloadHashes(ctx, []PreseedToken{{Hash: h, Label: "unbound"}}); !errors.Is(err, ErrUnboundToken) || n != 0 {
		t.Errorf("PreloadHashes unbound entry = (%d, %v), want (0, ErrUnboundToken)", n, err)
	}
	if _, _, err := s.MintBound(ctx, "t", "", "compute"); !errors.Is(err, ErrUnboundToken) {
		t.Errorf("MintBound with no node id error = %v, want ErrUnboundToken", err)
	}
}
