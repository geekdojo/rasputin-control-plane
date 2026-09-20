package setup

import (
	"context"
	"testing"
)

// Fail-closed table tests for the settings resolvers declared in
// .github/security-resolvers.tsv (gate 4, geekdojo/geekdojo-brain#491).
//
// TestGetBool_DefaultAppliesOnlyWhenUnset covers the happy shapes. This covers
// the one that decides whether a caller can be misled: a row that cannot be
// READ. GetBool answers with the caller's default in that case, which is the
// right value to hand back only because it comes with a non-nil error — so the
// property worth pinning is that the error is always there to be checked. A
// caller that drops it gets the permissive default with nothing to say so,
// which is why GetBool is in failopenlint's FO02 predicate list.
func TestGetBool_FailsClosedWhenTheRowCannotBeRead(t *testing.T) {
	ctx := context.Background()

	s := newStore(t)
	if err := s.SetBool(ctx, KeyObsEnabled, true); err != nil {
		t.Fatalf("SetBool: %v", err)
	}
	// Close the database underneath the store: every read now fails the way a
	// corrupt or unreadable settings file would at runtime.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	for _, def := range []bool{true, false} {
		got, err := s.GetBool(ctx, KeyObsEnabled, def)
		if err == nil {
			t.Fatalf("GetBool(def=%v) returned no error on an unreadable store — a "+
				"caller cannot tell an answer from a guess", def)
		}
		if got != def {
			t.Fatalf("GetBool(def=%v) = %v alongside its error; the documented "+
				"contract is that the default comes back, so a caller that checks "+
				"the error and one that reads the value agree about what happened",
				def, got)
		}
	}

	set, err := s.IsSet(ctx, KeyObsEnabled)
	if err == nil {
		t.Fatal("IsSet returned no error on an unreadable store")
	}
	if set {
		t.Fatal("IsSet = true on an unreadable store; a read that failed must not " +
			"read as 'the operator chose this'")
	}
}

// ParseBool decides every settings-backed boolean, including ones seeded from
// an environment variable. Anything it does not recognise is false, so a typo
// can never be the value that enables something.
func TestParseBool_FailsClosedOnEveryShapeOfInput(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"", false},
		{"   ", false},
		{"maybe", false},
		{"ture", false},
		{"2", false},
		{"-1", false},
		{"enabled", false},
		{"t", false},
		{"y", false},
		{"1", true},
		{"true", true},
		{"TRUE", true},
		{" yes ", true},
		{"On", true},
	} {
		if got := ParseBool(tc.in); got != tc.want {
			t.Errorf("ParseBool(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
