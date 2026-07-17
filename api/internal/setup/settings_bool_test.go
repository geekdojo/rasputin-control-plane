package setup

import (
	"context"
	"testing"
)

// The obs.enabled seed turns entirely on telling "never chosen" apart from
// "chosen false". Get returning "" for both is why IsSet exists — without it
// a seeded env var would re-apply on every boot and silently undo the
// operator's last click.
func TestIsSet_DistinguishesUnsetFromExplicitFalse(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	set, err := s.IsSet(ctx, KeyObsEnabled)
	if err != nil {
		t.Fatalf("IsSet: %v", err)
	}
	if set {
		t.Fatal("IsSet = true on a fresh store; want false")
	}

	if err := s.SetBool(ctx, KeyObsEnabled, false); err != nil {
		t.Fatalf("SetBool: %v", err)
	}
	set, err = s.IsSet(ctx, KeyObsEnabled)
	if err != nil {
		t.Fatalf("IsSet: %v", err)
	}
	if !set {
		t.Error("IsSet = false after an explicit SetBool(false); want true — an explicit opt-out must not read as 'never chosen' or the seed would overwrite it")
	}
}

func TestGetBool_DefaultAppliesOnlyWhenUnset(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	got, err := s.GetBool(ctx, KeyObsEnabled, true)
	if err != nil {
		t.Fatalf("GetBool: %v", err)
	}
	if !got {
		t.Error("GetBool = false on unset key; want the supplied default (true)")
	}

	if err := s.SetBool(ctx, KeyObsEnabled, false); err != nil {
		t.Fatalf("SetBool: %v", err)
	}
	got, err = s.GetBool(ctx, KeyObsEnabled, true)
	if err != nil {
		t.Fatalf("GetBool: %v", err)
	}
	if got {
		t.Error("GetBool = true; a stored false must beat the default")
	}
}

func TestSetBool_GetBool_RoundTrip(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for _, want := range []bool{true, false, true} {
		if err := s.SetBool(ctx, KeyObsEnabled, want); err != nil {
			t.Fatalf("SetBool(%v): %v", want, err)
		}
		got, err := s.GetBool(ctx, KeyObsEnabled, !want)
		if err != nil {
			t.Fatalf("GetBool: %v", err)
		}
		if got != want {
			t.Errorf("round-trip %v -> %v", want, got)
		}
	}
}

// ParseBool has to accept what the env var accepted, or a value seeded from
// RASPUTIN_OBS_ENABLED=true would land in the table and then read back false.
func TestParseBool_MatchesEnvSpellings(t *testing.T) {
	for _, s := range []string{"1", "true", "TRUE", "yes", "on", " on "} {
		if !ParseBool(s) {
			t.Errorf("ParseBool(%q) = false; want true", s)
		}
	}
	for _, s := range []string{"", "0", "false", "no", "off", "nonsense"} {
		if ParseBool(s) {
			t.Errorf("ParseBool(%q) = true; want false", s)
		}
	}
}
