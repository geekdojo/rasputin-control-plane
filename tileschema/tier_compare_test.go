package tileschema

import "testing"

// Dec 12 (auth-methodology §9 item 12, geekdojo/geekdojo-brain#522): a catalog
// upgrade that RAISES an app's tier needs the owner's consent. "Raises" is the
// rank going up — never a string comparison — and every uncertain input leans
// towards asking.
func TestTierRaised(t *testing.T) {
	cases := []struct {
		from, to string
		want     bool
	}{
		// Up the ladder, by one step and by two.
		{TierRoutine, TierElevated, true},
		{TierRoutine, TierHostTrusting, true},
		{TierElevated, TierHostTrusting, true},
		// Equal tiers and every way down need nothing.
		{TierRoutine, TierRoutine, false},
		{TierElevated, TierElevated, false},
		{TierHostTrusting, TierHostTrusting, false},
		{TierHostTrusting, TierRoutine, false},
		{TierHostTrusting, TierElevated, false},
		{TierElevated, TierRoutine, false},
		// Empty is routine on either side, as EffectiveTier says.
		{"", TierRoutine, false},
		{TierRoutine, "", false},
		{"", TierElevated, true},
		{TierElevated, "", false},
		// An installed tier this build does not know reads as the lowest, so
		// the upgrade asks rather than assuming it was already consented.
		{"root-plus", TierElevated, true},
		{"root-plus", TierRoutine, false},
		// A target tier this build does not know is never assumed lower.
		{TierHostTrusting, "root-plus", true},
		{TierRoutine, "root-plus", true},
		// Strings that sort the "wrong" way: "elevated" < "host-trusting" <
		// "routine" alphabetically, which is exactly the comparison to avoid.
		{TierRoutine, TierHostTrusting, true},
		{TierElevated, TierRoutine, false},
	}
	for _, c := range cases {
		if got := TierRaised(c.from, c.to); got != c.want {
			t.Errorf("TierRaised(%q, %q) = %v, want %v", c.from, c.to, got, c.want)
		}
	}
}

// Consent names a tier; it covers any target at or below it, and nothing it
// cannot rank.
func TestTierCovers(t *testing.T) {
	cases := []struct {
		accepted, tier string
		want           bool
	}{
		{TierHostTrusting, TierHostTrusting, true},
		{TierHostTrusting, TierElevated, true},
		{TierHostTrusting, TierRoutine, true},
		{TierElevated, TierElevated, true},
		{TierElevated, TierHostTrusting, false},
		{TierRoutine, TierElevated, false},
		{TierRoutine, TierRoutine, true},
		{TierHostTrusting, "", true}, // empty target is routine
		// An empty or unknown ACCEPTANCE covers nothing: consent is never
		// inferred from absence.
		{"", TierRoutine, false},
		{"", TierElevated, false},
		{"root-plus", TierRoutine, false},
		// An unknown target cannot be covered by any acceptance.
		{TierHostTrusting, "root-plus", false},
	}
	for _, c := range cases {
		if got := TierCovers(c.accepted, c.tier); got != c.want {
			t.Errorf("TierCovers(%q, %q) = %v, want %v", c.accepted, c.tier, got, c.want)
		}
	}
}

func TestKnownTier(t *testing.T) {
	for _, tier := range []string{TierRoutine, TierElevated, TierHostTrusting} {
		if !KnownTier(tier) {
			t.Errorf("KnownTier(%q) = false", tier)
		}
	}
	for _, tier := range []string{"", "Routine", "HOST-TRUSTING", "root-plus", " routine"} {
		if KnownTier(tier) {
			t.Errorf("KnownTier(%q) = true", tier)
		}
	}
}
