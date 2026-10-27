package tileschema

import (
	"strings"
	"testing"
)

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

// geekdojo/geekdojo-brain#884: a host-PID container reads the environment of
// any co-located container running as the same uid, so the host-PID fact now
// forces a host-trusting declaration — and that declaration is what puts an
// upgrade from an app accepted at elevated through the consent gate. The gate
// itself (apps.CheckUpgradeConsent, the compose handler) reads tiers only and
// is proven by its own tests; this proves the link from the fact to the tier
// those tests start from.
func TestHostPIDTile_UpgradeFromElevatedNeedsHostTrustingConsent(t *testing.T) {
	facts := okFacts()
	facts.HostPIDOrIPC = true

	tileAt := func(tier string) Tile {
		tile := okTile()
		tile.Requires = []string{CapabilityPrivilegeTiers}
		tile.Privilege = &Privilege{
			Tier:   tier,
			Grants: []string{GrantHostPIDOrIPC},
			Why:    "Watches every process on the node",
		}
		return tile
	}

	// TC-884-03: declaring elevated is refused by the tier rule, not by a
	// missing requires or grant — the message proves which check fired.
	err := ValidateTileSafety(tileAt(TierElevated), facts)
	const want = `declares privilege tier "elevated" but its compose takes "host-trusting" (host-pid-ipc)`
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("elevated host-pid tile: got %v, want an error containing %q", err, want)
	}

	// TC-884-04: declaring host-trusting loads.
	ok := tileAt(TierHostTrusting)
	if err := ValidateTileSafety(ok, facts); err != nil {
		t.Fatalf("host-trusting host-pid tile: got %v, want nil", err)
	}

	// TC-884-05: the calls the upgrade saga and the HTTP gate make. An app
	// accepted at elevated is raised, elevated consent does not cover it,
	// host-trusting consent does.
	tier := ok.DeclaredPrivilege().EffectiveTier()
	if !TierRaised(TierElevated, tier) {
		t.Errorf("TierRaised(elevated, %q) = false, want true", tier)
	}
	if TierCovers(TierElevated, tier) {
		t.Errorf("TierCovers(elevated, %q) = true, want false", tier)
	}
	if !TierCovers(TierHostTrusting, tier) {
		t.Errorf("TierCovers(host-trusting, %q) = false, want true", tier)
	}
}
