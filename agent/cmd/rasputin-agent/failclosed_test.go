package main

import "testing"

// Fail-closed table test for bmcConfigFromEnv, the resolver declared in
// .github/security-resolvers.tsv (gate 4, geekdojo/geekdojo-brain#491).
//
// TestBMCConfigFromEnvCoversEveryField already checks that every field is
// wired. This checks the other half: what each security-relevant field does
// when its variable is absent, empty or malformed. Two of them decide whether
// a BMC's certificate is checked at all, so "unrecognised" has to mean "check
// it", never "skip it".
func TestBMCConfigFromEnv_FailsClosedOnEveryShapeOfInput(t *testing.T) {
	t.Run("nothing set at all", func(t *testing.T) {
		t.Setenv("RASPUTIN_BMC_TURINGPI_INSECURE", "")
		t.Setenv("RASPUTIN_BMC_TURINGPI_FINGERPRINT", "")
		cfg := bmcConfigFromEnv(t.TempDir())
		if cfg.TuringPiInsecure {
			t.Fatal("TuringPiInsecure is true with nothing set — verification must be on by default")
		}
		if cfg.TuringPiFingerprint != "" {
			t.Fatalf("TuringPiFingerprint = %q with nothing set, want empty", cfg.TuringPiFingerprint)
		}
	})

	for _, tc := range []struct {
		name string
		env  string
		want bool
	}{
		{"empty", "", false},
		{"a word that is not a boolean", "maybe", false},
		{"the name of the variable", "RASPUTIN_BMC_TURINGPI_INSECURE", false},
		{"a near-miss spelling", "yes", false},
		{"a typo of true", "ture", false},
		{"a number that is not 0 or 1", "2", false},
		{"punctuation", "-", false},
		{"only whitespace", "   ", false},
		// The two that must still work, or the escape hatch is unusable and
		// someone reaches for a worse one.
		{"true", "true", true},
		{"1 with surrounding whitespace", " 1 ", true},
		{"TRUE in capitals", "TRUE", true},
	} {
		t.Run("TuringPiInsecure: "+tc.name, func(t *testing.T) {
			t.Setenv("RASPUTIN_BMC_TURINGPI_INSECURE", tc.env)
			if got := bmcConfigFromEnv(t.TempDir()).TuringPiInsecure; got != tc.want {
				t.Fatalf("TuringPiInsecure = %v for %q, want %v — an unrecognised value "+
					"must never be the one that switches verification off", got, tc.env, tc.want)
			}
		})
	}
}
