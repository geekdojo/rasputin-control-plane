package inventory

import "testing"

// TC-741-24: AgentPredates is true only for a parseable version below a
// parseable floor; equal, newer, empty and unparseable read false, and a
// v-prefix on either side is ignored. ExplainNoResponder, the console's
// "predates" message and enrollRejected's killed-enroll message go through
// it; their own tests are unchanged.
func TestAgentPredates(t *testing.T) {
	for _, tc := range []struct {
		version, floor string
		want           bool
	}{
		{"2026.09.1-dev.150", "2026.10.0-dev.191", true},
		{"v2026.09.1-dev.150", "2026.10.0-dev.191", true},
		{"2026.09.1-dev.150", "v2026.10.0-dev.191", true},
		{" 2026.09.1-dev.150 ", "2026.10.0-dev.191", true},
		{"2026.10.0-dev.191", "2026.10.0-dev.191", false},
		{"2026.10.0", "2026.10.0-dev.191", false},
		{"2027.01.0", "2026.10.0-dev.191", false},
		{"", "2026.10.0-dev.191", false},
		{"dev", "2026.10.0-dev.191", false},
		{"2026.09.1-dev.150", "", false},
	} {
		if got := AgentPredates(tc.version, tc.floor); got != tc.want {
			t.Errorf("AgentPredates(%q, %q) = %v, want %v", tc.version, tc.floor, got, tc.want)
		}
	}
}
