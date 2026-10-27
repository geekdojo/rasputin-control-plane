package inventory

import (
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/releases"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

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

// TC-776-12: AgentAtLeast is true only at the floor, above it, and for a
// v-prefixed version at or above it. Below, empty, a dev build's "0.0.1-dev",
// garbage and an empty floor are all false: the gate fails closed.
func TestAgentAtLeast(t *testing.T) {
	const floor = "2026.10.4-dev.204"
	for _, tc := range []struct {
		version, floor string
		want           bool
	}{
		{"2026.10.4-dev.204", floor, true},
		{"2026.10.4-dev.205", floor, true},
		{"2026.10.4", floor, true},
		{"2026.11.0-dev.1", floor, true},
		{"v2026.10.4-dev.204", floor, true},
		{"v2026.10.5", floor, true},
		{"2026.10.4-dev.203", floor, false},
		{"2026.10.3", floor, false},
		{"v2026.10.3", floor, false},
		{"", floor, false},
		{"0.0.1-dev", floor, false},
		{"garbage", floor, false},
		{"2026.10.4-dev.204", "", false},
	} {
		if got := AgentAtLeast(tc.version, tc.floor); got != tc.want {
			t.Errorf("AgentAtLeast(%q, %q) = %v, want %v", tc.version, tc.floor, got, tc.want)
		}
	}
}

// TC-776-06 (F-776-01): docker.deploy_secrets' floor is strictly greater than
// the stable v2026.10.3, the newest release when the verb was authored. A
// floor on the 2026.10.3 base would sort below that stable release and let an
// agent with no subscription for the verb through the gate.
func TestDeploySecretsFloorIsAboveTheLastStable(t *testing.T) {
	floor, ok := proto.VerbMinAgentVersion(proto.AppDeploySecretsVerb)
	if !ok {
		t.Fatal("docker.deploy_secrets has no floor")
	}
	c, err := releases.Compare(releases.SchemeCalVer, floor, "2026.10.3")
	if err != nil || c <= 0 {
		t.Fatalf("Compare(%q, 2026.10.3) = %d, %v; want > 0", floor, c, err)
	}
	if AgentAtLeast("2026.10.3", floor) {
		t.Fatalf("an agent at v2026.10.3 passes the %s gate", floor)
	}
}
