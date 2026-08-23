package proto

import "testing"

// The api's RPC deadline and the agent's work budget are one contract split
// across two processes. If the api's is not strictly longer, it times out on
// top of an agent that is still working and the operator gets
// "deploy rpc: context deadline exceeded" for every slow deploy — the same
// message whether the image is missing, the compose is wrong or the network is
// slow. That inversion shipped (60s api over a 120s agent) and made five of
// eight bench deploys fail identically and opaquely.
func TestDeployRPCOutlivesTheAgentWorkBudget(t *testing.T) {
	if AppDeployRPC <= AppDeployWork {
		t.Fatalf("AppDeployRPC (%s) must be strictly greater than AppDeployWork (%s), "+
			"or the api gives up first and the agent's real error is never seen",
			AppDeployRPC, AppDeployWork)
	}
}

// A cold multi-container pull to an arm64 node over a home connection does not
// finish in a minute. Bench 2026-08-23: every failed deploy sat at exactly
// 1m 0s while successes landed at 51s and 57s.
func TestDeployWorkBudgetLeavesRoomForAColdPull(t *testing.T) {
	const wantAtLeastSeconds = 300
	if got := int(AppDeployWork.Seconds()); got < wantAtLeastSeconds {
		t.Errorf("AppDeployWork = %ds, want >= %ds — below this a cold multi-container "+
			"pull cannot finish and deploys fail on a timer rather than on their merits",
			got, wantAtLeastSeconds)
	}
}
