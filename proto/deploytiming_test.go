package proto

import (
	"testing"
	"time"
)

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

// The ordering invariant above is worthless if it only holds for the default.
// Every budget a tile can declare — and every value that could reach the api
// from a row it did not write — must keep the api's deadline strictly longer,
// or a per-app budget just reintroduces the opaque-timeout bug one tile at a
// time.
func TestDeployRPCOutlivesEveryPerAppBudget(t *testing.T) {
	seconds := []int{
		-86400, -1, 0, 1, 59,
		int(AppDeployWorkMin.Seconds()),
		120, 300, 900,
		int(AppDeployWorkMax.Seconds()),
		int(AppDeployWorkMax.Seconds()) + 1,
		86400,
	}
	for _, s := range seconds {
		work, rpc := AppDeployWorkFor(s), AppDeployRPCFor(s)
		if rpc <= work {
			t.Errorf("budget %ds: rpc %s must be strictly greater than work %s", s, rpc, work)
		}
		if work < AppDeployWorkMin || work > AppDeployWorkMax {
			t.Errorf("budget %ds: work %s escaped [%s, %s] — a bad row must not be able "+
				"to hand the agent an unbounded context", s, work, AppDeployWorkMin, AppDeployWorkMax)
		}
	}
}

// Zero is not "no patience". It is what a tile published before the field
// existed says, and what an api older than the field sends, so it has to mean
// the default in both directions.
func TestUndeclaredBudgetIsTheDefault(t *testing.T) {
	if got := AppDeployWorkFor(0); got != AppDeployWork {
		t.Errorf("AppDeployWorkFor(0) = %s, want the default %s", got, AppDeployWork)
	}
	if got := AppDeployRPCFor(0); got != AppDeployRPC {
		t.Errorf("AppDeployRPCFor(0) = %s, want %s", got, AppDeployRPC)
	}
}

// The point of the field is that a tile can be given LESS patience as well as
// more. A clamp that silently floored everything at the default would make a
// fast tile's declaration a no-op and leave the operator waiting five minutes
// for a one-image app that will never come up.
func TestADeclaredBudgetIsHonouredInBothDirections(t *testing.T) {
	if got := AppDeployWorkFor(90); got != 90*time.Second {
		t.Errorf("a tile asking for 90s got %s — a shorter budget must be honoured", got)
	}
	if got := AppDeployWorkFor(900); got != 900*time.Second {
		t.Errorf("a tile asking for 900s got %s — a longer budget must be honoured", got)
	}
}
