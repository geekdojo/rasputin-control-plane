package proto

import (
	"testing"
	"time"
)

// natsDefaultResponseExpiration is nats-server's
// DEFAULT_ALLOW_RESPONSE_EXPIRATION (server/const.go), which
// validateResponsePermissions (server/auth.go) substitutes whenever a minted
// credential leaves ResponsePermission.Expires at zero. It is duplicated here
// on purpose: proto must not import the server, and the whole failure was that
// this number, chosen by somebody else, silently became our contract.
const natsDefaultResponseExpiration = 2 * time.Minute

// deploytiming_test.go's TestDeployRPCOutlivesTheAgentWorkBudget states the
// contract one layer up: the api must lose the race so the agent's real error
// is what the operator sees. This is the same contract one layer down — the
// agent must still be ALLOWED TO SPEAK when it finishes. A reply grant shorter
// than the work budget produces exactly the failure that invariant exists to
// prevent, from the other direction: the agent answers, the bus refuses the
// publish, and the api reports "rpc: context deadline exceeded" for a handler
// that completed and had a real answer to give.
//
// Parameterised over every agent-side work budget rather than asserted against
// the largest one, because "the largest" is a fact about today's constants.
func TestReplyGrantOutlivesEveryAgentWorkBudget(t *testing.T) {
	budgets := []struct {
		name   string
		budget time.Duration
	}{
		{"deploy default", AppDeployWork},
		{"deploy floor", AppDeployWorkMin},
		{"deploy ceiling", AppDeployWorkMax},
		{"deploy ceiling via a per-app budget", AppDeployWorkFor(int(AppDeployWorkMax.Seconds()))},
		{"deploy ceiling via an out-of-range per-app budget", AppDeployWorkFor(86400)},
		{"updater download context", UpdateDownloadWork},
		{"updater install context", UpdateInstallWork},
		{"storage enumerate context", StorageEnumerateWork},
		{"storage claim context", StorageClaimWork},
		{"storage mount context", StorageMountWork},
		{"storage inspect context", StorageInspectWork},
		{"backup preflight context", BackupPreflightWork},
		{"backup write context", BackupWriteWork},
		{"backup prune context", BackupPruneWork},
		{"backup stage-volume context", BackupStageWork},
		{"backup unstage context", BackupUnstageWork},
		{"backup transfer context", BackupTransferWork},
		{"backup restore-volume context", BackupRestoreVolumeWork},
	}
	for _, b := range budgets {
		if BusReplyGrantTTL <= b.budget {
			t.Errorf("BusReplyGrantTTL (%s) must be strictly greater than the %s (%s), "+
				"or a handler that uses its whole budget loses the right to reply and "+
				"the operator gets an opaque rpc timeout for work that succeeded",
				BusReplyGrantTTL, b.name, b.budget)
		}
	}
}

// The api's deadline is longer than the agent's budget by design (see
// AppDeployRPCSlack), so the last instant a reply can still matter is the api's,
// not the agent's. A grant that expired in between would deny a reply the api
// was still waiting for.
func TestReplyGrantOutlivesTheAPIDeadline(t *testing.T) {
	for _, seconds := range []int{0, 60, 300, 900, int(AppDeployWorkMax.Seconds()), 86400} {
		if rpc := AppDeployRPCFor(seconds); BusReplyGrantTTL <= rpc {
			t.Errorf("budget %ds: BusReplyGrantTTL (%s) must outlive the api's own deadline (%s)",
				seconds, BusReplyGrantTTL, rpc)
		}
	}
}

// Zero is the bug. nats-server does not read a zero Expires as "no expiry"; it
// overwrites it with two minutes. Guarding the derivation guards the value
// mintUserJWT stamps into every credential.
func TestReplyGrantIsNotTheServerDefault(t *testing.T) {
	if BusReplyGrantTTL == 0 {
		t.Fatal("BusReplyGrantTTL is zero — nats-server substitutes 2 minutes for zero, " +
			"which is shorter than every agent work budget")
	}
	if BusReplyGrantTTL <= natsDefaultResponseExpiration {
		t.Fatalf("BusReplyGrantTTL = %s, which is no better than the nats-server default (%s)",
			BusReplyGrantTTL, natsDefaultResponseExpiration)
	}
}

// The derivation is the point: hand-typing the TTL is what lets a later budget
// increase reopen the hole silently. If somebody replaces the max() with a
// literal, this fails the moment the two disagree.
func TestReplyGrantIsDerivedFromTheBudgets(t *testing.T) {
	if AgentWorkBudgetMax != AppDeployWorkMax {
		t.Logf("note: the binding budget is no longer deploy's ceiling (%s); it is %s",
			AppDeployWorkMax, AgentWorkBudgetMax)
	}
	if want := AgentWorkBudgetMax + BusReplyGrantSlack; BusReplyGrantTTL != want {
		t.Errorf("BusReplyGrantTTL = %s, want %s — it must stay derived from the budgets, "+
			"not hand-typed alongside them", BusReplyGrantTTL, want)
	}
	if BusReplyGrantSlack <= 0 {
		t.Errorf("BusReplyGrantSlack = %s: the grant must outlive the budget STRICTLY, "+
			"with room for the handler's teardown and a queued write", BusReplyGrantSlack)
	}
}
