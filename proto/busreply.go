package proto

import "time"

// The bus reply grant.
//
// A node's minted bus credential (api/internal/busauth/callout.go, mintUserJWT)
// allows publishing on rasputin.node.<id>.> and nothing else. _INBOX is
// deliberately absent from that allow list and must stay absent: a node that
// could publish to any inbox could forge the ack for a request the api sent to
// a DIFFERENT node, which is the whole reason the grant is per-node.
//
// So an agent's only route to answering a request is NATS's dynamic response
// permission. When the server delivers a message carrying a reply subject to a
// connection that cannot already publish there, it mints a grant for that one
// literal subject (server/client.go: `!client.pubAllowedFullCheck(reply, …)` in
// deliverMsg) and enforces it on the way back (responseAllowed). The grant has
// two bounds — a message count and a lifetime — and the server substitutes its
// OWN defaults for whichever we leave at zero: 1 message
// (DEFAULT_ALLOW_RESPONSE_MAX_MSGS) and 2 minutes
// (DEFAULT_ALLOW_RESPONSE_EXPIRATION), both in server/const.go, applied by
// validateResponsePermissions in server/auth.go. Verified against the pinned
// nats-server v2.11.17.
//
// MaxMsgs was set to -1 on purpose, to defeat the default of 1. Expires was
// left at zero — so every reply grant died 120 seconds after delivery while
// agent handlers were budgeted for five, fifteen and thirty minutes. Past 120s
// the agent silently lost the right to answer at all: Msg.Respond is an async
// publish that returns nil, so nothing on the agent side failed; the violation
// came back on the async error channel, which had no handler.
//
// Confirmed on rasputin-local node c23: a Home Assistant deploy ran out its
// 300s agent budget and its reply was denied with
// `Permissions Violation for Publish to "_INBOX.1Xl6B13nLwrsZd1wJXJt7j.1oZd3uig"`,
// while Vaultwarden deploys finishing in 50–64s on the same connection the same
// night replied fine. Not a reconnect: the only disconnect was five hours
// earlier and both violations name connection [36]. It is not deploy-specific
// either — an OS bundle download over two minutes has its ack dropped the same
// way and surfaces as an opaque "download rpc: context deadline exceeded".
//
// The contract, therefore: THE REPLY GRANT MUST OUTLIVE EVERY AGENT-SIDE WORK
// BUDGET. It is derived from those budgets rather than hand-typed, so raising
// one cannot quietly reopen the hole; busreply_test.go is the guard.
const (
	// AgentWorkBudgetMax is the longest any agent handler may spend before it
	// answers. Deploy's per-tile ceiling is the largest today (30m); the
	// updater's download and install contexts (15m each), storage's claim
	// (15m — wipefs + sfdisk + mkfs on a disk that may be a spinning archive
	// drive), backup's write (15m — copying a sealed archive onto a target
	// that may be a USB 2.0 stick) and backup's volume staging (30m — a
	// local copy of one app volume that may be tens of gigabytes on an SD
	// card, with the app STOPPED for part of it), backup's transfer (45m —
	// sealing and uploading one staged volume) and backup's volume restore
	// (45m — downloading, unpacking and swapping one volume, #291 phase 2)
	// are the others. EVERY
	// agent-side budget belongs in this max(): one left out is a handler that
	// finishes with a real answer and is denied the publish that carries it.
	AgentWorkBudgetMax = max(AppDeployWorkMax, UpdateDownloadWork, UpdateInstallWork,
		StorageClaimWork, BackupWriteWork, BackupPreflightWork, BackupPruneWork,
		BackupStageWork, BackupUnstageWork, BackupTransferWork, BackupRestoreVolumeWork)

	// BusReplyGrantSlack is headroom on top of that ceiling for the handler's
	// teardown after its context expires, the marshal, and a queued write on a
	// busy connection. It is deliberately generous because a longer grant buys
	// no new capability: the grant is scoped to ONE literal inbox subject the
	// server just delivered to this one connection, and the server prunes the
	// entry anyway (pruneReplyPerms).
	BusReplyGrantSlack = 15 * time.Minute

	// BusReplyGrantTTL is what mintUserJWT puts in the minted credential's
	// jwt.ResponsePermission.Expires. Never leave that field zero: zero does
	// not mean "unbounded", it means two minutes, chosen by nats-server rather
	// than by us.
	BusReplyGrantTTL = AgentWorkBudgetMax + BusReplyGrantSlack
)
