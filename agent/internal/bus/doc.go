// Package bus is the agent's NATS connection: an outbound-only client that
// dials the controlplane, presents the node-bound join token as its NATS
// credentials, and reconnects forever on its own. It also owns Respond, the
// shared reply encoder every subsystem handler uses.
//
// Subject dispatch does NOT live here. Each subsystem (docker, storage,
// updater, openwrt, tailscale, bmc, …) subscribes its own subjects directly on
// the *nats.Conn this package hands back.
//
// There is no ack/dedup here, and none anywhere else either. Commands are core
// NATS request/reply, not JetStream: the api Requests on
// rasputin.node.<id>.cmd.… and waits for the reply until its context deadline.
// The one JetStream stream that exists (JOBS, rasputin.job.>) is a
// limits-retention archive of job events with no consumer, and node commands
// are not in it. So there is no work queue to drain on reconnect — a command
// issued while the agent was down was never queued and is never delivered —
// no Nats-Msg-Id dedup key anywhere in the tree, and no agent-side idempotency
// ledger. A reply lost in flight is therefore indistinguishable from work that
// never happened: neither side can tell whether the operation ran.
//
// The interim discipline lives on the api: a step whose effect cannot be undone
// declares jobs.WorkflowStep.Irreversible (merged in #198), which makes the
// saga runner refuse to auto-retry it and refuse to run it at all once the job
// ledger records an attempt. That is a refusal, not idempotency. The real
// mechanism — an agent operation ledger for irreversible RPCs — is tracked as
// geekdojo/geekdojo-brain#396.
//
// See projects/rasputin/design/control-plane/architecture.md §5
// in the geekdojo-brain.
package bus
