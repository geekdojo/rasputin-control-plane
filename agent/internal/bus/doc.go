// Package bus is the agent's NATS connection: an outbound-only Client that
// dials the controlplane, presents the node-bound join token as its NATS
// credentials, and keeps a connection up for the life of the process. It also
// owns Respond, the shared reply encoder every subsystem handler uses.
//
// "Keeps a connection up" is two mechanisms, and it matters which is which:
//
//  1. Within one *nats.Conn, nats.go reconnects on its own through network
//     loss (MaxReconnects(-1)); subscriptions survive, and the agent only
//     re-publishes its registration (Client's onConnected).
//  2. nats.go also has a CLOSED state it enters when it decides a failure is
//     permanent — and a closed conn is dead for good, subscriptions included.
//     The Client then re-dials: a brand new conn, bounded exponential backoff
//     (2s doubling to a 60s cap, jittered), forever, and on success re-runs
//     the agent's subscription setup (onConn) before onConnected.
//
// The route to CLOSED that bit on hardware is repeated auth errors: by
// default nats.go closes the conn the second time the same server rejects its
// credentials (Conn.processAuthError). A controlplane that comes back from a
// wipe accepts TCP before its token store is seeded, so every node's
// reconnect is rejected twice and closed, and nothing short of a process
// restart got them back (e3bench, 2026-09-04, 17 hours off the bus). The
// Client opts out of that default with nats.IgnoreAuthErrorAbort AND re-dials
// from closed, because closed is also reachable by other routes (a Drain, a
// server error the client treats as fatal).
//
// Subject dispatch does NOT live here. Each subsystem (docker, storage,
// updater, openwrt, tailscale, bmc, …) subscribes its own subjects on the
// *nats.Conn the Client hands to onConn — on EVERY new conn, which is why the
// agent collects its handler registrations as a list it can re-run rather
// than subscribing once inline.
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
