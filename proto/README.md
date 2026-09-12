# proto

The wire contract between `rasputin-api` and `rasputin-agent`: hand-written Go
types, and the NATS subject names they travel on.

## What this is

A standalone Go module (`github.com/geekdojo/rasputin-control-plane/proto`, its
own `go.mod`) that `api/`, `agent/` and `backupxfer/` import through `replace`
directives. Both sides of every bus message compile against the same Go
definition, so a field renamed here breaks the build on both ends at once.

It contains:

- **Message types** — plain Go structs with `json:"..."` tags, marshalled with
  `encoding/json` and sent as JSON over NATS. Most are named for their role on
  the bus: a `...Cmd` request, a `...Ack` reply, an `...Evt` broadcast.
- **Enumerations** — named `string` types with their allowed values as
  constants (`NodeRole`, `NodeStatus`, `UpdateChangeType`, ...).
- **Subject builders** — `subjects.go` (`NodeCmdSubject` and friends) and the
  subject conventions in its package comment.
- **Contract helpers** that both sides need to agree on, not just data shapes:
  which agent release answers which verb (`agentverbs.go`), the bus reply-grant
  bounds (`busreply.go`), the mesh-CA trust fingerprint (`meshtrust.go`), and
  the count-or-percentage fleet knob (`intorstring.go`).

The files are split by subsystem: inventory, diag, system, jobs, updates,
apps, firewall, IDS, mesh, BMC, alerts, metrics, and the storage/backup family
(`storage`, `backup`, `backupstate`, `backuptarget`, `quiesce`, `restore`).
Tests live beside them (`*_test.go`) and pin subject names, selected JSON
round-trips, and helper behaviour.

## What this is not

- **Not a language-neutral schema.** There are no `.proto` or `.cue` files and
  no code generation. The Go structs *are* the definition; anything that is not
  Go and needs these shapes has to mirror them by hand.
- **Not self-validating.** A message is whatever `encoding/json` produces and
  accepts: by default unknown fields are dropped and missing fields decode to
  zero values. There are a few explicit helpers here (`ValidRole`,
  `ValidFirewallIntentKind`, `IntOrString.Validate`, ...), but calling them —
  or decoding strictly with `DisallowUnknownFields`, as some api HTTP handlers
  do — is the receiving code's choice, not something the types enforce.
- **Not separately versioned.** The module has no release tags of its own. It
  moves with the repo, and agent-vs-api skew is handled at runtime (see
  `agentverbs.go`), not by a schema version.

## The schema-language decision

This README once proposed choosing between **Protobuf** (strict, codegen for Go
and TypeScript) and **CUE** (schema + validation over Go structs) "when the
first Job kind needs a wire schema", with the choice to be recorded in a wiki
page, `agent-protocol.md`, that was never written. That decision was never
made. The ad-hoc JSON the README called acceptable "for scaffolding" is what
every Job kind since has shipped on, and the Go types in this directory grew up
around it.

So the question is still open, not settled in favour of either option. If it is
revisited, the starting point is the Go types here, not a blank schema.
