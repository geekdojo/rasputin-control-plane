// Package backupxfer is the backup transport — the one protocol both the api
// and the agent speak, in one package, so the two ends cannot drift.
//
// design/storage.md §4.1 puts the bytes on the agent's wire: the control plane
// decides WHERE a volume goes and hands the hosting agent a destination URI
// plus a scoped, short-lived credential; the agent seals the staged volume
// (§4.6) and streams it there. Today the URI resolves to the api's ingest
// endpoint on the controlplane, backed by the claimed disk (§4.8). Later it
// resolves to an S3 prefix. The agent-side code is identical in both cases —
// that is the requirement this package is shaped around, and Transport is the
// seam: one interface, one implementation per URI scheme.
//
// # Why one module, imported by both binaries
//
// The staging root was derived twice, once per binary, and the two derivations
// disagreed in the only configuration that shipped (rasputin-control-plane#228).
// A wire protocol is the same hazard with more surface: header names, trailer
// names, the token format, the member path, the refusal codes, the sealed
// archive format. Each is defined once here. The api mounts Ingest; the agent
// calls Transport; a test in either module drives both ends for real.
//
// # What is in here
//
//   - seal.go     the sealed archive format (X25519 + HKDF + ChaCha20-Poly1305
//     STREAM), moved from the api so a compute node can seal its
//     own bytes before they leave it. WRITE ONLY: nothing in this
//     package can open an archive.
//   - token.go    the upload credential: a MAC-signed grant scoped to one
//     member of one generation of one run, with a TTL.
//   - wire.go     the HTTP shape: paths, headers, trailers, receipts, refusals.
//   - client.go   Transport, and its HTTP implementation.
//   - server.go   Ingest, the http.Handler that lands members on the target.
//
// # What a credential can do, stated once
//
// Upload one named member into one in-flight generation, once, of at most
// the bytes a seal of the staged tar can produce. It cannot read anything
// (there is no read route), cannot list anything, cannot overwrite a member
// that has landed, cannot name a member outside the generation directory,
// cannot touch another generation, cannot fill the disk, cannot hold the
// upload slot in silence past IdleTimeout, and is refused after its TTL and
// after the generation closes. A node that leaks its credential leaks the
// ability to replace ITS OWN not-yet-landed volume with different sealed
// bytes for a few minutes — and the manifest records the plaintext digest the
// stage verb reported, so a substituted member shows up on restore day as a
// digest the manifest does not vouch for. The credential is a bearer: it is
// not bound to the presenting connection, so its holder need not be the node
// it names — that is the whole reason its scope is this narrow.
package backupxfer
