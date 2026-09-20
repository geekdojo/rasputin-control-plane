// Package console owns the cluster's console root password: the operator
// picks it in the first-run wizard, the api hashes it, and the
// console.root_push job delivers the HASH to every node in inventory over
// that node's own command lane.
//
// Decision #558 (geekdojo/geekdojo-brain#587): nothing is baked into an
// image. A fielded node keeps whatever its image shipped with until this
// job reaches it, so the job is the only thing that ever sets the value and
// it is re-runnable from Settings.
//
// # What is secret, and where it is allowed to be
//
// The PASSWORD exists only for the length of the HTTP request that carries
// it. It is hashed in the handler and is never stored, logged or returned.
//
// The HASH is secret material too — it is exactly what an offline cracker
// needs — so it follows the write-only operator-slot pattern the firewall's
// PPPoE secret and the BMC credentials already use (the 1A.4 rule,
// geekdojo/geekdojo-brain#479):
//
//   - it lives in its own table, read by exactly one function (HashForDispatch);
//   - no reader-facing API returns it, and Status deliberately cannot;
//   - it is NOT in the console.root_push job spec — the push step reads it
//     at dispatch time — so it is in no step result, no job event and no
//     log line, all of which the jobs API serves unredacted;
//   - at rest it is a row in rasputin.db, which dbutil opens through
//     api/internal/atrest at 0600 (sidecars included).
//
// Everything that needs to NAME a password — a step result, an event, the
// UI, an agent's ack — uses proto.ConsoleRootHashID instead: the first 16
// hex characters of the SHA-256 of the whole crypt string, salt included,
// which cannot be tested against a password guess by anyone who does not
// already hold the hash.
//
// # Mixed fleets
//
// The verb is new, so a fielded agent may not answer it. Such a node is
// FAILED with a reason that names its version and the release that answers
// (proto.VerbMinAgentVersion), never skipped — a skipped node is a node
// whose console still takes the image's password with nothing saying so.
package console
