package proto

import "strings"

// Which agent release answers which verb.
//
// A node-scoped request that draws no responder (NATS ErrNoResponders) has
// three honest readings, and the api can tell them apart because inventory
// already holds both facts it needs: the node's presence and the agent
// version it reported at registration. The node is offline; the node is
// online but its agent predates the verb and has no subscription for it; or
// the node is online, its agent is new enough, and it still did not answer —
// a real fault. Before this table the first two were reported as the same
// thing, and on e3bench (2026-09-04) a compute node running 2026.08.4-dev.130
// was called OFFLINE by a backup run and "no container runtime" by the
// orphaned-volumes list, when it was online with Docker fine and simply
// running an agent that had never heard of storage.backup_stage_volume or
// docker.volumes.list.
//
// Each entry is the FIRST published release whose agent subscribes to the
// verb, derived from `git log -S"<verb>" -- proto agent` (the commit that
// introduced the subject constant and its handler) and `git tag --contains`
// on that commit (the first tag containing it). Bare CalVer, the way the
// agent reports its own version (build-release.sh stamps main.AgentVersion
// without the tag's leading "v"), so inventory's Node.AgentVersion compares
// against it directly under releases.SchemeCalVer.
//
// A new verb belongs here the release it ships, with that release's version:
// a verb missing from this table is still reported honestly ("did not
// answer"), but without the "update the node" advice that turns a fault
// report into an instruction.
var verbMinAgentVersion = map[string]string{
	// diag.health: 5adf6e9 (2026-07-01), first in v2026.07.1-dev.33.
	"diag.health": "2026.07.1-dev.33",
	// app.leaf: 6128ace (2026-08-08), first in v2026.08.2-dev.91.
	"app.leaf": "2026.08.2-dev.91",
	// storage.enumerate/claim/mount/inspect: 1295df4 (2026-08-31), first in
	// v2026.08.5-dev.132.
	"storage.enumerate": "2026.08.5-dev.132",
	"storage.claim":     "2026.08.5-dev.132",
	"storage.mount":     "2026.08.5-dev.132",
	"storage.inspect":   "2026.08.5-dev.132",
	// storage.backup_preflight/write/prune: 9f9aae9 (2026-09-02), first in
	// v2026.08.5-dev.134.
	"storage.backup_preflight": "2026.08.5-dev.134",
	"storage.backup_write":     "2026.08.5-dev.134",
	"storage.backup_prune":     "2026.08.5-dev.134",
	// storage.backup_stage_volume/backup_unstage: 580c453 (2026-09-02), first
	// in v2026.08.5-dev.136.
	"storage.backup_stage_volume": "2026.08.5-dev.136",
	"storage.backup_unstage":      "2026.08.5-dev.136",
	// storage.backup_transfer: 994c690 (2026-09-03), first in v2026.08.5-dev.138.
	"storage.backup_transfer": "2026.08.5-dev.138",
	// docker.volumes.list/remove: a5a28ac (2026-09-03), first in
	// v2026.08.5-dev.138.
	"docker.volumes.list":   "2026.08.5-dev.138",
	"docker.volumes.remove": "2026.08.5-dev.138",
	// storage.backup_restore_volume (#291 phase 2): entered when the verb was
	// authored, before its release existed, as the NEXT release run after
	// v2026.08.5-dev.139 (the newest published control-plane release at the
	// time). If a release was cut between this entry and the one that ships
	// the verb, an agent at that in-between version is reported as "should
	// answer and did not" rather than "predates the verb"; confirm with
	// `git tag --contains` once the release exists and correct the floor.
	"storage.backup_restore_volume": "2026.08.5-dev.140",
}

// StorageInspectProbeMinAgentVersion is the first agent release whose
// storage.inspect honours StorageInspectCmd.Probe and answers with a
// WriteProbe. Not a verb — the subject is unchanged, so an older agent still
// ANSWERS, just without the probe — which is why it is a separate floor and
// not an entry in verbMinAgentVersion: a no-responder explanation would never
// fire for it. The health poll compares the node's reported agent version
// against this when an ack comes back without a probe, so the row can say
// "update the node" rather than "the agent did not probe" (#398).
//
// Entered when the field was authored, before its release existed, as the
// NEXT release run after v2026.08.5-dev.143 (the newest published
// control-plane release at the time). Confirm with `git tag --contains` once
// the release exists and correct the floor if a release was cut in between.
const StorageInspectProbeMinAgentVersion = "2026.08.5-dev.144"

// metadataMinAgentVersion is the same table for registration-metadata keys
// the api acts on: the first agent release whose registration carries the
// key. A node whose agent predates the key has not failed to report it —
// it never could — and a consumer that tells the two apart can say "update
// the node" instead of "the node did not answer". Same conventions as
// verbMinAgentVersion: bare CalVer, the release the key ships.
var metadataMinAgentVersion = map[string]string{
	// meshCaFingerprint (converge_trust, e3bench 2026-09-04): entered when
	// the field was authored, before its release existed, as the NEXT release
	// run after v2026.08.5-dev.140 (the newest published control-plane
	// release at the time). If a release was cut between this entry and the
	// one that ships the field, an agent at that in-between version reads as
	// "should report and did not" rather than "predates the field"; confirm
	// with `git tag --contains` once the release exists and correct the
	// floor.
	MetadataMeshCAFingerprint: "2026.08.5-dev.141",
}

// MetadataMinAgentVersion reports the first agent release whose registration
// carries the metadata key, as the bare CalVer string the agent reports
// itself under. ok is false for a key this table does not record.
func MetadataMinAgentVersion(key string) (version string, ok bool) {
	version, ok = metadataMinAgentVersion[key]
	return version, ok
}

// VerbMinAgentVersion reports the first agent release that answers verb (a
// dotted cmd verb such as "storage.backup_stage_volume"), as the bare CalVer
// string the agent reports itself under. ok is false for a verb this table
// does not record.
func VerbMinAgentVersion(verb string) (version string, ok bool) {
	version, ok = verbMinAgentVersion[verb]
	return version, ok
}

// CmdSubjectVerb takes a subject built by NodeCmdSubject apart again:
// "rasputin.node.<node-id>.cmd.<verb>" → (node-id, verb). ok is false for any
// other subject shape. Node ids carry no dots (they are hostnames' first
// labels), so the first ".cmd." is the boundary.
func CmdSubjectVerb(subject string) (nodeID, verb string, ok bool) {
	const prefix = "rasputin.node."
	if !strings.HasPrefix(subject, prefix) {
		return "", "", false
	}
	rest := subject[len(prefix):]
	i := strings.Index(rest, ".cmd.")
	if i <= 0 {
		return "", "", false
	}
	nodeID, verb = rest[:i], rest[i+len(".cmd."):]
	if verb == "" {
		return "", "", false
	}
	return nodeID, verb, true
}
