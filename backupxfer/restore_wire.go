package backupxfer

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The HTTP shape of the RESTORE half of the transport — design/storage.md
// §4.5's app-volume restore (geekdojo-brain#291, phase 2), the reverse of
// the ingest above. Both ends read these constants and nothing else.
//
//	GET <source>/<generation>/<member>
//	Authorization: Bearer <credential>            Grant.Use == UseRestore
//	→ 200
//	  Content-Type: application/vnd.rasputin.volume-tar
//	  X-Rasputin-Plaintext-Sha256: <hex>          what the manifest recorded
//	  X-Rasputin-Plaintext-Bytes: <n>
//	  <the plaintext tar, chunked, unsealed as it streams>
//
// # Who serves it, and why it is not in this package
//
// The api does. It is the one process that ever holds a §4.6 private key
// (unwrapped in the operator's browser and lent for one restore), and this
// package's documented invariant is that it NEVER holds one: an agent
// imports backupxfer, and an opener here would be a private-key consumer in
// exactly the processes §4.6 says must not have one. So the server side of
// this route — credential check, member lookup, unseal-as-you-stream — lives
// in the api's storage package beside its Unseal, and only the wire shape,
// the credential and the CLIENT (which handles plaintext it did not
// decrypt) live here.
//
// # The credential, in reverse
//
// The same signed Grant as an upload credential, with Use set to
// UseRestore. The ingest endpoint refuses a restore credential and the
// restore endpoint refuses an upload one — a leaked upload credential cannot
// read a volume back, and a leaked restore credential cannot write one. What
// a restore credential can do, stated once: fetch ONE named member of ONE
// generation, unsealed, once per request, for the one restore that minted
// it, until its TTL. It cannot list, cannot name another member, cannot
// reach another generation, and is refused once the restore ends. Its holder
// need not be the node it names — it is a bearer, which is why its scope is
// this narrow — and what it yields is plaintext app data, which is why the
// api only hands one to the node the app is installed on, over TLS, inside
// the command that carries it and nowhere else.

// EgressPathPrefix is where the api mounts the restore-stream endpoint. The
// source URI the api hands an agent is the public base URL plus this prefix;
// the agent appends the generation and the member.
const EgressPathPrefix = "/api/backup/egress/"

// EgressContentType names the body: a plaintext tar of one app volume.
const EgressContentType = "application/vnd.rasputin.volume-tar"

// UseRestore is Grant.Use for a download credential. The zero value is an
// upload credential — every grant minted before this field existed is one.
const UseRestore = "restore"

// RestoreCredentialTTL is how long a restore credential is honoured: the
// agent's restore budget plus the api's round-trip slack. Minted immediately
// before the restore verb is sent, so this is the whole window in which the
// member can be fetched.
const RestoreCredentialTTL = proto.BackupRestoreVolumeWork + 5*time.Minute

// Refusal codes the restore endpoint adds to the ingest's. Same convention:
// one HTTP status, one sentence, carried into the agent's ack unchanged.
const (
	CodeNoRestore     = "no-restore"     // 409: no restore has that generation open
	CodeMemberMissing = "member-missing" // 404: the generation holds no such member
	CodeUnsealFailed  = "unseal-failed"  // 422: the member did not open under the restore's key
	CodeReadFailed    = "read-failed"    // 500: the target could not be read
)

// EgressDestination is the source URI the api hands an agent for the
// restore-stream endpoint it serves itself: the public base URL plus
// EgressPathPrefix.
func EgressDestination(publicBaseURL string) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(publicBaseURL), "/")
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("backupxfer: %q is not an http(s) base URL", publicBaseURL)
	}
	return base + EgressPathPrefix, nil
}

// SplitEgressPath takes the request path below EgressPathPrefix and returns
// the generation and the member, refusing by shape — the same containment
// check as SplitIngestPath, on the read side.
func SplitEgressPath(p string) (generation, member string, ok bool) {
	rest, found := strings.CutPrefix(p, EgressPathPrefix)
	if !found {
		return "", "", false
	}
	generation, member, found = strings.Cut(rest, "/")
	if !found || !proto.BackupValidGenerationID(generation) || !proto.BackupValidMemberPath(member) {
		return "", "", false
	}
	return generation, member, true
}
