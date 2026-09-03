package backupxfer

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The HTTP shape of the ingest protocol. Both ends read these constants and
// nothing else, which is what keeps them one protocol.
//
//	PUT <destination>/<generation>/<member>
//	Authorization: Bearer <credential>
//	Content-Type: application/vnd.rasputin.archive
//	Expect: 100-continue
//	X-Rasputin-Plaintext-Sha256: <hex>         what the stage verb reported
//	X-Rasputin-Plaintext-Bytes: <n>
//	Trailer: X-Rasputin-Sealed-Sha256, X-Rasputin-Sealed-Bytes
//	<sealed archive, chunked>
//	X-Rasputin-Sealed-Sha256: <hex>            over the bytes just sent
//	X-Rasputin-Sealed-Bytes: <n>
//
// # Why the sealed digest is a TRAILER
//
// Sealing mints a fresh ephemeral key per member, so the sealed bytes — and
// their digest — do not exist until the seal has run. Declaring the digest up
// front would force the agent to seal to disk first and upload second, i.e. a
// second staged copy, doubling §4.7's peak on the node that can least afford
// it. Streaming the seal straight into the request and declaring the digest
// in a trailer keeps the peak at one staged volume. The endpoint hashes what
// it receives and compares; a mismatch means the member never becomes
// visible. The plaintext digest, which IS known before a byte goes out, still
// travels as a header.
//
// # Why Expect: 100-continue
//
// §4.7: "the agent opens the connection, waits for the server to accept, and
// only then sends." The endpoint holds a semaphore on inbound uploads; it
// verifies the credential and takes a slot BEFORE it reads the body, and the
// body is what a 100 Continue releases. So a refused credential costs no
// bytes, and a queued upload sends nothing until the disk is free to take it.
// The connection is the lease: TCP close, including on agent death, releases
// the slot. No grant, no TTL, no renewal — that design was tabled (§4.7) and
// this is the alternative it was tabled for.

// IngestPathPrefix is where the api mounts the endpoint. The destination URI
// the api hands an agent is the public base plus this prefix; the agent
// appends the generation and the member.
const IngestPathPrefix = "/api/backup/ingest/"

// ContentType names the body: a sealed archive, and nothing else is accepted.
const ContentType = "application/vnd.rasputin.archive"

// Header and trailer names.
const (
	HeaderPlaintextDigest = "X-Rasputin-Plaintext-Sha256"
	HeaderPlaintextBytes  = "X-Rasputin-Plaintext-Bytes"
	TrailerSealedDigest   = "X-Rasputin-Sealed-Sha256"
	TrailerSealedBytes    = "X-Rasputin-Sealed-Bytes"
)

// Refusal codes the endpoint answers with. Each maps to one HTTP status and
// one sentence; the agent carries the code into its ack unchanged.
const (
	CodeCredentialInvalid = "credential-invalid" // 401
	CodeCredentialExpired = "credential-expired" // 401
	CodeCredentialScope   = "credential-scope"   // 403: valid, but not for this member
	CodeNoGeneration      = "no-generation"      // 409: no run has this generation open
	CodeMemberExists      = "member-exists"      // 409: landed or in flight; never overwritten
	CodeMemberInvalid     = "member-invalid"     // 400: not a member path
	CodeNotAnArchive      = "not-an-archive"     // 415: the body is not a sealed archive
	CodeDigestMismatch    = "digest-mismatch"    // 422: the trailer disagrees with the bytes
	CodeWriteFailed       = "write-failed"       // 500/507: the target could not take it
	CodeOverBound         = "over-bound"         // 413: more bytes than the credential authorises
	CodeUnsupported       = "unsupported"        // 501: this build cannot ingest here
)

// Receipt is the endpoint's answer to a landed member: the facts the manifest
// records, and no secret. It is also what Ingest.Landed returns, so the api
// can read its own record rather than trust an ack that may have been lost.
type Receipt struct {
	Generation string `json:"generation"`
	Member     string `json:"member"`
	// NodeID is the node the credential was issued to — who sealed this.
	NodeID string `json:"nodeId"`
	// SealedDigest and SealedBytes are over what the endpoint WROTE, computed
	// by the endpoint, and equal to what the trailer declared or the member
	// would not exist.
	SealedDigest string `json:"sealedDigest"`
	SealedBytes  uint64 `json:"sealedBytes"`
	// PlaintextDigest and PlaintextBytes are what the agent declared in the
	// headers, recorded for the manifest; the endpoint cannot verify them.
	PlaintextDigest string `json:"plaintextDigest,omitempty"`
	PlaintextBytes  uint64 `json:"plaintextBytes,omitempty"`
	// KeyID, Scope and EphemeralPublicKey are read from the sealed header.
	KeyID              string    `json:"keyId,omitempty"`
	Scope              string    `json:"scope,omitempty"`
	EphemeralPublicKey string    `json:"ephemeralPublicKey,omitempty"`
	LandedAt           time.Time `json:"landedAt"`
	// GrantID is the credential's nonce — a name for the grant that landed
	// this, safe to record.
	GrantID string `json:"grantId,omitempty"`
}

// Problem is the endpoint's error body.
type Problem struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// RefusedError is what the client returns when the endpoint answered with a
// refusal — as opposed to a transport failure, where nothing answered.
type RefusedError struct {
	Status  int
	Problem Problem
}

func (e *RefusedError) Error() string {
	return fmt.Sprintf("destination refused (%d %s): %s", e.Status, e.Problem.Code, e.Problem.Detail)
}

// IngestDestination is the destination URI the api hands an agent for the
// endpoint it serves itself: the public base URL plus IngestPathPrefix. The
// agent appends the generation and the member.
func IngestDestination(publicBaseURL string) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(publicBaseURL), "/")
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("backupxfer: %q is not an http(s) base URL", publicBaseURL)
	}
	return base + IngestPathPrefix, nil
}

// MemberURL is the full URL for one member under a destination.
func MemberURL(destination, generation, member string) (string, error) {
	if !proto.BackupValidGenerationID(generation) || !proto.BackupValidMemberPath(member) {
		return "", ErrGrantShape
	}
	u, err := url.Parse(strings.TrimSpace(destination))
	if err != nil {
		return "", fmt.Errorf("backupxfer: destination: %w", err)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/" + generation + "/" + member
	u.RawPath = ""
	return u.String(), nil
}

// SplitIngestPath takes the request path below IngestPathPrefix and returns
// the generation and the member, refusing by shape.
func SplitIngestPath(p string) (generation, member string, ok bool) {
	rest, found := strings.CutPrefix(p, IngestPathPrefix)
	if !found {
		return "", "", false
	}
	generation, member, found = strings.Cut(rest, "/")
	if !found || !proto.BackupValidGenerationID(generation) || !proto.BackupValidMemberPath(member) {
		return "", "", false
	}
	return generation, member, true
}
