package quiesce

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The transfer verb: seal a staged volume to the target's public key and
// stream it to the destination the api named, on the credential the api
// minted. design/storage.md §4.1 and §4.7; geekdojo-brain#295.
//
// # What this verb does not do, and why the split is the safety property
//
// It does not stop, start or touch the app. Stage did that, released its
// watchdog, and reported the outcome before the api could even send this
// verb. So nothing that happens here — a dead api, a refused credential, a
// connection that dies at 90% — can reach the container. §4.7's restart
// contract is not "also honoured" by this verb; it is out of this verb's
// reach by construction.
//
// It does not unstage. A failed transfer leaves the staged tar where it is so
// the api can retry the upload without re-quiescing (§4.7: "a stalled upload
// is just another upload attempt"); the api's unstage verb, which it already
// sends after every volume, is what gives the space back.
//
// It does not know what the destination is. The URI's scheme picks a
// backupxfer.Transport and that is the whole extent of the agent's interest:
// the same code runs whether the URI is the api's ingest endpoint or, later,
// an S3 prefix.
//
// # Peak disk on this node
//
// One staged volume. The seal streams straight into the upload
// (backupxfer.NewSealedStream) — there is no second copy on disk, sealed or
// otherwise. The sealed digest the destination verifies is computed as the
// bytes go out and declared in the request's trailer.

// SetCABundle points the HTTP transport at a PEM bundle to trust beside the
// system roots — the per-installation mesh CA that signs the api's HTTPS
// leaf. Same wiring the updater's download client has.
func (s *Stager) SetCABundle(path string) { s.caBundlePath = path }

// transport resolves a destination's transport. Seam for tests.
func (s *Stager) transport(destination string) (backupxfer.Transport, error) {
	if s.transportFor != nil {
		return s.transportFor(destination)
	}
	return backupxfer.TransportFor(destination, backupxfer.HTTPOptions{CABundlePath: s.caBundlePath})
}

// Transfer carries out one BackupTransferCmd. Like Stage it ALWAYS returns
// an ack; a refusal is an ack with OK false and a code.
func (s *Stager) Transfer(ctx context.Context, cmd proto.BackupTransferCmd) (ack *proto.BackupTransferAck) {
	ack = &proto.BackupTransferAck{StagingName: cmd.StagingName, Member: cmd.Member, KeyID: cmd.KeyID}
	defer func() {
		if r := recover(); r != nil {
			s.logf("rasputin-agent: transfer: PANIC transferring %s: %v", cmd.StagingName, r)
			s.failTransfer(ack, proto.StorageRefusalBackendError, fmt.Errorf("panic while transferring: %v", r))
		}
	}()
	if err := validateTransfer(s.stagingRoot, cmd); err != nil {
		return s.failTransfer(ack, proto.BackupRefusalStagingMissing, err)
	}
	tr, err := s.transport(cmd.Destination)
	if err != nil {
		if errors.Is(err, backupxfer.ErrUnsupportedDestination) {
			return s.failTransfer(ack, proto.BackupRefusalDestinationUnsupported, err)
		}
		return s.failTransfer(ack, proto.StorageRefusalBackendError, err)
	}

	// The staged file, by validated name, directly under the root, and only
	// a regular file: the same containment the write verb applies.
	staged := filepath.Join(s.stagingRoot, cmd.StagingName)
	info, err := os.Lstat(staged)
	if err != nil {
		return s.failTransfer(ack, proto.BackupRefusalStagingMissing, fmt.Errorf("%s: %w", staged, err))
	}
	if !info.Mode().IsRegular() {
		return s.failTransfer(ack, proto.BackupRefusalStagingMissing, fmt.Errorf("%s is not a regular file; this verb sends only what the stage verb wrote", staged))
	}
	if cmd.PlaintextBytes > 0 && byteCount(info.Size()) != cmd.PlaintextBytes {
		return s.failTransfer(ack, proto.BackupRefusalDigestMismatch,
			fmt.Errorf("the staged copy is %d bytes and the stage verb reported %d; it is not the copy the manifest would describe", info.Size(), cmd.PlaintextBytes))
	}
	f, err := os.Open(staged)
	if err != nil {
		return s.failTransfer(ack, proto.StorageRefusalBackendError, err)
	}
	defer func() { _ = f.Close() }()

	// The plaintext is hashed as it is read for sealing — one pass over the
	// file, and the digest the ack reports is over the bytes that were
	// actually sealed rather than the bytes the stage verb saw.
	plainDigest := sha256.New()
	stream := backupxfer.NewSealedStream(io.TeeReader(f, plainDigest), cmd.PublicKey, cmd.KeyID, cmd.Scope)
	defer func() { _ = stream.Close() }()

	rc, err := tr.Put(ctx, backupxfer.PutRequest{
		Destination:     cmd.Destination,
		Generation:      cmd.GenerationID,
		Member:          cmd.Member,
		Credential:      cmd.Credential,
		PlaintextDigest: cmd.PlaintextDigest,
		PlaintextBytes:  cmd.PlaintextBytes,
		Body:            stream,
		Sealed:          stream.Sealed,
	})
	if err != nil {
		var refused *backupxfer.RefusedError
		if errors.As(err, &refused) {
			ack.DestinationCode = refused.Problem.Code
			return s.failTransfer(ack, proto.BackupRefusalDestinationRefused, err)
		}
		// The seal's own error, if it had one, is what the transport saw as
		// a broken body; report it by name.
		if _, serr := stream.Result(); serr != nil && !errors.Is(serr, backupxfer.ErrStreamAbandoned) {
			return s.failTransfer(ack, proto.StorageRefusalBackendError, fmt.Errorf("seal %s: %w", cmd.StagingName, serr))
		}
		return s.failTransfer(ack, proto.BackupRefusalTransferFailed, redactCredential(err, cmd.Credential))
	}
	res, serr := stream.Result()
	if serr != nil || res == nil {
		return s.failTransfer(ack, proto.StorageRefusalBackendError, fmt.Errorf("seal %s: %v", cmd.StagingName, serr))
	}
	gotPlain := hex.EncodeToString(plainDigest.Sum(nil))
	if cmd.PlaintextDigest != "" && !strings.EqualFold(gotPlain, strings.TrimSpace(cmd.PlaintextDigest)) {
		// The member has landed; what is refused is the CLAIM. The api
		// records this as a failed volume rather than indexing a member
		// whose plaintext is not the copy the stage verb described.
		return s.failTransfer(ack, proto.BackupRefusalDigestMismatch,
			fmt.Errorf("the staged copy hashed to %s as it was sealed and the stage verb reported %s; it changed between staging and transfer", gotPlain, cmd.PlaintextDigest))
	}
	if rc.SealedDigest != res.Digest || rc.SealedBytes != res.SizeBytes {
		return s.failTransfer(ack, proto.BackupRefusalDigestMismatch,
			fmt.Errorf("the destination confirmed sha256 %s over %d bytes and this node sealed %s over %d", rc.SealedDigest, rc.SealedBytes, res.Digest, res.SizeBytes))
	}
	ack.OK = true
	ack.Landed = true
	ack.SealedDigest = res.Digest
	ack.SealedBytes = res.SizeBytes
	ack.PlaintextDigest = gotPlain
	ack.PlaintextBytes = res.PlaintextBytes
	ack.Alg = res.Alg
	ack.EphemeralPublicKey = res.EphemeralPublicKey
	return ack
}

func (s *Stager) failTransfer(ack *proto.BackupTransferAck, refusal proto.StorageRefusal, err error) *proto.BackupTransferAck {
	ack.OK = false
	ack.Landed = false
	ack.Refusal = refusal
	ack.Detail = err.Error()
	ack.SealedDigest, ack.SealedBytes = "", 0
	return ack
}

func validateTransfer(root string, cmd proto.BackupTransferCmd) error {
	if strings.TrimSpace(root) == "" {
		return errors.New("this agent has no staging root configured")
	}
	if !proto.BackupValidStagingName(cmd.StagingName) {
		return fmt.Errorf("%q is not a plain file name", cmd.StagingName)
	}
	if strings.TrimSpace(cmd.Destination) == "" {
		return errors.New("the command names no destination")
	}
	if strings.TrimSpace(cmd.Credential) == "" {
		return errors.New("the command carries no upload credential")
	}
	if err := backupxfer.ValidatePublicKey(cmd.PublicKey); err != nil {
		return err
	}
	if strings.TrimSpace(cmd.Scope) == "" {
		return errors.New("the command names no scope; the scope is sealed into the member and cannot be empty")
	}
	if !proto.BackupValidGenerationID(cmd.GenerationID) {
		return fmt.Errorf("%q is not a usable generation id", cmd.GenerationID)
	}
	if !proto.BackupValidMemberPath(cmd.Member) {
		return fmt.Errorf("%q is not a member path", cmd.Member)
	}
	return nil
}

// redactCredential keeps the credential out of an ack. The transport already
// does this for its own errors; this makes it hold for anything wrapped
// around them.
func redactCredential(err error, credential string) error {
	if credential == "" || !strings.Contains(err.Error(), credential) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), credential, "[credential]"))
}
