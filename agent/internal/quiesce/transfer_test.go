package quiesce

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/backupxfer/sealtest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// The transfer verb against the REAL ingest endpoint — the same handler the
// api mounts, from the same module — over a real socket, with the REAL stager
// staging a real volume first. This is the agent's half of the protocol
// functional test; the api's half (api/internal/storage) drives the fan-out
// over NATS against the same endpoint.

const (
	xferGen  = "20260903T120000Z-JOB12345-full"
	xferJob  = "01JOB"
	xferNode = "compute-1"
)

type xferRig struct {
	ingest *backupxfer.Ingest
	srv    *httptest.Server
	genDir string
	dest   string
	priv   *ecdh.PrivateKey
	pubB64 string
}

func newXferRig(t *testing.T) *xferRig {
	t.Helper()
	auth, err := backupxfer.NewAuthority()
	if err != nil {
		t.Fatal(err)
	}
	ing := backupxfer.New(auth, 1)
	mux := http.NewServeMux()
	mux.Handle("PUT "+backupxfer.IngestPathPrefix, ing)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	genDir, err := ing.Open(filepath.Join(t.TempDir(), "generations"), xferGen, xferJob)
	if err != nil {
		t.Fatal(err)
	}
	dest, err := backupxfer.IngestDestination(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &xferRig{ingest: ing, srv: srv, genDir: genDir, dest: dest, priv: priv,
		pubB64: base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())}
}

func (r *xferRig) cred(t *testing.T, member string) string {
	t.Helper()
	tok, err := r.ingest.Mint(backupxfer.Grant{Generation: xferGen, Member: member, NodeID: xferNode, JobID: xferJob}, backupxfer.CredentialTTL)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (r *xferRig) transferCmd(t *testing.T, staged *proto.BackupStageVolumeAck, member string) proto.BackupTransferCmd {
	t.Helper()
	return proto.BackupTransferCmd{
		StagingName: staged.StagingName, Destination: r.dest, Credential: r.cred(t, member),
		PublicKey: r.pubB64, KeyID: "key-1", Scope: proto.BackupScopeFull,
		GenerationID: xferGen, Member: member, AppID: staged.AppID, Volume: staged.Volume,
		PlaintextDigest: staged.Digest, PlaintextBytes: staged.SizeBytes,
	}
}

// stageVault stages a `stop`-strategy volume through the real stager and
// asserts the app is back BEFORE any transfer happens.
func stageVault(t *testing.T, rt *fakeRuntime, s *Stager) *proto.BackupStageVolumeAck {
	t.Helper()
	root := rt.volDir("app-vw", "vaultwarden-data")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "db.sqlite3"), bytes.Repeat([]byte("vault "), 50000), 0o600); err != nil {
		t.Fatal(err)
	}
	rt.running["app-vw"] = true
	ack := s.Stage(context.Background(), stageCmd("app-vw", "vaultwarden-data", tileschema.BackupCritical, tileschema.QuiesceStop, "gen.vol0"))
	if !ack.OK {
		t.Fatalf("stage refused: %s %s", ack.Refusal, ack.Detail)
	}
	if !ack.AppRestored || !rt.isRunning("app-vw") {
		t.Fatal("the app is not running after the stage — the restart contract is settled before transfer exists")
	}
	return ack
}

func TestTransferSealsAndLandsAStagedVolume(t *testing.T) {
	r := newXferRig(t)
	rt := newFake(t)
	s := newStager(t, rt)
	staged := stageVault(t, rt, s)
	member := proto.BackupMemberPath("vaultwarden", "vaultwarden-data")

	ack := s.Transfer(context.Background(), r.transferCmd(t, staged, member))
	if !ack.OK || !ack.Landed {
		t.Fatalf("transfer refused: %s (%s) %s", ack.Refusal, ack.DestinationCode, ack.Detail)
	}
	sealed, err := os.ReadFile(filepath.Join(r.genDir, filepath.FromSlash(member)))
	if err != nil {
		t.Fatalf("the member is not on the target: %v", err)
	}
	sum := sha256.Sum256(sealed)
	if ack.SealedDigest != hex.EncodeToString(sum[:]) || ack.SealedBytes != uint64(len(sealed)) {
		t.Errorf("ack says %s/%d, target holds %s/%d", ack.SealedDigest, ack.SealedBytes, hex.EncodeToString(sum[:]), len(sealed))
	}
	// The member opens to exactly the staged tar, and the ack's plaintext
	// digest is the stage verb's.
	plain, header, err := sealtest.Open(sealed, r.priv)
	if err != nil {
		t.Fatal(err)
	}
	stagedBytes, _ := os.ReadFile(staged.StagedPath)
	if !bytes.Equal(plain, stagedBytes) {
		t.Error("the member does not open to the staged tar")
	}
	if ack.PlaintextDigest != staged.Digest || ack.PlaintextBytes != staged.SizeBytes {
		t.Errorf("plaintext facts %s/%d, stage said %s/%d", ack.PlaintextDigest, ack.PlaintextBytes, staged.Digest, staged.SizeBytes)
	}
	if header.Scope != proto.BackupScopeFull || header.KeyID != "key-1" || ack.Alg != backupxfer.SealAlg || ack.EphemeralPublicKey != header.EphemeralPublicKey {
		t.Errorf("header = %+v, ack = %+v", header, ack)
	}
	if rc, ok := r.ingest.Landed(xferGen, member); !ok || rc.NodeID != xferNode || rc.SealedDigest != ack.SealedDigest {
		t.Error("the endpoint's record disagrees with the ack")
	}
	// Peak disk on the node: the staged tar, and nothing else — no sealed
	// copy was written anywhere under the staging root.
	ents, _ := os.ReadDir(s.stagingRoot)
	if len(ents) != 1 || ents[0].Name() != "gen.vol0" {
		t.Errorf("staging root holds %d entries after transfer; sealing must stream, not copy", len(ents))
	}
	// The staged file is left for unstage — the api's call.
	if u := s.Unstage(proto.BackupUnstageCmd{StagingName: "gen.vol0"}); !u.OK || !u.Existed {
		t.Errorf("unstage = %+v", u)
	}
	// And the credential is spent: a second transfer of the same member is
	// refused by the endpoint, whatever the agent does.
	staged2 := stageVault(t, rt, s)
	if ack2 := s.Transfer(context.Background(), r.transferCmd(t, staged2, member)); ack2.OK || ack2.DestinationCode != backupxfer.CodeMemberExists {
		t.Errorf("a replay landed or was refused with the wrong code: %+v", ack2)
	}
}

func TestTransferRefusalsLeaveTheAppRunningAndTheStageIntact(t *testing.T) {
	r := newXferRig(t)
	rt := newFake(t)
	s := newStager(t, rt)
	staged := stageVault(t, rt, s)
	member := proto.BackupMemberPath("vaultwarden", "vaultwarden-data")
	other := proto.BackupMemberPath("paperless", "paperless-data")

	cases := []struct {
		name    string
		mutate  func(*proto.BackupTransferCmd)
		refusal proto.StorageRefusal
		code    string
	}{
		{"credential scoped to another member", func(c *proto.BackupTransferCmd) { c.Credential = r.cred(t, other) }, proto.BackupRefusalDestinationRefused, backupxfer.CodeCredentialScope},
		{"garbage credential", func(c *proto.BackupTransferCmd) { c.Credential = "rbx1.nope.nope" }, proto.BackupRefusalDestinationRefused, backupxfer.CodeCredentialInvalid},
		{"no credential", func(c *proto.BackupTransferCmd) { c.Credential = "" }, proto.BackupRefusalStagingMissing, ""},
		{"s3 destination", func(c *proto.BackupTransferCmd) { c.Destination = "s3://bucket/prefix" }, proto.BackupRefusalDestinationUnsupported, ""},
		{"unreachable destination", func(c *proto.BackupTransferCmd) { c.Destination = "http://127.0.0.1:1/api/backup/ingest/" }, proto.BackupRefusalTransferFailed, ""},
		{"staging name that is a path", func(c *proto.BackupTransferCmd) { c.StagingName = "../etc/shadow" }, proto.BackupRefusalStagingMissing, ""},
		{"staged file missing", func(c *proto.BackupTransferCmd) { c.StagingName = "gen.vol9" }, proto.BackupRefusalStagingMissing, ""},
		{"member that is not one", func(c *proto.BackupTransferCmd) { c.Member = "archive.rasputin-archive" }, proto.BackupRefusalStagingMissing, ""},
		{"bad public key", func(c *proto.BackupTransferCmd) { c.PublicKey = "AAAA" }, proto.BackupRefusalStagingMissing, ""},
		{"empty scope", func(c *proto.BackupTransferCmd) { c.Scope = "" }, proto.BackupRefusalStagingMissing, ""},
		{"staged size disagrees with the stage ack", func(c *proto.BackupTransferCmd) { c.PlaintextBytes = 7 }, proto.BackupRefusalDigestMismatch, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := r.transferCmd(t, staged, member)
			tc.mutate(&cmd)
			ack := s.Transfer(context.Background(), cmd)
			if ack.OK || ack.Landed {
				t.Fatalf("landed: %+v", ack)
			}
			if ack.Refusal != tc.refusal || ack.DestinationCode != tc.code {
				t.Errorf("refusal = %s/%s, want %s/%s: %s", ack.Refusal, ack.DestinationCode, tc.refusal, tc.code, ack.Detail)
			}
			if strings.Contains(ack.Detail, cmd.Credential) && cmd.Credential != "" {
				t.Error("the credential is in the ack")
			}
			if !rt.isRunning("app-vw") {
				t.Fatal("a transfer refusal touched the app")
			}
			if _, err := os.Stat(staged.StagedPath); err != nil {
				t.Fatal("a transfer refusal removed the staged copy; the api retries the upload without re-quiescing and needs it")
			}
			if _, err := os.Stat(filepath.Join(r.genDir, filepath.FromSlash(member))); err == nil {
				t.Fatal("a member landed despite the refusal")
			}
		})
	}
}

// TestTransferSurvivesTheDestinationDyingMidUpload: the connection is cut
// while the body is streaming. The verb reports a transport failure, the app
// is untouched (it was restarted at stage time), the staged copy is intact
// for a retry, and no partial member exists on the target.
func TestTransferSurvivesTheDestinationDyingMidUpload(t *testing.T) {
	r := newXferRig(t)
	rt := newFake(t)
	s := newStager(t, rt)
	staged := stageVault(t, rt, s)
	member := proto.BackupMemberPath("vaultwarden", "vaultwarden-data")

	// A proxy in front of the real endpoint that forwards the first few KiB
	// of the request and then drops both sides.
	upstream, _ := net.Dial("tcp", strings.TrimPrefix(r.srv.URL, "http://"))
	_ = upstream.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		up, err := net.Dial("tcp", strings.TrimPrefix(r.srv.URL, "http://"))
		if err != nil {
			_ = c.Close()
			return
		}
		// Client → upstream for 64 KiB, upstream → client throughout (so
		// the 100 Continue reaches the client), then cut everything.
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := up.Read(buf)
				if n > 0 {
					_, _ = c.Write(buf[:n])
				}
				if err != nil {
					return
				}
			}
		}()
		buf := make([]byte, 4096)
		forwarded := 0
		for forwarded < 64<<10 {
			n, err := c.Read(buf)
			if n > 0 {
				_, _ = up.Write(buf[:n])
				forwarded += n
			}
			if err != nil {
				break
			}
		}
		_ = up.Close()
		_ = c.Close()
	}()
	cmd := r.transferCmd(t, staged, member)
	cmd.Destination = "http://" + ln.Addr().String() + backupxfer.IngestPathPrefix
	ack := s.Transfer(context.Background(), cmd)
	if ack.OK || ack.Landed {
		t.Fatalf("a torn upload was reported landed: %+v", ack)
	}
	if ack.Refusal != proto.BackupRefusalTransferFailed {
		t.Errorf("refusal = %s (%s): %s", ack.Refusal, ack.DestinationCode, ack.Detail)
	}
	if !rt.isRunning("app-vw") {
		t.Fatal("the app is down after a torn upload; the restart contract must not depend on the transfer")
	}
	if _, err := os.Stat(staged.StagedPath); err != nil {
		t.Fatal("the staged copy is gone; a retry would have to re-quiesce")
	}
	// The endpoint's side: no partial, no record, and the retry lands.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, ok := r.ingest.Landed(xferGen, member); ok {
			t.Fatal("the endpoint recorded a member that never finished")
		}
		left := false
		_ = filepath.Walk(r.genDir, func(p string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				left = true
			}
			return nil
		})
		if !left || time.Now().After(deadline) {
			if left {
				t.Fatal("a partial member is on the target after a torn upload")
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	retry := s.Transfer(context.Background(), r.transferCmd(t, staged, member))
	if !retry.OK {
		t.Fatalf("the retry on a fresh credential failed: %s %s", retry.Refusal, retry.Detail)
	}
}

func TestTransferRefusesAStagedCopyThatChangedSinceStaging(t *testing.T) {
	r := newXferRig(t)
	rt := newFake(t)
	s := newStager(t, rt)
	staged := stageVault(t, rt, s)
	member := proto.BackupMemberPath("vaultwarden", "vaultwarden-data")
	// Same length, different bytes: the size check passes and the inline
	// plaintext hash is what catches it.
	b, _ := os.ReadFile(staged.StagedPath)
	b[len(b)/2] ^= 0xff
	if err := os.WriteFile(staged.StagedPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	ack := s.Transfer(context.Background(), r.transferCmd(t, staged, member))
	if ack.OK || ack.Refusal != proto.BackupRefusalDigestMismatch {
		t.Fatalf("ack = %+v", ack)
	}
	if !errors.Is(context.Background().Err(), nil) {
		t.Fatal("unreachable")
	}
}
