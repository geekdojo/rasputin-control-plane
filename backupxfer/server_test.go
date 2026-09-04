package backupxfer_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/backupxfer/sealtest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The protocol, end to end: the real HTTP transport against the real ingest
// endpoint, over a real socket, onto a real directory. Every refusal the
// package doc promises is exercised here as a request, not as a unit.

const (
	genID  = "20260903T120000Z-JOB12345-full"
	jobID  = "01JOB"
	nodeID = "e3bench-compute1"
	memVW  = "volumes/vaultwarden/vaultwarden-data.rasputin-archive"
	memPL  = "volumes/paperless/paperless-data.rasputin-archive"
)

type rig struct {
	t       *testing.T
	ingest  *backupxfer.Ingest
	srv     *httptest.Server
	gensDir string
	genDir  string
	key     testKeypair
	dest    string
}

func newRig(t *testing.T, concurrency int) *rig {
	t.Helper()
	auth, err := backupxfer.NewAuthority()
	if err != nil {
		t.Fatal(err)
	}
	ing := backupxfer.New(auth, concurrency)
	mux := http.NewServeMux()
	mux.Handle("PUT "+backupxfer.IngestPathPrefix, ing)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	gens := filepath.Join(t.TempDir(), "mnt", "generations")
	dir, err := ing.Open(gens, genID, jobID)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	dest, err := backupxfer.IngestDestination(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &rig{t: t, ingest: ing, srv: srv, gensDir: gens, genDir: dir, key: newTestKeypair(t), dest: dest}
}

func (r *rig) mint(member string) string {
	r.t.Helper()
	tok, err := r.ingest.Mint(backupxfer.Grant{Generation: genID, Member: member, NodeID: nodeID, JobID: jobID, MaxBytes: 1 << 30}, backupxfer.CredentialTTL)
	if err != nil {
		r.t.Fatalf("Mint: %v", err)
	}
	return tok
}

func (r *rig) transport() backupxfer.Transport {
	tr, err := backupxfer.TransportFor(r.dest, backupxfer.HTTPOptions{AcceptWait: 5 * time.Second})
	if err != nil {
		r.t.Fatal(err)
	}
	return tr
}

// put streams a fresh seal of plaintext for member on cred, the way the agent
// does — through a pipe, digest in the trailer.
func (r *rig) put(ctx context.Context, cred, member string, plaintext []byte) (*backupxfer.Receipt, error) {
	stream := backupxfer.NewSealedStream(bytes.NewReader(plaintext), r.key.publicB64, "key-1", proto.BackupScopeFull)
	sum := sha256.Sum256(plaintext)
	return r.transport().Put(ctx, backupxfer.PutRequest{
		Destination: r.dest, Generation: genID, Member: member, Credential: cred,
		PlaintextDigest: hex.EncodeToString(sum[:]), PlaintextBytes: uint64(len(plaintext)),
		Body: stream, Sealed: stream.Sealed,
	})
}

func (r *rig) memberPath(member string) string {
	return filepath.Join(r.genDir, filepath.FromSlash(member))
}

// noPartials asserts nothing but landed members sits under the generation.
func (r *rig) noPartials() {
	r.t.Helper()
	_ = filepath.Walk(r.genDir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasPrefix(info.Name(), ".upload-") {
			r.t.Errorf("a partial upload is left on the target: %s", p)
		}
		return nil
	})
}

// waitForNoPartials polls for the endpoint's cleanup after a torn connection.
func (r *rig) waitForNoPartials(within time.Duration) {
	r.t.Helper()
	deadline := time.Now().Add(within)
	for {
		found := false
		_ = filepath.Walk(r.genDir, func(p string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() && strings.HasPrefix(info.Name(), ".upload-") {
				found = true
			}
			return nil
		})
		if !found || time.Now().After(deadline) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func refusedWith(t *testing.T, err error, code string) {
	t.Helper()
	var re *backupxfer.RefusedError
	if !errors.As(err, &re) {
		t.Fatalf("err = %v, want a refusal with code %s", err, code)
	}
	if re.Problem.Code != code {
		t.Fatalf("refused with %s (%d: %s), want %s", re.Problem.Code, re.Status, re.Problem.Detail, code)
	}
}

func TestIngestLandsAMemberAndRecordsIt(t *testing.T) {
	r := newRig(t, 1)
	plaintext := bytes.Repeat([]byte("vault "), 100000)
	rc, err := r.put(context.Background(), r.mint(memVW), memVW, plaintext)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if rc.Generation != genID || rc.Member != memVW || rc.NodeID != nodeID || rc.KeyID != "key-1" || rc.Scope != proto.BackupScopeFull {
		t.Errorf("receipt = %+v", rc)
	}
	sealed, err := os.ReadFile(r.memberPath(memVW))
	if err != nil {
		t.Fatalf("the member is not on the target: %v", err)
	}
	sum := sha256.Sum256(sealed)
	if rc.SealedDigest != hex.EncodeToString(sum[:]) || rc.SealedBytes != uint64(len(sealed)) {
		t.Errorf("receipt digest %s/%d does not match the bytes on the target %s/%d", rc.SealedDigest, rc.SealedBytes, hex.EncodeToString(sum[:]), len(sealed))
	}
	plain, _, err := sealtest.Open(sealed, r.key.priv)
	if err != nil || !bytes.Equal(plain, plaintext) {
		t.Errorf("the member on the target does not open to the plaintext: %v", err)
	}
	if got, ok := r.ingest.Landed(genID, memVW); !ok || got.SealedDigest != rc.SealedDigest {
		t.Error("the endpoint's own record does not name the member it just landed")
	}
	psum := sha256.Sum256(plaintext)
	if rc.PlaintextDigest != hex.EncodeToString(psum[:]) || rc.PlaintextBytes != uint64(len(plaintext)) {
		t.Errorf("plaintext facts on the receipt = %s/%d", rc.PlaintextDigest, rc.PlaintextBytes)
	}
	r.noPartials()
	if st, err := os.Stat(r.memberPath(memVW)); err == nil && st.Mode().Perm() != 0o600 {
		t.Errorf("member mode = %v", st.Mode())
	}
}

func TestIngestRefusesASecondMemberOnTheFirstsCredential(t *testing.T) {
	r := newRig(t, 1)
	cred := r.mint(memVW)
	_, err := r.put(context.Background(), cred, memPL, []byte("paperless"))
	refusedWith(t, err, backupxfer.CodeCredentialScope)
	if _, err := os.Stat(r.memberPath(memPL)); err == nil {
		t.Fatal("a member landed on a credential scoped to another member")
	}
	// And the credential is still good for what it was minted for.
	if _, err := r.put(context.Background(), cred, memVW, []byte("vault")); err != nil {
		t.Fatalf("the credential's own member was refused after a mis-scoped attempt: %v", err)
	}
}

func TestIngestRefusesAnExpiredOrForgedCredential(t *testing.T) {
	r := newRig(t, 1)
	short, err := r.ingest.Mint(backupxfer.Grant{Generation: genID, Member: memVW, NodeID: nodeID, JobID: jobID, MaxBytes: 1 << 30}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	_, err = r.put(context.Background(), short, memVW, []byte("late"))
	refusedWith(t, err, backupxfer.CodeCredentialExpired)

	other, _ := backupxfer.NewAuthority()
	forged, _ := other.Mint(backupxfer.Grant{Generation: genID, Member: memVW, NodeID: nodeID, JobID: jobID, MaxBytes: 1 << 30}, time.Minute)
	_, err = r.put(context.Background(), forged, memVW, []byte("forged"))
	refusedWith(t, err, backupxfer.CodeCredentialInvalid)
	_, err = r.put(context.Background(), "garbage", memVW, []byte("garbage"))
	refusedWith(t, err, backupxfer.CodeCredentialInvalid)
	if _, err := os.Stat(r.memberPath(memVW)); err == nil {
		t.Fatal("a member landed on a bad credential")
	}
}

func TestIngestRefusesReplayAfterTheMemberLands(t *testing.T) {
	r := newRig(t, 1)
	cred := r.mint(memVW)
	if _, err := r.put(context.Background(), cred, memVW, []byte("first")); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(r.memberPath(memVW))
	_, err := r.put(context.Background(), cred, memVW, []byte("second, different bytes"))
	refusedWith(t, err, backupxfer.CodeMemberExists)
	// A FRESH credential for the same member is refused too: the member
	// exists, and members are never overwritten.
	_, err = r.put(context.Background(), r.mint(memVW), memVW, []byte("third"))
	refusedWith(t, err, backupxfer.CodeMemberExists)
	after, _ := os.ReadFile(r.memberPath(memVW))
	if !bytes.Equal(before, after) {
		t.Fatal("the landed member changed under a replay")
	}
	r.noPartials()
}

func TestIngestRefusesACredentialForAClosedRun(t *testing.T) {
	r := newRig(t, 1)
	cred := r.mint(memVW)
	r.ingest.Close(genID)
	_, err := r.put(context.Background(), cred, memVW, []byte("late"))
	refusedWith(t, err, backupxfer.CodeNoGeneration)
	// Nor can one be minted for a run that is not open.
	if _, err := r.ingest.Mint(backupxfer.Grant{Generation: genID, Member: memVW, NodeID: nodeID, JobID: "other", MaxBytes: 1 << 30}, time.Minute); err == nil {
		t.Error("a credential was minted for a run that has no generation open")
	}
	if _, err := r.ingest.Mint(backupxfer.Grant{Generation: "20260903T120000Z-OTHER-full", Member: memVW, NodeID: nodeID, JobID: jobID, MaxBytes: 1 << 30}, time.Minute); err == nil {
		t.Error("a credential was minted for a generation that is not open")
	}
}

// TestIngestRefusesAMemberThatEscapesTheGeneration: the containment check,
// hit with raw requests because the client refuses to build these URLs.
func TestIngestRefusesAMemberThatEscapesTheGeneration(t *testing.T) {
	r := newRig(t, 1)
	cred := r.mint(memVW)
	escape := filepath.Join(r.gensDir, "..", "escaped.rasputin-archive")
	for _, path := range []string{
		backupxfer.IngestPathPrefix + genID + "/volumes/../../escaped.rasputin-archive",
		backupxfer.IngestPathPrefix + genID + "/../escaped.rasputin-archive",
		backupxfer.IngestPathPrefix + genID + "/archive.rasputin-archive",
		backupxfer.IngestPathPrefix + genID + "/manifest.json",
		backupxfer.IngestPathPrefix + genID + "/volumes/vaultwarden/.upload-x.rasputin-archive",
		backupxfer.IngestPathPrefix + "../" + genID + "/" + memVW,
		backupxfer.IngestPathPrefix + genID + "/volumes/vaultwarden/vaultwarden-data.rasputin-archive/",
	} {
		req := httptest.NewRequest(http.MethodPut, "http://ingest"+path, strings.NewReader("x"))
		req.URL.Path = path // keep the raw path; httptest cleans it
		req.Header.Set("Authorization", "Bearer "+cred)
		w := httptest.NewRecorder()
		r.ingest.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest && w.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want a refusal", path, w.Code)
		}
	}
	if _, err := os.Stat(escape); err == nil {
		t.Fatal("a file was written outside the generation directory")
	}
	// A symlink planted where the app directory goes must not be followed.
	elsewhere := t.TempDir()
	if err := os.MkdirAll(filepath.Join(r.genDir, "volumes"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(r.genDir, "volumes", "vaultwarden")); err != nil {
		t.Fatal(err)
	}
	_, err := r.put(context.Background(), cred, memVW, []byte("through the link"))
	refusedWith(t, err, backupxfer.CodeWriteFailed)
	if ents, _ := os.ReadDir(elsewhere); len(ents) != 0 {
		t.Fatalf("the endpoint wrote through a planted symlink: %v", ents)
	}
}

func TestIngestRefusesABodyThatIsNotASealedArchive(t *testing.T) {
	r := newRig(t, 1)
	body := bytes.NewReader([]byte("SQLite format 3\x00 and a lot of clear text"))
	_, err := r.transport().Put(context.Background(), backupxfer.PutRequest{
		Destination: r.dest, Generation: genID, Member: memVW, Credential: r.mint(memVW),
		Body: body, Sealed: func() (string, uint64) { return strings.Repeat("0", 64), 1 },
	})
	refusedWith(t, err, backupxfer.CodeNotAnArchive)
	if _, err := os.Stat(r.memberPath(memVW)); err == nil {
		t.Fatal("a clear-text body landed as a member")
	}
	r.noPartials()
}

func TestIngestRefusesADigestTheBytesDoNotMatch(t *testing.T) {
	r := newRig(t, 1)
	stream := backupxfer.NewSealedStream(bytes.NewReader([]byte("honest bytes")), r.key.publicB64, "key-1", proto.BackupScopeFull)
	_, err := r.transport().Put(context.Background(), backupxfer.PutRequest{
		Destination: r.dest, Generation: genID, Member: memVW, Credential: r.mint(memVW),
		Body: stream, Sealed: func() (string, uint64) { return strings.Repeat("a", 64), 12 },
	})
	refusedWith(t, err, backupxfer.CodeDigestMismatch)
	if _, err := os.Stat(r.memberPath(memVW)); err == nil {
		t.Fatal("a member whose declared digest did not match landed")
	}
	if _, ok := r.ingest.Landed(genID, memVW); ok {
		t.Fatal("the endpoint recorded a member it discarded")
	}
	r.noPartials()
}

// failingReader delivers n bytes then fails, which makes net/http abort the
// request mid-body — what an agent dying looks like from the endpoint.
type failingReader struct {
	r    io.Reader
	left int
}

func (f *failingReader) Read(p []byte) (int, error) {
	if f.left <= 0 {
		return 0, errors.New("agent died mid-upload")
	}
	if len(p) > f.left {
		p = p[:f.left]
	}
	n, err := f.r.Read(p)
	f.left -= n
	return n, err
}

func TestIngestLeavesNoPartialMemberWhenTheUploadDies(t *testing.T) {
	r := newRig(t, 1)
	var sealed bytes.Buffer
	if _, err := backupxfer.Seal(&sealed, bytes.NewReader(bytes.Repeat([]byte("z"), 300<<10)), r.key.publicB64, "key-1", proto.BackupScopeFull); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(sealed.Bytes())
	cred := r.mint(memVW)
	_, err := r.transport().Put(context.Background(), backupxfer.PutRequest{
		Destination: r.dest, Generation: genID, Member: memVW, Credential: cred,
		Body:   &failingReader{r: bytes.NewReader(sealed.Bytes()), left: 100 << 10},
		Sealed: func() (string, uint64) { return hex.EncodeToString(sum[:]), uint64(sealed.Len()) },
	})
	if err == nil {
		t.Fatal("an upload that died mid-body was reported as landed")
	}
	// The client's error returns before the endpoint has seen the EOF; give
	// the handler a moment to finish tearing down. What is asserted is the
	// state it leaves, not the instant it leaves it.
	r.waitForNoPartials(2 * time.Second)
	if _, err := os.Stat(r.memberPath(memVW)); err == nil {
		t.Fatal("a partial member is visible on the target")
	}
	if _, ok := r.ingest.Landed(genID, memVW); ok {
		t.Fatal("the endpoint recorded a member that never finished")
	}
	r.noPartials()
	// The slot was released with the connection, and a retry — a fresh
	// credential, §4.7's "retry without re-quiescing" — lands.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := r.put(ctx, r.mint(memVW), memVW, []byte("retry")); err != nil {
		t.Fatalf("the retry after a dead upload failed: %v — the slot leaked", err)
	}
}

// countingReader records whether the body was ever read.
type countingReader struct {
	r     io.Reader
	reads atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	c.reads.Add(1)
	return c.r.Read(p)
}

func TestIngestRefusesBeforeABodyByteIsSent(t *testing.T) {
	r := newRig(t, 1)
	body := &countingReader{r: strings.NewReader("never sent")}
	_, err := r.transport().Put(context.Background(), backupxfer.PutRequest{
		Destination: r.dest, Generation: genID, Member: memPL, Credential: r.mint(memVW),
		Body: body, Sealed: func() (string, uint64) { return "", 0 },
	})
	refusedWith(t, err, backupxfer.CodeCredentialScope)
	if body.reads.Load() != 0 {
		t.Errorf("the body was read %d time(s) for a request the endpoint refused; Expect: 100-continue is not in effect", body.reads.Load())
	}
}

// gatedReader blocks its first read until released, so one upload can be held
// mid-body while another queues behind it.
type gatedReader struct {
	r       io.Reader
	release chan struct{}
	reads   atomic.Int64
}

func (g *gatedReader) Read(p []byte) (int, error) {
	if g.reads.Add(1) == 1 {
		<-g.release
	}
	return g.r.Read(p)
}

func TestIngestBackpressureIsTheConnection(t *testing.T) {
	r := newRig(t, 1)
	seal := func(s string) ([]byte, string) {
		var b bytes.Buffer
		res, err := backupxfer.Seal(&b, strings.NewReader(s), r.key.publicB64, "key-1", proto.BackupScopeFull)
		if err != nil {
			t.Fatal(err)
		}
		return b.Bytes(), res.Digest
	}
	first, firstDigest := seal("first, holding the slot")
	second, secondDigest := seal("second, queued")
	gate := &gatedReader{r: bytes.NewReader(first), release: make(chan struct{})}
	firstDone := make(chan error, 1)
	go func() {
		_, err := r.transport().Put(context.Background(), backupxfer.PutRequest{
			Destination: r.dest, Generation: genID, Member: memVW, Credential: r.mint(memVW),
			Body: gate, Sealed: func() (string, uint64) { return firstDigest, uint64(len(first)) },
		})
		firstDone <- err
	}()
	// Wait until the first upload holds the slot (its body has been asked for).
	deadline := time.Now().Add(5 * time.Second)
	for gate.reads.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the first upload never reached its body")
		}
		time.Sleep(10 * time.Millisecond)
	}
	queued := &countingReader{r: bytes.NewReader(second)}
	secondDone := make(chan error, 1)
	go func() {
		_, err := r.transport().Put(context.Background(), backupxfer.PutRequest{
			Destination: r.dest, Generation: genID, Member: memPL, Credential: r.mint(memPL),
			Body: queued, Sealed: func() (string, uint64) { return secondDigest, uint64(len(second)) },
		})
		secondDone <- err
	}()
	time.Sleep(300 * time.Millisecond)
	if queued.reads.Load() != 0 {
		t.Fatal("the second upload sent body bytes while the first held the only slot")
	}
	close(gate.release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second, after the slot freed: %v", err)
	}
	for _, m := range []string{memVW, memPL} {
		if _, ok := r.ingest.Landed(genID, m); !ok {
			t.Errorf("%s did not land", m)
		}
	}
}

func TestIngestAbandonRemovesThePartialGenerationOnly(t *testing.T) {
	r := newRig(t, 1)
	if _, err := r.put(context.Background(), r.mint(memVW), memVW, []byte("v")); err != nil {
		t.Fatal(err)
	}
	// A committed generation beside it must survive.
	committed := filepath.Join(r.gensDir, "20260901T000000Z-OLD-full")
	if err := os.MkdirAll(committed, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := r.ingest.Abandon(genID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(r.genDir); !errors.Is(err, os.ErrNotExist) {
		t.Error("the partial generation is still on the target")
	}
	if _, err := os.Stat(committed); err != nil {
		t.Error("Abandon removed a committed generation")
	}
	if _, _, open := r.ingest.OpenGeneration(); open {
		t.Error("a generation is still open after Abandon")
	}
	// Reopening works; opening while one is open does not.
	if _, err := r.ingest.Open(r.gensDir, genID, jobID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ingest.Open(r.gensDir, "20260903T130000Z-NEXT-full", "02JOB"); err == nil {
		t.Error("two generations open at once")
	}
}

func TestTransportForRefusesWhatItCannotSpeak(t *testing.T) {
	if _, err := backupxfer.TransportFor("s3://bucket/prefix", backupxfer.HTTPOptions{}); !errors.Is(err, backupxfer.ErrUnsupportedDestination) {
		t.Errorf("s3: %v", err)
	}
	if _, err := backupxfer.TransportFor("ftp://x", backupxfer.HTTPOptions{}); !errors.Is(err, backupxfer.ErrUnsupportedDestination) {
		t.Errorf("ftp: %v", err)
	}
	if _, err := backupxfer.IngestDestination("not a url"); err == nil {
		t.Error("a non-URL base was accepted")
	}
	if u, err := backupxfer.MemberURL("https://rasputin.local/api/backup/ingest/", genID, memVW); err != nil ||
		u != "https://rasputin.local/api/backup/ingest/"+genID+"/"+memVW {
		t.Errorf("MemberURL = %q, %v", u, err)
	}
}

// TestIngestRefusesMoreBytesThanTheCredentialAuthorises: a credential minted
// for a small member cannot be used to stream a large one — the blast radius
// of a leaked credential is bounded in bytes as well as in name.
func TestIngestRefusesMoreBytesThanTheCredentialAuthorises(t *testing.T) {
	r := newRig(t, 1)
	small := []byte("a small volume")
	bound := backupxfer.SealedSizeBound(uint64(len(small)))
	cred, err := r.ingest.Mint(backupxfer.Grant{Generation: genID, Member: memVW, NodeID: nodeID, JobID: jobID, MaxBytes: bound}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// A seal of the small volume fits the bound exactly as minted.
	if _, err := r.put(context.Background(), cred, memVW, small); err != nil {
		t.Fatalf("the member the credential was minted for was refused: %v", err)
	}
	// A seal of something far larger, on a credential for the small one,
	// is cut off at the bound and discarded.
	big := bytes.Repeat([]byte("x"), 2<<20)
	cred2, _ := r.ingest.Mint(backupxfer.Grant{Generation: genID, Member: memPL, NodeID: nodeID, JobID: jobID, MaxBytes: bound}, time.Minute)
	_, err = r.put(context.Background(), cred2, memPL, big)
	refusedWith(t, err, backupxfer.CodeOverBound)
	if _, err := os.Stat(r.memberPath(memPL)); err == nil {
		t.Fatal("an over-bound upload landed")
	}
	r.waitForNoPartials(2 * time.Second)
	r.noPartials()
	if _, err := r.ingest.Mint(backupxfer.Grant{Generation: genID, Member: memPL, NodeID: nodeID, JobID: jobID}, time.Minute); err == nil {
		t.Error("a credential with no byte bound was minted")
	}
}

// A restore credential — valid, signed by the same authority, naming this very
// member — is refused by the ingest endpoint: it may fetch, never land. The
// other direction is the api's restore endpoint's test.
func TestIngestRefusesARestoreCredential(t *testing.T) {
	r := newRig(t, 1)
	tok, err := r.ingest.Authority().Mint(backupxfer.Grant{
		Generation: genID, Member: memVW, NodeID: nodeID, JobID: jobID, MaxBytes: 1 << 30, Use: backupxfer.UseRestore,
	}, backupxfer.RestoreCredentialTTL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.put(context.Background(), tok, memVW, []byte("plaintext"))
	var refused *backupxfer.RefusedError
	if !errors.As(err, &refused) || refused.Problem.Code != backupxfer.CodeCredentialScope || refused.Status != http.StatusForbidden {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(r.memberPath(memVW)); err == nil {
		t.Fatal("the member landed on a restore credential")
	}
	r.noPartials()
}
