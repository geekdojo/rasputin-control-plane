package storage

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// timeNow is a one-word alias so the schedule cases read as prose.
func timeNow() time.Time { return time.Now().UTC() }

// §4.6's write path, tested from both sides.
//
// The DECRYPTION lives here, in the test binary, and nowhere else — which is
// the property under test as much as it is a means of testing. The api seals to
// a public key and holds no private key; a package-level opener would be a
// private-key consumer in exactly the process §4.6 says must not have one.
// Restore is a separate, interactive path (§4.5 unpacks before the api's first
// start), and it is where an opener belongs.

// openSealed is the reader half of Seal, implemented independently against the
// documented format so a bug shared between a writer and its own reader cannot
// hide.
func openSealed(t *testing.T, sealedBytes []byte, priv *ecdh.PrivateKey) ([]byte, sealHeader) {
	t.Helper()
	if !bytes.HasPrefix(sealedBytes, []byte(SealMagic)) {
		t.Fatalf("sealed archive does not start with the magic; got %q", firstBytes(sealedBytes, len(SealMagic)))
	}
	rest := sealedBytes[len(SealMagic):]
	nl := bytes.IndexByte(rest, '\n')
	if nl < 0 {
		t.Fatal("sealed archive has no header line")
	}
	headerBytes := rest[:nl]
	body := rest[nl+1:]

	var h sealHeader
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		t.Fatalf("header is not JSON: %v", err)
	}
	epkRaw, err := base64.RawURLEncoding.DecodeString(h.EphemeralPublicKey)
	if err != nil {
		t.Fatalf("epk: %v", err)
	}
	epk, err := ecdh.X25519().NewPublicKey(epkRaw)
	if err != nil {
		t.Fatalf("epk: %v", err)
	}
	shared, err := priv.ECDH(epk)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	salt := append(append([]byte{}, epkRaw...), priv.PublicKey().Bytes()...)
	key, err := hkdf.Key(sha256.New, shared, salt, sealInfo, chacha20poly1305.KeySize)
	if err != nil {
		t.Fatalf("hkdf: %v", err)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("aead: %v", err)
	}

	var plain []byte
	nonce := make([]byte, chacha20poly1305.NonceSize)
	chunk := h.ChunkSize + aead.Overhead()
	var counter uint64
	sawLast := false
	for len(body) > 0 {
		n := chunk
		last := false
		if len(body) < chunk {
			n = len(body)
			last = true
		}
		for {
			for i := range nonce {
				nonce[i] = 0
			}
			binary.BigEndian.PutUint64(nonce[0:8], counter)
			if last {
				nonce[8] = 1
			}
			out, derr := aead.Open(nil, nonce, body[:n], headerBytes)
			if derr == nil {
				plain = append(plain, out...)
				sawLast = last
				break
			}
			if last {
				t.Fatalf("chunk %d failed to open: %v", counter, derr)
			}
			// A full-sized final chunk: retry with the last flag set.
			last = true
		}
		body = body[n:]
		counter++
	}
	if !sawLast {
		t.Error("no chunk carried the last-chunk flag; a truncated archive would be indistinguishable from a complete one")
	}
	return plain, h
}

func firstBytes(b []byte, n int) string {
	if len(b) < n {
		n = len(b)
	}
	return string(b[:n])
}

// TestSealRoundTripsAndDigestMatches is the core §4.6 assertion: an archive
// sealed to a public key opens with the matching private key, and the digest the
// api recorded is a digest of the bytes it actually wrote.
func TestSealRoundTripsAndDigestMatches(t *testing.T) {
	key := newTestKeypair(t)
	plaintext := bytes.Repeat([]byte("the mesh CA and every bus token, in clear. "), 5000)

	var out bytes.Buffer
	res, err := Seal(&out, bytes.NewReader(plaintext), key.publicB64, "key-1", proto.BackupScopeIdentityOnly)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	sum := sha256.Sum256(out.Bytes())
	if res.Digest != hex.EncodeToString(sum[:]) {
		t.Errorf("digest = %s, but the sealed bytes hash to %s — the agent re-hashes before it writes, so a wrong digest is a refused generation",
			res.Digest, hex.EncodeToString(sum[:]))
	}
	if res.SizeBytes != uint64(out.Len()) {
		t.Errorf("size = %d, sealed %d bytes", res.SizeBytes, out.Len())
	}
	if res.PlaintextBytes != uint64(len(plaintext)) {
		t.Errorf("plaintextBytes = %d, want %d", res.PlaintextBytes, len(plaintext))
	}
	if res.Alg != SealAlg {
		t.Errorf("alg = %q, want %q", res.Alg, SealAlg)
	}

	// The ciphertext must not be the plaintext. Obvious, and worth an
	// assertion: a construction that silently degraded to a copy would still
	// round-trip through a decoder that also degraded.
	if bytes.Contains(out.Bytes(), plaintext[:64]) {
		t.Fatal("the sealed archive contains its own plaintext")
	}

	got, header := openSealed(t, out.Bytes(), key.priv)
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round trip produced %d bytes, want %d", len(got), len(plaintext))
	}
	if header.KeyID != "key-1" {
		t.Errorf("header keyId = %q", header.KeyID)
	}
	if header.Scope != proto.BackupScopeIdentityOnly {
		t.Errorf("header scope = %q — the scope has to be INSIDE the sealed archive, where nobody holding the disk can edit it", header.Scope)
	}
	if header.EphemeralPublicKey == key.publicB64 {
		t.Error("the ephemeral public key equals the recipient's: no fresh keypair was minted")
	}
}

// TestSealMintsAFreshEphemeralKeyPerRun is §4.6's "fresh ephemeral key per run".
//
// Two seals of identical plaintext to the same recipient must produce different
// ciphertext. If they did not, the STREAM construction's nonce counter would be
// reused across runs under one content key, which is the failure mode that
// makes a chunked AEAD unsafe.
func TestSealMintsAFreshEphemeralKeyPerRun(t *testing.T) {
	key := newTestKeypair(t)
	plaintext := []byte("identical input, twice")

	var a, b bytes.Buffer
	ra, err := Seal(&a, bytes.NewReader(plaintext), key.publicB64, "key-1", "")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	rb, err := Seal(&b, bytes.NewReader(plaintext), key.publicB64, "key-1", "")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if ra.EphemeralPublicKey == rb.EphemeralPublicKey {
		t.Fatal("two runs used the same ephemeral key: nonces would repeat under one content key")
	}
	if bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("two seals of the same plaintext produced identical archives")
	}
	if ra.Digest == rb.Digest {
		t.Fatal("two seals produced the same digest")
	}
}

// TestSealRefusesWithoutAUsablePublicKey covers the branch that must never
// fall back to writing in clear.
func TestSealRefusesWithoutAUsablePublicKey(t *testing.T) {
	cases := []struct {
		name string
		key  string
		want string
	}{
		{"no key at all", "", "no archive public key"},
		{"not base64url", "!!!!not base64!!!!", "base64url"},
		{"wrong length", base64.RawURLEncoding.EncodeToString([]byte("short")), "X25519 public key is"},
		{"all zeroes", base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "all zeroes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			_, err := Seal(&out, strings.NewReader("secrets"), tc.key, "key-1", "")
			if err == nil {
				t.Fatal("Seal accepted an unusable public key — an archive sealed to nothing, or written in clear")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
			if out.Len() != 0 {
				t.Errorf("a refused seal still wrote %d bytes", out.Len())
			}
		})
	}
}

// TestSealDetectsTampering proves the header is authenticated. A disk holding
// the archive also holds the header; if the scope or the key-id could be edited
// without breaking the tags, the sidecar manifest would not be the only
// forgeable record of what a generation is.
func TestSealDetectsTampering(t *testing.T) {
	key := newTestKeypair(t)
	var out bytes.Buffer
	if _, err := Seal(&out, strings.NewReader("payload that must not open after an edit"), key.publicB64, "key-1", proto.BackupScopeIdentityOnly); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	sealedBytes := out.Bytes()
	edited := bytes.Replace(sealedBytes, []byte(`"scope":"identity-only"`), []byte(`"scope":"full-------"`), 1)
	if bytes.Equal(edited, sealedBytes) {
		t.Fatal("the header does not carry the scope in the shape this test edits")
	}

	// Decrypt by hand rather than through openSealed, which t.Fatals on a bad
	// chunk — here a failure to open is the PASS.
	rest := edited[len(SealMagic):]
	nl := bytes.IndexByte(rest, '\n')
	headerBytes, body := rest[:nl], rest[nl+1:]
	var h sealHeader
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		t.Fatalf("edited header: %v", err)
	}
	epkRaw, _ := base64.RawURLEncoding.DecodeString(h.EphemeralPublicKey)
	epk, _ := ecdh.X25519().NewPublicKey(epkRaw)
	shared, _ := key.priv.ECDH(epk)
	salt := append(append([]byte{}, epkRaw...), key.priv.PublicKey().Bytes()...)
	ck, _ := hkdf.Key(sha256.New, shared, salt, sealInfo, chacha20poly1305.KeySize)
	aead, _ := chacha20poly1305.New(ck)
	nonce := make([]byte, chacha20poly1305.NonceSize)
	nonce[8] = 1
	if _, err := aead.Open(nil, nonce, body, headerBytes); err == nil {
		t.Fatal("an edited header still opened: the scope inside the archive is forgeable")
	}
}

// TestNoKeyMaterialReachesTheLedger is the assertion the whole slice hangs on.
//
// A step result, a job event and a job error are all PERSISTED and RENDERED —
// the Tasks view shows them. So the surface under test is the ledger as the
// store hands it back, not anything the saga returned in memory.
//
// It scans for four things: the recipient's private key in both encodings a
// leak would plausibly take, and both §4.6 wrappings. The private key is the
// catastrophic one; the wrappings are ciphertext, but they are still the
// narrowest-surface rule the claim saga follows and there is no reason for
// either to be in a job feed.
func TestNoKeyMaterialReachesTheLedger(t *testing.T) {
	h := newRunHarness(t, nil, runHarnessOpts{})
	jobID := h.submit(t, RunSpec{Reason: ReasonScheduled})
	j := h.waitTerminal(t, jobID)
	if j.Status != jobs.StatusSucceeded {
		t.Fatalf("job status = %s (%s)", j.Status, j.Error)
	}

	ledger := h.ledgerText(t, jobID)
	forbidden := map[string]string{
		"the recipient's private key (base64url)": h.key.privateB64(),
		"the recipient's private key (hex)":       h.key.privateHex(),
		"the passphrase-wrapped private key":      testWrappedPass,
		"the recovery-code-wrapped private key":   testWrappedRecovery,
	}
	for what, needle := range forbidden {
		if needle == "" {
			t.Fatalf("nothing to look for: %s", what)
		}
		if strings.Contains(ledger, needle) {
			t.Errorf("%s appears in the job ledger — a step result, an event or the job error", what)
		}
	}

	// The PUBLIC key is allowed to be there, and asserting it IS present keeps
	// the scan honest: a test that found nothing because the ledger was empty
	// would pass for the wrong reason.
	if !strings.Contains(ledger, h.key.publicB64) {
		t.Error("the ledger does not contain the target's public key, so this scan may have been looking at nothing")
	}
	if !strings.Contains(ledger, "identity-only") {
		t.Error("the ledger never mentions the scope; the run's own output must say what it captured")
	}
}

// TestAssembleWritesTheManifestFirst is the streaming property: a reader learns
// the scope before it reads a byte of anything else, so a restore can refuse an
// identity-only archive it was told was complete without buffering the lot.
func TestAssembleWritesTheManifestFirst(t *testing.T) {
	h := newRunHarness(t, nil, runHarnessOpts{})
	snap := t.TempDir() + "/snapshot.db"
	writeTestFile(t, snap, "SQLITE-SNAPSHOT-BYTES")

	var buf bytes.Buffer
	m, err := Assemble(&buf, AssembleOptions{
		Sources:      IdentitySources{TrustDir: h.trustDir, MeshStateDir: h.meshDir},
		SnapshotPath: snap,
		GenerationID: "20260902T000000Z-test-identity-only",
		JobID:        "job-1",
		ClusterID:    "home1",
		KeyID:        "key-1",
	})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if m.Scope != proto.BackupScopeIdentityOnly || m.Complete {
		t.Errorf("manifest scope=%q complete=%v", m.Scope, m.Complete)
	}

	tr := tar.NewReader(&buf)
	first, err := tr.Next()
	if err != nil {
		t.Fatalf("read first tar entry: %v", err)
	}
	if first.Name != proto.BackupManifestFile {
		t.Fatalf("first archive entry is %q, want the manifest — a reader must learn the scope before the payload", first.Name)
	}
	body, err := io.ReadAll(tr)
	if err != nil {
		t.Fatalf("read manifest entry: %v", err)
	}
	var inner Manifest
	if err := json.Unmarshal(body, &inner); err != nil {
		t.Fatalf("manifest inside the archive is not JSON: %v", err)
	}
	if inner.Scope != proto.BackupScopeIdentityOnly {
		t.Errorf("the manifest inside the archive says scope=%q", inner.Scope)
	}
	if inner.AppVolumes.CapturedCount != 0 || inner.AppVolumes.Reason == "" {
		t.Error("the archive's own manifest does not carry the empty fan-out's report")
	}

	// Every remaining entry is listed, in order, with the digest the manifest
	// promised.
	seen := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("tar read %s: %v", hdr.Name, err)
		}
		sum := sha256.Sum256(data)
		found := false
		for _, e := range m.Entries {
			if e.Path == hdr.Name {
				found = true
				if e.SHA256 != hex.EncodeToString(sum[:]) {
					t.Errorf("%s: manifest digest %s, archive contains %s", hdr.Name, e.SHA256, hex.EncodeToString(sum[:]))
				}
			}
		}
		if !found {
			t.Errorf("the archive holds %s, which the manifest does not list", hdr.Name)
		}
		seen[hdr.Name] = true
	}
	for _, e := range m.Entries {
		if !seen[e.Path] {
			t.Errorf("the manifest lists %s, which is not in the archive", e.Path)
		}
	}
}

// TestAssembleRefusesWithoutASnapshot: an archive with no rasputin.db restores
// as an appliance with no users, no nodes and no apps.
func TestAssembleRefusesWithoutASnapshot(t *testing.T) {
	h := newRunHarness(t, nil, runHarnessOpts{})
	var buf bytes.Buffer
	_, err := Assemble(&buf, AssembleOptions{
		Sources:      IdentitySources{TrustDir: h.trustDir, MeshStateDir: h.meshDir},
		GenerationID: "g",
	})
	if err == nil {
		t.Fatal("Assemble produced an archive with no database in it")
	}
	if !strings.Contains(err.Error(), "no users, no nodes and no apps") {
		t.Errorf("error = %q", err)
	}
}

// TestFanOutIsDeclaredAndEmpty pins the shape of the phase that will eventually
// stop being empty. It asserts the report says what is missing and names the
// issues, so a future edit that quietly drops the reason fails here.
func TestFanOutIsDeclaredAndEmpty(t *testing.T) {
	r := FanOutAppVolumes()
	if r.Captured == nil {
		t.Error("Captured is nil rather than an empty slice: `\"captured\": null` is not the answer `[]` is")
	}
	if r.CapturedCount != 0 || len(r.Captured) != 0 {
		t.Errorf("this build captures no app volumes; got %d", r.CapturedCount)
	}
	if r.Reason == "" {
		t.Fatal("the fan-out reports nothing captured and does not say why")
	}
	for _, issue := range []string{"#292", "#293", "#294", "#295", "#296"} {
		if !strings.Contains(strings.Join(r.BlockedBy, " "), issue) {
			t.Errorf("blockedBy does not name %s", issue)
		}
	}
	if !strings.Contains(r.Reason, "not a complete backup") {
		t.Error("the reason does not say, in words, that this is not a complete backup")
	}
	if AppVolumeFanOutReason() != r.Reason {
		t.Error("the exported reason and the report's reason have drifted apart; every surface must say the same words")
	}
}

// TestBackupScheduleDefaultsAndBounds covers §4.1's cadence: weekly by default,
// overridable, and bounded.
func TestBackupScheduleDefaultsAndBounds(t *testing.T) {
	ctx := context.Background()
	st := newMemorySettings()

	got, err := GetBackupSchedule(ctx, st, true)
	if err != nil {
		t.Fatalf("GetBackupSchedule: %v", err)
	}
	if !got.Enabled {
		t.Error("scheduled backups default to OFF; §4.1 makes the weekly run the product's behaviour, not an opt-in")
	}
	if got.Interval() != DefaultBackupCadence {
		t.Errorf("default cadence = %s, want %s", got.Interval(), DefaultBackupCadence)
	}

	if _, err := SetBackupSchedule(ctx, st, BackupSchedule{Enabled: true, Every: "1m"}); err == nil {
		t.Error("a one-minute cadence was accepted; every run is a FULL and stages a copy of the identity set")
	}
	if _, err := SetBackupSchedule(ctx, st, BackupSchedule{Enabled: true, Every: "10000h"}); err == nil {
		t.Error("a cadence beyond the ceiling was accepted")
	}
	saved, err := SetBackupSchedule(ctx, st, BackupSchedule{Enabled: true, Every: "24h"})
	if err != nil {
		t.Fatalf("SetBackupSchedule: %v", err)
	}
	if saved.Interval() != 24*time.Hour {
		t.Errorf("saved cadence = %s", saved.Interval())
	}

	// A corrupt stored value must not be able to turn backups off.
	_ = st.Set(ctx, KeyBackupSchedule, `{"enabled":true,"every":"not a duration"}`)
	got, err = GetBackupSchedule(ctx, st, true)
	if err != nil {
		t.Fatalf("GetBackupSchedule: %v", err)
	}
	if got.Interval() != DefaultBackupCadence {
		t.Errorf("a corrupt cadence resolved to %s rather than falling back to the default — a bad value that read as `never` would be an outage nobody sees until they need a restore", got.Interval())
	}
}

// TestDueFuncGatesTheSchedule covers each branch of the scheduler gate.
func TestDueFuncGatesTheSchedule(t *testing.T) {
	h := newRunHarness(t, nil, runHarnessOpts{})
	ctx := context.Background()
	due := DueFunc(h.store, h.settings, true)

	// A fresh installation with a claimed target: due now, not in a week.
	if ok, reason := due(ctx); !ok {
		t.Errorf("a never-backed-up installation is not due: %s", reason)
	}

	// Schedule off.
	if _, err := SetBackupSchedule(ctx, h.settings, BackupSchedule{Enabled: false}); err != nil {
		t.Fatalf("SetBackupSchedule: %v", err)
	}
	ok, reason := due(ctx)
	if ok {
		t.Error("a disabled schedule fired anyway")
	}
	if !strings.Contains(reason, "turned off") {
		t.Errorf("the skip reason is %q, which does not distinguish a disabled schedule from a broken one", reason)
	}

	// A run in flight.
	if _, err := SetBackupSchedule(ctx, h.settings, BackupSchedule{Enabled: true, Every: "1h"}); err != nil {
		t.Fatalf("SetBackupSchedule: %v", err)
	}
	if err := h.store.StartRun(ctx, "job-inflight", ReasonManual, proto.BackupScopeIdentityOnly, timeNow()); err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	if ok, reason := due(ctx); ok {
		t.Error("the schedule fired while a run was already in flight")
	} else if !strings.Contains(reason, "already running") {
		t.Errorf("the skip reason is %q", reason)
	}

	// Finished, and inside the cadence.
	if err := h.store.FinishRun(ctx, "job-inflight", RunResult{
		GenerationID: "g", Digest: "d", SizeBytes: 1, GenerationsKept: 1, At: timeNow(),
	}); err != nil {
		t.Fatalf("FinishRun: %v", err)
	}
	if ok, _ := due(ctx); ok {
		t.Error("the schedule fired again immediately after a success, inside the cadence")
	}
}

// TestSealTerminatesOnAnExactChunkBoundary is the branch a plaintext that is a
// whole multiple of the chunk size takes, and the reason it exists.
//
// Without it the stream would end with a chunk whose last-flag is NOT set, and
// a reader could not distinguish "the archive ended here" from "the archive was
// truncated at a boundary" — which is precisely the failure a digest alone
// might miss on a disk that filled mid-write. The mutation gate flagged this
// path as uncovered; a plaintext of 5000 × 42 bytes never lands on a boundary.
func TestSealTerminatesOnAnExactChunkBoundary(t *testing.T) {
	key := newTestKeypair(t)
	for _, size := range []int{0, sealChunkSize, 2 * sealChunkSize} {
		t.Run(fmt.Sprintf("%d bytes", size), func(t *testing.T) {
			plaintext := bytes.Repeat([]byte("x"), size)
			var out bytes.Buffer
			res, err := Seal(&out, bytes.NewReader(plaintext), key.publicB64, "key-1", proto.BackupScopeIdentityOnly)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			if res.PlaintextBytes != uint64(size) {
				t.Errorf("plaintextBytes = %d, want %d", res.PlaintextBytes, size)
			}
			// openSealed asserts a last-flagged chunk was seen, so a stream that
			// ended without terminating fails here.
			got, _ := openSealed(t, out.Bytes(), key.priv)
			if !bytes.Equal(got, plaintext) {
				t.Errorf("round trip produced %d bytes, want %d", len(got), size)
			}
		})
	}
}

// TestSealDetectsTruncationAtAChunkBoundary is the property the branch above
// buys: lopping a whole chunk off the end of a boundary-aligned archive must
// not open cleanly as a shorter archive.
func TestSealDetectsTruncationAtAChunkBoundary(t *testing.T) {
	key := newTestKeypair(t)
	var out bytes.Buffer
	if _, err := Seal(&out, bytes.NewReader(bytes.Repeat([]byte("y"), 2*sealChunkSize)),
		key.publicB64, "key-1", proto.BackupScopeIdentityOnly); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	full := out.Bytes()
	// Drop the final (empty, last-flagged) chunk: 16 bytes of tag.
	truncated := full[:len(full)-16]

	rest := truncated[len(SealMagic):]
	nl := bytes.IndexByte(rest, '\n')
	headerBytes, body := rest[:nl], rest[nl+1:]
	var h sealHeader
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		t.Fatalf("header: %v", err)
	}
	epkRaw, _ := base64.RawURLEncoding.DecodeString(h.EphemeralPublicKey)
	epk, _ := ecdh.X25519().NewPublicKey(epkRaw)
	shared, _ := key.priv.ECDH(epk)
	salt := append(append([]byte{}, epkRaw...), key.priv.PublicKey().Bytes()...)
	ck, _ := hkdf.Key(sha256.New, shared, salt, sealInfo, chacha20poly1305.KeySize)
	aead, _ := chacha20poly1305.New(ck)

	// Every remaining chunk is a FULL one, so none of them can carry the
	// last-chunk flag: a reader walking this stream never sees a terminator and
	// therefore knows it is looking at a truncation rather than an archive.
	chunk := h.ChunkSize + aead.Overhead()
	nonce := make([]byte, chacha20poly1305.NonceSize)
	for i := 0; i*chunk < len(body); i++ {
		end := min((i+1)*chunk, len(body))
		for j := range nonce {
			nonce[j] = 0
		}
		binary.BigEndian.PutUint64(nonce[0:8], uint64(i))
		nonce[8] = 1 // claim it is the last chunk
		if _, err := aead.Open(nil, nonce, body[i*chunk:end], headerBytes); err == nil {
			t.Fatalf("chunk %d opened as a terminating chunk; truncation would be undetectable", i)
		}
	}
}
