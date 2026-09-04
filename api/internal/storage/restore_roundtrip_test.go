package storage

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// TestRestoreRoundTrip is the backup → wipe → restore round-trip
// design/storage.md §4.4 makes a gate ("a backup nobody has restored is not
// a backup") and geekdojo/geekdojo-brain#300 tracks, for the IDENTITY SET.
//
// It is repeatable by construction: `go test ./api/...` runs it on every
// change, and scripts/test-restore-roundtrip.sh runs it alone, verbosely.
// Nothing here touches hardware or needs root.
//
// What it exercises, for real:
//
//   - the custody path, cross-language: the recovery-code wrapping in
//     testdata/recovery-code-vector.json was produced by the BROWSER code
//     (ui/lib/archive-key.ts via scripts/gen-recovery-code-vector.sh) and is
//     opened here in Go, with HKDF-SHA-256 and AES-256-GCM as the browser
//     documents them, and the key inside must derive the fixture's public
//     key. The same fixture is opened by the browser code in
//     ui/lib/recovery-vector.test.ts, so one vector pins both sides;
//   - a real backup.run — the real saga over a real SQLite database holding
//     real users, passkey credentials and bus tokens, the real assembler and
//     the real seal to that fixture's public key — landing a generation on
//     a temp target;
//   - a FRESH data dir standing in for a re-flashed /var/lib/rasputin, given
//     a fresh install's own files so the apply has something to move aside;
//   - PrepareRestore with the recovered key, then ApplyPendingRestore as the
//     next start would run it, then RecordAppliedRestore into the restored
//     database;
//   - the assertions §4.4 is about: the restored rasputin.db opens and its
//     digest is the one the manifest recorded for the captured snapshot;
//     users, credentials and bus tokens match the pre-wipe database ROW FOR
//     ROW; a pre-wipe bus token still VALIDATES against the restored store
//     (a node's existing join token authenticates with no re-registration);
//     the mesh CA and Headscale state are byte-identical; the backup target
//     row came back with the identity, so the disk is still this cluster's
//     target; and the private key appears in no log line, no ledger row and
//     no report.
//
// What it does NOT prove, said plainly: app data. Phase 1 restores the
// identity set; every app volume in the generation is named as present and
// not restored, and this test asserts that naming. The app-data half of #300
// waits on the phase-2 reverse transport.

// recoveryVector is testdata/recovery-code-vector.json.
type recoveryVector struct {
	KeyID                 string `json:"keyId"`
	Alg                   string `json:"alg"`
	PublicKey             string `json:"publicKey"`
	WrappedByPassphrase   string `json:"wrappedByPassphrase"`
	WrappedByRecoveryCode string `json:"wrappedByRecoveryCode"`
	RecoveryCode          string `json:"recoveryCode"`
	PrivateKey            string `json:"privateKey"`
}

func loadRecoveryVector(t *testing.T) recoveryVector {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "recovery-code-vector.json"))
	if err != nil {
		t.Fatalf("the cross-language custody fixture is missing; regenerate it with scripts/gen-recovery-code-vector.sh: %v", err)
	}
	var v recoveryVector
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// openRecoveryCodeWrapping is the browser's recovery-code unwrap, in Go,
// written from archive-key.ts's description of the blob and nothing else:
//
//	blob   = base64url(JSON{v:2, cipher:"AES-256-GCM", kdf:"hkdf-sha256",
//	         salt, iv, ct})
//	kek    = HKDF-SHA-256(secret = canonical recovery code, salt,
//	         info = "rasputin.archive-key.v2/recovery-code", 32 bytes)
//	key    = AES-256-GCM-open(kek, iv, ct,
//	         aad = "rasputin.archive-key.v2|<keyId>|recovery-code")
//
// TEST ONLY. Production Go never unwraps: the browser does, and the key
// transits once. This exists so the round-trip's custody step is the real
// recovery path rather than the test handing itself the key.
func openRecoveryCodeWrapping(t *testing.T, keyID, blob, code string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(blob)
	if err != nil {
		t.Fatalf("blob is not base64url: %v", err)
	}
	var b struct {
		V      int    `json:"v"`
		Cipher string `json:"cipher"`
		KDF    string `json:"kdf"`
		Salt   string `json:"salt"`
		IV     string `json:"iv"`
		CT     string `json:"ct"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("blob is not JSON: %v", err)
	}
	if b.V != 2 || b.Cipher != "AES-256-GCM" || b.KDF != "hkdf-sha256" {
		t.Fatalf("blob names a construction this test does not implement: %+v", b)
	}
	salt, _ := base64.RawURLEncoding.DecodeString(b.Salt)
	iv, _ := base64.RawURLEncoding.DecodeString(b.IV)
	ct, _ := base64.RawURLEncoding.DecodeString(b.CT)
	canonical := strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9', r >= 'A' && r <= 'Z':
			return r
		case r >= 'a' && r <= 'z':
			return r - 'a' + 'A'
		}
		return -1
	}, code)
	kek, err := hkdf.Key(sha256.New, []byte(canonical), salt, "rasputin.archive-key.v2/recovery-code", 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	key, err := gcm.Open(nil, iv, ct, []byte("rasputin.archive-key.v2|"+keyID+"|recovery-code"))
	if err != nil {
		t.Fatalf("the recovery code did not open the browser's wrapping: %v", err)
	}
	return key
}

// identitySnapshot is the row-level view of the identity tables the
// round-trip compares before and after.
type identitySnapshot struct {
	users       []string
	credentials []string
	busTokens   []string
	targets     []string
}

func snapshotIdentity(t *testing.T, dbPath string) identitySnapshot {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows := func(q string) []string {
		r, err := db.Query(q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		defer func() { _ = r.Close() }()
		var out []string
		for r.Next() {
			var line string
			if err := r.Scan(&line); err != nil {
				t.Fatal(err)
			}
			out = append(out, line)
		}
		return out
	}
	return identitySnapshot{
		users:       rows(`SELECT hex(id) || '|' || name || '|' || display_name FROM users ORDER BY name`),
		credentials: rows(`SELECT hex(id) || '|' || hex(user_id) || '|' || hex(public_key) || '|' || sign_count FROM credentials ORDER BY id`),
		busTokens:   rows(`SELECT token_hash || '|' || label || '|' || COALESCE(node_id, '') FROM bus_tokens ORDER BY token_hash`),
		targets:     rows(`SELECT job_id || '|' || part_uuid || '|' || key_id || '|' || status FROM backup_targets ORDER BY job_id`),
	}
}

func TestRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	vec := loadRecoveryVector(t)

	// --- the custody path, cross-language ---------------------------------
	priv := openRecoveryCodeWrapping(t, vec.KeyID, vec.WrappedByRecoveryCode, vec.RecoveryCode)
	if len(priv) != 32 {
		t.Fatalf("recovered %d bytes, want 32", len(priv))
	}
	if got, _ := PublicKeyForPrivate(priv); got != vec.PublicKey {
		t.Fatalf("the key inside the browser's wrapping derives %s; the fixture's public key is %s", got, vec.PublicKey)
	}
	if want, _ := base64.RawURLEncoding.DecodeString(vec.PrivateKey); !bytes.Equal(priv, want) {
		t.Fatal("Go's unwrap and the browser's lend disagree about the private key")
	}
	ecdhPriv, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	key := testKeypair{priv: ecdhPriv, publicB64: vec.PublicKey}

	// --- a real backup of a real identity set -----------------------------
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	h := newRunHarness(t, nil, runHarnessOpts{key: &key, keyID: vec.KeyID})
	// The marker the claim would have written, so the restore's custody check
	// has the disk's own public key to compare against.
	marker := proto.StorageBackupSet{
		MarkerVersion: proto.StorageMarkerVersion, ClusterID: "home1", PartUUID: runPartUUID,
		KeyID: vec.KeyID, KeyAlg: vec.Alg, PublicKey: vec.PublicKey,
		WrappedByPassphrase: vec.WrappedByPassphrase, WrappedByRecoveryCode: vec.WrappedByRecoveryCode,
		Label: "the archive disk", CreatedAt: time.Now().UTC(),
	}
	mb, _ := json.Marshal(marker)
	if err := os.WriteFile(filepath.Join(h.mountDir, proto.StorageMarkerFile), mb, 0o600); err != nil {
		t.Fatal(err)
	}
	// Real users, a real passkey credential row and real bus tokens, through
	// the stores that own those tables — so the schema the restore brings back
	// is the shipping one.
	authStore, err := auth.OpenStore(ctx, h.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	operator := &auth.User{ID: []byte("0123456789abcdef"), Name: "bryce", DisplayName: "Bryce", CreatedAt: time.Now().UTC()}
	if err := authStore.CreateUser(ctx, operator); err != nil {
		t.Fatal(err)
	}
	if err := authStore.CreateCredential(ctx, &auth.Credential{
		ID: []byte("cred-touch-id-0001"), UserID: operator.ID, PublicKey: []byte("COSE-PUBLIC-KEY"),
		AttestationType: "none", SignCount: 7, BackupEligible: true, Nickname: "MacBook", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	_ = authStore.Close()
	busStore, err := busauth.OpenStore(ctx, h.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	nodeToken, _, err := busStore.MintBound(ctx, "node-2 join token", "node-2")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := busStore.MintBound(ctx, "firewall join token", "node-fw"); err != nil {
		t.Fatal(err)
	}
	_ = busStore.Close()
	before := snapshotIdentity(t, h.dbPath)
	if len(before.users) != 1 || len(before.credentials) != 1 || len(before.busTokens) != 2 || len(before.targets) != 1 {
		t.Fatalf("pre-wipe identity is not what was seeded: %+v", before)
	}

	jobID := h.submit(t, RunSpec{Reason: ReasonManual})
	j := h.waitTerminal(t, jobID)
	if j.Status != jobs.StatusSucceeded {
		t.Fatalf("backup.run %s: %s", j.Status, j.Error)
	}
	run := h.run(t, jobID)
	if run.GenerationID == "" || run.KeyID != vec.KeyID {
		t.Fatalf("run row: %+v", run)
	}
	var manifest Manifest
	mj, err := os.ReadFile(filepath.Join(h.generationDir(run.GenerationID), proto.BackupManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(mj, &manifest); err != nil {
		t.Fatal(err)
	}
	var dbEntry ManifestEntry
	for _, e := range manifest.Entries {
		if e.Path == "rasputin.db" {
			dbEntry = e
		}
	}
	if dbEntry.SHA256 == "" {
		t.Fatal("the manifest records no digest for rasputin.db")
	}

	// --- the wipe: a re-flashed controlplane --------------------------------
	fresh := filepath.Join(t.TempDir(), "var-lib-rasputin")
	if err := os.MkdirAll(fresh, 0o700); err != nil {
		t.Fatal(err)
	}
	// What a first boot leaves there: an empty database with the shipping
	// schema, a freshly generated CA, empty mesh state.
	freshAuth, err := auth.OpenStore(ctx, filepath.Join(fresh, "rasputin.db"))
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := freshAuth.CountUsers(ctx); n != 0 {
		t.Fatal("the fresh database is not fresh")
	}
	_ = freshAuth.Close()
	if err := os.MkdirAll(filepath.Join(fresh, "trust"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(fresh, "trust", "mesh-ca.key"), "FRESH-CA-KEY")
	writeTestFile(t, filepath.Join(fresh, "trust", "mesh-ca.pem"), "FRESH-CA-PEM")
	if err := os.MkdirAll(filepath.Join(fresh, "mesh", "headscale"), 0o700); err != nil {
		t.Fatal(err)
	}

	// The restore mounts the disk through the agent; the run harness's fake
	// does not answer that verb, so answer it here with the same mount.
	sub, err := h.nc.Subscribe(proto.StorageMountSubject(runNodeID), func(m *nats.Msg) {
		b, _ := json.Marshal(proto.StorageMountAck{OK: true, PartUUID: runPartUUID, MountPath: h.mountDir})
		_ = m.Respond(b)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	// And the enumerate the first-run picker runs, listing this disk with
	// the marker the claim wrote.
	esub, err := h.nc.Subscribe(proto.StorageEnumerateSubject(runNodeID), func(m *nats.Msg) {
		b, _ := json.Marshal(proto.StorageEnumerateAck{OK: true, Backend: "mock", Ts: time.Now().UTC(), Candidates: []proto.StorageCandidate{{
			DevicePath: "/dev/sdb", Model: "Archive Disk", SizeBytes: 2 << 40, Transport: proto.StorageTransportUSB,
			HasBackupSet: true, BackupSet: &marker, Fingerprint: "fp-1",
		}}})
		_ = m.Respond(b)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = esub.Unsubscribe() })

	// --- the restore ---------------------------------------------------------
	// What the first-run picker would show: this disk, restorable, with the
	// generation the run just wrote and the app-volume gap named on it.
	cfg := RestoreConfig{NC: h.nc, SelfNodeID: runNodeID, DataDir: fresh, ClusterID: "home1"}
	cands, err := ListRestoreCandidates(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(cands.Candidates) != 1 || !cands.Candidates[0].Restorable || cands.Candidates[0].Marker.KeyID != vec.KeyID {
		t.Fatalf("candidates: %+v", cands.Candidates)
	}
	var offered *RestoreGeneration
	for i := range cands.Candidates[0].Generations {
		if cands.Candidates[0].Generations[i].ID == run.GenerationID {
			offered = &cands.Candidates[0].Generations[i]
		}
	}
	if offered == nil || !offered.Restorable || offered.KeyID != vec.KeyID {
		t.Fatalf("the generation the run wrote is not offered: %+v", cands.Candidates[0].Generations)
	}
	report, err := PrepareRestore(ctx, cfg, RestoreRequest{
		PartUUID: runPartUUID, GenerationID: run.GenerationID, KeyID: vec.KeyID, PrivateKey: priv,
	})
	if err != nil {
		t.Fatalf("PrepareRestore: %v", err)
	}
	for i := range priv {
		priv[i] = 0
	}
	layout := RestoreLayout{DataDir: fresh, TrustDir: filepath.Join(fresh, "trust"), MeshStateDir: filepath.Join(fresh, "mesh")}
	applied, ok, err := ApplyPendingRestore(layout)
	if err != nil || !ok {
		t.Fatalf("ApplyPendingRestore: %v %v", err, ok)
	}

	// --- the assertions ------------------------------------------------------
	// 1. The restored database is the captured snapshot, byte for byte.
	dbBytes, err := os.ReadFile(filepath.Join(fresh, "rasputin.db"))
	if err != nil {
		t.Fatal(err)
	}
	if got := mustSHA(dbBytes); got != dbEntry.SHA256 {
		t.Fatalf("restored rasputin.db digest %s, manifest recorded %s", got, dbEntry.SHA256)
	}
	// 2. It opens, and the identity tables match the pre-wipe rows exactly.
	after := snapshotIdentity(t, filepath.Join(fresh, "rasputin.db"))
	if strings.Join(after.users, "\n") != strings.Join(before.users, "\n") {
		t.Fatalf("users differ:\n before %v\n after  %v", before.users, after.users)
	}
	if strings.Join(after.credentials, "\n") != strings.Join(before.credentials, "\n") {
		t.Fatalf("credentials differ:\n before %v\n after  %v", before.credentials, after.credentials)
	}
	if strings.Join(after.busTokens, "\n") != strings.Join(before.busTokens, "\n") {
		t.Fatalf("bus tokens differ:\n before %v\n after  %v", before.busTokens, after.busTokens)
	}
	if strings.Join(after.targets, "\n") != strings.Join(before.targets, "\n") {
		t.Fatalf("backup targets differ:\n before %v\n after  %v", before.targets, after.targets)
	}
	// 3. The identities work: the operator is there for the auth store, and a
	//    node's pre-wipe join token validates against the restored bus store.
	restoredAuth, err := auth.OpenStore(ctx, filepath.Join(fresh, "rasputin.db"))
	if err != nil {
		t.Fatal(err)
	}
	if u, err := restoredAuth.GetUserByName(ctx, "bryce"); err != nil || u == nil || !bytes.Equal(u.ID, operator.ID) {
		t.Fatalf("operator not in the restored database: %v %+v", err, u)
	}
	_ = restoredAuth.Close()
	restoredBus, err := busauth.OpenStore(ctx, filepath.Join(fresh, "rasputin.db"))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := restoredBus.Validate(ctx, nodeToken, "node-2"); err != nil || !ok {
		t.Fatalf("node-2's pre-wipe join token does not validate after the restore: %v %v", ok, err)
	}
	if ok, _ := restoredBus.Validate(ctx, nodeToken, "node-3"); ok {
		t.Fatal("the token validated for a node it is not bound to")
	}
	_ = restoredBus.Close()
	// 4. The mesh CA and Headscale state are byte-identical to what was
	//    captured; the fresh CA went aside.
	for _, f := range []string{"mesh-ca.key", "mesh-ca.pem"} {
		want, _ := os.ReadFile(filepath.Join(h.trustDir, f))
		got, err := os.ReadFile(filepath.Join(fresh, "trust", f))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("trust/%s differs after restore: %v", f, err)
		}
	}
	for _, f := range []string{"config.yaml", filepath.Join("db", "headscale.sqlite")} {
		want, _ := os.ReadFile(filepath.Join(h.meshDir, "headscale", f))
		got, err := os.ReadFile(filepath.Join(fresh, "mesh", "headscale", f))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("mesh/headscale/%s differs after restore: %v", f, err)
		}
	}
	// 5. The record lands in the restored database and says what was not
	//    restored.
	restoredStore, err := OpenStore(ctx, filepath.Join(fresh, "rasputin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restoredStore.Close() })
	rec, err := RecordAppliedRestore(ctx, restoredStore, fresh)
	if err != nil || rec == nil || rec.ID != report.ID {
		t.Fatalf("RecordAppliedRestore: %v %+v", err, rec)
	}
	latest, err := restoredStore.LatestRestore(ctx)
	if err != nil || latest == nil || latest.GenerationID != run.GenerationID || latest.Phase != RestorePhase {
		t.Fatalf("latest restore: %v %+v", err, latest)
	}
	if !strings.Contains(latest.Warning, "APP DATA WAS NOT RESTORED") {
		t.Fatal("the record does not say app data was not restored")
	}
	if len(latest.AppVolumesPresent) != len(manifest.AppVolumes.Captured) {
		t.Fatalf("the record names %d present app volumes; the generation captured %d", len(latest.AppVolumesPresent), len(manifest.AppVolumes.Captured))
	}
	targets, err := restoredStore.ListTargets(ctx)
	if err != nil || len(targets) != 1 || targets[0].PartUUID != runPartUUID || targets[0].KeyID != vec.KeyID {
		t.Fatalf("the backup target did not come back with the identity: %v %+v", err, targets)
	}
	if applied.AppliedAt == nil || len(applied.Restored) < 5 {
		t.Fatalf("applied report: %+v", applied)
	}
	// 6. The key is nowhere: not in the run's ledger, not in a log line, not
	//    in the report.
	ledger := h.ledgerText(t, jobID)
	rj, _ := json.Marshal(latest)
	for name, text := range map[string]string{"job ledger": ledger, "log": logs.String(), "restore record": string(rj)} {
		if strings.Contains(text, key.privateB64()) || strings.Contains(text, key.privateHex()) || strings.Contains(text, vec.RecoveryCode) {
			t.Fatalf("custody material reached the %s", name)
		}
	}
}
