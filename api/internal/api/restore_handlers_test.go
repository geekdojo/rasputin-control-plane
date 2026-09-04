package api

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// The restore routes: open only while no operator exists, custody-gated,
// and leak-free. The generation is built with the real assembler and the
// real seal onto a temp mount; a fake agent answers the mount and enumerate
// verbs; the fixture's setup probe decides whether first-run is over.

const (
	rtNodeID   = "self-node"
	rtPartUUID = "abcd-0001"
	rtKeyID    = "ak-test"
)

type restoreFixture struct {
	*apiFixture
	mount    string
	dataDir  string
	priv     *ecdh.PrivateKey
	pubB64   string
	genID    string
	restarts atomic.Int32
}

func newRestoreFixture(t *testing.T) *restoreFixture {
	t.Helper()
	f := newAPIFixture(t)
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rf := &restoreFixture{apiFixture: f, priv: priv, pubB64: base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())}
	rf.mount = filepath.Join(f.dir, "mnt")
	rf.dataDir = filepath.Join(f.dir, "fresh-data")
	if err := os.MkdirAll(rf.dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	rf.genID = buildRestoreGeneration(t, rf.mount, rf.pubB64)
	marker := readTestMarker(t, rf.mount)
	startFakeRestoreAgent(t, f.nc, rf.mount, marker)
	f.srv.SetRestore(&storage.RestoreConfig{NC: f.nc, SelfNodeID: rtNodeID, DataDir: rf.dataDir, ClusterID: "home1"}, func() {
		rf.restarts.Add(1)
	})
	f.srv.SetBackupStore(newTestBackupStore(t, f.dir))
	return rf
}

func newTestBackupStore(t *testing.T, dir string) *storage.Store {
	t.Helper()
	st, err := storage.OpenStore(context.Background(), filepath.Join(dir, "backup.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// buildRestoreGeneration writes a marker and one sealed generation under
// mount and returns the generation id.
func buildRestoreGeneration(t *testing.T, mount, pubB64 string) string {
	t.Helper()
	marker := proto.StorageBackupSet{
		MarkerVersion: proto.StorageMarkerVersion, ClusterID: "home1", PartUUID: rtPartUUID,
		KeyID: rtKeyID, PublicKey: pubB64,
		WrappedByPassphrase: "WRAPPED-PP", WrappedByRecoveryCode: "WRAPPED-RC", CreatedAt: time.Now().UTC(),
	}
	mb, _ := json.Marshal(marker)
	if err := os.MkdirAll(mount, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mount, proto.StorageMarkerFile), mb, 0o600); err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "snapshot.db"), []byte("DB-BYTES"), 0o600); err != nil {
		t.Fatal(err)
	}
	genID := proto.BackupGenerationID(time.Now(), "job-1", proto.BackupScopeFull)
	report := storage.NewAppVolumeReport(storage.AppEnumeration{AppsInstalled: 1, AppsResolved: 1}, []storage.VolumeRecord{{
		App: "vaultwarden", Volume: "data", Class: "critical", Node: "n-compute", Captured: true,
		Member: proto.BackupMemberPath("vaultwarden", "data"), SealedSHA256: strings.Repeat("cd", 32), SizeBytes: 10, AppRestored: true,
	}}, 1)
	var tarBuf bytes.Buffer
	m, err := storage.Assemble(&tarBuf, storage.AssembleOptions{
		Sources: storage.IdentitySources{}, SnapshotPath: filepath.Join(src, "snapshot.db"),
		GenerationID: genID, JobID: "job-1", ClusterID: "home1", KeyID: rtKeyID,
		AppVolumes: report, Scope: proto.BackupScopeFull,
	})
	if err != nil {
		t.Fatal(err)
	}
	var sealed bytes.Buffer
	if _, err := backupxfer.Seal(&sealed, bytes.NewReader(tarBuf.Bytes()), pubB64, rtKeyID, proto.BackupScopeFull); err != nil {
		t.Fatal(err)
	}
	gen := filepath.Join(mount, proto.BackupGenerationsDir, genID)
	if err := os.MkdirAll(gen, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gen, proto.BackupArchiveFile), sealed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	mj, _ := m.JSON()
	if err := os.WriteFile(filepath.Join(gen, proto.BackupManifestFile), mj, 0o600); err != nil {
		t.Fatal(err)
	}
	return genID
}

func readTestMarker(t *testing.T, mount string) *proto.StorageBackupSet {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(mount, proto.StorageMarkerFile))
	if err != nil {
		t.Fatal(err)
	}
	var set proto.StorageBackupSet
	if err := json.Unmarshal(b, &set); err != nil {
		t.Fatal(err)
	}
	return &set
}

func startFakeRestoreAgent(t *testing.T, nc *nats.Conn, mount string, marker *proto.StorageBackupSet) {
	t.Helper()
	respond := func(m *nats.Msg, v any) {
		b, _ := json.Marshal(v)
		_ = m.Respond(b)
	}
	s1, err := nc.Subscribe(proto.StorageMountSubject(rtNodeID), func(m *nats.Msg) {
		respond(m, proto.StorageMountAck{OK: true, PartUUID: rtPartUUID, MountPath: mount})
	})
	if err != nil {
		t.Fatal(err)
	}
	s2, err := nc.Subscribe(proto.StorageEnumerateSubject(rtNodeID), func(m *nats.Msg) {
		respond(m, proto.StorageEnumerateAck{OK: true, Backend: "mock", Ts: time.Now().UTC(), Candidates: []proto.StorageCandidate{{
			DevicePath: "/dev/sdb", Model: "Archive", SizeBytes: 1 << 40, Transport: proto.StorageTransportUSB,
			HasBackupSet: true, BackupSet: marker, Fingerprint: "fp",
		}}})
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s1.Unsubscribe(); _ = s2.Unsubscribe() })
}

func (rf *restoreFixture) do(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest(method, path, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	rf.handler.ServeHTTP(w, r)
	return w
}

func (rf *restoreFixture) privB64() string {
	return base64.RawURLEncoding.EncodeToString(rf.priv.Bytes())
}
func (rf *restoreFixture) privHex() string { return hex.EncodeToString(rf.priv.Bytes()) }

func TestRestoreRoutesAreOpenOnlyBeforeTheFirstOperator(t *testing.T) {
	rf := newRestoreFixture(t)
	if w := rf.do(t, http.MethodGet, "/api/restore/candidates", nil); w.Code != http.StatusOK {
		t.Fatalf("candidates on a fresh box: %d %s", w.Code, w.Body.String())
	}
	rf.hasUsers = true
	if w := rf.do(t, http.MethodGet, "/api/restore/candidates", nil); w.Code != http.StatusConflict {
		t.Fatalf("candidates with an operator: %d %s", w.Code, w.Body.String())
	}
	w := rf.do(t, http.MethodPost, "/api/restore", map[string]string{
		"partUuid": rtPartUUID, "generationId": rf.genID, "keyId": rtKeyID, "privateKey": rf.privB64(),
	})
	if w.Code != http.StatusConflict {
		t.Fatalf("restore with an operator: %d %s", w.Code, w.Body.String())
	}
	if rf.restarts.Load() != 0 {
		t.Fatal("a refused restore asked for a restart")
	}
	if ents, _ := os.ReadDir(rf.dataDir); len(ents) != 0 {
		t.Fatalf("data dir written: %v", ents)
	}
}

func TestRestoreRoutesAnswer503Unconfigured(t *testing.T) {
	f := newAPIFixture(t)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/restore/candidates", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("%d", w.Code)
	}
	w = httptest.NewRecorder()
	f.handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/restore", strings.NewReader("{}")))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("%d", w.Code)
	}
}

func TestRestoreCandidatesDescribeTheDisk(t *testing.T) {
	rf := newRestoreFixture(t)
	w := rf.do(t, http.MethodGet, "/api/restore/candidates", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var resp storage.RestoreCandidatesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ClusterID != "home1" || len(resp.Candidates) != 1 || !resp.Candidates[0].Restorable || len(resp.Candidates[0].Generations) != 1 {
		t.Fatalf("resp = %+v", resp)
	}
	if g := resp.Candidates[0].Generations[0]; g.ID != rf.genID || !g.Restorable || len(g.AppVolumesPresent) != 1 {
		t.Fatalf("generation = %+v", g)
	}
	if strings.Contains(w.Body.String(), rf.privB64()) || strings.Contains(w.Body.String(), rf.privHex()) {
		t.Fatal("private key in the candidates response")
	}
}

func TestRestoreRefusesTheWrongKeyAndBadBodies(t *testing.T) {
	rf := newRestoreFixture(t)
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	cases := []struct {
		name string
		body any
		want int
	}{
		{"wrong key", map[string]string{"partUuid": rtPartUUID, "generationId": rf.genID, "keyId": rtKeyID,
			"privateKey": base64.RawURLEncoding.EncodeToString(other.Bytes())}, http.StatusForbidden},
		{"unknown field", map[string]string{"partUuid": rtPartUUID, "generationId": rf.genID, "keyId": rtKeyID,
			"privateKey": rf.privB64(), "passphrase": "hunter2"}, http.StatusBadRequest},
		{"not base64url", map[string]string{"partUuid": rtPartUUID, "generationId": rf.genID, "keyId": rtKeyID,
			"privateKey": "not+base64/url=="}, http.StatusBadRequest},
		{"short key", map[string]string{"partUuid": rtPartUUID, "generationId": rf.genID, "keyId": rtKeyID,
			"privateKey": base64.RawURLEncoding.EncodeToString([]byte("short"))}, http.StatusBadRequest},
		{"unknown generation", map[string]string{"partUuid": rtPartUUID, "generationId": "20200101T000000Z-x-full", "keyId": rtKeyID,
			"privateKey": rf.privB64()}, http.StatusUnprocessableEntity},
		{"wrong key id", map[string]string{"partUuid": rtPartUUID, "generationId": rf.genID, "keyId": "ak-other",
			"privateKey": rf.privB64()}, http.StatusUnprocessableEntity},
	}
	for _, c := range cases {
		w := rf.do(t, http.MethodPost, "/api/restore", c.body)
		if w.Code != c.want {
			t.Fatalf("%s: %d %s (want %d)", c.name, w.Code, w.Body.String(), c.want)
		}
		if strings.Contains(w.Body.String(), rf.privB64()) || strings.Contains(w.Body.String(), rf.privHex()) {
			t.Fatalf("%s: key in the response", c.name)
		}
	}
	if rf.restarts.Load() != 0 {
		t.Fatal("a refused restore asked for a restart")
	}
	if ents, _ := os.ReadDir(rf.dataDir); len(ents) != 0 {
		t.Fatalf("data dir written: %v", ents)
	}
}

func TestRestorePreparesAndAsksForARestart(t *testing.T) {
	rf := newRestoreFixture(t)
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	w := rf.do(t, http.MethodPost, "/api/restore", map[string]string{
		"partUuid": rtPartUUID, "generationId": rf.genID, "keyId": rtKeyID, "privateKey": rf.privB64(),
	})
	if w.Code != http.StatusAccepted {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var resp restoreResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Report == nil || !resp.Restarting || resp.Report.GenerationID != rf.genID || len(resp.Report.Restored) != 1 || resp.Report.Restored[0].Path != "rasputin.db" {
		t.Fatalf("resp = %+v", resp)
	}
	if len(resp.Report.AppVolumesPresent) != 1 || resp.Report.AppVolumesPresent[0].Name != "vaultwarden/data" {
		t.Fatalf("the app volume gap is not named: %+v", resp.Report.AppVolumesPresent)
	}
	if b, err := os.ReadFile(filepath.Join(rf.dataDir, "restore-pending", "rasputin.db")); err != nil || string(b) != "DB-BYTES" {
		t.Fatalf("staged db: %v %q", err, b)
	}
	deadline := time.Now().Add(5 * time.Second)
	for rf.restarts.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if rf.restarts.Load() != 1 {
		t.Fatal("the restart hook was not called")
	}
	for name, text := range map[string]string{"response": w.Body.String(), "log": logs.String()} {
		if strings.Contains(text, rf.privB64()) || strings.Contains(text, rf.privHex()) {
			t.Fatalf("the private key reached the %s", name)
		}
	}
	// A second restore while one is pending is refused.
	w = rf.do(t, http.MethodPost, "/api/restore", map[string]string{
		"partUuid": rtPartUUID, "generationId": rf.genID, "keyId": rtKeyID, "privateKey": rf.privB64(),
	})
	if w.Code != http.StatusConflict {
		t.Fatalf("second restore: %d %s", w.Code, w.Body.String())
	}
}

func TestListRestoresIsAuthenticatedAndReadsTheLedger(t *testing.T) {
	rf := newRestoreFixture(t)
	if w := rf.do(t, http.MethodGet, "/api/backup/restores", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d", w.Code)
	}
	cookie := rf.authenticate(t)
	st := rf.srv.backup
	if err := st.RecordRestore(context.Background(), &storage.RestoreReport{
		ID: "rs-1", Phase: storage.RestorePhase, GenerationID: rf.genID, KeyID: rtKeyID, PartUUID: rtPartUUID,
		PreparedAt: time.Now().UTC(), Restored: []storage.RestoredEntry{}, NotRestored: []storage.NotRestoredItem{},
		AppVolumesPresent: []storage.AppVolumeMention{{Name: "vaultwarden/data"}}, AppVolumesAbsent: []storage.AppVolumeMention{},
	}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/api/backup/restores", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	rf.handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var rows []storage.RestoreReport
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil || len(rows) != 1 || rows[0].ID != "rs-1" {
		t.Fatalf("rows = %+v (%v)", rows, err)
	}
}
