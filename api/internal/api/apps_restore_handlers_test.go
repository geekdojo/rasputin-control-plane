package api

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/catalogsync"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// The app-volume restore routes (#291 phase 2): the listing offers the
// generation that holds the app; the submit refuses an app that is not
// installed, a node that is offline and a key that does not open the disk —
// each BEFORE a job exists — and a good request leaves a job whose spec
// carries a session handle and never the key; the egress route answers 503
// unconfigured and refuses a request with no credential.

const (
	arNodeID   = "self-node"
	arPartUUID = "abcd-0002"
	arKeyID    = "ak-app"
	arAppID    = "01J6ZK3Q9V8XKX2M5TQ7R4A9C0"
)

type appRestoreFixture struct {
	*apiFixture
	cookie   *http.Cookie
	mount    string
	priv     *ecdh.PrivateKey
	pubB64   string
	genID    string
	backup   *storage.Store
	sessions *storage.RestoreSessions
}

func newAppRestoreFixture(t *testing.T) *appRestoreFixture {
	t.Helper()
	f := newAPIFixture(t)
	cookie := f.authenticate(t)
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	af := &appRestoreFixture{apiFixture: f, cookie: cookie, priv: priv, pubB64: base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())}
	af.mount = filepath.Join(f.dir, "mnt-app")

	// The catalog: vaultwarden classifies one critical volume.
	b := oneTileBundle(7, "vaultwarden")
	b.Tiles[0].Tile.Volumes = []tileschema.Volume{{Name: "vaultwarden-data", Backup: tileschema.BackupCritical, Quiesce: tileschema.QuiesceStop}}
	catalog, err := catalogsync.New(t.TempDir(), stubVerifier{}, b)
	if err != nil {
		t.Fatal(err)
	}
	f.srv.SetCatalogSync(catalog, nil)

	// The ledger: a claimed target on this node with the key.
	backup, err := storage.OpenStore(f.ctx, filepath.Join(f.dir, "backup-app.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backup.Close() })
	if err := backup.CreatePending(f.ctx, "job-claim", arNodeID, "/dev/sdb", "the archive disk", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := backup.MarkClaimed(f.ctx, "job-claim", storage.ClaimResult{
		PartUUID: arPartUUID, DevicePath: "/dev/sdb", MountPath: af.mount, FSType: "ext4", SizeBytes: 1 << 40, At: time.Now().UTC(),
		Key: &storage.ArchiveKey{KeyID: arKeyID, Alg: "x25519", PublicKey: af.pubB64, WrappedByPassphrase: "WRAPPED-PP", WrappedByRecoveryCode: "WRAPPED-RC"},
	}); err != nil {
		t.Fatal(err)
	}
	f.srv.SetBackupStore(backup)
	af.backup = backup

	// The disk: a marker and one generation whose manifest records the
	// app's volume by id.
	af.genID = buildAppRestoreGeneration(t, af.mount, af.pubB64)
	marker := readTestMarker(t, af.mount)
	startFakeRestoreAgent(t, f.nc, af.mount, marker)

	// The node the app is on: online.
	now := time.Now().UTC()
	if err := f.inv.Insert(f.ctx, &proto.Node{ID: arNodeID, Role: proto.RoleControlPlane, Hostname: arNodeID + ".test", FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	if err := f.inv.Insert(f.ctx, &proto.Node{ID: "n-off", Role: proto.RoleCompute, Hostname: "n-off.test", FirstSeen: now.Add(-time.Hour), LastSeen: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}

	auth, err := backupxfer.NewAuthority()
	if err != nil {
		t.Fatal(err)
	}
	sessions := storage.NewRestoreSessions()
	egress := storage.NewRestoreEgress(auth, sessions)
	cfg := &storage.RestoreAppConfig{
		NC: f.nc, SelfNodeID: arNodeID, Apps: f.appsStore, Tiles: catalog, Inventory: f.inv,
		Sessions: sessions, Egress: egress, EgressBaseURL: "https://cp.test", Store: backup,
	}
	f.srv.runner.Register(storage.RestoreAppWorkflow(backup, *cfg))
	f.srv.SetAppRestore(cfg, egress)
	af.sessions = sessions
	return af
}

// buildAppRestoreGeneration writes a marker and one sealed generation whose
// manifest records vaultwarden-data for arAppID, and returns the id.
func buildAppRestoreGeneration(t *testing.T, mount, pubB64 string) string {
	t.Helper()
	marker := proto.StorageBackupSet{
		MarkerVersion: proto.StorageMarkerVersion, ClusterID: "home1", PartUUID: arPartUUID,
		KeyID: arKeyID, PublicKey: pubB64, WrappedByPassphrase: "WRAPPED-PP", WrappedByRecoveryCode: "WRAPPED-RC", CreatedAt: time.Now().UTC(),
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
		App: "vaultwarden", AppID: arAppID, TileID: "vaultwarden", Volume: "vaultwarden-data", Class: "critical", Node: arNodeID, Captured: true,
		Member: proto.BackupMemberPath("vaultwarden", "vaultwarden-data"), SealedSHA256: strings.Repeat("cd", 32), SealedSizeBytes: 10,
		SizeBytes: 10, SHA256: strings.Repeat("ab", 32), FileCount: 1, AppRestored: true,
	}}, 1)
	var tarBuf bytes.Buffer
	m, err := storage.Assemble(&tarBuf, storage.AssembleOptions{
		Sources: storage.IdentitySources{}, SnapshotPath: filepath.Join(src, "snapshot.db"),
		GenerationID: genID, JobID: "job-1", ClusterID: "home1", KeyID: arKeyID, AppVolumes: report, Scope: proto.BackupScopeFull,
	})
	if err != nil {
		t.Fatal(err)
	}
	var sealed bytes.Buffer
	if _, err := backupxfer.Seal(&sealed, bytes.NewReader(tarBuf.Bytes()), pubB64, arKeyID, proto.BackupScopeFull); err != nil {
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

func (af *appRestoreFixture) seedApp(t *testing.T, node string) {
	t.Helper()
	now := time.Now().UTC()
	if err := af.appsStore.Create(af.ctx, &apps.App{
		ID: arAppID, Name: "vaultwarden", ComposeYAML: "services: {}", TargetNode: node, SourceTile: "vaultwarden",
		LastStatus: proto.AppStatusRunning, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
}

func (af *appRestoreFixture) privB64() string {
	return base64.RawURLEncoding.EncodeToString(af.priv.Bytes())
}
func (af *appRestoreFixture) privHex() string { return hex.EncodeToString(af.priv.Bytes()) }

func (af *appRestoreFixture) post(t *testing.T, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	return af.do(t, http.MethodPost, "/api/apps/"+arAppID+"/restore", string(b), af.cookie)
}

func (af *appRestoreFixture) goodBody() map[string]any {
	return map[string]any{"partUuid": arPartUUID, "generationId": af.genID, "keyId": arKeyID, "privateKey": af.privB64()}
}

func TestAppRestoreSourcesOfferTheGenerationThatHoldsTheApp(t *testing.T) {
	af := newAppRestoreFixture(t)
	af.seedApp(t, arNodeID)
	w := af.do(t, http.MethodGet, "/api/apps/"+arAppID+"/restore-sources", "", af.cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var out storage.AppRestoreSources
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.Installed || !out.NodeOnline || out.NodeID != arNodeID || out.Marker == nil || out.Marker.WrappedByPassphrase != "WRAPPED-PP" {
		t.Fatalf("sources: %+v", out)
	}
	if len(out.Generations) != 1 || out.Generations[0].ID != af.genID || !out.Generations[0].Restorable || len(out.Generations[0].Volumes) != 1 {
		t.Fatalf("generations: %+v", out.Generations)
	}
	// The listing carries wrapped ciphertext and the public key, never the
	// private key (which the api does not even hold here).
	if strings.Contains(w.Body.String(), af.privB64()) {
		t.Fatal("private key in the listing")
	}
	// Unauthenticated: refused.
	if w := af.do(t, http.MethodGet, "/api/apps/"+arAppID+"/restore-sources", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d", w.Code)
	}
}

func TestAppRestoreRefusesBeforeAJobExists(t *testing.T) {
	af := newAppRestoreFixture(t)
	// Not installed: 404, and the body says install it first.
	if w := af.post(t, af.goodBody()); w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "install the app first") {
		t.Fatalf("not installed: %d %s", w.Code, w.Body.String())
	}
	// Installed on an offline node: 409 naming the node, not queued.
	af.seedApp(t, "n-off")
	if w := af.post(t, af.goodBody()); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "n-off") || !strings.Contains(w.Body.String(), "not queued") {
		t.Fatalf("offline: %d %s", w.Code, w.Body.String())
	}
	if j, _ := af.jobsStore.ListJobs(af.ctx, 10); len(j) != 0 {
		t.Fatalf("jobs were created for refused requests: %d", len(j))
	}
	if _, active := af.sessions.Active(); active {
		t.Fatal("a session was opened for a refused request")
	}
}

func TestAppRestoreRefusesTheWrongKeyWithNoJobAndNoSession(t *testing.T) {
	af := newAppRestoreFixture(t)
	af.seedApp(t, arNodeID)
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	body := af.goodBody()
	body["privateKey"] = base64.RawURLEncoding.EncodeToString(other.Bytes())
	w := af.post(t, body)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "does not belong to this disk") {
		t.Fatalf("wrong key: %d %s", w.Code, w.Body.String())
	}
	if j, _ := af.jobsStore.ListJobs(af.ctx, 10); len(j) != 0 {
		t.Fatal("a job was created for a key that does not open the disk")
	}
	if _, active := af.sessions.Active(); active {
		t.Fatal("a session holds a key that does not open the disk")
	}
	for name, body := range map[string]map[string]any{
		"unknown field":  {"partUuid": arPartUUID, "generationId": af.genID, "keyId": arKeyID, "privateKey": af.privB64(), "passphrase": "hunter2"},
		"short key":      {"partUuid": arPartUUID, "generationId": af.genID, "keyId": arKeyID, "privateKey": base64.RawURLEncoding.EncodeToString([]byte("short"))},
		"bad generation": {"partUuid": arPartUUID, "generationId": "../x", "keyId": arKeyID, "privateKey": af.privB64()},
	} {
		if w := af.post(t, body); w.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body.String())
		}
	}
	if w := af.post(t, map[string]any{"partUuid": arPartUUID, "generationId": af.genID, "keyId": "ak-other", "privateKey": af.privB64()}); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("wrong key id: %d %s", w.Code, w.Body.String())
	}
}

func TestAppRestoreSubmitsAJobWithASessionHandleAndNeverTheKey(t *testing.T) {
	af := newAppRestoreFixture(t)
	af.seedApp(t, arNodeID)
	w := af.post(t, af.goodBody())
	if w.Code != http.StatusAccepted {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var resp appRestoreResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.Job == nil || resp.Job.Kind != storage.RestoreAppJobKind {
		t.Fatalf("response: %v %s", err, w.Body.String())
	}
	var spec storage.RestoreAppSpec
	if err := json.Unmarshal(resp.Job.Spec, &spec); err != nil || spec.SessionID == "" || spec.AppID != arAppID || spec.GenerationID != af.genID {
		t.Fatalf("spec: %v %s", err, resp.Job.Spec)
	}
	for _, text := range []string{w.Body.String(), string(resp.Job.Spec)} {
		if strings.Contains(text, af.privB64()) || strings.Contains(text, af.privHex()) {
			t.Fatal("the private key is in the response or the spec")
		}
	}
	// The job runs to a terminal state (no agent answers the verb here, so
	// it ends failed with the node named) and the session dies with it.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		j, _ := af.jobsStore.GetJob(af.ctx, resp.Job.ID)
		if j != nil && (j.Status == jobs.StatusSucceeded || j.Status == jobs.StatusFailed) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	af.srv.runner.Wait()
	if _, active := af.sessions.Active(); active {
		t.Fatal("the session outlived the job")
	}
	// A second submit is refused while a session is active.
	sid, err := af.sessions.Open(af.priv.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	_ = af.sessions.Bind(sid, "job-elsewhere")
	if w := af.post(t, af.goodBody()); w.Code != http.StatusConflict {
		t.Fatalf("concurrent restore: %d %s", w.Code, w.Body.String())
	}
}

func TestRestoreEgressRouteIsUnauthenticatedButCredentialed(t *testing.T) {
	f := newAPIFixture(t)
	path := backupxfer.EgressPathPrefix + "20260904T000000Z-x-full/volumes/vaultwarden/vaultwarden-data.rasputin-archive"
	if w := f.do(t, http.MethodGet, path, "", nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured: %d", w.Code)
	}
	af := newAppRestoreFixture(t)
	if w := af.do(t, http.MethodGet, path, "", nil); w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), backupxfer.CodeCredentialInvalid) {
		t.Fatalf("no credential: %d %s", w.Code, w.Body.String())
	}
}
