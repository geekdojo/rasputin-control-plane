package storage

import (
	"archive/tar"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/backupxfer/fsat"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
	"github.com/nats-io/nats.go"
)

// Harness for the backup.run saga: a real jobs.Runner over an in-process NATS
// server, a real SQLite database (so `VACUUM INTO` is exercised rather than
// mocked), a real staging directory on disk, a REAL ingest endpoint
// (backupxfer.Ingest, the handler the api mounts) served over a real socket
// onto a real temp target, and fake agents answering the backup verbs.
//
// The fake agents RE-HASH what they are told to write, exactly as the real
// one does, and their transfer verb is the REAL transport client
// (backupxfer.TransportFor) sealing with the REAL seal — so the protocol
// functional test drives both ends of backupxfer for real; only the docker
// runtime and the block-device backend are faked.

// testKeypair is a real X25519 keypair. The PRIVATE half exists only in the
// test binary — this package has no field, parameter or return value that
// could carry it, which is the property backup_seal_test.go asserts.
type testKeypair struct {
	priv      *ecdh.PrivateKey
	publicB64 string
}

func newTestKeypair(t *testing.T) testKeypair {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate X25519 key: %v", err)
	}
	return testKeypair{
		priv:      priv,
		publicB64: base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()),
	}
}

// privateB64 and privateHex are the two encodings a leak would most plausibly
// take. The scan in backup_seal_test.go looks for both.
func (k testKeypair) privateB64() string {
	return base64.RawURLEncoding.EncodeToString(k.priv.Bytes())
}

func (k testKeypair) privateHex() string { return hex.EncodeToString(k.priv.Bytes()) }

const (
	runNodeID   = "n-backup"
	runPartUUID = "part-uuid-target"
	// Stand-ins for the two §4.6 wrappings. Opaque ciphertext to the api, and
	// the scan asserts neither reaches a step result or an event.
	testWrappedPass     = "WRAPPED-BY-PASSPHRASE-BLOB-AAAA"
	testWrappedRecovery = "WRAPPED-BY-RECOVERY-CODE-BLOB-BBBB"
)

// fakeBackupAgent answers the three backup verbs and records what it was asked.
//
// The recording is the point of several cases: "how many times was write
// called?" is the only way to prove the runner did not retry an Irreversible
// step, and "what Keep did prune get?" is the only way to prove §4.4's
// retention reached the disk.
type fakeBackupAgent struct {
	nodeID      string
	stagingRoot string
	// mountPath is the target's mount on the fake's node — a real temp
	// directory, because the ingest endpoint writes members under it.
	mountPath string
	// key is the target keypair the transfer verb seals to (public half
	// only, as the command carries it).
	mu        sync.Mutex
	preflight func(cmd proto.BackupPreflightCmd) proto.BackupPreflightAck
	write     func(cmd proto.BackupWriteCmd) proto.BackupWriteAck
	prune     func(cmd proto.BackupPruneCmd) proto.BackupPruneAck

	preflightCmds []proto.BackupPreflightCmd
	writeCmds     []proto.BackupWriteCmd
	pruneCmds     []proto.BackupPruneCmd
	// writeDigests is what the agent computed over the staged bytes itself,
	// one per write call, so a test can compare it with what the api claimed.
	writeDigests []string
	// writeBodies is the sealed archive the agent actually read, kept so a test
	// can open the header and check what is bound into the AEAD — the one
	// surface that cannot be edited after the fact.
	writeBodies [][]byte
	// staged and unstaged are the app-volume phase's record, and
	// maxLiveStaged is the most staged copies that existed at once — §4.7's
	// peak, observed rather than assumed.
	staged        []stagedVolume
	unstaged      []string
	maxLiveStaged int
	// transfers is every transfer command and ack, in order; credentials
	// remembers the credential each member was handed so a test can replay
	// or mis-scope one.
	transfers []transferRecord
	// credentials is SHARED between the harness's fakes (one book per
	// harness), so a case can have one node present another node's
	// credential — the mis-scoped upload the endpoint must refuse.
	credentials *credentialBook
	// generations is the fake target's contents, oldest first.
	generations []string
	// The restore verb's record: where each app's volumes live on this
	// node, every call answered, and the stop/start counts.
	volumeDirs map[string]string
	restores   []restoreCall
	stops      int
	starts     int
}

// credentialBook remembers the credential each volume was handed.
type credentialBook struct {
	mu sync.Mutex
	by map[string]string
}

func (b *credentialBook) put(volume, cred string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.by == nil {
		b.by = map[string]string{}
	}
	b.by[volume] = cred
}

func (b *credentialBook) get(volume string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.by[volume]
}

type transferRecord struct {
	cmd proto.BackupTransferCmd
	ack proto.BackupTransferAck
}

func (f *fakeBackupAgent) transferRecords() []transferRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]transferRecord(nil), f.transfers...)
}

func (f *fakeBackupAgent) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.writeCmds)
}

func (f *fakeBackupAgent) lastWrite() (proto.BackupWriteCmd, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.writeCmds) == 0 {
		return proto.BackupWriteCmd{}, false
	}
	return f.writeCmds[len(f.writeCmds)-1], true
}

func (f *fakeBackupAgent) lastPrune() (proto.BackupPruneCmd, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.pruneCmds) == 0 {
		return proto.BackupPruneCmd{}, false
	}
	return f.pruneCmds[len(f.pruneCmds)-1], true
}

func (f *fakeBackupAgent) start(t *testing.T, nc *nats.Conn) *fakeBackupAgent {
	t.Helper()
	respond := func(m *nats.Msg, v any) {
		b, err := json.Marshal(v)
		if err != nil {
			t.Errorf("fake backup agent marshal: %v", err)
			return
		}
		_ = m.Respond(b)
	}
	var subs []*nats.Subscription

	sub, err := nc.Subscribe(proto.BackupPreflightSubject(f.nodeID), func(m *nats.Msg) {
		var cmd proto.BackupPreflightCmd
		_ = json.Unmarshal(m.Data, &cmd)
		f.mu.Lock()
		f.preflightCmds = append(f.preflightCmds, cmd)
		fn := f.preflight
		f.mu.Unlock()
		if fn == nil {
			respond(m, proto.BackupPreflightAck{
				OK: true, Present: true, PartUUID: cmd.PartUUID,
				MountPath: f.mountPath, TotalBytes: 2 << 40,
				FreeBytes: 1 << 40, RequiredBytes: cmd.EstimateBytes, Sufficient: true,
				// The real agent answers with the root its write verb reads,
				// and so does this one — a fake that omitted it would let the
				// api go back to guessing without a test noticing.
				StagingRoot: f.stagingRoot,
			})
			return
		}
		respond(m, fn(cmd))
	})
	if err != nil {
		t.Fatalf("fake preflight sub: %v", err)
	}
	subs = append(subs, sub)

	sub, err = nc.Subscribe(proto.BackupWriteSubject(f.nodeID), func(m *nats.Msg) {
		var cmd proto.BackupWriteCmd
		_ = json.Unmarshal(m.Data, &cmd)
		// Re-hash the staged file for real, like the agent does. A fake that
		// echoed the digest back would make the digest untestable.
		digest := ""
		var body []byte
		if f.stagingRoot != "" && proto.BackupValidStagingName(cmd.StagingName) {
			if b, rerr := os.ReadFile(filepath.Join(f.stagingRoot, cmd.StagingName)); rerr == nil {
				sum := sha256.Sum256(b)
				digest = hex.EncodeToString(sum[:])
				body = b
			}
		}
		f.mu.Lock()
		f.writeCmds = append(f.writeCmds, cmd)
		f.writeDigests = append(f.writeDigests, digest)
		f.writeBodies = append(f.writeBodies, body)
		f.generations = append(f.generations, cmd.GenerationID)
		fn := f.write
		f.mu.Unlock()
		if fn == nil {
			// The commit, the way the real write verb does it: the identity
			// archive and the manifest go BESIDE the members the ingest
			// endpoint landed in `.partial-<gen>`, and the rename is the
			// generation. A fake that only recorded the command would leave
			// the layout untested.
			if f.mountPath != "" && body != nil {
				gens := filepath.Join(f.mountPath, proto.BackupGenerationsDir)
				partial := filepath.Join(gens, proto.BackupPartialDirName(cmd.GenerationID))
				if err := os.MkdirAll(partial, 0o700); err != nil {
					t.Errorf("fake write: %v", err)
				}
				if err := os.WriteFile(filepath.Join(partial, proto.BackupArchiveFile), body, 0o600); err != nil {
					t.Errorf("fake write: %v", err)
				}
				if err := os.WriteFile(filepath.Join(partial, proto.BackupManifestFile), []byte(cmd.ManifestJSON), 0o600); err != nil {
					t.Errorf("fake write: %v", err)
				}
				if err := os.Rename(partial, filepath.Join(gens, cmd.GenerationID)); err != nil {
					t.Errorf("fake write: commit: %v", err)
				}
			}
			respond(m, defaultWriteAck(cmd, digest))
			return
		}
		respond(m, fn(cmd))
	})
	if err != nil {
		t.Fatalf("fake write sub: %v", err)
	}
	subs = append(subs, sub)

	sub, err = nc.Subscribe(proto.BackupPruneSubject(f.nodeID), func(m *nats.Msg) {
		var cmd proto.BackupPruneCmd
		_ = json.Unmarshal(m.Data, &cmd)
		f.mu.Lock()
		f.pruneCmds = append(f.pruneCmds, cmd)
		fn := f.prune
		gens := append([]string(nil), f.generations...)
		f.mu.Unlock()
		if fn == nil {
			respond(m, defaultPruneAck(cmd, gens))
			return
		}
		respond(m, fn(cmd))
	})
	if err != nil {
		t.Fatalf("fake prune sub: %v", err)
	}
	subs = append(subs, sub)

	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})
	return f
}

// lastSealed is the sealed archive the agent last read, for the test that
// checks the scope is bound into the AEAD's additional data.
func (f *fakeBackupAgent) lastSealed() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.writeBodies) == 0 {
		return nil
	}
	return f.writeBodies[len(f.writeBodies)-1]
}

func defaultWriteAck(cmd proto.BackupWriteCmd, digest string) proto.BackupWriteAck {
	return proto.BackupWriteAck{
		OK: true, PartUUID: cmd.PartUUID,
		Generation: proto.BackupGeneration{
			ID:           cmd.GenerationID,
			ArchivePath:  "/mnt/rasputin-backup/generations/" + cmd.GenerationID + "/" + proto.BackupArchiveFile,
			ManifestPath: "/mnt/rasputin-backup/generations/" + cmd.GenerationID + "/" + proto.BackupManifestFile,
			SizeBytes:    cmd.SizeBytes,
			Digest:       digest,
			WrittenAt:    time.Now().UTC(),
			Scope:        proto.BackupScopeFull,
		},
		FreeBytes: 1 << 40,
	}
}

// defaultPruneAck applies the CONVERGENT rule the real verb applies: keep the
// newest Keep, delete the rest. Written out here rather than stubbed so the
// api-side test of "prune keeps exactly 4" is exercising the same rule.
func defaultPruneAck(cmd proto.BackupPruneCmd, gens []string) proto.BackupPruneAck {
	ack := proto.BackupPruneAck{OK: true, PartUUID: cmd.PartUUID}
	// gens is oldest-first; the verb orders newest-first.
	for i := len(gens) - 1; i >= 0; i-- {
		g := gens[i]
		idx := len(gens) - 1 - i
		if idx < cmd.Keep || g == cmd.ProtectGenerationID {
			ack.Kept = append(ack.Kept, g)
			continue
		}
		ack.Pruned = append(ack.Pruned, g)
	}
	return ack
}

// ----- runner harness -----------------------------------------------------

type runHarness struct {
	nc       *nats.Conn
	store    *Store
	jobStore *jobs.Store
	runner   *jobs.Runner
	// agent is the controlplane node's fake; compute is the compute node's
	// (stage/transfer/unstage only), present when opts.computeAgent asked for
	// it. A case with an app on computeNodeID and no compute agent is the
	// offline-node case.
	agent       *fakeBackupAgent
	compute     *fakeBackupAgent
	key         testKeypair
	stagingDir  string
	trustDir    string
	meshDir     string
	dbPath      string
	mountDir    string
	ingest      *backupxfer.Ingest
	settings    *memorySettings
	targetJobID string
	// The app-volume restore surface (#291 phase 2), wired when
	// opts.restore is set: the session registry, the egress endpoint served
	// on the SAME socket as the ingest, and the config the workflow was
	// registered with.
	sessions   *RestoreSessions
	egress     *RestoreEgress
	restoreCfg RestoreAppConfig
	baseURL    string
	inv        *inventory.Store
}

// generationDir is the committed generation's directory on the fake target.
func (h *runHarness) generationDir(genID string) string {
	return filepath.Join(h.mountDir, proto.BackupGenerationsDir, genID)
}

// memorySettings is the ScheduleSettings slice, in memory. The real one is the
// setup package's settings table; importing it here would be a dependency this
// package has for no other reason.
type memorySettings struct {
	mu sync.Mutex
	kv map[string]string
}

func newMemorySettings() *memorySettings { return &memorySettings{kv: map[string]string{}} }

func (m *memorySettings) Get(_ context.Context, key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.kv[key], nil
}

func (m *memorySettings) Set(_ context.Context, key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.kv[key] = value
	return nil
}

type runHarnessOpts struct {
	// noTarget leaves the ledger without a claimed target.
	noTarget bool
	// noKey claims a target with no §4.6 public key — a disk claimed before
	// encryption was configured, or under the pre-amendment symmetric design.
	noKey bool
	// noPartUUID claims a target with no partition UUID.
	noPartUUID bool
	// badKey claims a target whose public key is not a usable X25519 key.
	badKey string
	// retain overrides §4.4's four generations.
	retain int
	// targetNodeID claims the target on a node other than the one the api runs
	// on. Empty means runNodeID, the co-located case.
	targetNodeID string
	// selfNodeID overrides what the api believes its own node is. Only set to
	// "" deliberately, to cover the api that does not know.
	selfNodeID *string
	// apps and tiles are the fan-out's two inputs. Nil `tiles` still supplies
	// an empty catalog, because a nil one is a DIFFERENT case — step 1 refuses
	// an api that cannot enumerate at all — and only the test for that refusal
	// should reach it.
	apps  []*apps.App
	tiles TileVolumes
	// noAppSource leaves RunConfig.Apps and .Tiles nil, for the step-1 refusal.
	noAppSource bool
	// appsErr makes the installed-app list fail.
	appsErr error
	// stageOutcomes decides what the fake agents do with each volume, keyed
	// by volume name.
	stageOutcomes map[string]stageOutcome
	// computeAgent starts a second fake agent on computeNodeID, so an app
	// deployed there has a node to stage on. Without it that node is offline.
	computeAgent bool
	// noIngest leaves RunConfig.Ingest nil, for the step-1 refusal.
	noIngest bool
	// nodes seeds an inventory store with these rows and hands it to the
	// run as RunConfig.Inventory, so a silent node is read against what
	// inventory says about it. Nil leaves Inventory nil: every silence then
	// reads as offline.
	nodes []*proto.Node
	// key, when set, is the target keypair the run seals to instead of a
	// fresh one — the restore round-trip supplies the keypair a browser-
	// produced fixture wrapped. keyID likewise overrides the target's key id.
	key   *testKeypair
	keyID string
	// restore registers backup.restore_app beside backup.run, with the
	// restore-stream endpoint on the ingest's socket and the fake agents
	// answering the restore verb (startRestoreAgent).
	restore bool
	// restoreOutcomes decides what the fake agents do with each restore,
	// keyed by volume name.
	restoreOutcomes map[string]restoreOutcome
}

func newRunHarness(t *testing.T, agent *fakeBackupAgent, opts runHarnessOpts) *runHarness {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "rasputin.db")

	st, err := OpenStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	js, err := jobs.OpenStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("jobs.OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = js.Close() })

	// A real identity set on disk: the trust dir's two PEMs and a Headscale
	// state tree. Real files, because Assemble hashes them twice and a stub
	// would not exercise that.
	trustDir := filepath.Join(dir, "trust")
	if err := os.MkdirAll(trustDir, 0o700); err != nil {
		t.Fatalf("trust dir: %v", err)
	}
	writeTestFile(t, filepath.Join(trustDir, "mesh-ca.key"), "-----BEGIN PRIVATE KEY-----\nMESH-CA-KEY-MATERIAL\n-----END PRIVATE KEY-----\n")
	writeTestFile(t, filepath.Join(trustDir, "mesh-ca.pem"), "-----BEGIN CERTIFICATE-----\nMESH-CA-CERT\n-----END CERTIFICATE-----\n")
	meshDir := filepath.Join(dir, "mesh")
	if err := os.MkdirAll(filepath.Join(meshDir, "headscale", "db"), 0o700); err != nil {
		t.Fatalf("headscale dir: %v", err)
	}
	writeTestFile(t, filepath.Join(meshDir, "headscale", "config.yaml"), "server_url: https://cp.test\n")
	writeTestFile(t, filepath.Join(meshDir, "headscale", "db", "headscale.sqlite"), "HEADSCALE-STATE")

	// The AGENT's staging root, and deliberately not a directory the api could
	// have derived from anything it is given: `dir` is this harness's stand-in
	// for the api's data dir, and the staging root is under an `agent-state`
	// subdirectory the way the shipping image has it. Under the code this
	// replaces the api would have staged into <dir>/backup-staging and every
	// saga test below would fail on the write — which is exactly what the
	// e3bench run did and no test did.
	stagingDir := filepath.Join(dir, "agent-state", "backup-staging")
	if err := EnsureStagingDir(stagingDir); err != nil {
		t.Fatalf("staging dir: %v", err)
	}

	nc := startNATS(t)
	key := newTestKeypair(t)
	if opts.key != nil {
		key = *opts.key
	}

	// The target: a real directory standing in for the claimed disk's mount,
	// and the REAL ingest endpoint served on a real socket. The api's fan-out
	// mints credentials through this Ingest and the fake agents upload to
	// this server, exactly as the shipping halves do.
	mountDir := filepath.Join(dir, "mnt", "rasputin-backup")
	if err := os.MkdirAll(mountDir, 0o700); err != nil {
		t.Fatalf("mount dir: %v", err)
	}
	auth, err := backupxfer.NewAuthority()
	if err != nil {
		t.Fatal(err)
	}
	ingest := backupxfer.New(auth, 1)
	sessions := NewRestoreSessions()
	egress := NewRestoreEgress(auth, sessions)
	mux := http.NewServeMux()
	mux.Handle("PUT "+backupxfer.IngestPathPrefix, ingest)
	mux.Handle("GET "+backupxfer.EgressPathPrefix, egress)
	ingestSrv := httptest.NewServer(mux)
	t.Cleanup(ingestSrv.Close)

	if agent == nil {
		agent = &fakeBackupAgent{}
	}
	book := &credentialBook{}
	agent.nodeID = runNodeID
	agent.stagingRoot = stagingDir
	agent.mountPath = mountDir
	agent.credentials = book
	agent.start(t, nc)
	agent.startVolumeAgent(t, nc, opts.stageOutcomes)
	if opts.restore {
		agent.startRestoreAgent(t, nc, opts.restoreOutcomes)
	}

	h := &runHarness{
		nc: nc, store: st, jobStore: js, agent: agent, key: key,
		stagingDir: stagingDir, trustDir: trustDir, meshDir: meshDir,
		dbPath: dbPath, mountDir: mountDir, ingest: ingest, settings: newMemorySettings(),
		sessions: sessions, egress: egress, baseURL: ingestSrv.URL,
	}
	if opts.computeAgent {
		computeStaging := filepath.Join(dir, "compute-state", "backup-staging")
		if err := EnsureStagingDir(computeStaging); err != nil {
			t.Fatalf("compute staging dir: %v", err)
		}
		h.compute = &fakeBackupAgent{nodeID: computeNodeID, stagingRoot: computeStaging, credentials: book}
		h.compute.startVolumeAgent(t, nc, opts.stageOutcomes)
		if opts.restore {
			h.compute.startRestoreAgent(t, nc, opts.restoreOutcomes)
		}
	}

	if !opts.noTarget {
		h.targetJobID = seedRunTarget(t, st, key, opts)
	}

	r := jobs.NewRunner(js, nc)
	r.SetBackoff(func(int) time.Duration { return 0 })
	// No staging directory is configured here, because the api has none to
	// configure: it stages where the preflight ack says the agent reads.
	self := runNodeID
	if opts.selfNodeID != nil {
		self = *opts.selfNodeID
	}
	cfg := RunConfig{
		ClusterID:     "home1",
		SelfNodeID:    self,
		Sources:       IdentitySources{TrustDir: trustDir, MeshStateDir: meshDir},
		DB:            st.DB(),
		DBPath:        dbPath,
		Retain:        opts.retain,
		IngestBaseURL: ingestSrv.URL,
		// The schedule setting and the job ledger, wired the way main wires
		// them: a run reads its retention depth from the one and the sizes
		// of earlier captures from the other.
		Settings: h.settings,
		Jobs:     js,
	}
	if !opts.noIngest {
		cfg.Ingest = ingest
	}
	if len(opts.nodes) > 0 {
		inv := newInventory(t)
		for _, n := range opts.nodes {
			if err := inv.Insert(ctx, n); err != nil {
				t.Fatalf("inv insert %s: %v", n.ID, err)
			}
		}
		cfg.Inventory = inv
		h.inv = inv
	}
	if !opts.noAppSource {
		tiles := opts.tiles
		if tiles == nil {
			tiles = fakeTiles{}
		}
		cfg.Apps = &fakeApps{list: opts.apps, err: opts.appsErr}
		cfg.Tiles = tiles
	}
	if opts.restore {
		cfg.Restores = sessions
		h.restoreCfg = RestoreAppConfig{
			NC: nc, SelfNodeID: self, Apps: &fakeApps{list: opts.apps, err: opts.appsErr}, Tiles: cfg.Tiles,
			Inventory: h.inv, Sessions: sessions, Egress: egress, EgressBaseURL: ingestSrv.URL, Store: st,
		}
		r.Register(RestoreAppWorkflow(st, h.restoreCfg))
	}
	r.Register(RunWorkflow(st, cfg))
	h.runner = r
	return h
}

// submitRestore opens a session for the harness's private key, submits a
// backup.restore_app job for it, binds the two, and returns the job id —
// the handler's sequence, without the HTTP.
func (h *runHarness) submitRestore(t *testing.T, spec RestoreAppSpec) string {
	t.Helper()
	priv := h.key.priv.Bytes()
	sid, err := h.sessions.Open(priv)
	if err != nil {
		t.Fatalf("sessions.Open: %v", err)
	}
	spec.SessionID = sid
	body, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	j, err := h.runner.Submit(context.Background(), RestoreAppJobKind, body, "test")
	if err != nil {
		t.Fatalf("Submit restore: %v", err)
	}
	if err := h.sessions.Bind(sid, j.ID); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	return j.ID
}

func writeTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// seedRunTarget puts a claimed backup target in the ledger through the
// store's own writes, so the row is shaped exactly as a real claim leaves it.
func seedRunTarget(t *testing.T, st *Store, key testKeypair, opts runHarnessOpts) string {
	t.Helper()
	ctx := context.Background()
	jobID := "job-claim-1"
	nodeID := runNodeID
	if opts.targetNodeID != "" {
		nodeID = opts.targetNodeID
	}
	if err := st.CreatePending(ctx, jobID, nodeID, "/dev/sdb", "the archive disk", time.Now().UTC()); err != nil {
		t.Fatalf("CreatePending: %v", err)
	}
	pub := key.publicB64
	if opts.noKey {
		pub = ""
	}
	if opts.badKey != "" {
		pub = opts.badKey
	}
	partUUID := runPartUUID
	if opts.noPartUUID {
		partUUID = ""
	}
	res := ClaimResult{
		PartUUID:   partUUID,
		DevicePath: "/dev/sdb",
		MountPath:  "/mnt/rasputin-backup",
		FSType:     "ext4",
		SizeBytes:  2 << 40,
		At:         time.Now().UTC(),
	}
	keyID := "key-1"
	if opts.keyID != "" {
		keyID = opts.keyID
	}
	if pub != "" {
		res.Key = &ArchiveKey{
			KeyID:                 keyID,
			Alg:                   "x25519+argon2id",
			PublicKey:             pub,
			WrappedByPassphrase:   testWrappedPass,
			WrappedByRecoveryCode: testWrappedRecovery,
		}
	} else if opts.noPartUUID {
		// A row with no partition UUID still needs to be claimed for step 1 to
		// reach the check that refuses it.
		res.KeyIDOverride = keyID
	}
	if err := st.MarkClaimed(ctx, jobID, res); err != nil {
		t.Fatalf("MarkClaimed: %v", err)
	}
	return jobID
}

func (h *runHarness) submit(t *testing.T, spec RunSpec) string {
	t.Helper()
	body, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	j, err := h.runner.Submit(context.Background(), RunJobKind, body, "test")
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	return j.ID
}

// waitTerminal polls until the job is terminal, then waits for the runner's
// goroutine to unwind — the second half is what makes OnTerminal's effect
// observable rather than a coin flip. Same reasoning as the claim harness's.
func (h *runHarness) waitTerminal(t *testing.T, jobID string) *jobs.Job {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		j, err := h.jobStore.GetJob(context.Background(), jobID)
		if err != nil {
			t.Fatalf("GetJob: %v", err)
		}
		if j != nil && (j.Status == jobs.StatusSucceeded || j.Status == jobs.StatusFailed) {
			h.runner.Wait()
			return j
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("job %s never reached a terminal status", jobID)
	return nil
}

func (h *runHarness) run(t *testing.T, jobID string) *BackupRun {
	t.Helper()
	row, err := h.store.GetRun(context.Background(), jobID)
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	return row
}

// ledgerText is everything the job ledger PUBLISHES for one job: the job's own
// error, every step result, and every event payload (which is where sc.Log
// lines land — see jobs.Runner.emit).
//
// It is the exact surface the "no key material escapes" assertion has to cover,
// which is why it is assembled from the store rather than from anything the
// saga returned.
func (h *runHarness) ledgerText(t *testing.T, jobID string) string {
	t.Helper()
	ctx := context.Background()
	var b strings.Builder
	j, err := h.jobStore.GetJob(ctx, jobID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if j != nil {
		b.WriteString(j.Error)
		b.WriteString("\n")
		b.Write(j.Spec)
		b.WriteString("\n")
	}
	steps, err := h.jobStore.ListSteps(ctx, jobID)
	if err != nil {
		t.Fatalf("ListSteps: %v", err)
	}
	for _, st := range steps {
		b.WriteString(st.Name)
		b.WriteString("\n")
		b.WriteString(st.Error)
		b.WriteString("\n")
		b.Write(st.Result)
		b.WriteString("\n")
	}
	events, err := h.jobStore.ListEvents(ctx, jobID)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	for _, ev := range events {
		b.WriteString(ev.Type)
		b.WriteString("\n")
		b.Write(ev.Data)
		b.WriteString("\n")
	}
	return b.String()
}

// stagingEntries lists what is left in the staging directory. §4.7's discipline
// is that nothing should be: an orphaned staged archive is a permanent disk
// leak with no owner, and the sealed one is a plaintext-adjacent artefact
// nobody should have to remember to delete.
func (h *runHarness) stagingEntries(t *testing.T) []string {
	t.Helper()
	ents, err := os.ReadDir(h.stagingDir)
	if err != nil {
		t.Fatalf("read staging dir: %v", err)
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// ----- the app-volume fan-out's two inputs --------------------------------

// fakeApps is the installed-app list. A slice rather than a database: the join
// PlanAppVolumes performs is between two facts, and standing up an app store to
// supply one of them would test the store instead.
type fakeApps struct {
	list []*apps.App
	err  error
}

func (f *fakeApps) List(context.Context) ([]*apps.App, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.list, nil
}

// Get is AppGetter: the app by id, or nil — the store's own contract for a
// missing row.
func (f *fakeApps) Get(_ context.Context, id string) (*apps.App, error) {
	if f.err != nil {
		return nil, f.err
	}
	for _, a := range f.list {
		if a != nil && a.ID == id {
			return a, nil
		}
	}
	return nil, nil
}

// fakeTiles is the catalog side of the join, written per test rather than
// loaded from the shipped catalog. The classification is CONTENT; a saga test
// that broke every time a tile was re-classed would be testing the content.
type fakeTiles map[string]tileschema.Tile

func (f fakeTiles) Get(id string) (tileschema.Tile, bool) {
	t, ok := f[id]
	return t, ok
}

// Source names the fake the way the store names a real catalog, so a record
// that quotes it reads the same shape in a test as on a cluster.
func (f fakeTiles) Source() string { return "v0 (test tiles)" }

// testApp and testTile build the two halves of one installed app in one line
// each, so a case reads as the cluster it describes.
func testApp(id, name, node, tile string) *apps.App {
	return &apps.App{ID: id, Name: name, TargetNode: node, SourceTile: tile}
}

func testTile(id string, vols ...tileschema.Volume) tileschema.Tile {
	return tileschema.Tile{ID: id, Volumes: vols}
}

func vol(name, class, quiesce string) tileschema.Volume {
	return tileschema.Volume{Name: name, Backup: class, Quiesce: quiesce}
}

// stagedVolume is what the fake agent was asked to stage and what it produced,
// so a test can assert on the ORDER volumes were asked for as well as on the
// archive that came out.
type stagedVolume struct {
	cmd proto.BackupStageVolumeCmd
	ack proto.BackupStageVolumeAck
}

// stageOutcome lets a case decide, per volume, what the agent does with it —
// a refusal, an app that does not come back, a wrong digest.
type stageOutcome struct {
	// body is the volume's content. Empty means a default.
	body string
	// dir, when set, is a REAL directory the fake stages as a real tar —
	// the shape the agent's walk produces — so a restore can put it back
	// and a test can compare bytes.
	dir string
	// refusal, when set, is answered instead of a copy.
	refusal proto.StorageRefusal
	detail  string
	// appRestored false is §4.7's intolerable outcome.
	appRestored *bool
	// digest, when set, is what the agent CLAIMS — a value other than the real
	// hash is the corrupted-handoff case.
	digest string
	// downtimeMillis and interrupting describe a `stop`.
	downtimeMillis int64
	interrupting   bool
	consistency    proto.BackupConsistency

	// The transfer knobs. Each is one way the protocol can be abused or
	// can fail, exercised over the real endpoint:
	//   reuseCredentialOf  upload on the credential minted for ANOTHER
	//                      volume (by volume name) — the scope check;
	//   replay             upload for real, then upload AGAIN on the same
	//                      credential — the replay-after-landing check;
	//   lieLanded          report landed without uploading — the api must
	//                      believe its own endpoint, not the ack;
	//   garbleAck          upload for real, then answer with an unreadable
	//                      reply — the lost-ack case, which the endpoint's
	//                      record must carry;
	//   transferRefusal    refuse the transfer agent-side without uploading.
	reuseCredentialOf string
	replay            bool
	lieLanded         bool
	garbleAck         bool
	transferRefusal   proto.StorageRefusal
	// replayAck records what the endpoint said to the replay.
	replayAck *proto.BackupTransferAck
}

// startVolumeAgent answers the two staging verbs against a real staging root,
// writing real tar files the api then re-hashes. A fake that echoed a digest
// back would make the digest check untestable, which is the same reason the
// write verb's fake re-hashes.
func (f *fakeBackupAgent) startVolumeAgent(t *testing.T, nc *nats.Conn, outcomes map[string]stageOutcome) *fakeBackupAgent {
	t.Helper()
	respond := func(m *nats.Msg, v any) {
		b, err := json.Marshal(v)
		if err != nil {
			t.Errorf("fake volume agent marshal: %v", err)
			return
		}
		_ = m.Respond(b)
	}
	var subs []*nats.Subscription

	sub, err := nc.Subscribe(proto.BackupStageVolumeSubject(f.nodeID), func(m *nats.Msg) {
		var cmd proto.BackupStageVolumeCmd
		_ = json.Unmarshal(m.Data, &cmd)
		out := outcomes[cmd.Volume]

		// The refusals the real stager applies before it copies anything, so a
		// test cannot accidentally assert on a build that stages a `bulk`
		// volume the shipped agent would refuse.
		if cmd.Class == "bulk" || cmd.Class == "cache" {
			out.refusal = proto.BackupRefusalClassNotStaged
			out.detail = "class " + cmd.Class + " is never staged"
		}
		ack := proto.BackupStageVolumeAck{
			AppID: cmd.AppID, Volume: cmd.Volume, StagingName: cmd.StagingName,
			ServiceInterrupting: out.interrupting || cmd.Quiesce == "stop",
			DowntimeMillis:      out.downtimeMillis,
			WasRunning:          true,
			Stopped:             cmd.Quiesce == "stop",
			AppRestored:         true,
			Consistency:         out.consistency,
		}
		if out.appRestored != nil {
			ack.AppRestored = *out.appRestored
			ack.RestoreDetail = "the compose stack did not come up"
		}
		if out.refusal != "" {
			ack.OK = false
			ack.Refusal = out.refusal
			ack.Detail = out.detail
			f.recordStage(cmd, ack)
			respond(m, ack)
			return
		}
		body := out.body
		if body == "" {
			body = "TAR-OF-" + cmd.Volume
		}
		files := 1
		if out.dir != "" {
			var n int
			body, n = tarOfDir(t, out.dir)
			files = n
		}
		path := filepath.Join(f.stagingRoot, cmd.StagingName)
		if !proto.BackupValidStagingName(cmd.StagingName) {
			t.Errorf("the api asked for staging name %q, which the real agent would refuse", cmd.StagingName)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Errorf("fake stage write: %v", err)
		}
		sum := sha256.Sum256([]byte(body))
		ack.OK = true
		ack.StagedPath = path
		ack.SizeBytes = uint64(len(body))
		ack.PlaintextBytes = uint64(len(body))
		ack.FileCount = files
		ack.Digest = hex.EncodeToString(sum[:])
		if out.digest != "" {
			ack.Digest = out.digest
		}
		f.recordStage(cmd, ack)
		respond(m, ack)
	})
	if err != nil {
		t.Fatalf("fake stage sub: %v", err)
	}
	subs = append(subs, sub)

	sub, err = nc.Subscribe(proto.BackupTransferSubject(f.nodeID), func(m *nats.Msg) {
		var cmd proto.BackupTransferCmd
		_ = json.Unmarshal(m.Data, &cmd)
		out := outcomes[cmd.Volume]
		f.mu.Lock()
		if f.credentials == nil {
			f.credentials = &credentialBook{}
		}
		book := f.credentials
		f.mu.Unlock()
		book.put(cmd.Volume, cmd.Credential)
		record := func(ack proto.BackupTransferAck) {
			f.mu.Lock()
			f.transfers = append(f.transfers, transferRecord{cmd: cmd, ack: ack})
			f.mu.Unlock()
		}
		if out.transferRefusal != "" {
			ack := proto.BackupTransferAck{OK: false, StagingName: cmd.StagingName, Member: cmd.Member, Refusal: out.transferRefusal, Detail: "injected"}
			record(ack)
			respond(m, ack)
			return
		}
		if out.lieLanded {
			ack := proto.BackupTransferAck{OK: true, Landed: true, StagingName: cmd.StagingName, Member: cmd.Member,
				SealedDigest: strings.Repeat("f", 64), SealedBytes: 12, PlaintextDigest: cmd.PlaintextDigest}
			record(ack)
			respond(m, ack)
			return
		}
		cred := cmd.Credential
		if out.reuseCredentialOf != "" {
			cred = book.get(out.reuseCredentialOf)
			if cred == "" {
				t.Errorf("no credential recorded for %s to reuse", out.reuseCredentialOf)
			}
		}
		ack := realTransfer(t, f.stagingRoot, cmd, cred)
		if out.replay && ack.OK {
			again := realTransfer(t, f.stagingRoot, cmd, cred)
			f.mu.Lock()
			out.replayAck = &again
			outcomes[cmd.Volume] = out
			f.mu.Unlock()
		}
		record(ack)
		if out.garbleAck {
			_ = m.Respond([]byte("{not json"))
			return
		}
		respond(m, ack)
	})
	if err != nil {
		t.Fatalf("fake transfer sub: %v", err)
	}
	subs = append(subs, sub)

	sub, err = nc.Subscribe(proto.BackupUnstageSubject(f.nodeID), func(m *nats.Msg) {
		var cmd proto.BackupUnstageCmd
		_ = json.Unmarshal(m.Data, &cmd)
		f.mu.Lock()
		f.unstaged = append(f.unstaged, cmd.StagingName)
		f.mu.Unlock()
		ack := proto.BackupUnstageAck{OK: true, StagingName: cmd.StagingName}
		if proto.BackupValidStagingName(cmd.StagingName) {
			p := filepath.Join(f.stagingRoot, cmd.StagingName)
			if info, err := os.Stat(p); err == nil {
				ack.Existed = true
				ack.FreedBytes = uint64(info.Size())
				_ = os.Remove(p)
			}
		}
		respond(m, ack)
	})
	if err != nil {
		t.Fatalf("fake unstage sub: %v", err)
	}
	subs = append(subs, sub)

	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})
	return f
}

func (f *fakeBackupAgent) recordStage(cmd proto.BackupStageVolumeCmd, ack proto.BackupStageVolumeAck) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.staged = append(f.staged, stagedVolume{cmd: cmd, ack: ack})
	// The §4.7 invariant this whole phase is arranged around: never more than
	// one staged copy on the agent's root at a time. Recorded here rather than
	// asserted, because the assertion belongs to the test that cares.
	live := len(f.staged) - len(f.unstaged)
	if live > f.maxLiveStaged {
		f.maxLiveStaged = live
	}
}

// stagedOrder is the sequence of volume names the api asked for, which is the
// only way to assert on the fan-out's ordering.
func (f *fakeBackupAgent) stagedOrder() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.staged))
	for _, s := range f.staged {
		out = append(out, s.cmd.Volume)
	}
	return out
}

// realTransfer is the agent's transfer verb, reduced to the protocol: the
// staged file, sealed with backupxfer.Seal through a pipe, uploaded with the
// REAL HTTP transport on the credential given. The agent module has the full
// verb (quiesce.Stager.Transfer) and tests it against the same endpoint; this
// is the same client code path, minus the runtime.
func realTransfer(t *testing.T, stagingRoot string, cmd proto.BackupTransferCmd, credential string) proto.BackupTransferAck {
	t.Helper()
	ack := proto.BackupTransferAck{StagingName: cmd.StagingName, Member: cmd.Member, KeyID: cmd.KeyID}
	f, err := os.Open(filepath.Join(stagingRoot, cmd.StagingName))
	if err != nil {
		ack.Refusal, ack.Detail = proto.BackupRefusalStagingMissing, err.Error()
		return ack
	}
	defer func() { _ = f.Close() }()
	plain := sha256.New()
	stream := backupxfer.NewSealedStream(io.TeeReader(f, plain), cmd.PublicKey, cmd.KeyID, cmd.Scope)
	defer func() { _ = stream.Close() }()
	tr, err := backupxfer.TransportFor(cmd.Destination, backupxfer.HTTPOptions{AcceptWait: 5 * time.Second})
	if err != nil {
		ack.Refusal, ack.Detail = proto.BackupRefusalDestinationUnsupported, err.Error()
		return ack
	}
	rc, err := tr.Put(context.Background(), backupxfer.PutRequest{
		Destination: cmd.Destination, Generation: cmd.GenerationID, Member: cmd.Member, Credential: credential,
		PlaintextDigest: cmd.PlaintextDigest, PlaintextBytes: cmd.PlaintextBytes,
		Body: stream, Sealed: stream.Sealed,
	})
	if err != nil {
		var refused *backupxfer.RefusedError
		if errorsAs(err, &refused) {
			ack.Refusal, ack.DestinationCode, ack.Detail = proto.BackupRefusalDestinationRefused, refused.Problem.Code, err.Error()
		} else {
			ack.Refusal, ack.Detail = proto.BackupRefusalTransferFailed, err.Error()
		}
		return ack
	}
	res, serr := stream.Result()
	if serr != nil {
		ack.Refusal, ack.Detail = proto.StorageRefusalBackendError, serr.Error()
		return ack
	}
	ack.OK, ack.Landed = true, true
	ack.SealedDigest, ack.SealedBytes = rc.SealedDigest, rc.SealedBytes
	ack.PlaintextDigest = hex.EncodeToString(plain.Sum(nil))
	ack.PlaintextBytes = res.PlaintextBytes
	ack.Alg, ack.EphemeralPublicKey = res.Alg, res.EphemeralPublicKey
	return ack
}

// errorsAs is errors.As without importing errors into a file that has no
// other use for it.
func errorsAs(err error, target **backupxfer.RefusedError) bool {
	for err != nil {
		if re, ok := err.(*backupxfer.RefusedError); ok {
			*target = re
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// ----- the restore verb's fake -----------------------------------------------

// restoreOutcome lets a case decide what the fake agent does with a restore.
type restoreOutcome struct {
	// refusal, when set, is answered instead of a restore.
	refusal proto.StorageRefusal
	detail  string
	// appRestored false is §4.7's intolerable outcome.
	appRestored *bool
	// silent drops the request on the floor — the api's RPC times out or
	// sees no responder. Used with a short budget.
	silent bool
}

// restoreCall is one restore verb the fake answered: the command and the
// ack, plus what it saw of the stream.
type restoreCall struct {
	cmd proto.BackupRestoreVolumeCmd
	ack proto.BackupRestoreVolumeAck
}

// tarOfDir writes a deterministic tar of dir's regular files and
// directories, in walk order — the shape the agent's walk produces — and
// returns it with the regular-file count.
func tarOfDir(t *testing.T, dir string) (string, int) {
	t.Helper()
	var buf strings.Builder
	tw := tar.NewWriter(&buf)
	files := 0
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if rel == "." {
			return nil
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		hdr.Format = tar.FormatPAX
		if info.IsDir() {
			hdr.Name += "/"
			return tw.WriteHeader(hdr)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		b, err := os.ReadFile(p) //nolint:gosec // G304: the test's own temp dir
		if err != nil {
			return err
		}
		_, err = tw.Write(b)
		files++
		return err
	})
	if err != nil {
		t.Fatalf("tarOfDir: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String(), files
}

// registerVolume tells the fake agent where an app's volume lives on its
// node, so the restore verb has a directory to replace.
func (f *fakeBackupAgent) registerVolume(appID, volume, dir string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.volumeDirs == nil {
		f.volumeDirs = map[string]string{}
	}
	f.volumeDirs[appID+"/"+volume] = dir
}

func (f *fakeBackupAgent) restoreCalls() []restoreCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]restoreCall(nil), f.restores...)
}

// startRestoreAgent answers storage.backup_restore_volume the way the real
// verb does, reduced to the protocol: fetch on the credential with the REAL
// client (backupxfer.FetcherFor), unpack with the REAL fsat unpack into a
// staging tree beside the volume, verify the stream's length and digest
// against the command, then "stop" the app, exchange the trees, "start" it.
// The runtime is the fake — stop and start are counters — and the exchange
// is two renames, which is what a fake may do and the agent may not; the
// agent module's own tests hold the atomic exchange and the watchdog.
func (f *fakeBackupAgent) startRestoreAgent(t *testing.T, nc *nats.Conn, outcomes map[string]restoreOutcome) {
	t.Helper()
	respond := func(m *nats.Msg, v any) {
		b, err := json.Marshal(v)
		if err != nil {
			t.Errorf("fake restore agent marshal: %v", err)
			return
		}
		_ = m.Respond(b)
	}
	sub, err := nc.Subscribe(proto.BackupRestoreVolumeSubject(f.nodeID), func(m *nats.Msg) {
		var cmd proto.BackupRestoreVolumeCmd
		_ = json.Unmarshal(m.Data, &cmd)
		out := outcomes[cmd.Volume]
		if out.silent {
			return
		}
		f.mu.Lock()
		if f.credentials == nil {
			f.credentials = &credentialBook{}
		}
		book := f.credentials
		dir := f.volumeDirs[cmd.AppID+"/"+cmd.Volume]
		f.mu.Unlock()
		book.put("restore:"+cmd.Volume, cmd.Credential)
		ack := proto.BackupRestoreVolumeAck{AppID: cmd.AppID, Volume: cmd.Volume, Member: cmd.Member, AppRestored: true, WasRunning: true}
		record := func() {
			f.mu.Lock()
			f.restores = append(f.restores, restoreCall{cmd: cmd, ack: ack})
			f.mu.Unlock()
			respond(m, ack)
		}
		if out.refusal != "" {
			ack.Refusal, ack.Detail = out.refusal, out.detail
			record()
			return
		}
		if dir == "" {
			ack.Refusal, ack.Detail = proto.BackupRefusalVolumeNotFound, "the app is not deployed on this node; install it first"
			record()
			return
		}
		fetcher, err := backupxfer.FetcherFor(cmd.Source, backupxfer.HTTPOptions{})
		if err != nil {
			ack.Refusal, ack.Detail = proto.BackupRefusalSourceRefused, err.Error()
			record()
			return
		}
		stream, err := fetcher.Get(context.Background(), backupxfer.GetRequest{Source: cmd.Source, Generation: cmd.GenerationID, Member: cmd.Member, Credential: cmd.Credential})
		if err != nil {
			var refused *backupxfer.RefusedError
			if errorsAs(err, &refused) {
				ack.Refusal, ack.SourceCode = proto.BackupRefusalSourceRefused, refused.Problem.Code
			} else {
				ack.Refusal = proto.BackupRefusalTransferFailed
			}
			ack.Detail = err.Error()
			record()
			return
		}
		staging := dir + ".restore-staging"
		_ = os.RemoveAll(staging)
		if err := os.Mkdir(staging, 0o700); err != nil {
			t.Errorf("fake restore staging: %v", err)
		}
		root, err := fsat.OpenRoot(staging)
		if err != nil {
			t.Errorf("fake restore staging: %v", err)
		}
		res, uerr := backupxfer.Unpack(root, io.LimitReader(stream.Body, int64(cmd.PlaintextBytes)+1), backupxfer.UnpackBounds{MaxBytes: cmd.PlaintextBytes})
		_ = root.Close()
		_ = stream.Body.Close()
		if uerr != nil {
			_ = os.RemoveAll(staging)
			ack.Refusal, ack.Detail = proto.BackupRefusalArchiveInvalid, uerr.Error()
			record()
			return
		}
		ack.ReceivedBytes, ack.Digest, ack.FileCount, ack.DirCount, ack.UnpackedBytes = res.StreamBytes, res.Digest, res.Files, res.Dirs, res.Bytes
		if res.StreamBytes != cmd.PlaintextBytes || !strings.EqualFold(res.Digest, cmd.PlaintextDigest) {
			_ = os.RemoveAll(staging)
			ack.Refusal, ack.Detail = proto.BackupRefusalDigestMismatch, "the stream is not what the manifest recorded"
			record()
			return
		}
		// The quiesce, faked: stop, swap, start — counted so a test can
		// assert the app was stopped exactly once per volume and is back.
		f.mu.Lock()
		f.stops++
		f.mu.Unlock()
		ack.Stopped = true
		ack.StoppedAt = time.Now().UTC()
		previous := dir + ".previous"
		_ = os.RemoveAll(previous)
		if err := os.Rename(dir, previous); err != nil {
			t.Errorf("fake restore swap: %v", err)
		}
		if err := os.Rename(staging, dir); err != nil {
			t.Errorf("fake restore swap: %v", err)
		}
		ack.Replaced, ack.OK, ack.PreviousKept = true, true, previous
		f.mu.Lock()
		f.starts++
		f.mu.Unlock()
		ack.RestartedAt = time.Now().UTC()
		ack.DowntimeMillis = ack.RestartedAt.Sub(ack.StoppedAt).Milliseconds()
		ack.RestoredBy = "driver"
		if out.appRestored != nil {
			ack.AppRestored = *out.appRestored
			ack.RestoreDetail = "the compose stack did not come up"
		}
		record()
	})
	if err != nil {
		t.Fatalf("fake restore sub: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
}

// quiesceCounts reports how many times the fake restore agent stopped and
// started the app — under the lock, so a test reading them after the job
// ended does not race the handler goroutine that wrote them.
func (f *fakeBackupAgent) quiesceCounts() (stops, starts int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stops, f.starts
}
