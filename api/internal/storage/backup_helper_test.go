package storage

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
	"github.com/nats-io/nats.go"
)

// Harness for the backup.run saga: a real jobs.Runner over an in-process NATS
// server, a real SQLite database (so `VACUUM INTO` is exercised rather than
// mocked), a real staging directory on disk, and a fake agent answering the
// three backup verbs.
//
// The fake agent RE-HASHES what it is told to write, exactly as the real one
// does. That is deliberate: the api's half of §4.7's handoff is "stage these
// bytes and tell the agent their digest", and a fake that trusted the digest
// would pass whatever the api computed, including a wrong one.

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
	// generations is the fake target's contents, oldest first.
	generations []string
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
				MountPath: "/mnt/rasputin-backup", TotalBytes: 2 << 40,
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
			Scope:        proto.BackupScopeControlplaneLocal,
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
	nc          *nats.Conn
	store       *Store
	jobStore    *jobs.Store
	runner      *jobs.Runner
	agent       *fakeBackupAgent
	key         testKeypair
	stagingDir  string
	trustDir    string
	meshDir     string
	dbPath      string
	settings    *memorySettings
	targetJobID string
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
	tiles fakeTiles
	// noAppSource leaves RunConfig.Apps and .Tiles nil, for the step-1 refusal.
	noAppSource bool
	// appsErr makes the installed-app list fail.
	appsErr error
	// stageOutcomes decides what the fake agent does with each volume, keyed by
	// volume name.
	stageOutcomes map[string]stageOutcome
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
	if agent == nil {
		agent = &fakeBackupAgent{}
	}
	agent.nodeID = runNodeID
	agent.stagingRoot = stagingDir
	agent.start(t, nc)
	agent.startVolumeAgent(t, nc, opts.stageOutcomes)

	h := &runHarness{
		nc: nc, store: st, jobStore: js, agent: agent, key: key,
		stagingDir: stagingDir, trustDir: trustDir, meshDir: meshDir,
		dbPath: dbPath, settings: newMemorySettings(),
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
		ClusterID:  "home1",
		SelfNodeID: self,
		Sources:    IdentitySources{TrustDir: trustDir, MeshStateDir: meshDir},
		DB:         st.DB(),
		DBPath:     dbPath,
		Retain:     opts.retain,
	}
	if !opts.noAppSource {
		tiles := opts.tiles
		if tiles == nil {
			tiles = fakeTiles{}
		}
		cfg.Apps = &fakeApps{list: opts.apps, err: opts.appsErr}
		cfg.Tiles = tiles
	}
	r.Register(RunWorkflow(st, cfg))
	h.runner = r
	return h
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
	if pub != "" {
		res.Key = &ArchiveKey{
			KeyID:                 "key-1",
			Alg:                   "x25519+argon2id",
			PublicKey:             pub,
			WrappedByPassphrase:   testWrappedPass,
			WrappedByRecoveryCode: testWrappedRecovery,
		}
	} else if opts.noPartUUID {
		// A row with no partition UUID still needs to be claimed for step 1 to
		// reach the check that refuses it.
		res.KeyIDOverride = "key-1"
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

// fakeTiles is the catalog side of the join, written per test rather than
// loaded from the shipped catalog. The classification is CONTENT; a saga test
// that broke every time a tile was re-classed would be testing the content.
type fakeTiles map[string]tileschema.Tile

func (f fakeTiles) Get(id string) (tileschema.Tile, bool) {
	t, ok := f[id]
	return t, ok
}

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
		ack.FileCount = 1
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
