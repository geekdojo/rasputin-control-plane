package storage

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
)

// startNATS spins up an in-process NATS server on a random port and returns a
// connected client. Server shuts down on test cleanup.
func startNATS(t *testing.T) *nats.Conn {
	t.Helper()
	srv := natsserver.RunRandClientPortServer()
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatalf("nats connect: %v", err)
	}
	t.Cleanup(nc.Close)
	return nc
}

func newStore(t *testing.T) *Store {
	t.Helper()
	st, err := OpenStore(context.Background(), filepath.Join(t.TempDir(), "storage.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func newInventory(t *testing.T, nodeIDs ...string) *inventory.Store {
	t.Helper()
	inv, err := inventory.OpenStore(context.Background(), filepath.Join(t.TempDir(), "inv.db"))
	if err != nil {
		t.Fatalf("inventory OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = inv.Close() })
	for _, id := range nodeIDs {
		if err := inv.Insert(context.Background(), &proto.Node{
			ID: id, Role: proto.RoleCompute, Hostname: id + ".test",
			FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("inv insert %s: %v", id, err)
		}
	}
	return inv
}

// ----- the fake agent -----------------------------------------------------

// fakeAgent answers the three storage verbs the api half calls, and records
// what it was asked.
//
// The recording is the point of several tests. "How many times was claim
// called?" is the only way to prove the runner did not retry an irreversible
// step, and "was claim called at all?" is the only way to prove the adopt path
// really does not format.
type fakeAgent struct {
	nodeID string

	mu sync.Mutex
	// enumerate is called with the 1-based call number, so a test can answer
	// differently the second time — which is exactly how the disk-changed-
	// between-the-picker-and-the-saga case is produced.
	enumerate      func(call int) proto.StorageEnumerateAck
	claim          func(cmd proto.StorageClaimCmd) proto.StorageClaimAck
	inspect        func(cmd proto.StorageInspectCmd) proto.StorageInspectAck
	enumerateCalls int
	claimCmds      []proto.StorageClaimCmd
	inspectCmds    []proto.StorageInspectCmd
}

func (f *fakeAgent) claimCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.claimCmds)
}

func (f *fakeAgent) inspectCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.inspectCmds)
}

func (f *fakeAgent) lastClaim() (proto.StorageClaimCmd, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.claimCmds) == 0 {
		return proto.StorageClaimCmd{}, false
	}
	return f.claimCmds[len(f.claimCmds)-1], true
}

// start subscribes the fake to its node's three subjects for the test's life.
func (f *fakeAgent) start(t *testing.T, nc *nats.Conn) *fakeAgent {
	t.Helper()
	respond := func(m *nats.Msg, v any) {
		b, err := json.Marshal(v)
		if err != nil {
			t.Errorf("fake agent marshal: %v", err)
			return
		}
		_ = m.Respond(b)
	}

	subs := []*nats.Subscription{}
	sub, err := nc.Subscribe(proto.StorageEnumerateSubject(f.nodeID), func(m *nats.Msg) {
		f.mu.Lock()
		f.enumerateCalls++
		n := f.enumerateCalls
		fn := f.enumerate
		f.mu.Unlock()
		if fn == nil {
			respond(m, proto.StorageEnumerateAck{OK: true, Backend: "mock", Ts: time.Now().UTC()})
			return
		}
		respond(m, fn(n))
	})
	if err != nil {
		t.Fatalf("fake enumerate sub: %v", err)
	}
	subs = append(subs, sub)

	sub, err = nc.Subscribe(proto.StorageClaimSubject(f.nodeID), func(m *nats.Msg) {
		var cmd proto.StorageClaimCmd
		_ = json.Unmarshal(m.Data, &cmd)
		f.mu.Lock()
		f.claimCmds = append(f.claimCmds, cmd)
		fn := f.claim
		f.mu.Unlock()
		if fn == nil {
			respond(m, defaultClaimAck(cmd))
			return
		}
		respond(m, fn(cmd))
	})
	if err != nil {
		t.Fatalf("fake claim sub: %v", err)
	}
	subs = append(subs, sub)

	sub, err = nc.Subscribe(proto.StorageInspectSubject(f.nodeID), func(m *nats.Msg) {
		var cmd proto.StorageInspectCmd
		_ = json.Unmarshal(m.Data, &cmd)
		f.mu.Lock()
		f.inspectCmds = append(f.inspectCmds, cmd)
		fn := f.inspect
		f.mu.Unlock()
		if fn == nil {
			respond(m, defaultInspectAck(cmd))
			return
		}
		respond(m, fn(cmd))
	})
	if err != nil {
		t.Fatalf("fake inspect sub: %v", err)
	}
	subs = append(subs, sub)

	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})
	return f
}

// defaultClaimAck is a successful format. Note the fingerprint: it is NOT the
// one that was sent, because the partition table the fingerprint hashes is the
// thing the format just replaced. Real agents behave the same way, and a saga
// that read that difference as drift would fail every successful claim.
func defaultClaimAck(cmd proto.StorageClaimCmd) proto.StorageClaimAck {
	return proto.StorageClaimAck{
		OK:          true,
		DevicePath:  cmd.DevicePath,
		PartUUID:    "part-uuid-new",
		Label:       cmd.Label,
		FSLabel:     proto.StorageBackupLabel,
		FSType:      "ext4",
		MountPath:   "/mnt/rasputin-backup",
		SizeBytes:   2 << 40,
		Fingerprint: "fp-after-format",
		BackupSet: &proto.StorageBackupSet{
			MarkerVersion: proto.StorageMarkerVersion,
			ClusterID:     cmd.ClusterID,
			PartUUID:      "part-uuid-new",
			KeyID:         cmd.KeyID,
			Label:         cmd.Label,
			CreatedAt:     time.Now().UTC(),
		},
	}
}

func defaultInspectAck(cmd proto.StorageInspectCmd) proto.StorageInspectAck {
	return proto.StorageInspectAck{
		OK:         true,
		Present:    true,
		PartUUID:   cmd.PartUUID,
		DevicePath: "/dev/sdb",
		MountPath:  "/mnt/rasputin-backup",
		FSType:     "ext4",
		FSLabel:    proto.StorageBackupLabel,
		TotalBytes: 2 << 40,
		BackupSet: &proto.StorageBackupSet{
			MarkerVersion: proto.StorageMarkerVersion,
			PartUUID:      cmd.PartUUID,
			CreatedAt:     time.Now().UTC(),
			Generations:   3,
		},
	}
}

// ----- candidate builders -------------------------------------------------

const (
	testNode      = "n-store"
	testDevice    = "/dev/sdb"
	testFingerpr  = "fp-confirmed"
	testBootDisk  = "/dev/nvme0n1"
	testOtherFing = "fp-something-else"
)

// blankCandidate is an attached disk with no Rasputin backup set: the ordinary
// case, and the only one this saga formats.
func blankCandidate() proto.StorageCandidate {
	return proto.StorageCandidate{
		DevicePath: testDevice, Model: "Samsung T7", Serial: "S1234",
		WWN: "0x5001", SizeBytes: 2 << 40, Transport: proto.StorageTransportUSB,
		Removable: true, Fingerprint: testFingerpr,
	}
}

// protectedCandidate is the disk holding the mounted boot and persistent
// partitions — the refusal the whole feature exists for.
func protectedCandidate() proto.StorageCandidate {
	c := blankCandidate()
	c.DevicePath = testBootDisk
	c.Transport = proto.StorageTransportNVMe
	c.Removable = false
	c.Protected = true
	c.ProtectedReason = "holds the mounted persistent partition (/var/lib/rasputin)"
	return c
}

// testSetCreated is the marker's creation time. A FIXED instant, not
// time.Now(): the marker is a file on the disk, so two enumerations of the same
// unchanged disk report the same one — and the wipe confirmation token commits
// to it, so a fixture that moved would mint a different token each time it was
// called and hide exactly the property those tests assert.
var testSetCreated = time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

// backupSetCandidate is a disk that already carries a Rasputin archive: the
// restore disk §4.8 refuses to wipe without a second, separate choice.
func backupSetCandidate() proto.StorageCandidate {
	c := blankCandidate()
	c.HasBackupSet = true
	c.BackupSet = &proto.StorageBackupSet{
		MarkerVersion: proto.StorageMarkerVersion,
		ClusterID:     "home1",
		PartUUID:      "part-uuid-existing",
		KeyID:         "key-existing",
		Label:         "the archive",
		CreatedAt:     testSetCreated,
		Generations:   4,
	}
	return c
}

// unreadableMarkerCandidate announces a Rasputin backup set whose marker could
// not be parsed. Before the wipe verb this disk was a dead end: nothing to adopt
// it BY, and the backup-set refusal in the way of formatting it.
func unreadableMarkerCandidate() proto.StorageCandidate {
	c := backupSetCandidate()
	c.BackupSet = nil
	return c
}

// protectedBackupSetCandidate is the boot medium, carrying a backup set. The
// combination exists to prove a wipe cannot outrun the boot-device exclusion.
func protectedBackupSetCandidate() proto.StorageCandidate {
	c := backupSetCandidate()
	c.Protected = true
	c.ProtectedReason = "holds the mounted persistent partition (/var/lib/rasputin)"
	return c
}

func ptr(c proto.StorageCandidate) *proto.StorageCandidate { return &c }

// wipeSpecFor makes the spec mutation for a confirmed wipe of one candidate,
// with the token the picker would have published for exactly that disk.
func wipeSpecFor(c proto.StorageCandidate) func(*ClaimSpec) {
	// Minted from a candidate that is by construction wipe-eligible where the
	// test means it to be. CandidateWipeToken returns "" for a protected disk,
	// so the protected case supplies an empty token and refuses twice over —
	// once at step 1 for the empty token, and at step 2 for being the boot
	// medium. Force a non-empty token there so the case proves the SECOND.
	tok := CandidateWipeToken(&c)
	if tok == "" {
		tok = WipeToken(c.Fingerprint, c.WWN, c.Serial, c.SizeBytes, c.BackupSet)
	}
	return func(s *ClaimSpec) { s.Wipe = &WipeConfirmation{Token: tok} }
}

// assertTokenNotPublished proves a refusal did not hand the caller the answer.
// The whole value of the confirmation is that getting one means having looked
// at the disk; a refusal that prints the expected token converts a wipe from a
// decision into a retry.
func assertTokenNotPublished(t *testing.T, h *harness, jobID, token string) {
	t.Helper()
	if token == "" {
		t.Fatal("no token to look for — this assertion would prove nothing")
	}
	ctx := context.Background()
	j, err := h.jobStore.GetJob(ctx, jobID)
	if err != nil || j == nil {
		t.Fatalf("GetJob: %v", err)
	}
	if strings.Contains(j.Error, token) {
		t.Errorf("the refusal message carries the expected wipe token: %s", j.Error)
	}
	steps, err := h.jobStore.ListSteps(ctx, jobID)
	if err != nil {
		t.Fatalf("ListSteps: %v", err)
	}
	for _, st := range steps {
		if strings.Contains(string(st.Result), token) {
			t.Errorf("step %q result carries the expected wipe token: %s", st.Name, st.Result)
		}
	}
	events, err := h.jobStore.ListEvents(ctx, jobID)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	for _, ev := range events {
		if strings.Contains(string(ev.Data), token) {
			t.Errorf("event %q carries the expected wipe token: %s", ev.Type, ev.Data)
		}
	}
}

func ackWith(cands ...proto.StorageCandidate) proto.StorageEnumerateAck {
	return proto.StorageEnumerateAck{
		OK: true, Backend: "mock", Candidates: cands, Ts: time.Now().UTC(),
	}
}

// ----- runner harness -----------------------------------------------------

type harness struct {
	nc       *nats.Conn
	store    *Store
	jobStore *jobs.Store
	inv      *inventory.Store
	runner   *jobs.Runner
	agent    *fakeAgent
}

// newHarness wires a real jobs.Runner over an in-process NATS server with the
// claim workflow registered and a fake agent answering for testNode.
func newHarness(t *testing.T, agent *fakeAgent) *harness {
	t.Helper()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "rasputin.db")

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

	nc := startNATS(t)
	inv := newInventory(t, testNode)
	if agent == nil {
		agent = &fakeAgent{nodeID: testNode}
	}
	agent.nodeID = testNode
	agent.start(t, nc)

	r := jobs.NewRunner(js, nc)
	r.SetBackoff(func(int) time.Duration { return 0 })
	r.Register(ClaimWorkflow(st, inv, Config{ClusterID: "home1"}))

	return &harness{nc: nc, store: st, jobStore: js, inv: inv, runner: r, agent: agent}
}

func (h *harness) submit(t *testing.T, spec ClaimSpec) string {
	t.Helper()
	body, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	j, err := h.runner.Submit(context.Background(), ClaimJobKind, body, "test")
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	return j.ID
}

// waitTerminal polls until the job reaches a terminal status, then waits for
// the runner's goroutine to unwind.
//
// The second half is load-bearing, not tidiness. The runner marks the job
// terminal and THEN fires OnTerminal, so a test that stops at the job status
// reads the backup_targets row inside that window and sees it still pending —
// which is indistinguishable from the hook never having fired, i.e. from the
// #53 bug these tests exist to catch. Waiting on the WaitGroup makes the
// difference observable instead of a coin flip.
func (h *harness) waitTerminal(t *testing.T, jobID string) *jobs.Job {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
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

func (h *harness) target(t *testing.T, jobID string) *BackupTarget {
	t.Helper()
	row, err := h.store.GetByJob(context.Background(), jobID)
	if err != nil {
		t.Fatalf("GetByJob: %v", err)
	}
	return row
}

func baseSpec() ClaimSpec {
	return ClaimSpec{
		NodeID: testNode, DevicePath: testDevice,
		Fingerprint: testFingerpr, Label: "backup disk",
	}
}

// stepCtx builds a bare StepCtx for driving one step directly. Log is a no-op
// here: what the saga writes to the live stream is asserted on the job_events
// table instead, which is where sc.Log actually lands.
func stepCtx(jobID string, spec ClaimSpec, nc *nats.Conn, prior map[string]json.RawMessage) *jobs.StepCtx {
	raw, _ := json.Marshal(spec)
	return &jobs.StepCtx{
		Ctx: context.Background(), JobID: jobID, NATS: nc,
		Spec: raw, PriorResults: prior, Log: func(string, string) {},
	}
}
