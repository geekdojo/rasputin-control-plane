package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
)

const goodPassword = "a perfectly fine console password"

// discardLog is the workflow logger for tests that do not read the journal.
var discardLog = slog.New(slog.DiscardHandler)

func newStore(t *testing.T) *Store {
	t.Helper()
	st, err := OpenStore(context.Background(), filepath.Join(t.TempDir(), "rasputin.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

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

// ─── the write-only slot ────────────────────────────────────────────────────

func TestSetPasswordStoresOnlyAHash(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)

	if _, _, err := st.HashForDispatch(ctx); !errors.Is(err, ErrNoPassword) {
		t.Fatalf("HashForDispatch on a fresh store: %v, want ErrNoPassword", err)
	}
	if id, err := st.CurrentHashID(ctx); err != nil || id != "" {
		t.Fatalf("CurrentHashID on a fresh store: (%q, %v)", id, err)
	}

	hashID, err := st.SetPassword(ctx, goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	if hashID == "" {
		t.Fatal("SetPassword returned no id")
	}
	hashValue, gotID, err := st.HashForDispatch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hash := string(hashValue.Reveal())
	if gotID != hashID {
		t.Fatalf("dispatch id %q, stored id %q", gotID, hashID)
	}
	if err := proto.ValidConsoleRootHash(hash); err != nil {
		t.Fatalf("stored hash is not wire-valid: %v", err)
	}
	if strings.Contains(hash, goodPassword) {
		t.Fatal("the stored hash contains the password")
	}

	// The reader-facing view carries the id and never the hash.
	status, err := st.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecret(t, "the status view", string(raw), hash)
	if !status.Set || status.HashID != hashID || status.SetAt == nil {
		t.Fatalf("status = %+v", status)
	}
}

func TestSetPasswordRefusesAPasswordTheConsoleCouldNotTake(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	for _, pw := range []string{"", "short", "has a\nnewline in it and is long enough"} {
		if _, err := st.SetPassword(ctx, pw); err == nil {
			t.Errorf("%q was accepted", pw)
		}
	}
	if _, _, err := st.HashForDispatch(ctx); !errors.Is(err, ErrNoPassword) {
		t.Fatalf("a refused password left something stored: %v", err)
	}
}

// Changing the password invalidates what every node is known to hold.
func TestSetPasswordResetsNodeStateToPending(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	first, err := st.SetPassword(ctx, goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordNode(ctx, NodeState{NodeID: "n1", Status: NodeApplied, HashID: first}); err != nil {
		t.Fatal(err)
	}
	status, _ := st.Status(ctx)
	if !status.Nodes[0].Current {
		t.Fatal("n1 should read as current before the change")
	}
	if _, err := st.SetPassword(ctx, "a different console password"); err != nil {
		t.Fatal(err)
	}
	status, _ = st.Status(ctx)
	if status.Nodes[0].Status != NodePending || status.Nodes[0].Current {
		t.Fatalf("after a password change n1 is %+v, want pending and not current", status.Nodes[0])
	}
}

func TestForgetNode(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	if err := st.RecordNode(ctx, NodeState{NodeID: "gone", Status: NodeFailed, Detail: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := st.ForgetNode(ctx, "gone"); err != nil {
		t.Fatal(err)
	}
	status, _ := st.Status(ctx)
	if len(status.Nodes) != 0 {
		t.Fatalf("a removed node is still reported: %+v", status.Nodes)
	}
}

// ─── the push job ───────────────────────────────────────────────────────────

// fleet is a set of fake agents on a real bus.
type fleet struct {
	t     *testing.T
	nc    *nats.Conn
	store *Store
	nodes []*proto.Node
	mu    sync.Mutex
	// seen records the hash each node was actually sent, so a test can
	// prove the control plane delivered the real thing.
	seen map[string]string
	// logs is every job log line the last run emitted.
	logs []string
}

func newFleet(t *testing.T) *fleet {
	return &fleet{t: t, nc: startNATS(t), store: newStore(t), seen: map[string]string{}}
}

func (f *fleet) add(id string, role proto.NodeRole, status proto.NodeStatus, agentVersion string) *proto.Node {
	n := &proto.Node{ID: id, Role: role, Hostname: id, Status: status, AgentVersion: agentVersion}
	f.nodes = append(f.nodes, n)
	return n
}

// agent subscribes a fake agent that answers with ack(hash).
func (f *fleet) agent(id string, reply func(cmd proto.ConsoleRootHashCmd) proto.ConsoleRootHashAck) {
	f.t.Helper()
	_, err := f.nc.Subscribe(proto.NodeCmdSubject(id, proto.ConsoleRootHashVerb), func(m *nats.Msg) {
		var cmd proto.ConsoleRootHashCmd
		_ = json.Unmarshal(m.Data, &cmd)
		f.mu.Lock()
		f.seen[id] = cmd.Hash
		f.mu.Unlock()
		out, _ := json.Marshal(reply(cmd))
		_ = m.Respond(out)
	})
	if err != nil {
		f.t.Fatal(err)
	}
	if err := f.nc.Flush(); err != nil {
		f.t.Fatal(err)
	}
}

// applying is the fake agent that takes the hash.
func applying(id string) func(proto.ConsoleRootHashCmd) proto.ConsoleRootHashAck {
	return func(cmd proto.ConsoleRootHashCmd) proto.ConsoleRootHashAck {
		return proto.ConsoleRootHashAck{NodeID: id, OK: true, HashID: proto.ConsoleRootHashID(cmd.Hash), Changed: true}
	}
}

// refusing is a node whose image cannot take a delivered hash — the mixed-
// fleet case that must fail, not skip.
func refusing(id, detail string) func(proto.ConsoleRootHashCmd) proto.ConsoleRootHashAck {
	return func(proto.ConsoleRootHashCmd) proto.ConsoleRootHashAck {
		return proto.ConsoleRootHashAck{NodeID: id, OK: false, Detail: detail}
	}
}

func (f *fleet) list(context.Context) ([]*proto.Node, error) { return f.nodes, nil }

// run executes the whole workflow by hand and returns each step's result
// plus the error the job would have failed with.
func (f *fleet) run(t *testing.T, spec PushSpec) (map[string]json.RawMessage, error) {
	t.Helper()
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	wf := PushWorkflow(f.store, f.list, discardLog, time.Now)
	prior := map[string]json.RawMessage{}
	var logged []string
	for _, step := range wf.Steps {
		ctx, cancel := context.WithTimeout(context.Background(), step.Timeout)
		sc := &jobs.StepCtx{
			Ctx: ctx, JobID: "job-1", Spec: raw, NATS: f.nc, PriorResults: prior,
			Log: func(level, msg string) { logged = append(logged, level+": "+msg) },
		}
		res, err := step.Do(sc)
		cancel()
		if err != nil {
			f.logs = logged
			return prior, fmt.Errorf("%s: %w", step.Name, err)
		}
		if res != nil {
			prior[step.Name] = res
		}
	}
	f.logs = logged
	return prior, nil
}

func TestPushAppliesToEveryNodeIncludingTheControlPlane(t *testing.T) {
	ctx := context.Background()
	f := newFleet(t)
	f.add("cp", proto.RoleControlPlane, proto.StatusOnline, "2026.09.4-dev.172")
	f.add("compute1", proto.RoleCompute, proto.StatusOnline, "2026.09.4-dev.172")
	f.add("fw", proto.RoleFirewall, proto.StatusOnline, "2026.09.4-dev.180")
	for _, n := range f.nodes {
		f.agent(n.ID, applying(n.ID))
	}
	hashID, err := f.store.SetPassword(ctx, goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	hashValue, _, err := f.store.HashForDispatch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hash := string(hashValue.Reveal())

	results, err := f.run(t, PushSpec{Reason: "test"})
	if err != nil {
		t.Fatalf("the push failed: %v", err)
	}

	var del DeliverResult
	if err := json.Unmarshal(results["deliver"], &del); err != nil {
		t.Fatal(err)
	}
	if del.Applied != 3 || del.Failed != 0 {
		t.Fatalf("applied=%d failed=%d, want 3/0", del.Applied, del.Failed)
	}
	// The controlplane is a node like any other (#558).
	for _, id := range []string{"cp", "compute1", "fw"} {
		if got := f.seen[id]; got != hash {
			t.Errorf("%s was sent %q, want the stored hash", id, got)
		}
	}
	status, err := f.store.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Nodes) != 3 {
		t.Fatalf("%d node records, want 3", len(status.Nodes))
	}
	for _, n := range status.Nodes {
		if n.Status != NodeApplied || n.HashID != hashID || !n.Current {
			t.Errorf("%s = %+v", n.NodeID, n)
		}
	}
}

// The whole point of the write-only slot: nothing the ledger keeps or the
// UI streams carries the hash.
func TestPushNeverPutsTheHashInTheLedger(t *testing.T) {
	ctx := context.Background()
	f := newFleet(t)
	f.add("cp", proto.RoleControlPlane, proto.StatusOnline, "2026.09.4-dev.172")
	f.add("old", proto.RoleCompute, proto.StatusOnline, "2026.08.5-dev.140")
	f.agent("cp", applying("cp"))
	// "old" has no subscription at all — an agent that predates the verb.
	if _, err := f.store.SetPassword(ctx, goodPassword); err != nil {
		t.Fatal(err)
	}
	hashValue, _, err := f.store.HashForDispatch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hash := string(hashValue.Reveal())

	spec, _ := json.Marshal(PushSpec{Reason: "ledger check"})
	results, jobErr := f.run(t, PushSpec{Reason: "ledger check"})
	if jobErr == nil {
		t.Fatal("a node that could not apply the hash did not fail the job")
	}

	assertNoSecret(t, "the job spec", string(spec), hash)
	for name, res := range results {
		assertNoSecret(t, "the "+name+" step result", string(res), hash)
	}
	assertNoSecret(t, "the job error", jobErr.Error(), hash)
	for _, line := range f.logs {
		assertNoSecret(t, "a job log line", line, hash)
	}
	status, _ := f.store.Status(ctx)
	raw, _ := json.Marshal(status)
	assertNoSecret(t, "the settings view", string(raw), hash)
}

// A node whose agent predates the verb FAILS, with a sentence naming its
// version and the release that answers. It is never skipped.
func TestPushFailsAnAgentThatPredatesTheVerb(t *testing.T) {
	ctx := context.Background()
	f := newFleet(t)
	f.add("cp", proto.RoleControlPlane, proto.StatusOnline, "2026.09.4-dev.172")
	f.add("old", proto.RoleCompute, proto.StatusOnline, "2026.08.5-dev.140")
	f.agent("cp", applying("cp"))
	if _, err := f.store.SetPassword(ctx, goodPassword); err != nil {
		t.Fatal(err)
	}

	results, err := f.run(t, PushSpec{})
	if err == nil {
		t.Fatal("the job succeeded with a node that never answered")
	}
	if !strings.Contains(err.Error(), "old") {
		t.Errorf("the failure does not name the node: %v", err)
	}

	var del DeliverResult
	if uerr := json.Unmarshal(results["deliver"], &del); uerr != nil {
		t.Fatal(uerr)
	}
	if len(del.Results) != 2 {
		t.Fatalf("%d results, want one per node — a skipped node is the bug", len(del.Results))
	}
	byID := map[string]NodeResult{}
	for _, r := range del.Results {
		byID[r.NodeID] = r
	}
	old := byID["old"]
	if old.Status != NodeFailed {
		t.Fatalf("the old node is %q, want failed", old.Status)
	}
	floor, _ := proto.VerbMinAgentVersion(proto.ConsoleRootHashVerb)
	for _, want := range []string{"2026.08.5-dev.140", floor, "Update the node"} {
		if !strings.Contains(old.Detail, want) {
			t.Errorf("the reason does not mention %q: %q", want, old.Detail)
		}
	}
	// And it is durable, so Settings says so after the job is gone.
	status, _ := f.store.Status(ctx)
	for _, n := range status.Nodes {
		if n.NodeID == "old" && (n.Status != NodeFailed || n.Detail == "") {
			t.Errorf("the failure was not recorded: %+v", n)
		}
	}
}

// An agent that answers "I cannot" fails its node with the agent's own
// reason — the mixed-fleet case where the image half has not landed.
func TestPushFailsARefusingAgentWithItsReason(t *testing.T) {
	ctx := context.Background()
	f := newFleet(t)
	f.add("cp", proto.RoleControlPlane, proto.StatusOnline, "2026.09.4-dev.172")
	f.add("readonly", proto.RoleCompute, proto.StatusOnline, "2026.09.4-dev.172")
	f.agent("cp", applying("cp"))
	const reason = "this node's /etc/shadow is on a read-only filesystem"
	f.agent("readonly", refusing("readonly", reason))
	if _, err := f.store.SetPassword(ctx, goodPassword); err != nil {
		t.Fatal(err)
	}

	results, err := f.run(t, PushSpec{})
	if err == nil {
		t.Fatal("a refusing agent did not fail the job")
	}
	if !strings.Contains(err.Error(), reason) {
		t.Errorf("the job error does not carry the agent's reason: %v", err)
	}
	var del DeliverResult
	_ = json.Unmarshal(results["deliver"], &del)
	if del.Applied != 1 || del.Failed != 1 {
		t.Fatalf("applied=%d failed=%d, want 1/1", del.Applied, del.Failed)
	}
	status, _ := f.store.Status(ctx)
	for _, n := range status.Nodes {
		if n.NodeID == "readonly" && n.Detail != reason {
			t.Errorf("the recorded reason is %q", n.Detail)
		}
	}
}

// An offline node fails too, but reads as offline rather than as an old
// agent — the two send an operator to different places.
func TestPushDistinguishesOfflineFromAnOldAgent(t *testing.T) {
	ctx := context.Background()
	f := newFleet(t)
	f.add("down", proto.RoleCompute, proto.StatusOffline, "2026.09.4-dev.172")
	if _, err := f.store.SetPassword(ctx, goodPassword); err != nil {
		t.Fatal(err)
	}
	results, err := f.run(t, PushSpec{})
	if err == nil {
		t.Fatal("an offline node did not fail the job")
	}
	var del DeliverResult
	_ = json.Unmarshal(results["deliver"], &del)
	if len(del.Results) != 1 || del.Results[0].Status != NodeFailed {
		t.Fatalf("results = %+v", del.Results)
	}
	if d := del.Results[0].Detail; !strings.Contains(d, "offline") || strings.Contains(d, "predates") {
		t.Errorf("an offline node reads as %q", d)
	}
}

// An agent that acknowledges a DIFFERENT password is not a success.
func TestPushRefusesAnAckForAnotherPassword(t *testing.T) {
	ctx := context.Background()
	f := newFleet(t)
	f.add("liar", proto.RoleCompute, proto.StatusOnline, "2026.09.4-dev.172")
	f.agent("liar", func(proto.ConsoleRootHashCmd) proto.ConsoleRootHashAck {
		return proto.ConsoleRootHashAck{NodeID: "liar", OK: true, HashID: "0000000000000000", Changed: true}
	})
	if _, err := f.store.SetPassword(ctx, goodPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := f.run(t, PushSpec{}); err == nil {
		t.Fatal("an ack for another password was taken as success")
	}
}

func TestPushWithNoPasswordSetRefusesRatherThanDispatchingNothing(t *testing.T) {
	f := newFleet(t)
	f.add("cp", proto.RoleControlPlane, proto.StatusOnline, "2026.09.4-dev.172")
	f.agent("cp", applying("cp"))
	_, err := f.run(t, PushSpec{})
	if !strings.Contains(fmt.Sprint(err), "no console root password") {
		t.Fatalf("err = %v, want the no-password refusal", err)
	}
	if _, sent := f.seen["cp"]; sent {
		t.Fatal("a command was dispatched with no password set")
	}
}

func TestPushScopedToOneNodeRefusesAnUnregisteredNode(t *testing.T) {
	ctx := context.Background()
	f := newFleet(t)
	f.add("cp", proto.RoleControlPlane, proto.StatusOnline, "2026.09.4-dev.172")
	f.agent("cp", applying("cp"))
	if _, err := f.store.SetPassword(ctx, goodPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := f.run(t, PushSpec{NodeIDs: []string{"ghost"}}); err == nil {
		t.Fatal("a push naming an unregistered node succeeded")
	}
	// And a scoped push touches only its node.
	if _, err := f.run(t, PushSpec{NodeIDs: []string{"cp"}}); err != nil {
		t.Fatal(err)
	}
	status, _ := f.store.Status(ctx)
	if len(status.Nodes) != 1 || status.Nodes[0].NodeID != "cp" {
		t.Fatalf("a scoped push recorded %+v", status.Nodes)
	}
}

// A re-run against a converged fleet is a no-op that still succeeds — the
// Settings action is re-runnable (#558).
func TestPushIsRerunnable(t *testing.T) {
	ctx := context.Background()
	f := newFleet(t)
	f.add("cp", proto.RoleControlPlane, proto.StatusOnline, "2026.09.4-dev.172")
	f.agent("cp", func(cmd proto.ConsoleRootHashCmd) proto.ConsoleRootHashAck {
		return proto.ConsoleRootHashAck{NodeID: "cp", OK: true, HashID: proto.ConsoleRootHashID(cmd.Hash)}
	})
	if _, err := f.store.SetPassword(ctx, goodPassword); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := f.run(t, PushSpec{}); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	status, _ := f.store.Status(ctx)
	if len(status.Nodes) != 1 || !status.Nodes[0].Current {
		t.Fatalf("after three runs: %+v", status.Nodes)
	}
}

// ─── convergence on enrolment ───────────────────────────────────────────────

type recordingSubmitter struct {
	mu    sync.Mutex
	specs []PushSpec
	err   error
}

func (r *recordingSubmitter) submit(_ context.Context, kind string, spec json.RawMessage, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if kind != PushKind {
		return fmt.Errorf("unexpected kind %q", kind)
	}
	if r.err != nil {
		return r.err
	}
	var s PushSpec
	if err := json.Unmarshal(spec, &s); err != nil {
		return err
	}
	r.specs = append(r.specs, s)
	return nil
}

func (r *recordingSubmitter) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.specs)
}

func TestConvergerPushesToANodeThatDoesNotHoldThePassword(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	sub := &recordingSubmitter{}
	c := NewConverger(st, sub.submit)
	node := &proto.Node{ID: "newcomer", Status: proto.StatusOnline}

	// No password chosen yet: nothing to converge to, so nothing is sent.
	c.OnRegistered(ctx, node)
	if sub.count() != 0 {
		t.Fatal("a push was submitted with no password set")
	}

	hashID, err := st.SetPassword(ctx, goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	c.OnRegistered(ctx, node)
	if sub.count() != 1 {
		t.Fatalf("%d pushes, want 1 for a node that holds nothing", sub.count())
	}
	if got := sub.specs[0].NodeIDs; len(got) != 1 || got[0] != "newcomer" {
		t.Fatalf("the push was scoped to %v", got)
	}

	// A registration storm must not become a job storm: the node is
	// claimed (pending) until the push answers.
	for i := 0; i < 5; i++ {
		c.OnRegistered(ctx, node)
	}
	if sub.count() != 1 {
		t.Fatalf("%d pushes after a registration storm, want 1", sub.count())
	}

	// Once it holds the current password, re-registration is free.
	if err := st.RecordNode(ctx, NodeState{NodeID: "newcomer", Status: NodeApplied, HashID: hashID}); err != nil {
		t.Fatal(err)
	}
	c.OnRegistered(ctx, node)
	if sub.count() != 1 {
		t.Fatalf("%d pushes for a converged node, want 1", sub.count())
	}

	// A new password makes it stale again — the trigger is the fact, not
	// the node being new.
	if _, err := st.SetPassword(ctx, "another console password entirely"); err != nil {
		t.Fatal(err)
	}
	// SetPassword marks every node pending; a node whose push the api
	// restarted out of is released by ClearPendingOnStart.
	if err := ClearPendingOnStart(ctx, st); err != nil {
		t.Fatal(err)
	}
	c.OnRegistered(ctx, node)
	if sub.count() != 2 {
		t.Fatalf("%d pushes after the password changed, want 2", sub.count())
	}
}

func TestConvergerReleasesTheClaimWhenTheSubmitFails(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	sub := &recordingSubmitter{err: errors.New("the runner is quiesced")}
	c := NewConverger(st, sub.submit)
	if _, err := st.SetPassword(ctx, goodPassword); err != nil {
		t.Fatal(err)
	}
	c.OnRegistered(ctx, &proto.Node{ID: "n1", Status: proto.StatusOnline})
	status, _ := st.Status(ctx)
	if len(status.Nodes) != 1 || status.Nodes[0].Status != NodeFailed {
		t.Fatalf("a failed submit left %+v, want a failed record that the next registration retries", status.Nodes)
	}
	if !strings.Contains(status.Nodes[0].Detail, "quiesced") {
		t.Errorf("the reason is %q", status.Nodes[0].Detail)
	}
}

func TestClearPendingOnStartReleasesStuckClaims(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	if err := st.RecordNode(ctx, NodeState{NodeID: "stuck", Status: NodePending, UpdatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordNode(ctx, NodeState{NodeID: "fine", Status: NodeApplied, HashID: "abc"}); err != nil {
		t.Fatal(err)
	}
	if err := ClearPendingOnStart(ctx, st); err != nil {
		t.Fatal(err)
	}
	status, _ := st.Status(ctx)
	byID := map[string]NodeState{}
	for _, n := range status.Nodes {
		byID[n.NodeID] = n
	}
	if byID["stuck"].Status != NodeFailed || !strings.Contains(byID["stuck"].Detail, "restarted") {
		t.Fatalf("stuck = %+v", byID["stuck"])
	}
	if byID["fine"].Status != NodeApplied {
		t.Fatalf("a settled node was disturbed: %+v", byID["fine"])
	}
	if err := ClearPendingOnStart(ctx, nil); err != nil {
		t.Fatalf("a nil store should be a no-op: %v", err)
	}
}

// ─── helpers ────────────────────────────────────────────────────────────────

// assertNoSecret fails when text carries the hash, its digest, or the
// password.
func assertNoSecret(t *testing.T, where, text, hash string) {
	t.Helper()
	if strings.Contains(text, hash) {
		t.Errorf("%s carries the hash:\n%s", where, text)
	}
	if d := hash[strings.LastIndex(hash, "$")+1:]; d != "" && strings.Contains(text, d) {
		t.Errorf("%s carries the hash digest:\n%s", where, text)
	}
	if strings.Contains(text, goodPassword) {
		t.Errorf("%s carries the password:\n%s", where, text)
	}
	if strings.Contains(text, "$6$") {
		t.Errorf("%s carries something hash-shaped:\n%s", where, text)
	}
}

// A node with no derived presence must not read as a blank.
//
// Found by the functional check, not by a unit test: main wired the workflow
// straight to inventory.Store.List, which returns rows whose Status has not
// been derived yet (Presence does that), and every unanswered node came back
// as "the node is  — it will receive…". main now does List-then-Presence, the
// same pair bustls uses; this pins the other half, so a future caller that
// forgets gets a sentence that says what is actually known.
func TestPushSaysSoWhenItCannotReadANodesPresence(t *testing.T) {
	ctx := context.Background()
	f := newFleet(t)
	f.add("blank", proto.RoleCompute, "", "2026.09.4-dev.172") // no presence derived
	if _, err := f.store.SetPassword(ctx, goodPassword); err != nil {
		t.Fatal(err)
	}
	results, err := f.run(t, PushSpec{})
	if err == nil {
		t.Fatal("the job succeeded with a node that never answered")
	}
	var del DeliverResult
	_ = json.Unmarshal(results["deliver"], &del)
	d := del.Results[0].Detail
	if strings.Contains(d, "the node is  ") || strings.Contains(d, "the node is —") {
		t.Fatalf("a blank status was rendered into the reason: %q", d)
	}
	if !strings.Contains(d, "could not read its presence") {
		t.Errorf("reason = %q", d)
	}
}

// ─── #597: outcomes and the journal, on the real runner ────────────────────

// unchanging is the fake agent that already holds whatever it is sent.
func unchanging(id string) func(proto.ConsoleRootHashCmd) proto.ConsoleRootHashAck {
	return func(cmd proto.ConsoleRootHashCmd) proto.ConsoleRootHashAck {
		return proto.ConsoleRootHashAck{NodeID: id, OK: true, HashID: proto.ConsoleRootHashID(cmd.Hash), Changed: false}
	}
}

// rawAgent subscribes a fake agent that answers with bytes that are not an ack.
func (f *fleet) rawAgent(id string, data []byte) {
	f.t.Helper()
	if _, err := f.nc.Subscribe(proto.NodeCmdSubject(id, proto.ConsoleRootHashVerb), func(m *nats.Msg) {
		_ = m.Respond(data)
	}); err != nil {
		f.t.Fatal(err)
	}
	if err := f.nc.Flush(); err != nil {
		f.t.Fatal(err)
	}
}

// realRunner is a jobs.Runner on its own jobs store, over nc, with wf
// registered — how production runs the push.
func realRunner(t *testing.T, nc *nats.Conn, wf jobs.Workflow) (*jobs.Runner, *jobs.Store) {
	t.Helper()
	js, err := jobs.OpenStore(context.Background(), filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.Close() })
	r := jobs.NewRunner(js, nc)
	r.Register(wf)
	return r, js
}

// submitAndWait runs one push to its terminal state, OnTerminal included.
func submitAndWait(t *testing.T, r *jobs.Runner, js *jobs.Store, spec PushSpec) *jobs.Job {
	t.Helper()
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	j, err := r.Submit(context.Background(), PushKind, raw, "test")
	if err != nil {
		t.Fatal(err)
	}
	waitTerminal(t, js, j.ID)
	// The job reads terminal before its OnTerminal hook has run; Wait is
	// what guarantees the hook's record is in the journal.
	r.Wait()
	final, err := js.GetJob(context.Background(), j.ID)
	if err != nil {
		t.Fatal(err)
	}
	return final
}

// runPush runs one push on the real runner with the given journal and clock.
func (f *fleet) runPush(t *testing.T, spec PushSpec, log *slog.Logger, now func() time.Time) (*jobs.Job, *jobs.Store) {
	t.Helper()
	r, js := realRunner(t, f.nc, PushWorkflow(f.store, f.list, log, now))
	return submitAndWait(t, r, js, spec), js
}

// deliverOf reads the deliver step's recorded result.
func deliverOf(t *testing.T, js *jobs.Store, jobID string) DeliverResult {
	t.Helper()
	steps, err := js.ListSteps(context.Background(), jobID)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range steps {
		if st.Name == "deliver" {
			var del DeliverResult
			if err := json.Unmarshal(st.Result, &del); err != nil {
				t.Fatalf("decode deliver result %s: %v", st.Result, err)
			}
			return del
		}
	}
	t.Fatalf("job %s recorded no deliver step", jobID)
	return DeliverResult{}
}

// attrs returns rec's fields as resolved values, for exact comparison.
func attrs(rec slog.Record) map[string]any {
	out := map[string]any{}
	rec.Attrs(func(a slog.Attr) bool {
		out[a.Key] = a.Value.Resolve().Any()
		return true
	})
	return out
}

const (
	msgPlan     = "console: pushing the console root password"
	msgNodeOK   = "console: console root password delivered to a node"
	msgNodeFail = "console: console root password not applied on a node"
	msgSummary  = "console: console root password delivery finished"
	msgFailed   = "console: console root password push failed"
)

func counts(d DeliverResult) [4]int { return [4]int{d.Changed, d.Unchanged, d.Applied, d.Failed} }

// TC-597-01: a converged node reports unchanged, its Settings row says
// nothing was written, and the record step stamps the injected clock.
func TestPushReportsANodeThatAlreadyHeldThePasswordAsUnchanged(t *testing.T) {
	ctx := context.Background()
	f := newFleet(t)
	f.add("cp", proto.RoleControlPlane, proto.StatusOnline, "2026.09.4-dev.172")
	f.agent("cp", unchanging("cp"))
	hashID, err := f.store.SetPassword(ctx, goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Date(2026, 10, 4, 12, 30, 0, 0, time.UTC)
	log, rec := logkittest.New()

	j, js := f.runPush(t, PushSpec{Reason: "requested from Settings"}, log, func() time.Time { return fixed })
	if j.Status != jobs.StatusSucceeded {
		t.Fatalf("job %s: %s", j.Status, j.Error)
	}
	del := deliverOf(t, js, j.ID)
	if got := counts(del); got != [4]int{0, 1, 1, 0} {
		t.Fatalf("changed/unchanged/applied/failed = %v, want [0 1 1 0]", got)
	}
	if len(del.Results) != 1 || del.Results[0].Outcome != OutcomeUnchanged {
		t.Fatalf("results = %+v, want one row with outcome unchanged", del.Results)
	}
	status, err := f.store.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	n := status.Nodes[0]
	if n.Status != NodeApplied || n.HashID != hashID || !n.Current {
		t.Fatalf("store row = %+v, want applied, current, holding %s", n, hashID)
	}
	if !strings.Contains(n.Detail, "already held this password") || !strings.Contains(n.Detail, "nothing was written") {
		t.Errorf("store row detail = %q, want it to say the node already held it and nothing was written", n.Detail)
	}
	if !n.UpdatedAt.Equal(fixed) {
		t.Errorf("store row updatedAt = %s, want the injected clock's %s", n.UpdatedAt, fixed)
	}
	infos := rec.Matching(slog.LevelInfo, msgNodeOK)
	if len(infos) != 1 {
		t.Fatalf("%d per-node INFO records, want 1:\n%s", len(infos), rec.Text())
	}
	a := attrs(infos[0])
	if a["job_id"] != j.ID || a["hash_id"] != hashID || a["node_id"] != "cp" || a["outcome"] != "unchanged" {
		t.Errorf("per-node record fields = %v", a)
	}
}

// TC-597-02: a node that wrote the password reports changed.
func TestPushReportsANodeThatWroteThePasswordAsChanged(t *testing.T) {
	ctx := context.Background()
	f := newFleet(t)
	f.add("cp", proto.RoleControlPlane, proto.StatusOnline, "2026.09.4-dev.172")
	f.agent("cp", applying("cp"))
	if _, err := f.store.SetPassword(ctx, goodPassword); err != nil {
		t.Fatal(err)
	}
	log, rec := logkittest.New()

	j, js := f.runPush(t, PushSpec{}, log, time.Now)
	if j.Status != jobs.StatusSucceeded {
		t.Fatalf("job %s: %s", j.Status, j.Error)
	}
	del := deliverOf(t, js, j.ID)
	if del.Changed != 1 || del.Unchanged != 0 || del.Applied != 1 {
		t.Fatalf("changed/unchanged/applied = %d/%d/%d, want 1/0/1", del.Changed, del.Unchanged, del.Applied)
	}
	if del.Results[0].Outcome != OutcomeChanged {
		t.Fatalf("outcome = %q, want changed", del.Results[0].Outcome)
	}
	status, _ := f.store.Status(ctx)
	if d := status.Nodes[0].Detail; d != "" {
		t.Errorf("a changed node's row has detail %q, want none", d)
	}
	infos := rec.Matching(slog.LevelInfo, msgNodeOK)
	if len(infos) != 1 || attrs(infos[0])["outcome"] != "changed" {
		t.Fatalf("per-node INFO records:\n%s", rec.Text())
	}
}

// mixedFleet is the TC-597-03 fleet: one node that changes, one that
// already held it, and an online node whose agent predates the verb.
func mixedFleet(t *testing.T) (*fleet, string) {
	t.Helper()
	f := newFleet(t)
	f.add("a-changes", proto.RoleControlPlane, proto.StatusOnline, "2026.09.4-dev.172")
	f.add("b-same", proto.RoleCompute, proto.StatusOnline, "2026.09.4-dev.172")
	f.add("c-old", proto.RoleCompute, proto.StatusOnline, "2026.09.4-dev.100")
	f.agent("a-changes", applying("a-changes"))
	f.agent("b-same", unchanging("b-same"))
	if _, err := f.store.SetPassword(context.Background(), goodPassword); err != nil {
		t.Fatal(err)
	}
	hashValue, _, err := f.store.HashForDispatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	hash := string(hashValue.Reveal())
	return f, hash
}

// TC-597-03: a mixed fleet fails the job on the old agent, with the release
// it needs, and the summary counts every reading.
func TestPushMixedFleetCountsEachOutcomeAndFailsTheOldAgent(t *testing.T) {
	f, _ := mixedFleet(t)
	log, rec := logkittest.New()

	j, js := f.runPush(t, PushSpec{}, log, time.Now)
	if j.Status != jobs.StatusFailed {
		t.Fatalf("job %s, want failed", j.Status)
	}
	del := deliverOf(t, js, j.ID)
	if del.Changed != 1 || del.Unchanged != 1 || del.Failed != 1 || del.Applied != 2 {
		t.Fatalf("changed/unchanged/failed/applied = %d/%d/%d/%d, want 1/1/1/2", del.Changed, del.Unchanged, del.Failed, del.Applied)
	}
	for _, want := range []string{"c-old", "2026.09.4-dev.172"} {
		if !strings.Contains(j.Error, want) {
			t.Errorf("job error does not name %q: %s", want, j.Error)
		}
	}
	warns := rec.Matching(slog.LevelWarn, msgNodeFail)
	if len(warns) != 1 {
		t.Fatalf("%d WARN records, want 1:\n%s", len(warns), rec.Text())
	}
	w := attrs(warns[0])
	if w["node_id"] != "c-old" || w["outcome"] != "failed" || !strings.Contains(fmt.Sprint(w["detail"]), "2026.09.4-dev.172") {
		t.Errorf("WARN fields = %v", w)
	}
	sums := rec.Matching(slog.LevelInfo, msgSummary)
	if len(sums) != 1 {
		t.Fatalf("%d summary records, want 1", len(sums))
	}
	s := attrs(sums[0])
	if s["changed"] != int64(1) || s["unchanged"] != int64(1) || s["failed"] != int64(1) {
		t.Errorf("summary fields = %v, want 1/1/1", s)
	}
	if errs := rec.AtLevel(slog.LevelError); len(errs) != 1 {
		t.Errorf("%d ERROR records, want exactly 1:\n%s", len(errs), rec.Text())
	}
}

// TC-597-04: every way a node can fail sets outcome=failed, keeps the
// existing wording, and writes a WARN record.
func TestPushEveryFailurePathIsOutcomeFailed(t *testing.T) {
	const refusal = "this node's /etc/shadow is on a read-only filesystem"
	for name, tc := range map[string]struct {
		setup func(f *fleet)
		want  string
	}{
		"refusing agent": {
			setup: func(f *fleet) {
				f.add("n1", proto.RoleCompute, proto.StatusOnline, "2026.09.4-dev.172")
				f.agent("n1", refusing("n1", refusal))
			},
			want: refusal,
		},
		"ack for another password": {
			setup: func(f *fleet) {
				f.add("n1", proto.RoleCompute, proto.StatusOnline, "2026.09.4-dev.172")
				f.agent("n1", func(proto.ConsoleRootHashCmd) proto.ConsoleRootHashAck {
					return proto.ConsoleRootHashAck{NodeID: "n1", OK: true, HashID: "0000000000000000", Changed: true}
				})
			},
			want: "the agent acknowledged a different password",
		},
		"unparseable answer": {
			setup: func(f *fleet) {
				f.add("n1", proto.RoleCompute, proto.StatusOnline, "2026.09.4-dev.172")
				f.rawAgent("n1", []byte("not json"))
			},
			want: "the node's answer could not be read",
		},
		"offline node": {
			setup: func(f *fleet) {
				f.add("n1", proto.RoleCompute, proto.StatusOffline, "2026.09.4-dev.172")
			},
			want: "the node is offline",
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFleet(t)
			tc.setup(f)
			if _, err := f.store.SetPassword(context.Background(), goodPassword); err != nil {
				t.Fatal(err)
			}
			log, rec := logkittest.New()
			j, js := f.runPush(t, PushSpec{}, log, time.Now)
			del := deliverOf(t, js, j.ID)
			if len(del.Results) != 1 {
				t.Fatalf("results = %+v", del.Results)
			}
			r := del.Results[0]
			if r.Outcome != OutcomeFailed || r.Status != NodeFailed {
				t.Fatalf("outcome/status = %q/%q, want failed/failed", r.Outcome, r.Status)
			}
			if !strings.Contains(r.Detail, tc.want) {
				t.Errorf("detail = %q, want it to contain %q", r.Detail, tc.want)
			}
			warns := rec.Matching(slog.LevelWarn, msgNodeFail)
			if len(warns) != 1 {
				t.Fatalf("%d WARN records, want 1:\n%s", len(warns), rec.Text())
			}
			w := attrs(warns[0])
			if w["node_id"] != "n1" || w["outcome"] != "failed" || w["detail"] != r.Detail {
				t.Errorf("WARN fields = %v, want node_id n1, outcome failed, detail %q", w, r.Detail)
			}
		})
	}
}

// TC-597-05: the plan step writes one INFO record per job naming the job,
// the password id, the reason and the resolved targets.
func TestPushPlanRecordNamesTheJobReasonAndTargets(t *testing.T) {
	f := newFleet(t)
	f.add("n2", proto.RoleCompute, proto.StatusOnline, "2026.09.4-dev.172")
	f.add("n1", proto.RoleControlPlane, proto.StatusOnline, "2026.09.4-dev.172")
	f.agent("n1", applying("n1"))
	f.agent("n2", applying("n2"))
	hashID, err := f.store.SetPassword(context.Background(), goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		spec PushSpec
		want []string
	}{
		{PushSpec{Reason: "requested from Settings"}, []string{"n1", "n2"}},
		{PushSpec{Reason: "the console root password was set"}, []string{"n1", "n2"}},
		{PushSpec{Reason: "registration of n1", NodeIDs: []string{"n1"}}, []string{"n1"}},
	} {
		log, rec := logkittest.New()
		j, _ := f.runPush(t, tc.spec, log, time.Now)
		plans := rec.Matching(slog.LevelInfo, msgPlan)
		if len(plans) != 1 {
			t.Fatalf("%q: %d plan records, want 1", tc.spec.Reason, len(plans))
		}
		a := attrs(plans[0])
		if a["job_id"] != j.ID || a["hash_id"] != hashID || a["reason"] != tc.spec.Reason {
			t.Errorf("%q: plan fields = %v", tc.spec.Reason, a)
		}
		if got := fmt.Sprint(a["targets"]); got != fmt.Sprint(tc.want) {
			t.Errorf("%q: targets = %s, want %v", tc.spec.Reason, got, tc.want)
		}
	}
}

// TC-597-06: nothing the journal receives carries the hash or the password.
// (The ledger half is TestPushNeverPutsTheHashInTheLedger_RealRunner.)
func TestPushJournalCarriesNoSecret(t *testing.T) {
	f, hash := mixedFleet(t)
	log, rec := logkittest.New()
	f.runPush(t, PushSpec{Reason: "requested from Settings"}, log, time.Now)
	text := rec.Text()
	if len(rec.Records()) == 0 {
		t.Fatal("no journal records, so the absence check would prove nothing")
	}
	assertNoSecret(t, "the journal", text, hash)
}

// TC-597-07: a missing logger or clock is refused at construction.
func TestPushWorkflowRefusesANilLoggerOrClock(t *testing.T) {
	st := newStore(t)
	list := func(context.Context) ([]*proto.Node, error) { return nil, nil }
	for name, tc := range map[string]struct {
		build func()
		want  string
	}{
		"nil logger": {func() { PushWorkflow(st, list, nil, time.Now) }, "logger"},
		"nil clock":  {func() { PushWorkflow(st, list, discardLog, nil) }, "clock"},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				p := fmt.Sprint(recover())
				if !strings.Contains(p, "PushWorkflow") || !strings.Contains(p, tc.want) {
					t.Fatalf("panic = %q, want it to name PushWorkflow and the %s", p, tc.want)
				}
			}()
			tc.build()
		})
	}
}

// TC-597-08: re-running on a converged fleet reads as no change (#587).
func TestPushRerunOnAConvergedFleetIsUnchanged(t *testing.T) {
	ctx := context.Background()
	f := newFleet(t)
	f.add("cp", proto.RoleControlPlane, proto.StatusOnline, "2026.09.4-dev.172")
	var mu sync.Mutex
	held := ""
	f.agent("cp", func(cmd proto.ConsoleRootHashCmd) proto.ConsoleRootHashAck {
		mu.Lock()
		defer mu.Unlock()
		id := proto.ConsoleRootHashID(cmd.Hash)
		changed := held != id
		held = id
		return proto.ConsoleRootHashAck{NodeID: "cp", OK: true, HashID: id, Changed: changed}
	})
	if _, err := f.store.SetPassword(ctx, goodPassword); err != nil {
		t.Fatal(err)
	}
	for run := 1; run <= 3; run++ {
		log, rec := logkittest.New()
		j, js := f.runPush(t, PushSpec{Reason: "requested from Settings"}, log, time.Now)
		if j.Status != jobs.StatusSucceeded {
			t.Fatalf("run %d: %s %s", run, j.Status, j.Error)
		}
		del := deliverOf(t, js, j.ID)
		if run == 1 {
			if del.Changed != 1 || del.Unchanged != 0 {
				t.Fatalf("run 1: changed/unchanged = %d/%d, want 1/0", del.Changed, del.Unchanged)
			}
		} else {
			if del.Changed != 0 || del.Unchanged != 1 {
				t.Fatalf("run %d: changed/unchanged = %d/%d, want 0/1", run, del.Changed, del.Unchanged)
			}
			infos := rec.Matching(slog.LevelInfo, msgNodeOK)
			if len(infos) != 1 || attrs(infos[0])["outcome"] != "unchanged" {
				t.Fatalf("run %d: per-node records:\n%s", run, rec.Text())
			}
		}
		status, _ := f.store.Status(ctx)
		if len(status.Nodes) != 1 || !status.Nodes[0].Current {
			t.Fatalf("run %d: the node does not read current: %+v", run, status.Nodes)
		}
	}
}

// assertOneTerminalError checks the single ERROR record a failed job gets.
func assertOneTerminalError(t *testing.T, rec *logkittest.Recorder, j *jobs.Job) {
	t.Helper()
	errs := rec.AtLevel(slog.LevelError)
	if len(errs) != 1 {
		t.Fatalf("%d ERROR records, want exactly 1:\n%s", len(errs), rec.Text())
	}
	if errs[0].Message != msgFailed {
		t.Errorf("ERROR message = %q, want %q", errs[0].Message, msgFailed)
	}
	a := attrs(errs[0])
	if a["job_id"] != j.ID {
		t.Errorf("ERROR job_id = %v, want %s", a["job_id"], j.ID)
	}
	if a["error"] != j.Error {
		t.Errorf("ERROR error = %q, want the job's stored error %q", a["error"], j.Error)
	}
}

// TC-597-09: a push that fails before verify still reaches the journal, once.
func TestPushFailureBeforeVerifyIsJournalledOnce(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		noPassword bool
		nodes      Nodes
		spec       PushSpec
		nilBus     bool
		want       string
	}{
		"no password set":   {noPassword: true, want: ErrNoPassword.Error()},
		"unregistered node": {spec: PushSpec{NodeIDs: []string{"ghost"}}, want: "not registered: ghost"},
		"inventory error":   {nodes: func(context.Context) ([]*proto.Node, error) { return nil, errors.New("inventory is down") }, want: "list inventory: inventory is down"},
		"no bus connection": {nilBus: true, want: "no bus connection"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFleet(t)
			f.add("cp", proto.RoleControlPlane, proto.StatusOnline, "2026.09.4-dev.172")
			f.agent("cp", applying("cp"))
			hash := ""
			if !tc.noPassword {
				if _, err := f.store.SetPassword(ctx, goodPassword); err != nil {
					t.Fatal(err)
				}
				hashValue, _, _ := f.store.HashForDispatch(ctx)
				hash = string(hashValue.Reveal())
			}
			nodes := Nodes(f.list)
			if tc.nodes != nil {
				nodes = tc.nodes
			}
			nc := f.nc
			if tc.nilBus {
				nc = nil
			}
			log, rec := logkittest.New()
			r, js := realRunner(t, nc, PushWorkflow(f.store, nodes, log, time.Now))
			j := submitAndWait(t, r, js, tc.spec)
			if j.Status != jobs.StatusFailed || j.Error != tc.want {
				t.Fatalf("job %s %q, want failed %q", j.Status, j.Error, tc.want)
			}
			assertOneTerminalError(t, rec, j)
			if hash != "" {
				assertNoSecret(t, "the journal", rec.Text(), hash)
			}
		})
	}
}

// TC-597-10: a push orphaned by an api restart reaches the journal.
func TestPushOrphanedByARestartIsJournalled(t *testing.T) {
	ctx := context.Background()
	f := newFleet(t)
	log, rec := logkittest.New()
	r, js := realRunner(t, f.nc, PushWorkflow(f.store, f.list, log, time.Now))
	orphan := &jobs.Job{ID: "01ORPHANEDPUSH", Kind: PushKind, Spec: json.RawMessage(`{}`),
		Status: jobs.StatusQueued, CreatedBy: "test", CreatedAt: time.Now().UTC()}
	if err := js.CreateJob(ctx, orphan); err != nil {
		t.Fatal(err)
	}
	if err := js.MarkJobStarted(ctx, orphan.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := r.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	j, err := js.GetJob(ctx, orphan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if j.Status != jobs.StatusFailed || j.Error != "control plane restarted mid-job" {
		t.Fatalf("orphan = %s %q", j.Status, j.Error)
	}
	assertOneTerminalError(t, rec, j)
}

// TC-597-11: a verify failure is logged once, naming the failed node.
func TestPushVerifyFailureIsJournalledOnce(t *testing.T) {
	f, _ := mixedFleet(t)
	log, rec := logkittest.New()
	j, _ := f.runPush(t, PushSpec{}, log, time.Now)
	assertOneTerminalError(t, rec, j)
	if e := attrs(rec.AtLevel(slog.LevelError)[0])["error"]; !strings.Contains(fmt.Sprint(e), "c-old") {
		t.Errorf("ERROR error = %v, want it to name c-old", e)
	}
}
