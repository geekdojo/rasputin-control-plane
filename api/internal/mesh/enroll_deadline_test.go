package mesh

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// geekdojo/geekdojo-brain#402: on e3bench-compute1 the enroll's `tailscale
// up` was killed by the agent's own 30 s deadline while it waited on the
// login, and the api — whose dispatch step was ALSO 30 s — had given up on
// the request at the same moment, so the job recorded an rpc timeout and the
// agent's (already unreadable) ack went nowhere. These tests pin the api's
// half of the fix: the dispatch step outlives the agent's named budget, a
// dispatch that does time out says so in words an operator can act on, an
// old agent's bare `signal: killed` is read for what it is, a new agent's
// named kill is relayed verbatim, and a failed attempt of either kind is
// retried by converge_enrollment on the usual backoff.

// runEnrollUpTo runs the enroll workflow's steps before name, returning the
// chained results and the minted key so the caller can drive `name` itself
// under a context of its choosing and then check the key never leaks.
func runEnrollUpTo(t *testing.T, wf jobs.Workflow, spec []byte, nc *nats.Conn, ctx context.Context, name string) (prior map[string]json.RawMessage, key string) {
	t.Helper()
	prior = map[string]json.RawMessage{}
	for _, st := range wf.Steps {
		if st.Name == name {
			break
		}
		sc := &jobs.StepCtx{Ctx: ctx, JobID: "test-job", Spec: spec, NATS: nc, PriorResults: prior, Log: func(string, string) {}}
		res, err := st.Do(sc)
		if err != nil {
			t.Fatalf("step %s: %v", st.Name, err)
		}
		if res != nil {
			prior[st.Name] = res
		}
	}
	var s enrollSession
	if err := json.Unmarshal(prior["mint_key"], &s); err != nil || s.KeyValue == "" {
		t.Fatalf("mint_key left no key in its result: %v (%s)", err, prior["mint_key"])
	}
	return prior, s.KeyValue
}

// The api must lose the race with the agent on purpose: its dispatch step
// waits the agent's whole named budget and then some, so the agent's verdict
// is what the job records.
func TestEnrollWorkflow_DispatchOutlivesTheAgentBudget(t *testing.T) {
	f := newMeshFixture(t)
	wf := EnrollNodeWorkflow(f.svc, nil, f.nc)
	st := enrollStep(t, wf, "dispatch")
	if st.Timeout <= proto.MeshEnrollWork {
		t.Errorf("dispatch timeout %s must exceed the agent's enroll budget %s, or an api timeout replaces the agent's own reason", st.Timeout, proto.MeshEnrollWork)
	}
	if st.Timeout != enrollDispatchTimeout || enrollDispatchTimeout <= proto.MeshEnrollWork {
		t.Errorf("dispatch timeout must be derived from proto.MeshEnrollWork, got %s (const %s)", st.Timeout, enrollDispatchTimeout)
	}
}

// A dispatch that times out names the timeout, the node, and the agent's
// budget — the job feed line, readable without the agent log — and carries
// no key.
func TestEnrollWorkflow_DispatchTimeoutIsNamed(t *testing.T) {
	f := newMeshFixture(t)
	// An agent that takes the cmd and never answers.
	sub, err := f.nc.Subscribe(proto.MeshEnrollSubject("node-1"), func(*nats.Msg) {})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	wf := EnrollNodeWorkflow(f.svc, nil, f.nc)
	spec, _ := json.Marshal(EnrollSpec{NodeID: "node-1"})
	prior, key := runEnrollUpTo(t, wf, spec, f.nc, f.ctx, "dispatch")
	ctx, cancel := context.WithTimeout(f.ctx, 300*time.Millisecond)
	defer cancel()
	sc := &jobs.StepCtx{Ctx: ctx, JobID: "test-job", Spec: spec, NATS: f.nc, PriorResults: prior, Log: func(string, string) {}}
	_, err = enrollStep(t, wf, "dispatch").Do(sc)
	if err == nil {
		t.Fatal("dispatch succeeded with an agent that never answered")
	}
	msg := err.Error()
	for _, want := range []string{"dispatch timed out after", "no ack from node-1", "tailscale up", proto.MeshEnrollWork.String(), "retries after backoff"} {
		if !strings.Contains(msg, want) {
			t.Errorf("step error %q should say %q", msg, want)
		}
	}
	if strings.Contains(msg, "context deadline exceeded") {
		t.Errorf("step error still reads as a bare context error: %q", msg)
	}
	if strings.Contains(msg, key) {
		t.Errorf("step error carries the auth key: %q", msg)
	}
}

// No responder at all is read against inventory when inventory is at hand:
// an offline node is called offline, not "no responders available".
func TestEnrollWorkflow_NoResponderIsReadAgainstInventory(t *testing.T) {
	f := newConvergeFixture(t)
	f.addNode(t, "node-1", proto.RoleCompute, time.Now().UTC().Add(-time.Hour))
	wf := EnrollNodeWorkflow(f.svc, f.inv, f.nc)
	spec, _ := json.Marshal(EnrollSpec{NodeID: "node-1"})
	prior, key := runEnrollUpTo(t, wf, spec, f.nc, f.ctx, "dispatch")
	sc := &jobs.StepCtx{Ctx: f.ctx, JobID: "test-job", Spec: spec, NATS: f.nc, PriorResults: prior, Log: func(string, string) {}}
	_, err := enrollStep(t, wf, "dispatch").Do(sc)
	if err == nil {
		t.Fatal("dispatch succeeded with nobody subscribed")
	}
	if !strings.Contains(err.Error(), "node node-1 is offline") {
		t.Errorf("step error %q should read the silence as the node being offline", err)
	}
	if strings.Contains(err.Error(), key) {
		t.Errorf("step error carries the auth key: %q", err)
	}
}

// Without inventory to read the silence against, the bus error is relayed
// as it is — never hidden, never guessed at.
func TestEnrollWorkflow_NoResponderWithoutInventoryIsRelayed(t *testing.T) {
	f := newMeshFixture(t)
	wf := EnrollNodeWorkflow(f.svc, nil, f.nc)
	spec, _ := json.Marshal(EnrollSpec{NodeID: "node-1"})
	prior, key := runEnrollUpTo(t, wf, spec, f.nc, f.ctx, "dispatch")
	sc := &jobs.StepCtx{Ctx: f.ctx, JobID: "test-job", Spec: spec, NATS: f.nc, PriorResults: prior, Log: func(string, string) {}}
	_, err := enrollStep(t, wf, "dispatch").Do(sc)
	if err == nil || !strings.Contains(err.Error(), "enroll rpc: ") || !strings.Contains(err.Error(), "no responders") {
		t.Errorf("without inventory the bus error must be relayed, got %v", err)
	}
	if err != nil && strings.Contains(err.Error(), key) {
		t.Errorf("step error carries the auth key: %q", err)
	}
}

// fakeAgent answers every enroll on nodeID with ack.
func fakeAgent(t *testing.T, nc *nats.Conn, nodeID string, ack proto.MeshEnrollAck) {
	t.Helper()
	sub, err := nc.Subscribe(proto.MeshEnrollSubject(nodeID), func(m *nats.Msg) {
		body, _ := json.Marshal(ack)
		_ = m.Respond(body)
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
}

func dispatchAgainst(t *testing.T, f *convergeFixture, nodeID string) (key string, err error) {
	t.Helper()
	wf := EnrollNodeWorkflow(f.svc, f.inv, f.nc)
	spec, _ := json.Marshal(EnrollSpec{NodeID: nodeID})
	prior, key := runEnrollUpTo(t, wf, spec, f.nc, f.ctx, "dispatch")
	sc := &jobs.StepCtx{Ctx: f.ctx, JobID: "test-job", Spec: spec, NATS: f.nc, PriorResults: prior, Log: func(string, string) {}}
	_, err = enrollStep(t, wf, "dispatch").Do(sc)
	return key, err
}

// The bench ack, from the bench agent: `tailscale up: signal: killed
// (stderr=)` out of 2026.08.5-dev.142. The job names the kill, the agent
// version, and the release that fixes it, instead of relaying the string.
func TestEnrollWorkflow_OldAgentBareKillIsNamed(t *testing.T) {
	f := newConvergeFixture(t)
	if err := f.inv.Insert(f.ctx, &proto.Node{
		ID: "node-1", Role: proto.RoleCompute, Hostname: "node-1", AgentVersion: "2026.08.5-dev.142",
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("inv.Insert: %v", err)
	}
	fakeAgent(t, f.nc, "node-1", proto.MeshEnrollAck{OK: false, Backend: "tailscale", Detail: "tailscale up: signal: killed (stderr=)"})
	key, err := dispatchAgainst(t, f, "node-1")
	if err == nil {
		t.Fatal("dispatch succeeded on a negative ack")
	}
	msg := err.Error()
	for _, want := range []string{"tailscale up was killed while it waited on the login", "agent 2026.08.5-dev.142", "30s enroll deadline", proto.MeshEnrollDeadlineMinAgentVersion, "update the node", "retries after backoff"} {
		if !strings.Contains(msg, want) {
			t.Errorf("step error %q should say %q", msg, want)
		}
	}
	if strings.Contains(msg, key) {
		t.Errorf("step error carries the auth key: %q", msg)
	}
}

// A new agent names its own kill; the api relays that verbatim and does not
// second-guess it with the old-agent reading.
func TestEnrollWorkflow_NewAgentNamedKillIsRelayed(t *testing.T) {
	f := newConvergeFixture(t)
	if err := f.inv.Insert(f.ctx, &proto.Node{
		ID: "node-1", Role: proto.RoleCompute, Hostname: "node-1", AgentVersion: proto.MeshEnrollDeadlineMinAgentVersion,
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("inv.Insert: %v", err)
	}
	const detail = "tailscale up killed after 1m58s by the 2m0s enroll deadline while still running; headscale at https://cp.local:8443 had not answered the login (tailscaled reports NeedsLogin)"
	fakeAgent(t, f.nc, "node-1", proto.MeshEnrollAck{OK: false, Backend: "tailscale", Detail: detail})
	_, err := dispatchAgainst(t, f, "node-1")
	if err == nil {
		t.Fatal("dispatch succeeded on a negative ack")
	}
	if !strings.Contains(err.Error(), detail) {
		t.Errorf("step error %q should relay the agent's own reason verbatim", err)
	}
	if strings.Contains(err.Error(), "predates") {
		t.Errorf("a new agent's named kill must not be read as the old-agent bug: %q", err)
	}

	// A new agent's BARE signal is a real outside kill, relayed as-is.
	fakeAgent(t, f.nc, "node-2", proto.MeshEnrollAck{OK: false, Backend: "tailscale", Detail: "tailscale up: signal: killed (stderr=)"})
	if err := f.inv.Insert(f.ctx, &proto.Node{
		ID: "node-2", Role: proto.RoleCompute, Hostname: "node-2", AgentVersion: "2026.09.1-dev.3",
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("inv.Insert: %v", err)
	}
	_, err = dispatchAgainst(t, f, "node-2")
	if err == nil || strings.Contains(err.Error(), "predates") || !strings.Contains(err.Error(), "agent rejected enroll: tailscale up: signal: killed") {
		t.Errorf("a newer agent's bare signal is not this bug; got %v", err)
	}
}

// An ordinary rejection is unchanged.
func TestEnrollWorkflow_OrdinaryRejectionUnchanged(t *testing.T) {
	f := newConvergeFixture(t)
	fakeAgent(t, f.nc, "node-1", proto.MeshEnrollAck{OK: false, Backend: "tailscale", Detail: "tailscale: install mesh CA: read-only file system"})
	_, err := dispatchAgainst(t, f, "node-1")
	if err == nil || err.Error() != "agent rejected enroll: tailscale: install mesh CA: read-only file system" {
		t.Errorf("ordinary rejection changed: %v", err)
	}
}

// A job that failed with the dispatch-timeout sentence is a failed job like
// any other to converge_enrollment: retried after the backoff, not before.
func TestReconcileConverge_RetriesADispatchTimeoutAfterBackoff(t *testing.T) {
	f := newConvergeFixture(t)
	now := time.Now().UTC()
	f.addNode(t, "c20", proto.RoleCompute, now)
	f.addNode(t, "c21", proto.RoleCompute, now)
	timedOut := enrollDispatchError(f.ctx, nil, "c20", proto.MeshEnrollSubject("c20"), context.DeadlineExceeded, enrollDispatchTimeout).Error()
	for _, j := range []struct {
		id, node string
		at       time.Time
	}{
		{"job-c20-timeout", "c20", now.Add(-5 * time.Minute)}, // past the 30s first-retry window
		{"job-c21-timeout", "c21", now.Add(-5 * time.Second)}, // inside it
	} {
		spec, _ := json.Marshal(EnrollSpec{NodeID: j.node})
		if err := f.jstore.CreateJob(f.ctx, &jobs.Job{ID: j.id, Kind: "mesh.enroll_node", Spec: spec, Status: jobs.StatusQueued, CreatedBy: "auto-enroll", CreatedAt: j.at}); err != nil {
			t.Fatalf("CreateJob: %v", err)
		}
		if err := f.jstore.MarkJobFailed(f.ctx, j.id, timedOut, j.at); err != nil {
			t.Fatalf("MarkJobFailed: %v", err)
		}
	}
	// The seeded jobs are auto-enroll too; count only what converge adds.
	before := len(f.submittedEnrolls(t))

	step := reconcileConvergeEnrollment(f.svc, f.inv, f.jstore, f.runner)
	if _, err := step(stepCtx(f.ctx, f.nc, struct{}{})); err != nil {
		t.Fatalf("converge: %v", err)
	}
	got := f.submittedEnrolls(t)
	if len(got) != before+1 || !contains(got, "c20") {
		t.Errorf("submitted %v after seeding %d: want exactly c20 added (c21 is inside its backoff)", got, before)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
