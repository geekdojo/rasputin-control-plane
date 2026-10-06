package bmc

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// These tests run the REAL bmc.power workflow, on the real runner and a real
// bus, against a fake BMC host and a fake target. They exist because of
// geekdojo/geekdojo-brain#617: a reset was recorded as a success and the node
// had not reset.
//
// They use the workflow's public surface only, and the fakes speak raw JSON,
// so the same file runs unmodified against the code before the fix — where
// the cases that must fail report success instead.

// rig is one cluster as the bus sees it: a BMC host, and optionally the
// target's own agent.
type rig struct {
	t      *testing.T
	f      *fixture
	runner *jobs.Runner
	jstore *jobs.Store

	mu sync.Mutex
	// power is the state the fake BMC reads back.
	power proto.BMCPowerState
	// onVerb is what the BMC host does when it receives a power verb, before
	// it acks. nil means "set power to what the verb intends".
	onVerb func(r *rig, verb proto.BMCPowerVerb)
	// ackDetail is the detail on every ack.
	ackDetail string
	// targetBoot is the boot identity the target's agent reports. It is only
	// consulted when the target has an agent.
	targetBoot string
	verbs      []proto.BMCPowerVerb

	stop chan struct{}
	wg   sync.WaitGroup
}

const (
	rigHost   = "host-1"
	rigTarget = "node-1"
)

// newRig builds the cluster. waitBound replaces the production bound on the
// step that waits for the target to restart, so a case that must FAIL at that
// bound does so in seconds.
func newRig(t *testing.T, waitBound time.Duration) *rig {
	t.Helper()
	f := newFixture(t)
	inv := newInvStore(t)
	registerHost(t, f, inv, []string{rigTarget})
	if err := inv.Insert(f.ctx, &proto.Node{
		ID: rigTarget, Role: proto.RoleCompute, Hostname: rigTarget + ".local",
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("insert target: %v", err)
	}
	jstore, err := jobs.OpenStore(f.ctx, filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatalf("jobs store: %v", err)
	}
	t.Cleanup(func() { _ = jstore.Close() })

	r := &rig{t: t, f: f, jstore: jstore, power: proto.BMCStateOn, ackDetail: "fake bmc", stop: make(chan struct{})}
	r.runner = jobs.NewRunner(jstore, f.nc)
	r.runner.SetBackoff(func(int) time.Duration { return 0 })
	w := PowerWorkflow(f.svc, inv)
	for i := range w.Steps {
		if w.Steps[i].Name == "verify" {
			w.Steps[i].Timeout = waitBound
		}
	}
	r.runner.Register(w)

	for _, verb := range proto.AllBMCPowerVerbs {
		v := verb
		sub, err := f.nc.Subscribe(proto.BMCPowerSubject(rigHost, v), func(m *nats.Msg) {
			r.mu.Lock()
			hook := r.onVerb
			if v != proto.BMCPowerQuery {
				r.verbs = append(r.verbs, v)
			}
			r.mu.Unlock()
			if v != proto.BMCPowerQuery {
				if hook != nil {
					hook(r, v)
				} else {
					r.setPower(intendedByVerb(v))
				}
			}
			r.mu.Lock()
			ack, _ := json.Marshal(map[string]any{"ok": true, "state": r.power, "detail": r.ackDetail})
			r.mu.Unlock()
			_ = m.Respond(ack)
		})
		if err != nil {
			t.Fatalf("subscribe: %v", err)
		}
		t.Cleanup(func() { _ = sub.Unsubscribe() })
	}
	t.Cleanup(func() {
		close(r.stop)
		r.wg.Wait()
	})
	return r
}

func intendedByVerb(v proto.BMCPowerVerb) proto.BMCPowerState {
	if v == proto.BMCPowerOff {
		return proto.BMCStateOff
	}
	return proto.BMCStateOn
}

func (r *rig) setPower(s proto.BMCPowerState) {
	r.mu.Lock()
	r.power = s
	r.mu.Unlock()
}

func (r *rig) setTargetBoot(id string) {
	r.mu.Lock()
	r.targetBoot = id
	r.mu.Unlock()
}

// withTargetAgent gives the target a running agent on bootID. The agent
// answers diag.ping with its boot identity and keeps re-registering, the way
// an agent that reconnects does.
func (r *rig) withTargetAgent(bootID string) {
	r.t.Helper()
	r.setTargetBoot(bootID)
	sub, err := r.f.nc.Subscribe(proto.NodeCmdSubject(rigTarget, "diag.ping"), func(m *nats.Msg) {
		r.mu.Lock()
		pong := map[string]any{"nodeId": rigTarget}
		if r.targetBoot != "" {
			pong["bootId"] = r.targetBoot
		}
		r.mu.Unlock()
		payload, _ := json.Marshal(pong)
		_ = m.Respond(payload)
	})
	if err != nil {
		r.t.Fatalf("subscribe: %v", err)
	}
	r.t.Cleanup(func() { _ = sub.Unsubscribe() })
	if err := r.f.nc.Flush(); err != nil {
		r.t.Fatal(err)
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-r.stop:
				return
			case <-tick.C:
				r.mu.Lock()
				payload, _ := json.Marshal(map[string]any{"nodeId": rigTarget, "role": "compute", "bootId": r.targetBoot})
				r.mu.Unlock()
				_ = r.f.nc.Publish(proto.NodeRegisteredSubject(rigTarget), payload)
			}
		}
	}()
}

type jobResult struct {
	job    *jobs.Job
	steps  []*jobs.JobStep
	events string
}

func (r *rig) run(verb proto.BMCPowerVerb) jobResult {
	r.t.Helper()
	j, err := r.runner.Submit(context.Background(), "bmc.power", Spec{TargetNodeID: rigTarget, Verb: verb}, "test")
	if err != nil {
		r.t.Fatalf("Submit: %v", err)
	}
	r.runner.Wait()
	ctx := context.Background()
	done, err := r.jstore.GetJob(ctx, j.ID)
	if err != nil {
		r.t.Fatalf("GetJob: %v", err)
	}
	steps, err := r.jstore.ListSteps(ctx, j.ID)
	if err != nil {
		r.t.Fatalf("ListSteps: %v", err)
	}
	evs, err := r.jstore.ListEvents(ctx, j.ID)
	if err != nil {
		r.t.Fatalf("ListEvents: %v", err)
	}
	var log strings.Builder
	for _, e := range evs {
		log.WriteString(e.Type + " " + string(e.Data) + "\n")
	}
	return jobResult{job: done, steps: steps, events: log.String()}
}

// last returns the result of the job's last step, which is the job's result.
func (jr jobResult) last() string {
	if len(jr.steps) == 0 {
		return ""
	}
	return string(jr.steps[len(jr.steps)-1].Result)
}

func wantAll(t *testing.T, what, got string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("%s = %q, want it to contain %q", what, got, w)
		}
	}
}

// THE DEFECT. The BMC host acks the reset and reads back "on". The target is
// on the same boot afterwards: it never reset. Whatever the reason — the
// command reached another slot, a slot that ignores power verbs, or nothing —
// this is what it looks like from here, and it was recorded as a success.
func TestPowerJob_ResetFailsWhenTheTargetsBootIsUnchanged(t *testing.T) {
	for _, verb := range []proto.BMCPowerVerb{proto.BMCPowerReset, proto.BMCPowerCycle} {
		t.Run(string(verb), func(t *testing.T) {
			r := newRig(t, 3*time.Second)
			r.withTargetAgent("boot-aaaaaaaaaaaa")

			res := r.run(verb)
			if res.job.Status != jobs.StatusFailed {
				t.Fatalf("job status = %s, want failed: the target never left boot-aaaaaaaaaaaa", res.job.Status)
			}
			wantAll(t, "job error", res.job.Error,
				"did NOT restart", "acknowledged by the BMC", `reports "on"`,
				"still answering on boot", "boot-aaaaaaa")

			// And the failure is what is recorded against the node.
			st, err := r.f.store.Get(r.f.ctx, rigTarget)
			if err != nil || st == nil {
				t.Fatalf("bmc state row: %v, %v", st, err)
			}
			wantAll(t, "recorded result", st.LastCmdResult, "FAILED", "did NOT restart")
		})
	}
}

func TestPowerJob_ResetSucceedsWhenTheTargetsBootChanges(t *testing.T) {
	for _, verb := range []proto.BMCPowerVerb{proto.BMCPowerReset, proto.BMCPowerCycle} {
		t.Run(string(verb), func(t *testing.T) {
			r := newRig(t, 30*time.Second)
			r.withTargetAgent("boot-before-0000")
			r.onVerb = func(r *rig, v proto.BMCPowerVerb) {
				r.setPower(proto.BMCStateOn)
				r.setTargetBoot("boot-after-11111")
			}

			res := r.run(verb)
			if res.job.Status != jobs.StatusSucceeded {
				t.Fatalf("job status = %s (error %q), want succeeded", res.job.Status, res.job.Error)
			}
			wantAll(t, "job result", res.last(), `"evidence":"boot-identity"`, `"restartVerified":true`)
			wantAll(t, "job log", res.events, "is on boot boot-before-", "verified")

			st, _ := r.f.store.Get(r.f.ctx, rigTarget)
			if st == nil {
				t.Fatal("no bmc state row")
			}
			wantAll(t, "recorded result", st.LastCmdResult, "verified", "boot-before-")
		})
	}
}

// A BMC-only target: nothing answers for it. Boot identity cannot be the
// evidence, so the job rests on the BMC's read-back — and says, in its result
// and in its log, that the restart was NOT verified.
func TestPowerJob_ResetOfATargetWithNoAgentReportsTheWeakerEvidence(t *testing.T) {
	r := newRig(t, 30*time.Second)

	res := r.run(proto.BMCPowerReset)
	if res.job.Status != jobs.StatusSucceeded {
		t.Fatalf("job status = %s (error %q), want succeeded on the BMC's read-back", res.job.Status, res.job.Error)
	}
	wantAll(t, "job result", res.last(), `"evidence":"power-state-read-back"`, `"restartVerified":false`, "NOT VERIFIED")
	wantAll(t, "job log", res.events, "did not answer before the command", "will NOT be verified", "NOT VERIFIED")

	st, _ := r.f.store.Get(r.f.ctx, rigTarget)
	if st == nil {
		t.Fatal("no bmc state row")
	}
	wantAll(t, "recorded result", st.LastCmdResult, "NOT VERIFIED")
	if strings.Contains(res.last(), `"restartVerified":true`) || strings.Contains(res.last(), "boot-identity") {
		t.Errorf("job result = %q claims a verified restart", res.last())
	}
}

// The same, for a target whose agent answers and reports no boot identity.
func TestPowerJob_ResetOfATargetWithNoBootIdentityReportsTheWeakerEvidence(t *testing.T) {
	r := newRig(t, 30*time.Second)
	r.withTargetAgent("")

	res := r.run(proto.BMCPowerReset)
	if res.job.Status != jobs.StatusSucceeded {
		t.Fatalf("job status = %s (error %q), want succeeded on the BMC's read-back", res.job.Status, res.job.Error)
	}
	wantAll(t, "job result", res.last(), `"evidence":"power-state-read-back"`, `"restartVerified":false`)
	wantAll(t, "job log", res.events, "reports no boot identity")
}

// off and on: the state the BMC reads back must be the state intended.
func TestPowerJob_OffAndOnFailOnAStateMismatch(t *testing.T) {
	for _, tc := range []struct {
		verb     proto.BMCPowerVerb
		readBack proto.BMCPowerState
		want     []string
	}{
		{proto.BMCPowerOff, proto.BMCStateOn, []string{`reports the node "on" afterwards`, `"off" was intended`}},
		{proto.BMCPowerOn, proto.BMCStateOff, []string{`reports the node "off" afterwards`, `"on" was intended`}},
		{proto.BMCPowerOff, proto.BMCStateUnknown, []string{`reports the node "unknown" afterwards`, `"off" was intended`}},
		{proto.BMCPowerReset, proto.BMCStateOff, []string{`reports the node "off" afterwards`, `"on" was intended`}},
	} {
		t.Run(string(tc.verb)+" reads back "+string(tc.readBack), func(t *testing.T) {
			r := newRig(t, 30*time.Second)
			r.onVerb = func(r *rig, _ proto.BMCPowerVerb) { r.setPower(tc.readBack) }

			res := r.run(tc.verb)
			if res.job.Status != jobs.StatusFailed {
				t.Fatalf("job status = %s, want failed", res.job.Status)
			}
			wantAll(t, "job error", res.job.Error, tc.want...)
			wantAll(t, "job error", res.job.Error, "fake bmc")
		})
	}
}

func TestPowerJob_OffAndOnSucceedWhenTheStateMatches(t *testing.T) {
	for _, verb := range []proto.BMCPowerVerb{proto.BMCPowerOff, proto.BMCPowerOn} {
		t.Run(string(verb), func(t *testing.T) {
			r := newRig(t, 30*time.Second)
			// A running agent on the target changes nothing for off and on:
			// they do not restart it, and nothing waits for a new boot.
			r.withTargetAgent("boot-aaaaaaaaaaaa")

			res := r.run(verb)
			if res.job.Status != jobs.StatusSucceeded {
				t.Fatalf("job status = %s (error %q), want succeeded", res.job.Status, res.job.Error)
			}
			wantAll(t, "job result", res.last(), `"evidence":"power-state-read-back"`, `"restartVerified":false`)
		})
	}
}

// A status query changes nothing and claims nothing.
func TestPowerJob_StatusClaimsNothing(t *testing.T) {
	r := newRig(t, 30*time.Second)
	r.withTargetAgent("boot-aaaaaaaaaaaa")
	res := r.run(proto.BMCPowerQuery)
	if res.job.Status != jobs.StatusSucceeded {
		t.Fatalf("job status = %s (error %q), want succeeded", res.job.Status, res.job.Error)
	}
	wantAll(t, "job result", res.last(), `"evidence":"none"`, `"restartVerified":false`)
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.verbs) != 0 {
		t.Errorf("a status query sent power verbs: %v", r.verbs)
	}
}

// The BMC host refuses: what it observed is the job's error, word for word.
func TestPowerJob_TheBMCHostsOwnFailureIsTheJobsError(t *testing.T) {
	f := newFixture(t)
	inv := newInvStore(t)
	registerHost(t, f, inv, []string{rigTarget})
	_ = inv.Insert(f.ctx, &proto.Node{
		ID: rigTarget, Role: proto.RoleCompute, Hostname: rigTarget + ".local",
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	})
	jstore, err := jobs.OpenStore(f.ctx, filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = jstore.Close() })
	runner := jobs.NewRunner(jstore, f.nc)
	runner.Register(PowerWorkflow(f.svc, inv))

	const observed = `bitscope: reset of node "node-1" (pos B-0, bus address 04) failed (its BMC now reports "on"): node "node-1" (pos B-0, bus address 04) did NOT power off: its BMC reports "on" after the off command`
	sub, err := f.nc.Subscribe(proto.BMCPowerSubject(rigHost, proto.BMCPowerReset), func(m *nats.Msg) {
		ack, _ := json.Marshal(map[string]any{"ok": false, "state": "on", "detail": observed})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	j, err := runner.Submit(context.Background(), "bmc.power", Spec{TargetNodeID: rigTarget, Verb: "reset"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	runner.Wait()
	done, _ := jstore.GetJob(context.Background(), j.ID)
	if done.Status != jobs.StatusFailed || !strings.Contains(done.Error, observed) {
		t.Errorf("job = %s %q, want failed carrying what the driver observed", done.Status, done.Error)
	}
}
