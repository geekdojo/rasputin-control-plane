package jobs

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// These tests run the REAL node.reboot workflow, on the real runner and a real
// bus, against a fake agent. They exist because of
// geekdojo/geekdojo-brain#616: the job used to succeed when the agent
// re-registered and answered a ping, which an agent that never restarted
// anything does every time.
//
// They are written against the workflow's public surface only (its Kind, and
// its step names for the one timeout they shorten), and the fake agent speaks
// raw JSON, so the same file runs unmodified against the code before the fix —
// where the same-boot, refused and no-identity cases fail because the job
// reports success.

// fakeRebootAgent is a node agent as the bus sees it.
type fakeRebootAgent struct {
	t      *testing.T
	nc     *nats.Conn
	nodeID string

	mu     sync.Mutex
	bootID string
	// onReboot is what the agent does when told to reboot, after acking.
	onReboot func(a *fakeRebootAgent)
	// ack is the system.reboot reply.
	ack string
	// commands counts system.reboot commands received.
	commands int

	stop chan struct{}
	wg   sync.WaitGroup
}

func (a *fakeRebootAgent) boot() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.bootID
}

func (a *fakeRebootAgent) setBoot(id string) {
	a.mu.Lock()
	a.bootID = id
	a.mu.Unlock()
}

func (a *fakeRebootAgent) publishRegistered() {
	payload, _ := json.Marshal(map[string]any{"nodeId": a.nodeID, "role": "compute", "bootId": a.boot()})
	_ = a.nc.Publish(proto.NodeRegisteredSubject(a.nodeID), payload)
}

// startFakeRebootAgent subscribes the agent's commands. bootID "" is an agent
// that reports no boot identity.
func startFakeRebootAgent(t *testing.T, nc *nats.Conn, nodeID, bootID string, onReboot func(*fakeRebootAgent)) *fakeRebootAgent {
	t.Helper()
	a := &fakeRebootAgent{
		t: t, nc: nc, nodeID: nodeID, bootID: bootID, onReboot: onReboot,
		ack:  `{"ok":true,"delaySeconds":1}`,
		stop: make(chan struct{}),
	}
	sub := func(subj string, fn nats.MsgHandler) {
		s, err := nc.Subscribe(subj, fn)
		if err != nil {
			t.Fatalf("subscribe %s: %v", subj, err)
		}
		t.Cleanup(func() { _ = s.Unsubscribe() })
	}
	sub(proto.NodeCmdSubject(nodeID, "diag.ping"), func(m *nats.Msg) {
		pong := map[string]any{"nodeId": nodeID, "hostname": nodeID, "uptime": "1s"}
		if id := a.boot(); id != "" {
			pong["bootId"] = id
		}
		payload, _ := json.Marshal(pong)
		_ = m.Respond(payload)
	})
	sub(proto.NodeCmdSubject(nodeID, "system.reboot"), func(m *nats.Msg) {
		a.mu.Lock()
		a.commands++
		ack := a.ack
		a.mu.Unlock()
		_ = m.Respond([]byte(ack))
		if strings.Contains(ack, `"ok":false`) {
			return
		}
		ev, _ := json.Marshal(map[string]any{"nodeId": nodeID, "delaySeconds": 1})
		_ = nc.Publish(proto.NodeEvtSubject(nodeID, "rebooting"), ev)
		if a.onReboot != nil {
			a.onReboot(a)
		}
	})
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	t.Cleanup(func() {
		close(a.stop)
		a.wg.Wait()
	})
	return a
}

// keepRegistering re-publishes the agent's registration until the test ends,
// the way an agent that reconnects does. It is the fake's behaviour, not a
// wait: the job is what decides when it has seen enough.
func (a *fakeRebootAgent) keepRegistering() {
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-a.stop:
				return
			case <-tick.C:
				a.publishRegistered()
			}
		}
	}()
}

// runRebootJob runs node.reboot for nodeID to its end and returns the job. The
// step that waits for the node to come back is given waitBound instead of its
// production bound, so a case that must FAIL at that bound does so in seconds.
func runRebootJob(t *testing.T, nc *nats.Conn, nodeID string, waitBound time.Duration) (*Job, []*JobStep) {
	t.Helper()
	store := newStore(t)
	r := NewRunner(store, nc)
	r.SetBackoff(func(int) time.Duration { return 0 })
	w := RebootWorkflow()
	for i := range w.Steps {
		switch w.Steps[i].Name {
		case "wait_new_boot", "wait_online":
			w.Steps[i].Timeout = waitBound
		}
	}
	r.Register(w)

	spec, _ := json.Marshal(map[string]any{"nodeId": nodeID, "delaySeconds": 1})
	j, err := r.Submit(context.Background(), "node.reboot", spec, "test")
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	r.Wait()
	done, err := store.GetJob(context.Background(), j.ID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	steps, err := store.ListSteps(context.Background(), j.ID)
	if err != nil {
		t.Fatalf("ListSteps: %v", err)
	}
	return done, steps
}

// THE DEFECT. The agent acks, announces, re-registers and answers pings — and
// is on the same boot throughout, because nothing restarted. That is what the
// simulator did, and the job called it a success.
func TestNodeRebootJob_FailsWhenTheNodeComesBackOnTheSameBoot(t *testing.T) {
	nc := startNATS(t)
	const nodeID = "n-same"
	agent := startFakeRebootAgent(t, nc, nodeID, "boot-aaaaaaaaaaaa", nil)
	agent.keepRegistering()

	job, _ := runRebootJob(t, nc, nodeID, 3*time.Second)
	if job.Status != StatusFailed {
		t.Fatalf("job status = %s, want failed: the node never left boot-aaaaaaaaaaaa", job.Status)
	}
	for _, want := range []string{"never rebooted", "still answering on boot", "boot-aaaaaaa"} {
		if !strings.Contains(job.Error, want) {
			t.Errorf("job error = %q, want it to contain %q", job.Error, want)
		}
	}
}

// The node restarts: it comes back answering on a different boot identity.
func TestNodeRebootJob_SucceedsWhenTheBootIdentityChanges(t *testing.T) {
	nc := startNATS(t)
	const nodeID = "n-new"
	agent := startFakeRebootAgent(t, nc, nodeID, "boot-before-0000", func(a *fakeRebootAgent) {
		a.setBoot("boot-after-11111")
	})
	agent.keepRegistering()

	job, steps := runRebootJob(t, nc, nodeID, 30*time.Second)
	if job.Status != StatusSucceeded {
		t.Fatalf("job status = %s (error %q), want succeeded", job.Status, job.Error)
	}
	var verified bool
	for _, s := range steps {
		if s.Name == "wait_new_boot" {
			verified = strings.Contains(string(s.Result), "boot-before-0000") && strings.Contains(string(s.Result), `"differs"`)
		}
	}
	if !verified {
		t.Errorf("steps = %+v, want wait_new_boot to record the boot that was left and the verdict", steps)
	}
	agent.mu.Lock()
	defer agent.mu.Unlock()
	if agent.commands != 1 {
		t.Errorf("the agent was told to reboot %d times, want 1", agent.commands)
	}
}

// The agent refuses (no reboot command on the image, say). The job fails with
// the agent's reason and does not wait for a reboot that was never started.
func TestNodeRebootJob_FailsWhenTheAgentRefuses(t *testing.T) {
	nc := startNATS(t)
	const nodeID = "n-refused"
	agent := startFakeRebootAgent(t, nc, nodeID, "boot-aaaaaaaaaaaa", nil)
	agent.mu.Lock()
	agent.ack = `{"ok":false,"delaySeconds":0,"detail":"this node has no \"reboot\" command, so it cannot be rebooted"}`
	agent.mu.Unlock()
	agent.keepRegistering()

	job, _ := runRebootJob(t, nc, nodeID, 30*time.Second)
	if job.Status != StatusFailed {
		t.Fatalf("job status = %s, want failed", job.Status)
	}
	for _, want := range []string{"refused the reboot", "NOT rebooted", "no \"reboot\" command"} {
		if !strings.Contains(job.Error, want) {
			t.Errorf("job error = %q, want it to contain %q", job.Error, want)
		}
	}
}

// The agent announced the reboot and the OS command then failed. The node says
// so, and the job fails with the node's account instead of waiting out its
// bound.
func TestNodeRebootJob_FailsWhenTheNodeReportsItsRebootFailed(t *testing.T) {
	nc := startNATS(t)
	const nodeID = "n-execfail"
	agent := startFakeRebootAgent(t, nc, nodeID, "boot-aaaaaaaaaaaa", nil)
	// The failure is reported for as long as the test runs, so the job hears
	// it whenever its wait begins.
	agent.wg.Add(1)
	go func() {
		defer agent.wg.Done()
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-agent.stop:
				return
			case <-tick.C:
				ev, _ := json.Marshal(map[string]any{
					"nodeId": nodeID, "bootId": "boot-aaaaaaaaaaaa",
					"detail": `"/sbin/reboot" failed: exit status 1`,
				})
				_ = nc.Publish(proto.NodeEvtSubject(nodeID, "reboot_failed"), ev)
			}
		}
	}()

	// A bound long enough that reaching it would fail the test run, not pass
	// the assertion: the job must end on the node's report.
	job, _ := runRebootJob(t, nc, nodeID, 2*time.Minute)
	if job.Status != StatusFailed {
		t.Fatalf("job status = %s, want failed", job.Status)
	}
	for _, want := range []string{"reboot command failed", "still on boot boot-aaaaaaa", "exit status 1"} {
		if !strings.Contains(job.Error, want) {
			t.Errorf("job error = %q, want it to contain %q", job.Error, want)
		}
	}
}

// An agent that reports no boot identity at all goes away and comes back. The
// update saga would pass that as degraded; a plain reboot has nothing else to
// go on, so it is a failure that says the restart could not be shown.
func TestNodeRebootJob_FailsWhenTheNodeReportsNoBootIdentity(t *testing.T) {
	nc := startNATS(t)
	const nodeID = "n-noid"
	agent := startFakeRebootAgent(t, nc, nodeID, "", nil)
	agent.keepRegistering()

	job, _ := runRebootJob(t, nc, nodeID, 3*time.Second)
	if job.Status != StatusFailed {
		t.Fatalf("job status = %s, want failed: nothing showed that the node restarted", job.Status)
	}
	if !strings.Contains(job.Error, "never rebooted") || !strings.Contains(job.Error, "never went quiet") {
		t.Errorf("job error = %q, want it to say the node answered throughout", job.Error)
	}
}

// A node that does not answer is not sent a reboot.
func TestNodeRebootJob_DoesNotSendTheCommandToANodeThatIsNotAnswering(t *testing.T) {
	nc := startNATS(t)
	const nodeID = "n-absent"
	var commands int
	var mu sync.Mutex
	sub, err := nc.Subscribe(proto.NodeCmdSubject(nodeID, "system.reboot"), func(m *nats.Msg) {
		mu.Lock()
		commands++
		mu.Unlock()
		_ = m.Respond([]byte(`{"ok":true}`))
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	job, _ := runRebootJob(t, nc, nodeID, 3*time.Second)
	if job.Status != StatusFailed {
		t.Fatalf("job status = %s, want failed", job.Status)
	}
	if !strings.Contains(job.Error, "is not answering") {
		t.Errorf("job error = %q, want it to say the node is not answering", job.Error)
	}
	mu.Lock()
	defer mu.Unlock()
	if commands != 0 {
		t.Errorf("system.reboot was sent %d times to a node that never answered", commands)
	}
}
