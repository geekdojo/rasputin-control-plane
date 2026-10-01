package bootverify

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
)

// The wait itself (WaitForNewBoot) keeps its original tests, which drive it
// through the update saga's names in api/internal/updater: verify_test.go and
// verify_deadline_test.go. What is tested here is what this package added when
// the mechanism was shared: the probe that works on any node, and the rule
// that a plain restart is proven only by a changed identity.

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

// node is a fake agent. ping and precheck are the raw replies; "" means the
// agent does not answer that command at all.
type node struct {
	mu       sync.Mutex
	ping     string
	precheck string
}

func startNode(t *testing.T, nc *nats.Conn, id, ping, precheck string) *node {
	t.Helper()
	n := &node{ping: ping, precheck: precheck}
	answer := func(get func() string) nats.MsgHandler {
		return func(m *nats.Msg) {
			n.mu.Lock()
			reply := get()
			n.mu.Unlock()
			if reply == "" {
				// An agent with no such handler: the bus says nobody is there.
				_ = m.RespondMsg(&nats.Msg{Subject: m.Reply, Header: nats.Header{"Status": []string{"503"}}})
				return
			}
			_ = m.Respond([]byte(reply))
		}
	}
	for subj, get := range map[string]func() string{
		proto.NodeCmdSubject(id, "diag.ping"): func() string { return n.ping },
		proto.UpdatePrecheckSubject(id):       func() string { return n.precheck },
	} {
		s, err := nc.Subscribe(subj, answer(get))
		if err != nil {
			t.Fatalf("subscribe: %v", err)
		}
		t.Cleanup(func() { _ = s.Unsubscribe() })
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestClassify(t *testing.T) {
	for _, c := range []struct {
		prior, current string
		want           Identity
	}{
		{"a", "b", Differs},
		{"a", "a", Same},
		{"", "b", Unknown},
		{"a", "", Unknown},
		{"", "", Unknown},
	} {
		if got := Classify(c.prior, c.current); got != c.want {
			t.Errorf("Classify(%q,%q) = %q, want %q", c.prior, c.current, got, c.want)
		}
	}
}

func TestNodeProbe(t *testing.T) {
	const rpc = 5 * time.Second
	for _, tc := range []struct {
		name           string
		ping, precheck string
		want           string
		wantErr        error // nil, ErrUnreadable, or nats.ErrNoResponders
	}{
		{"the ping carries the identity", `{"nodeId":"n","bootId":"boot-1"}`, `{"ok":true,"bootId":"other"}`, "boot-1", nil},
		{"an older agent: identity from the precheck", `{"nodeId":"n"}`, `{"ok":true,"bootId":"boot-2"}`, "boot-2", nil},
		{"an older agent with no update backend: answered, no identity", `{"nodeId":"n"}`, ``, "", nil},
		{"an agent older than boot identity: answered, no identity", `{"nodeId":"n"}`, `{"ok":true}`, "", nil},
		{"an unreadable ping", `not json`, `{"ok":true,"bootId":"boot-3"}`, "", ErrUnreadable},
		{"an unreadable precheck is not 'no identity'", `{"nodeId":"n"}`, `not json`, "", ErrUnreadable},
		{"nothing answers the ping", ``, `{"ok":true,"bootId":"boot-4"}`, "", nats.ErrNoResponders},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nc := startNATS(t)
			startNode(t, nc, "n", tc.ping, tc.precheck)
			ctx, cancel := context.WithTimeout(context.Background(), rpc)
			defer cancel()
			got, err := NodeProbe(nc, "n").Ask(ctx)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("boot id = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPrecheckProbe(t *testing.T) {
	nc := startNATS(t)
	startNode(t, nc, "n", `{"bootId":"from-ping"}`, `{"ok":true,"bootId":"from-precheck"}`)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := PrecheckProbe(nc, "n").Ask(ctx)
	if err != nil || got != "from-precheck" {
		t.Errorf("got %q, %v; want from-precheck", got, err)
	}
}

func collect() (Logger, func() string) {
	var mu sync.Mutex
	var lines []string
	return func(level, msg string) {
			mu.Lock()
			lines = append(lines, level+": "+msg)
			mu.Unlock()
		}, func() string {
			mu.Lock()
			defer mu.Unlock()
			return strings.Join(lines, "\n")
		}
}

func TestVerifyRestart_ADifferentBootIsTheOnlyProof(t *testing.T) {
	nc := startNATS(t)
	startNode(t, nc, "n", `{"bootId":"boot-after"}`, ``)
	lg, logs := collect()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	got, err := VerifyRestart(ctx, nc, "n", "boot-before", lg)
	if err != nil || got != Differs {
		t.Fatalf("got %q, %v; want differs", got, err)
	}
	if !strings.Contains(logs(), "new boot") {
		t.Errorf("logs = %q, want the new boot named", logs())
	}
}

func TestVerifyRestart_TheSameBootFailsNamingIt(t *testing.T) {
	nc := startNATS(t)
	startNode(t, nc, "n", `{"bootId":"boot-before"}`, ``)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	got, err := VerifyRestart(ctx, nc, "n", "boot-before", nil)
	if err == nil {
		t.Fatal("a node still on the boot it was told to leave must not verify")
	}
	if got != Same || !strings.Contains(err.Error(), "still answering on boot boot-before") {
		t.Errorf("got %q, %v; want same, naming the boot", got, err)
	}
}

// The update saga passes this as degraded. A plain restart must not.
func TestVerifyRestart_AnAnswerWithoutAnIdentityIsNotProof(t *testing.T) {
	nc := startNATS(t)
	startNode(t, nc, "n", `{"nodeId":"n"}`, ``)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	got, err := VerifyRestart(ctx, nc, "n", "boot-before", nil)
	if !errors.Is(err, ErrRestartUnverified) {
		t.Fatalf("err = %v, want ErrRestartUnverified", err)
	}
	if got == Differs {
		t.Errorf("verdict = %q", got)
	}
	if !strings.Contains(err.Error(), "WITHOUT a boot identity") {
		t.Errorf("err = %q, want it to say what was observed", err)
	}
}

func TestVerifyRestart_NoPriorIdentityIsNotProofEvenWhenOneAppears(t *testing.T) {
	nc := startNATS(t)
	startNode(t, nc, "n", `{"bootId":"boot-after"}`, ``)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := VerifyRestart(ctx, nc, "n", "", nil)
	if !errors.Is(err, ErrRestartUnverified) || !strings.Contains(err.Error(), "no boot identity before the command") {
		t.Fatalf("err = %v, want ErrRestartUnverified naming the missing prior identity", err)
	}
}

// A DEFINITIVE report — the agent established that its reboot command failed
// with no shutdown under way — is the node's own fact that it did not reboot.
func TestVerifyRestart_TheNodesOwnFailureReportEndsTheWait(t *testing.T) {
	nc := startNATS(t)
	startNode(t, nc, "n", `{"bootId":"boot-before"}`, ``)

	// Reported for as long as the test runs, so the wait hears it whenever
	// its subscription lands.
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		ev, _ := json.Marshal(proto.SystemRebootFailedEvt{NodeID: "n", Detail: "exit status 1", Definitive: true})
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				_ = nc.Publish(proto.NodeEvtSubject("n", "reboot_failed"), ev)
			}
		}
	}()
	defer func() { close(stop); <-done }()

	// Reaching this bound would fail the run; the report must end the wait.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	got, err := VerifyRestart(ctx, nc, "n", "boot-before", nil)
	if !errors.Is(err, ErrRestartUnverified) || got != Same {
		t.Fatalf("got %q, %v; want same + ErrRestartUnverified", got, err)
	}
	for _, want := range []string{"reboot command failed", "still on boot boot-before", "exit status 1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %q, want it to contain %q", err, want)
		}
	}
	if ctx.Err() != nil {
		t.Error("the wait ran to its bound instead of ending on the node's report")
	}
}

// ---- geekdojo/geekdojo-brain#616, the bench race -------------------------
//
// cp-compute1 (CP dev.182) really rebooted, and the job failed in 3 s: the
// agent's reboot child was SIGTERMed by the shutdown it had started, the agent
// read that as a failed reboot and published reboot_failed, and the wait ended
// on the report instead of on the boot identity. These tests hold the wait to
// facts: a new boot identity passes, and only a definitive report or the node
// going critical ends it early.

// racingNode answers diag.ping. Its first answer is the dying pre-reboot agent:
// it publishes report on reboot_failed and then answers on the boot it is
// leaving — so the report is delivered to the waiter before that answer is.
// Every later answer is from the new boot.
func racingNode(t *testing.T, nc *nats.Conn, id, report, before, after string) {
	t.Helper()
	var mu sync.Mutex
	pings := 0
	s, err := nc.Subscribe(proto.NodeCmdSubject(id, "diag.ping"), func(m *nats.Msg) {
		mu.Lock()
		pings++
		first := pings == 1
		mu.Unlock()
		if first {
			_ = nc.Publish(proto.NodeEvtSubject(id, "reboot_failed"), []byte(report))
			_ = m.Respond([]byte(`{"bootId":"` + before + `"}`))
			return
		}
		_ = m.Respond([]byte(`{"bootId":"` + after + `"}`))
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Unsubscribe() })
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
}

// THE BENCH DEFECT, at the wait. The report an agent up to dev.182 sends when
// its reboot child is killed by the shutdown (no "definitive") arrives just
// before the node comes back on a new boot. The new boot is the fact; the
// report is not.
func TestVerifyRestart_AReportThatMayBeTheShutdownRaceDoesNotEndTheWait(t *testing.T) {
	for _, verify := range []struct {
		name string
		fn   func(context.Context, *nats.Conn, string, string, Logger) (Identity, error)
	}{{"VerifyRestart", VerifyRestart}, {"VerifyReboot", VerifyReboot}} {
		t.Run(verify.name, func(t *testing.T) {
			nc := startNATS(t)
			racingNode(t, nc, "n",
				`{"nodeId":"n","bootId":"boot-before","detail":"\"/usr/sbin/reboot\" failed: signal: terminated"}`,
				"boot-before", "boot-after")
			lg, logs := collect()
			// Reaching this bound would fail the run: the new boot must end it.
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			got, err := verify.fn(ctx, nc, "n", "boot-before", lg)
			if err != nil || got != Differs {
				t.Fatalf("got %q, %v; want differs — the node came back on a new boot", got, err)
			}
			if !strings.Contains(logs(), "signal: terminated") {
				t.Errorf("logs = %q, want the node's report recorded, not dropped", logs())
			}
		})
	}
}

// The same undefinitive report from a node that really did not reboot: it is
// still on the boot it was told to leave. The report does not end the wait;
// the node answering on its old boot when the bound is reached does, as it
// does without any report — and the failure carries the node's account.
func TestVerifyRestart_AnUndefinitiveReportFromANodeThatStaysUpStillFails(t *testing.T) {
	nc := startNATS(t)
	racingNode(t, nc, "n",
		`{"nodeId":"n","bootId":"boot-before","detail":"\"/sbin/reboot\" failed: exit status 1"}`,
		"boot-before", "boot-before")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got, err := VerifyRestart(ctx, nc, "n", "boot-before", nil)
	if err == nil || got != Same {
		t.Fatalf("got %q, %v; want same and a failure", got, err)
	}
	for _, want := range []string{"never rebooted", "still answering on boot boot-before", "exit status 1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %q, want it to contain %q", err, want)
		}
	}
}

// criticalNode answers diag.ping on the boot it was told to leave — its agent
// is alive and muted, or it is the pre-reboot answer — and, once it has been
// asked, the api's inventory service reports its presence transition to
// change: the node-offline alert's critical state.
func criticalNode(t *testing.T, nc *nats.Conn, id, boot string, change proto.InventoryChangeType) {
	t.Helper()
	var once sync.Once
	s, err := nc.Subscribe(proto.NodeCmdSubject(id, "diag.ping"), func(m *nats.Msg) {
		_ = m.Respond([]byte(`{"bootId":"` + boot + `"}`))
		once.Do(func() {
			ev, _ := json.Marshal(proto.InventoryChangeEvt{
				Change: change,
				Node:   proto.Node{ID: id, Status: proto.NodeStatus(change), LastSeen: time.Now().Add(-2 * time.Minute)},
				Ts:     time.Now(),
			})
			_ = nc.Publish(proto.InventoryChangedSubject(id, string(change)), ev)
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Unsubscribe() })
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
}

// A node told to reboot that goes critical — offline, or off-bus — without
// answering on a new boot: the reboot is not verified, and the wait ends on
// that fact rather than on its bound.
func TestVerifyReboot_TheNodeGoingCriticalEndsTheWait(t *testing.T) {
	for _, tc := range []struct {
		change proto.InventoryChangeType
		want   string
	}{
		{proto.InventoryOffline, "OFFLINE"},
		{proto.InventoryOffBus, "OFF BUS"},
	} {
		t.Run(string(tc.change), func(t *testing.T) {
			nc := startNATS(t)
			criticalNode(t, nc, "n", "boot-before", tc.change)
			// Reaching this bound would fail the run: the critical state must
			// end the wait.
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			start := time.Now()
			_, err := VerifyReboot(ctx, nc, "n", "boot-before", nil)
			if !errors.Is(err, ErrRestartUnverified) {
				t.Fatalf("err = %v, want ErrRestartUnverified", err)
			}
			if time.Since(start) > time.Minute {
				t.Errorf("the wait ran %v: it ended on its bound, not on the node going critical", time.Since(start))
			}
			for _, want := range []string{tc.want, "critical", "boot-before"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("err = %q, want it to contain %q", err, want)
				}
			}
		})
	}
}

// Stale is the warning tier, not critical: a reboot passes through it on every
// node. It must not end the wait.
func TestVerifyReboot_StaleIsNotCritical(t *testing.T) {
	nc := startNATS(t)
	var mu sync.Mutex
	pings := 0
	s, err := nc.Subscribe(proto.NodeCmdSubject("n", "diag.ping"), func(m *nats.Msg) {
		mu.Lock()
		pings++
		first := pings == 1
		mu.Unlock()
		if first {
			ev, _ := json.Marshal(proto.InventoryChangeEvt{Change: proto.InventoryStale, Node: proto.Node{ID: "n"}})
			_ = nc.Publish(proto.InventoryChangedSubject("n", string(proto.InventoryStale)), ev)
			_ = m.Respond([]byte(`{"bootId":"boot-before"}`))
			return
		}
		_ = m.Respond([]byte(`{"bootId":"boot-after"}`))
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Unsubscribe() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if got, err := VerifyReboot(ctx, nc, "n", "boot-before", nil); err != nil || got != Differs {
		t.Fatalf("got %q, %v; want differs", got, err)
	}
}

// Only node.reboot reads the critical state (VerifyReboot). A BMC reset or
// cycle cuts power and has its own account of the outage, and VerifyRestart —
// its wait — is unchanged by this: it still ends on its bound.
func TestVerifyRestart_DoesNotReadTheCriticalState(t *testing.T) {
	nc := startNATS(t)
	criticalNode(t, nc, "n", "boot-before", proto.InventoryOffline)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := VerifyRestart(ctx, nc, "n", "boot-before", nil)
	if err == nil || strings.Contains(err.Error(), "OFFLINE") || !strings.Contains(err.Error(), "never rebooted") {
		t.Fatalf("err = %v, want the bound's verdict, not the critical state", err)
	}
}
