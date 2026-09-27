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
		ev, _ := json.Marshal(proto.SystemRebootFailedEvt{NodeID: "n", Detail: "exit status 1"})
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
