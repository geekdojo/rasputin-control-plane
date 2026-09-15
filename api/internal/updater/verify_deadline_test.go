package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// ----- the step deadline is not evidence ------------------------------------
//
// waitForNewBoot's deadline verdict names one of four shapes, and the operator
// acts on whichever it names. Every shape must come from something the node
// actually DID. The step's own deadline cancelling a poll that was still in
// flight is something the api did to itself: it says nothing about the node,
// and it must not be read as "the node stopped answering".
//
// These tests hold a poll in flight until the deadline has fired, driven by a
// signal from the simulated node rather than by a sleep racing a timer, so the
// ordering is the same on every run.

// manualDeadline is a context whose deadline fires exactly when the test says
// so. Err reports context.DeadlineExceeded, the same value a real step deadline
// produces, and child contexts (waitForNewBoot's per-request one) inherit it.
type manualDeadline struct {
	context.Context
	done chan struct{}
	once sync.Once
}

func newManualDeadline() *manualDeadline {
	return &manualDeadline{Context: context.Background(), done: make(chan struct{})}
}

func (d *manualDeadline) Done() <-chan struct{} { return d.done }

func (d *manualDeadline) Err() error {
	select {
	case <-d.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func (d *manualDeadline) fire() { d.once.Do(func() { close(d.done) }) }

// pollKind is what the simulated node does with one precheck poll.
type pollKind int

const (
	// pollAnswers: an ack with the given boot id ("" = a pre-bootId agent).
	pollAnswers pollKind = iota
	// pollNoResponders: the bus reports nobody is subscribed, which is what a
	// rebooting agent's vanished subscription produces. Sent as the same 503
	// status reply the NATS server sends, so the api sees ErrNoResponders.
	pollNoResponders
	// pollHeldPastDeadline: the node has the poll and would answer with the
	// given boot id, but its answer is held until after the step deadline has
	// fired and waitForNewBoot has returned. A slow-but-alive node, cut off.
	pollHeldPastDeadline
)

type pollScript struct {
	kind   pollKind
	bootID string
}

type deadlineRun struct {
	verdict bootIdentity
	err     error
	polls   int32
	logs    []string
}

// runDeadlineScript drives waitForNewBoot against a node that follows script,
// one entry per poll, and then holds every poll beyond it. The deadline fires
// the moment the node is holding a poll — never earlier. That is the ordering
// guarantee: the api only sends a poll after it has fully processed the reply
// to the one before, so every scripted reply is an observation it has made, and
// the held poll is the only thing the deadline can cut off.
func runDeadlineScript(t *testing.T, priorBootID string, script []pollScript) deadlineRun {
	t.Helper()
	nc := startNATS(t)
	const nodeID = "deadline"

	d := newManualDeadline()
	release := make(chan struct{})
	// Registered after startNATS, so it runs first: held handlers return before
	// the connection and server go away.
	t.Cleanup(func() { close(release) })

	fireNow := make(chan struct{}, 1)
	signalFire := func() {
		select {
		case fireNow <- struct{}{}:
		default:
		}
	}
	// A registration hint makes the api poll again at once instead of sitting
	// out the poll interval. It is only a latency shortcut: if it is missed the
	// next poll still happens, just later.
	regCh := make(chan *nats.Msg, 1)
	hint := func() {
		select {
		case regCh <- &nats.Msg{}:
		default:
		}
	}

	var polls atomic.Int32
	sub, err := nc.Subscribe(proto.UpdatePrecheckSubject(nodeID), func(m *nats.Msg) {
		i := int(polls.Add(1)) - 1
		step := pollScript{kind: pollHeldPastDeadline, bootID: priorBootID}
		if i < len(script) {
			step = script[i]
		}
		switch step.kind {
		case pollAnswers:
			ack, _ := json.Marshal(proto.UpdatePrecheckAck{OK: true, BootID: step.bootID})
			_ = m.Respond(ack)
		case pollNoResponders:
			_ = m.RespondMsg(&nats.Msg{Header: nats.Header{"Status": []string{"503"}}})
		case pollHeldPastDeadline:
			signalFire()
			<-release
			ack, _ := json.Marshal(proto.UpdatePrecheckAck{OK: true, BootID: step.bootID})
			_ = m.Respond(ack)
			return
		}
		hint()
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	var mu sync.Mutex
	var logs []string
	lg := logFn(func(_, msg string) {
		mu.Lock()
		defer mu.Unlock()
		logs = append(logs, msg)
	})

	type result struct {
		verdict bootIdentity
		err     error
	}
	resCh := make(chan result, 1)
	go func() {
		v, err := waitForNewBoot(d, nc, verifyRequest{NodeID: nodeID, PriorBootID: priorBootID}, regCh, lg)
		resCh <- result{v, err}
	}()

	// A hard bound on the test itself, so a regression that hangs fails by
	// name instead of by the package timeout. Nothing is racing it.
	const bound = 30 * time.Second
	var res result
	select {
	case <-fireNow:
		d.fire()
		select {
		case res = <-resCh:
		case <-time.After(bound):
			t.Fatalf("waitForNewBoot did not return within %v of its deadline firing", bound)
		}
	case res = <-resCh:
	case <-time.After(bound):
		t.Fatalf("the simulated node never reached the end of its script within %v", bound)
	}

	mu.Lock()
	defer mu.Unlock()
	return deadlineRun{verdict: res.verdict, err: res.err, polls: polls.Load(), logs: append([]string(nil), logs...)}
}

func TestWaitForNewBoot_DeadlineVerdictComesFromTheNode(t *testing.T) {
	answer := func(boot string) pollScript { return pollScript{kind: pollAnswers, bootID: boot} }
	quiet := pollScript{kind: pollNoResponders}

	cases := []struct {
		name   string
		prior  string
		script []pollScript
		// minPolls guards against a vacuous pass: the node must have seen at
		// least this many polls for the row to be exercising its shape.
		minPolls    int32
		wantVerdict bootIdentity
		// wantErr "" means success is required; otherwise the error must
		// contain it.
		wantErr string
		// notErr must not appear in the error.
		notErr string
	}{
		{
			// The regression. Answered on the boot it was told to leave, and
			// the next answer was on its way when the deadline cut it off.
			// Alive, answering, never rebooted: c13, not c08.
			name:        "old boot answered, then deadline mid-poll",
			prior:       "old",
			script:      []pollScript{answer("old")},
			minPolls:    2,
			wantVerdict: bootSame,
			wantErr:     "node never rebooted: still answering on boot old",
			notErr:      "stopped answering",
		},
		{
			name:        "never answered: the only poll is cut off by the deadline",
			prior:       "old",
			script:      nil,
			minPolls:    1,
			wantVerdict: bootUnknown,
			wantErr:     "node never answered after the reboot was issued",
		},
		{
			name:        "never answered: nobody subscribed, then deadline mid-poll",
			prior:       "old",
			script:      []pollScript{quiet},
			minPolls:    2,
			wantVerdict: bootUnknown,
			wantErr:     "node never answered after the reboot was issued",
		},
		{
			name:        "went quiet, then deadline mid-poll",
			prior:       "old",
			script:      []pollScript{answer("old"), quiet},
			minPolls:    3,
			wantVerdict: bootUnknown,
			wantErr:     "node stopped answering and never came back",
			notErr:      "still answering",
		},
		{
			name:        "new boot observed",
			prior:       "old",
			script:      []pollScript{answer("old"), answer("new")},
			minPolls:    2,
			wantVerdict: bootDiffers,
		},
		// ----- the degraded flavour: no prior boot id -----
		{
			// Same root cause on the degraded path: a cancelled poll used to
			// count as "went quiet", turning "never rebooted" into c08.
			name:        "degraded: answered throughout, then deadline mid-poll",
			prior:       "",
			script:      []pollScript{answer("")},
			minPolls:    2,
			wantVerdict: bootUnknown,
			wantErr:     "node never rebooted: it answered prechecks throughout and never went quiet",
			notErr:      "stopped answering",
		},
		{
			name:        "degraded: went quiet, then deadline mid-poll",
			prior:       "",
			script:      []pollScript{answer(""), quiet},
			minPolls:    3,
			wantVerdict: bootUnknown,
			wantErr:     "node stopped answering and never came back",
			notErr:      "never rebooted",
		},
		{
			name:        "degraded: came back reporting an identity",
			prior:       "",
			script:      []pollScript{answer(""), answer("new")},
			minPolls:    2,
			wantVerdict: bootUnknown,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run := runDeadlineScript(t, tc.prior, tc.script)
			if run.polls < tc.minPolls {
				t.Fatalf("the node saw %d polls, want at least %d — the row is not exercising its shape", run.polls, tc.minPolls)
			}
			if run.verdict != tc.wantVerdict {
				t.Errorf("verdict = %q, want %q", run.verdict, tc.wantVerdict)
			}
			switch {
			case tc.wantErr == "" && run.err != nil:
				t.Errorf("err = %v, want success", run.err)
			case tc.wantErr != "" && run.err == nil:
				t.Errorf("err = nil, want %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(run.err.Error(), tc.wantErr):
				t.Errorf("err = %q, want it to contain %q", run.err, tc.wantErr)
			}
			if tc.notErr != "" && run.err != nil && strings.Contains(run.err.Error(), tc.notErr) {
				t.Errorf("err = %q — must not contain %q: that names a failure the node did not have", run.err, tc.notErr)
			}
		})
	}
}

// The log is the operator's other window onto the same wait, and it must not
// narrate a reboot the node never started. A poll the deadline cut off is not
// "the node stopped answering".
func TestWaitForNewBoot_DeadlineCancelledPollIsNotLoggedAsTheNodeGoingQuiet(t *testing.T) {
	run := runDeadlineScript(t, "old", []pollScript{{kind: pollAnswers, bootID: "old"}})
	if run.polls < 2 {
		t.Fatalf("the node saw %d polls, want 2", run.polls)
	}
	if containsSubstr(run.logs, "stopped answering") {
		t.Errorf("logs = %q — the node never stopped answering; the api's own deadline cut the poll off", run.logs)
	}
}

// The distinction the verdict rests on, one error at a time: a poll the step's
// own bound ended is not an observation; a poll the node or the bus ended is,
// whenever it lands.
func TestPollCancelledByStep(t *testing.T) {
	live := context.Background()
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancelExpired()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	cases := []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		{"poll succeeded", live, nil, false},
		{"poll succeeded as the deadline fired", expired, nil, false},
		{"per-request timeout, step still running", live, context.DeadlineExceeded, false},
		{"no responders, step still running", live, nats.ErrNoResponders, false},
		{"bus timeout, step still running", live, nats.ErrTimeout, false},
		{"connection closed, step still running", live, nats.ErrConnectionClosed, false},
		{"step deadline cut the poll off", expired, context.DeadlineExceeded, true},
		{"step deadline cut the poll off, wrapped", expired, fmt.Errorf("request: %w", context.DeadlineExceeded), true},
		{"step cancelled mid-poll", cancelled, context.Canceled, true},
		{"no responders, then the deadline fired", expired, nats.ErrNoResponders, false},
		{"connection closed, then the deadline fired", expired, nats.ErrConnectionClosed, false},
		{"unrelated error, step cancelled", cancelled, errors.New("boom"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pollCancelledByStep(tc.ctx, tc.err); got != tc.want {
				t.Errorf("pollCancelledByStep(ctx.Err=%v, %v) = %v, want %v", tc.ctx.Err(), tc.err, got, tc.want)
			}
		})
	}
}
