package console

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// lockedLog is the process log captured for one test: the standard logger and
// the workflow's own logger both write into it.
type lockedLog struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// The console root password push, run the way production runs it — through
// the real jobs.Runner, over a real bus. The hash reaches both agents, the job
// fails on the refusing node, the step results and the operator view name the
// password by its id, and neither the hash nor the plaintext password is in
// the view an operator reads. Nothing crypt-shaped is in the spec, a step
// result, a job event or the process log.
//
// The hash is the secret here, not just the password: it is what an offline
// cracker needs. The secret.Value type and the refusal at submit hold it out
// of the ledger (ADR-0009); this test holds the delivery and the read API.
func TestPushNeverPutsTheHashInTheLedger_RealRunner(t *testing.T) {
	logs := &lockedLog{}
	prevLog := log.Writer()
	log.SetOutput(logs)
	t.Cleanup(func() { log.SetOutput(prevLog) })
	ctx := context.Background()

	f := newFleet(t)
	f.add("cp", proto.RoleControlPlane, proto.StatusOnline, "2026.09.4-dev.172")
	f.add("refuser", proto.RoleCompute, proto.StatusOnline, "2026.09.4-dev.172")
	f.agent("cp", applying("cp"))
	// A node that refuses, so the FAILURE surfaces are exercised too: a job
	// error and a failed step's error are ledger surfaces like any other,
	// and an error is exactly where a value tends to get spilled.
	f.agent("refuser", refusing("refuser", "this node's /etc/shadow is on a read-only filesystem"))
	// TC-597-06: the TC-597-03 fleet's other two readings as well — a node
	// that already held it and an agent that predates the verb — so every
	// journal record the workflow writes (changed, unchanged, failed, the
	// summary and the terminal ERROR) lands in the process log checked below.
	f.add("same", proto.RoleCompute, proto.StatusOnline, "2026.09.4-dev.172")
	f.agent("same", unchanging("same"))
	f.add("old", proto.RoleCompute, proto.StatusOnline, "2026.09.4-dev.100")

	hashID, err := f.store.SetPassword(ctx, goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	hashValue, _, err := f.store.HashForDispatch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hash := string(hashValue.Reveal())
	// Two different claims, so two different proofs. The HASH travels: it
	// goes to each agent. The PASSWORD travels nowhere at all — it was
	// consumed by SetPassword — so its absence from the operator view is
	// checked on its own, and the vacuity question is answered below by
	// deriving the stored hash back from it.

	jobStore, err := jobs.OpenStore(ctx, t.TempDir()+"/jobs.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = jobStore.Close() })
	runner := jobs.NewRunner(jobStore, f.nc)
	// The workflow journals through the process logger, and that logger
	// writes into the same captured process log the checks below read.
	runner.Register(PushWorkflow(f.store, f.list, logkit.New(logs), time.Now))

	j, err := runner.Submit(ctx, PushKind, PushSpec{Reason: "ledger gate"}, "test")
	if err != nil {
		t.Fatal(err)
	}

	// The refusing node must fail the job — that is the behaviour #558 asks
	// for, and it is also what puts a reason into the ledger to be checked.
	final := waitTerminal(t, jobStore, j.ID)
	if final.Status != jobs.StatusFailed {
		t.Fatalf("job status = %s, want failed (a node refused): %s", final.Status, final.Error)
	}
	runner.Wait()

	f.mu.Lock()
	sawCP, sawRefuser := f.seen["cp"], f.seen["refuser"]
	f.mu.Unlock()
	if sawCP != hash || sawRefuser != hash {
		t.Fatalf("the agents were not sent the stored hash (cp=%d bytes, refuser=%d bytes)",
			len(sawCP), len(sawRefuser))
	}

	// The stored hash really is a hash OF this password: re-derive it over
	// the salt it carries. That is what makes "the password is in no
	// surface" a claim about a password that was actually used, rather than
	// about a string this test happened to make up.
	parts := strings.Split(hash, "$")
	salt := parts[len(parts)-2]
	if got := sha512CryptRounds([]byte(goodPassword), []byte(salt), CryptRounds); got != hash {
		t.Fatalf("the stored hash is not a hash of the password under test, so its absence proves nothing")
	}

	processLog := logs.String()
	// TC-597-06: the workflow's journal records are in the log being scanned,
	// so the crypt-shape check below is not run against an empty surface.
	for _, want := range []string{
		"console: pushing the console root password",
		"console: console root password delivery finished",
		"console: console root password push failed",
	} {
		if !strings.Contains(processLog, want) {
			t.Fatalf("the process log lacks the journal record %q, so its scan would prove nothing:\n%s", want, processLog)
		}
	}
	if !strings.Contains(sawCP+sawRefuser, hash) {
		t.Fatal("the console.root_hash command both agents received does not carry the console root password hash")
	}

	stored, err := jobStore.GetJob(ctx, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	specAndError := string(stored.Spec) + stored.Error

	steps, err := jobStore.ListSteps(ctx, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 4 {
		t.Fatalf("want 4 recorded steps (plan, deliver, record, verify), got %d", len(steps))
	}
	var stepText string
	for _, st := range steps {
		stepText += string(st.Result) + st.Error
	}

	events, err := jobStore.ListEvents(ctx, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Fatal("no job events recorded — the events surface would be checked vacuously")
	}
	var eventText string
	for _, ev := range events {
		eventText += string(ev.Data)
	}

	// And the view an operator reads in Settings.
	status, err := f.store.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	// The view an operator reads carries neither the hash nor the plaintext
	// (F-825-12), and the agents were sent the hash, never the plaintext. The
	// values are not printed: this repo's CI logs are public.
	if strings.Contains(string(blob), hash) {
		t.Error("the console root password view an operator sees carries the console root password hash")
	}
	if strings.Contains(string(blob), goodPassword) {
		t.Error("the console root password view an operator sees carries the console root password")
	}
	if strings.Contains(sawCP+sawRefuser, goodPassword) {
		t.Error("the command the agents received carries the console root password")
	}

	// The id IS allowed everywhere, and has to be: it is how a step result,
	// an event and the UI name which password a node holds.
	if !strings.Contains(stepText, hashID) {
		t.Errorf("the step results do not name the password by its id, so nothing could report which one a node holds")
	}
	if !strings.Contains(string(blob), hashID) {
		t.Errorf("the operator view does not carry the password id: %s", blob)
	}
	// Belt and braces: nothing crypt-shaped anywhere.
	for name, surface := range map[string]string{
		"the job spec and error": specAndError,
		"the step results":       stepText,
		"the job events":         eventText,
		"the process log":        processLog,
		"the operator view":      string(blob),
	} {
		if strings.Contains(surface, "$6$") {
			t.Errorf("%s carries something crypt-shaped:\n%s", name, surface)
		}
	}
}

// waitTerminal polls the ledger until the job reaches a terminal state. The
// bound is a hard deadline that fails naming what never happened, rather
// than an unbounded wait that would hang the suite.
func waitTerminal(t *testing.T, store *jobs.Store, jobID string) *jobs.Job {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		j, err := store.GetJob(context.Background(), jobID)
		if err != nil {
			t.Fatalf("GetJob: %v", err)
		}
		switch j.Status {
		case jobs.StatusSucceeded, jobs.StatusFailed, jobs.StatusCancelled:
			return j
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("job %s never reached a terminal state within 30s", jobID)
	return nil
}
