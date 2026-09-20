package console

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/ledgertest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The console root password's hash must not reach the job ledger.
//
// This is the assertion .github/ledger-secrets.tsv records for
// console.root_push, so it runs the workflow the way production runs it —
// through the real jobs.Runner, over a real bus — and reads back all four
// surfaces the ledger is made of: the persisted spec, every step's result
// and error, every job event, and the process log.
//
// The hash is the secret here, not just the password. It is what an offline
// cracker needs, and every one of these surfaces is readable by anyone who
// can read a job, is copied into backups, and cannot have a value withdrawn
// from it once it has landed.
func TestPushNeverPutsTheHashInTheLedger_RealRunner(t *testing.T) {
	logs := ledgertest.CaptureLog(t)
	ctx := context.Background()

	f := newFleet(t)
	f.add("cp", proto.RoleControlPlane, proto.StatusOnline, "2026.09.4-dev.172")
	f.add("refuser", proto.RoleCompute, proto.StatusOnline, "2026.09.4-dev.172")
	f.agent("cp", applying("cp"))
	// A node that refuses, so the FAILURE surfaces are exercised too: a job
	// error and a failed step's error are ledger surfaces like any other,
	// and an error is exactly where a value tends to get spilled.
	f.agent("refuser", refusing("refuser", "this node's /etc/shadow is on a read-only filesystem"))

	hashID, err := f.store.SetPassword(ctx, goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	hash, _, err := f.store.HashForDispatch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Two different claims, so two different proofs.
	//
	// The HASH is the one that travels: it goes to each agent, so its
	// arrival there is what makes the ledger scan non-vacuous, and
	// Surfaces.AssertPresent/AssertAbsent is exactly that pairing.
	//
	// The PASSWORD travels nowhere at all — it was consumed by SetPassword
	// and never existed again — so there is no surface to prove it reached,
	// and AssertPresent would be a claim that is false by design. Its
	// absence is checked with AssertAbsentIn, and the vacuity question is
	// answered below by deriving the stored hash back from it.
	sentinels := ledgertest.Secrets("the console root password hash", hash)
	passwordOnly := ledgertest.Secrets("the console root password", goodPassword)

	jobStore, err := jobs.OpenStore(ctx, t.TempDir()+"/jobs.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = jobStore.Close() })
	runner := jobs.NewRunner(jobStore, f.nc)
	runner.Register(PushWorkflow(f.store, f.list))

	spec, err := json.Marshal(PushSpec{Reason: "ledger gate"})
	if err != nil {
		t.Fatal(err)
	}
	j, err := runner.Submit(ctx, PushKind, spec, "test")
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
		t.Fatalf("the agents were not sent the stored hash (cp=%d bytes, refuser=%d bytes): the ledger check below would prove nothing",
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

	ledger := &ledgertest.Surfaces{Log: logs.String()}
	ledger.AssertPresent(t, "the console.root_hash command both agents received",
		sawCP+sawRefuser, sentinels)

	stored, err := jobStore.GetJob(ctx, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Spec = string(stored.Spec) + stored.Error

	steps, err := jobStore.ListSteps(ctx, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 4 {
		t.Fatalf("want 4 recorded steps (plan, deliver, record, verify), got %d", len(steps))
	}
	for _, st := range steps {
		ledger.Steps += string(st.Result) + st.Error
	}

	events, err := jobStore.ListEvents(ctx, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Fatal("no job events recorded — the events surface would be checked vacuously")
	}
	for _, ev := range events {
		ledger.Events += string(ev.Data)
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
	ledger.Extra = map[string]string{"the console root password view an operator sees": string(blob)}

	ledger.AssertAbsent(t, sentinels)

	// And the plaintext is in none of them, nor in what the agents were
	// sent — the hash is the only form that ever leaves this package.
	for where, got := range map[string]string{
		"the job spec and error":          ledger.Spec,
		"a step result or error":          ledger.Steps,
		"a job event":                     ledger.Events,
		"the process log":                 ledger.Log,
		"the operator view":               string(blob),
		"the command the agents received": sawCP + sawRefuser,
	} {
		ledgertest.AssertAbsentIn(t, where, got, passwordOnly)
	}

	// The id IS allowed everywhere, and has to be: it is how a step result,
	// an event and the UI name which password a node holds.
	if !strings.Contains(ledger.Steps, hashID) {
		t.Errorf("the step results do not name the password by its id, so nothing could report which one a node holds")
	}
	if !strings.Contains(string(blob), hashID) {
		t.Errorf("the operator view does not carry the password id: %s", blob)
	}
	// Belt and braces: nothing crypt-shaped anywhere.
	for name, surface := range map[string]string{
		"the job spec and error": ledger.Spec,
		"the step results":       ledger.Steps,
		"the job events":         ledger.Events,
		"the process log":        ledger.Log,
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
