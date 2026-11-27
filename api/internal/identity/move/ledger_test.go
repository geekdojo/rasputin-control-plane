package move

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/breakglass"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

type noApps struct{}

func (noApps) AppFacts(context.Context, string, string) (authz.AppFacts, error) {
	return authz.AppFacts{}, authz.ErrNoApp
}

// ledgerRig is the move on a real job store and runner, decided by the
// kind table over the move's state.
type ledgerRig struct {
	*world
	ledger *jobs.Store
	runner *jobs.Runner
}

func newLedgerRig(t *testing.T) *ledgerRig {
	t.Helper()
	w := newWorld(t)
	ledger, err := jobs.OpenStore(t.Context(), w.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	srv := natsserver.RunRandClientPortServer()
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	kp, err := authz.NewKindPolicy(noApps{}, authz.WithMoveState(w.state(t)))
	if err != nil {
		t.Fatal(err)
	}
	runner, err := jobs.NewAuthorizedRunner(ledger, nc, kp)
	if err != nil {
		t.Fatal(err)
	}
	runner.Register(w.mover.Workflow())
	return &ledgerRig{world: w, ledger: ledger, runner: runner}
}

func (r *ledgerRig) moves(t *testing.T) []*jobs.Job {
	t.Helper()
	js, err := r.ledger.ListJobsByKind(t.Context(), Kind, 100)
	if err != nil {
		t.Fatal(err)
	}
	return js
}

// TC-1004-21: #1010's fact. Over a real job store holding a succeeded
// system move, a failed repair move and a succeeded repair move, only the
// succeeded repair job has spec repair: true, status succeeded and
// CreatedBy break-glass; the system run has repair false and the
// scheduler's CreatedBy.
//
// TC-1004-17 (runner leg): a refused repair submission creates no job row.
func TestLedger_TC1004_21(t *testing.T) {
	ctx := t.Context()
	r := newLedgerRig(t)
	r.addOld(t, 1, "alice", 1)
	if _, err := r.runner.SubmitRawSpec(ctx, Kind, json.RawMessage(`{}`), "scheduler"); err != nil {
		t.Fatal(err)
	}
	r.runner.Wait()
	r.realm = map[string]accounts.Account{} // C9
	repair := breakglass.Session{}.Submitter()

	// Refused: a stale token, and a realm that holds a person.
	n := len(r.moves(t))
	_, err := r.runner.SubmitFor(ctx, repair, Kind, Spec{Repair: true, StateToken: "stale"}, nil)
	var kr *authz.KindRefusal
	if !errors.As(err, &kr) || kr.Code != authz.CodeStateChanged {
		t.Errorf("stale token: %v, want state_changed", err)
	}
	tok, _, err := r.state(t).RepairToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r.realm["p"] = accounts.Account{ID: "p", Username: "door"}
	if _, err := r.runner.SubmitFor(ctx, repair, Kind, Spec{Repair: true, StateToken: tok}, nil); !errors.As(err, &kr) || kr.Code != authz.CodeMoveState {
		t.Errorf("a person in the realm: %v, want move_state", err)
	}
	delete(r.realm, "p")
	if got := len(r.moves(t)); got != n {
		t.Errorf("refusals left %d job rows, want %d", got, n)
	}

	r.fail["import"] = errDown
	if _, err := r.runner.SubmitFor(ctx, repair, Kind, Spec{Repair: true, StateToken: tok}, nil); err != nil {
		t.Fatal(err)
	}
	r.runner.Wait()
	delete(r.fail, "import")
	if _, err := r.runner.SubmitFor(ctx, repair, Kind, Spec{Repair: true, StateToken: tok}, nil); err != nil {
		t.Fatal(err)
	}
	r.runner.Wait()

	js := r.moves(t)
	if len(js) != 3 {
		t.Fatalf("%d move jobs, want 3", len(js))
	}
	matching := 0
	for _, j := range js {
		var s Spec
		if err := json.Unmarshal(j.Spec, &s); err != nil {
			t.Fatal(err)
		}
		if s.Repair && j.Status == jobs.StatusSucceeded && j.CreatedBy == "break-glass" {
			matching++
		}
		if !s.Repair && (j.CreatedBy != "scheduler" || j.Status != jobs.StatusSucceeded) {
			t.Errorf("the system run: %s by %q", j.Status, j.CreatedBy)
		}
		if s.Repair && j.CreatedBy != "break-glass" {
			t.Errorf("a repair run by %q", j.CreatedBy)
		}
	}
	if matching != 1 {
		t.Errorf("%d jobs read as a succeeded repair run, want exactly 1", matching)
	}
}
