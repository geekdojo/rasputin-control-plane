package apps

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
	"github.com/nats-io/nats.go"
)

// geekdojo/geekdojo-brain#783, F-783-19: release_secrets, the last step of
// app.upgrade and app.edit.

// refusedCompose is a compose the secret token scanner refuses, which also
// mentions c.
var refusedCompose = composeNaming("Bad_Name", "c")

// releaseCtx is a release_secrets StepCtx for delAppID, submitted by alice.
func releaseCtx() (*jobs.StepCtx, *stepLog) {
	l := &stepLog{}
	return &jobs.StepCtx{Ctx: context.Background(), JobID: "job-rel", Spec: json.RawMessage(`{"appId":"` + delAppID + `"}`),
		CreatedBy: "alice", Log: l.log}, l
}

func runRelease(store *Store, d DeleteSecretsDeps) (json.RawMessage, *stepLog, error) {
	sc, l := releaseCtx()
	out, err := releaseUnusedSecrets(store, d, composeChangeSpecAppID)(sc)
	return out, l, err
}

func refsOf(t *testing.T, store *Store, appID string) []string {
	t.Helper()
	names, err := store.SecretRefNames(context.Background(), appID)
	if err != nil {
		t.Fatal(err)
	}
	return names
}

// TC-783-37: a ref named only by the previous compose is in use, one named
// by neither is unused, and a compose the scanner refuses names nothing. The
// read writes nothing.
func TestRelease_TC783_37_WhichNamesCountAsInUse(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name, previous string
		want           []string
	}{
		{"previous compose counts", composeNaming("b"), []string{"c", "d"}},
		{"a refused compose names nothing", refusedCompose, []string{"b", "c", "d"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tileschema.ScanSecretTokens(refusedCompose); err == nil {
				t.Fatal("the scanner accepts refusedCompose, so this case proves nothing")
			}
			store, _ := seedOnlineApp(t, "n", delAppID, "immich")
			withSecrets(t, store, delAppID, composeNaming("a"), tc.previous, "a", "b", "c", "d")
			before, _ := store.Get(ctx, delAppID)
			got, err := store.UnusedSecretRefs(ctx, delAppID)
			if err != nil || !slices.Equal(got, tc.want) {
				t.Fatalf("UnusedSecretRefs = %v, %v; want %v", got, err, tc.want)
			}
			if refs := refsOf(t, store, delAppID); !slices.Equal(refs, []string{"a", "b", "c", "d"}) {
				t.Errorf("refs = %v; want unchanged", refs)
			}
			if after, _ := store.Get(ctx, delAppID); after.ComposeYAML != before.ComposeYAML || after.PreviousComposeYAML != before.PreviousComposeYAML {
				t.Error("the row changed")
			}
		})
	}
}

func countRefs(t *testing.T, store *Store) int {
	t.Helper()
	var n int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM app_secret_refs`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TC-783-38: DropUnusedSecretRefs deletes exactly the unused refs, keeps a
// name that came back into use after an earlier read, and is sql.ErrNoRows
// with nothing deleted for a missing row.
func TestRelease_TC783_38_DropIsExact(t *testing.T) {
	ctx := context.Background()
	t.Run("drops the unused", func(t *testing.T) {
		store, _ := seedOnlineApp(t, "n", delAppID, "immich")
		withSecrets(t, store, delAppID, composeNaming("a"), "", "a", "c", "d")
		got, err := store.DropUnusedSecretRefs(ctx, delAppID)
		if err != nil || !slices.Equal(got, []string{"c", "d"}) || !slices.Equal(refsOf(t, store, delAppID), []string{"a"}) {
			t.Fatalf("Drop = %v, %v, refs %v; want [c d] dropped and [a] kept", got, err, refsOf(t, store, delAppID))
		}
	})
	t.Run("a name back in use is kept", func(t *testing.T) {
		store, _ := seedOnlineApp(t, "n", delAppID, "immich")
		withSecrets(t, store, delAppID, composeNaming("a"), "", "a", "c", "d")
		if got, _ := store.UnusedSecretRefs(ctx, delAppID); !slices.Equal(got, []string{"c", "d"}) {
			t.Fatalf("UnusedSecretRefs = %v", got)
		}
		withSecrets(t, store, delAppID, composeNaming("a", "c"), "")
		got, err := store.DropUnusedSecretRefs(ctx, delAppID)
		if err != nil || !slices.Equal(got, []string{"d"}) || !slices.Equal(refsOf(t, store, delAppID), []string{"a", "c"}) {
			t.Fatalf("Drop = %v, %v, refs %v; want [d] dropped, [a c] kept", got, err, refsOf(t, store, delAppID))
		}
	})
	t.Run("no app row", func(t *testing.T) {
		store, _ := seedOnlineApp(t, "n", delAppID, "immich")
		withSecrets(t, store, delAppID, "", "", "c")
		before := countRefs(t, store)
		if _, err := store.DropUnusedSecretRefs(ctx, "01J9ZK3Q0M8X7Y6W5V4T3S2R9Z"); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("err = %v; want sql.ErrNoRows", err)
		}
		if countRefs(t, store) != before {
			t.Error("a ref was deleted")
		}
	})
}

// TC-783-39: with nothing unused the step succeeds with none, never reading
// the store's state, never deleting.
func TestRelease_TC783_39_NothingUnusedMakesNoStoreCall(t *testing.T) {
	store, _ := seedOnlineApp(t, "n", delAppID, "immich")
	withSecrets(t, store, delAppID, composeNaming("a"), composeNaming("b"), "a", "b")
	st, del := &fakeStoreState{state: storestate.Sealed}, &fakeSecretDeleter{}
	out, _, err := runRelease(store, DeleteSecretsDeps{Secrets: del, Store: st, Log: discardLog()})
	if err != nil || string(out) != `{"secrets":"none"}` {
		t.Fatalf("release = %s, %v; want none", out, err)
	}
	if st.stateReads() != 0 || len(del.recorded()) != 0 {
		t.Errorf("state reads = %d, deletes = %d; want none", st.stateReads(), len(del.recorded()))
	}
}

// TC-783-40: the rollback rule over two compose changes. After B (previous
// A names x) x is kept; after C (previous B) x is deleted once, as alice,
// under the job's id, and its ref is gone.
func TestRelease_TC783_40_RollbackRuleOverTwoChanges(t *testing.T) {
	store, _ := seedOnlineApp(t, "n", delAppID, "immich")
	a, b, c := composeNaming("x", "y"), composeNaming("y"), composeNaming("y", "z")
	withSecrets(t, store, delAppID, a, "", "x", "y")
	del := &fakeSecretDeleter{}
	d := DeleteSecretsDeps{Secrets: del, Store: &fakeStoreState{}, Log: discardLog()}

	withSecrets(t, store, delAppID, b, a)
	if out, _, err := runRelease(store, d); err != nil || string(out) != `{"secrets":"none"}` {
		t.Fatalf("after B: %s, %v", out, err)
	}
	if !slices.Equal(refsOf(t, store, delAppID), []string{"x", "y"}) || len(del.recorded()) != 0 {
		t.Fatalf("after B: refs %v, %d deletes; want x kept and no delete", refsOf(t, store, delAppID), len(del.recorded()))
	}

	withSecrets(t, store, delAppID, c, b)
	out, _, err := runRelease(store, d)
	if err != nil || string(out) != `{"names":["x"],"secrets":"released"}` {
		t.Fatalf("after C: %s, %v", out, err)
	}
	calls := del.recorded()
	if len(calls) != 1 || calls[0].ref != mustRef(t, delAppID, "x") || calls[0].actor != secrets.OperatorActor("alice") || calls[0].jobID != "job-rel" {
		t.Errorf("deletes = %+v; want x once, as alice, under job-rel", calls)
	}
	if !slices.Equal(refsOf(t, store, delAppID), []string{"y"}) {
		t.Errorf("refs = %v; want [y]", refsOf(t, store, delAppID))
	}
}

// TC-783-41: a store that cannot take the deletes fails the step with its
// sentence; refs, row and store are untouched.
func TestRelease_TC783_41_StoreNotReadyFailsClosed(t *testing.T) {
	ctx := context.Background()
	readErr := errors.New("monitor: read failed")
	notReady := func(st storestate.State) string {
		return "The new compose is running, but the secret store " + storestate.Clause(st) + ", so the 2 secrets the app no longer uses were not deleted: c, d. They are deleted at the app's next compose change or with the app."
	}
	for _, tc := range []struct {
		name string
		st   *fakeStoreState
		want string
		is   error
	}{
		{"sealed", &fakeStoreState{state: storestate.Sealed}, notReady(storestate.Sealed), nil},
		{"unreachable", &fakeStoreState{state: storestate.Unreachable}, notReady(storestate.Unreachable), nil},
		{"quiesced", &fakeStoreState{state: storestate.Quiesced}, notReady(storestate.Quiesced), nil},
		{"state read fails", &fakeStoreState{err: readErr}, notReady("") + " Reading its state failed: " + readErr.Error(), readErr},
		{"not configured", &fakeStoreState{unconfigured: true}, "The new compose is running, but no secret store is configured, so the 2 stored secrets the app no longer uses were not deleted: c, d.", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, _ := seedOnlineApp(t, "n", delAppID, "immich")
			withSecrets(t, store, delAppID, composeNaming("a"), "", "a", "c", "d")
			before, _ := store.Get(ctx, delAppID)
			del := &fakeSecretDeleter{}
			_, _, err := runRelease(store, DeleteSecretsDeps{Secrets: del, Store: tc.st, Log: discardLog()})
			if err == nil || err.Error() != tc.want {
				t.Fatalf("err = %v; want %q", err, tc.want)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Errorf("err does not wrap its cause")
			}
			if !slices.Equal(refsOf(t, store, delAppID), []string{"a", "c", "d"}) || len(del.recorded()) != 0 {
				t.Errorf("refs = %v, deletes = %d; want unchanged and none", refsOf(t, store, delAppID), len(del.recorded()))
			}
			after, _ := store.Get(ctx, delAppID)
			if after.ComposeYAML != before.ComposeYAML || after.LastStatus != before.LastStatus || after.LastDetail != before.LastDetail {
				t.Errorf("row changed: %+v", after)
			}
		})
	}
}

// TC-783-42: a delete that fails in the middle of three leaves the others
// deleted, puts its ref back, writes one ERROR record with names only, and
// fails the step with the retry sentence.
func TestRelease_TC783_42_DeleteFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"sealed", secretstore.ErrSealed},
		{"forbidden", secrets.ErrForbidden},
		{"unexpected", errors.New("store: 500 internal")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, _ := seedOnlineApp(t, "n", delAppID, "immich")
			withSecrets(t, store, delAppID, composeNaming("a"), "", "a", "c", "d", "e")
			log, rec := logkittest.New()
			del := &fakeSecretDeleter{fail: map[string]error{"d": tc.err}}
			_, l, err := runRelease(store, DeleteSecretsDeps{Secrets: del, Store: &fakeStoreState{}, Log: log})
			const want = "The new compose is running, but 1 secret the app no longer uses could not be deleted from the secret store: d. They are deleted at the app's next compose change or with the app."
			if err == nil || err.Error() != want {
				t.Fatalf("err = %v; want %q", err, want)
			}
			if !strings.Contains(l.text(), "error: "+want) {
				t.Errorf("job log = %q; want the sentence", l.text())
			}
			if len(del.recorded()) != 3 {
				t.Errorf("deletes = %d; want 3", len(del.recorded()))
			}
			if !slices.Equal(refsOf(t, store, delAppID), []string{"a", "d"}) {
				t.Errorf("refs = %v; want [a d]: c and e gone, d put back", refsOf(t, store, delAppID))
			}
			recs := rec.AtLevel(slog.LevelError)
			if len(recs) != 1 {
				t.Fatalf("%d ERROR records; want 1", len(recs))
			}
			for k, v := range map[string]string{"component": "apps", "event": "apps.secrets_release_failed", "app_id": delAppID,
				"job_id": "job-rel", "user": "alice", "failed": "[d]", "unrecorded": "[]", "err": "d: " + tc.err.Error()} {
				if got, _ := logkittest.Attr(recs[0], k); got != v {
					t.Errorf("%s = %q; want %q", k, got, v)
				}
			}
		})
	}
}

// TC-783-43 (F-783-21): the put-back survives a cancelled step context, and a
// put-back that fails is named unrecorded and drops the retry clause.
func TestRelease_TC783_43_PutBack(t *testing.T) {
	t.Run("step context cancelled", func(t *testing.T) {
		store, _ := seedOnlineApp(t, "n", delAppID, "immich")
		withSecrets(t, store, delAppID, composeNaming("a"), "", "a", "d")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		del := &fakeSecretDeleter{fail: map[string]error{"d": context.Canceled}, onDelete: func(secrets.Ref) { cancel() }}
		sc, _ := releaseCtx()
		sc.Ctx = ctx
		if _, err := releaseUnusedSecrets(store, DeleteSecretsDeps{Secrets: del, Store: &fakeStoreState{}, Log: discardLog()}, composeChangeSpecAppID)(sc); err == nil {
			t.Fatal("the step succeeded")
		}
		if !slices.Equal(refsOf(t, store, delAppID), []string{"a", "d"}) {
			t.Errorf("refs = %v; want d put back", refsOf(t, store, delAppID))
		}
	})
	t.Run("put-back write fails", func(t *testing.T) {
		store, _ := seedOnlineApp(t, "n", delAppID, "immich")
		withSecrets(t, store, delAppID, composeNaming("a"), "", "a", "d")
		if _, err := store.db.Exec(`CREATE TRIGGER refuse_d BEFORE INSERT ON app_secret_refs WHEN NEW.name = 'd' BEGIN SELECT RAISE(FAIL, 'refused'); END`); err != nil {
			t.Fatal(err)
		}
		log, rec := logkittest.New()
		del := &fakeSecretDeleter{fail: map[string]error{"d": secretstore.ErrSealed}}
		_, _, err := runRelease(store, DeleteSecretsDeps{Secrets: del, Store: &fakeStoreState{}, Log: log})
		const want = "The new compose is running, but 1 secret the app no longer uses could not be deleted from the secret store: d."
		if err == nil || err.Error() != want {
			t.Fatalf("err = %v; want %q", err, want)
		}
		recs := rec.AtLevel(slog.LevelError)
		if len(recs) != 1 {
			t.Fatalf("%d ERROR records; want 1", len(recs))
		}
		if got, _ := logkittest.Attr(recs[0], "unrecorded"); got != "[d]" {
			t.Errorf("unrecorded = %q; want [d]", got)
		}
	})
}

// TC-783-44: app.upgrade and app.edit end in release_secrets after
// drop_volumes, never retried; deploy and revert have none; a nil
// DeleteSecretsDeps field is refused by name.
func TestRelease_TC783_44_WorkflowWiring(t *testing.T) {
	ctors := map[string]func(DeleteSecretsDeps) (jobs.Workflow, error){
		"UpgradeWorkflow": func(d DeleteSecretsDeps) (jobs.Workflow, error) {
			return UpgradeWorkflow(nil, nil, nil, nil, nil, testSource(t), d)
		},
		"EditWorkflow": func(d DeleteSecretsDeps) (jobs.Workflow, error) {
			return EditWorkflow(nil, nil, nil, nil, NewComposeStash(), testSource(t), d)
		},
	}
	for name, ctor := range ctors {
		t.Run(name, func(t *testing.T) {
			w := wf(t)(ctor(testSecretDeps()))
			n := len(w.Steps)
			if n < 2 || w.Steps[n-1].Name != "release_secrets" || w.Steps[n-2].Name != "drop_volumes" || w.Steps[n-1].Retries != 0 {
				t.Errorf("last steps = %+v; want drop_volumes then release_secrets, no retries", w.Steps[n-2:])
			}
			ok := testSecretDeps()
			for field, d := range map[string]DeleteSecretsDeps{
				"Secrets": {Store: ok.Store, Log: ok.Log},
				"Store":   {Secrets: ok.Secrets, Log: ok.Log},
				"Log":     {Secrets: ok.Secrets, Store: ok.Store},
			} {
				w, err := ctor(d)
				if err == nil || err.Error() != "apps: "+name+": DeleteSecretsDeps."+field+" is nil" || len(w.Steps) != 0 {
					t.Errorf("nil %s: %v, %d steps; want a refusal naming %s and the zero Workflow", field, err, len(w.Steps), name)
				}
			}
		})
	}
	for name, w := range map[string]jobs.Workflow{
		"deploy": wf(t)(DeployWorkflow(nil, nil, nil, nil, testSource(t))),
		"revert": wf(t)(RevertWorkflow(nil, nil, nil, nil, testSource(t))),
	} {
		for _, s := range w.Steps {
			if s.Name == "release_secrets" {
				t.Errorf("%s has a release_secrets step", name)
			}
		}
	}
}

// switchableDeployAgent answers docker.deploy on node n, OK or not as ok
// says when the command arrives.
func switchableDeployAgent(t *testing.T, nc *nats.Conn, ok *atomic.Bool) {
	t.Helper()
	for _, subject := range []string{proto.AppDeploySubject("n"), proto.AppDeploySecretsSubject("n")} {
		sub, err := nc.Subscribe(subject, func(m *nats.Msg) {
			ack := proto.AppDeployAck{OK: ok.Load(), Status: proto.AppStatusRunning}
			if !ack.OK {
				ack.Status, ack.Detail = proto.AppStatusFailed, "compose up failed"
			}
			b, _ := json.Marshal(ack)
			_ = m.Respond(b)
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = sub.Unsubscribe() })
	}
}

// TC-783-45: an edit that drops x and fails at push never releases; the ref
// stays, and the next successful edit deletes x.
func TestRelease_TC783_45_FailedJobLeavesTheRefForTheRetry(t *testing.T) {
	ctx := context.Background()
	const id = "01J9ZK3Q0M8X7Y6W5V4T3S2R1P"
	nc := startNATS(t)
	a := composeNaming("x")
	store, inv := seedComposeApp(t, id, a)
	b := "services:\n  web:\n    image: me/web:2\n"
	if err := store.EditCompose(ctx, id, ComposeHash(a), b, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordSecretRef(ctx, id, "x"); err != nil {
		t.Fatal(err)
	}
	fakePullAgent(t, nc, proto.AppPullAck{OK: true}, nil)
	var ok atomic.Bool
	switchableDeployAgent(t, nc, &ok)
	del := &fakeSecretDeleter{}
	stash := NewComposeStash()
	w := wf(t)(EditWorkflow(store, inv, nc, nil, stash, testSource(t), DeleteSecretsDeps{Secrets: del, Store: &fakeStoreState{}, Log: discardLog()}))

	if err := stash.Put("job-c", "services:\n  web:\n    image: me/web:3\n"); err != nil {
		t.Fatal(err)
	}
	run := runWorkflow(t, w, nc, `{"appId":"`+id+`"}`, "job-c")
	if run.failedAt != "push" {
		t.Fatalf("failed at %q (%v); want push", run.failedAt, run.err)
	}
	if _, ran := run.results["release_secrets"]; ran || len(del.recorded()) != 0 || !slices.Equal(refsOf(t, store, id), []string{"x"}) {
		t.Fatalf("after the failed edit: release ran=%v, deletes %d, refs %v; want no release and x kept", ran, len(del.recorded()), refsOf(t, store, id))
	}

	ok.Store(true)
	if err := stash.Put("job-d", "services:\n  web:\n    image: me/web:4\n"); err != nil {
		t.Fatal(err)
	}
	run = runWorkflow(t, w, nc, `{"appId":"`+id+`"}`, "job-d")
	if run.err != nil {
		t.Fatalf("step %s: %v", run.failedAt, run.err)
	}
	if calls := del.recorded(); len(calls) != 1 || calls[0].ref != mustRef(t, id, "x") || calls[0].jobID != "job-d" {
		t.Errorf("deletes = %+v; want x under job-d", calls)
	}
	if refs := refsOf(t, store, id); len(refs) != 0 {
		t.Errorf("refs = %v; want none", refs)
	}
}

// TC-783-46: refs piled up before this release (neither compose names them,
// one already absent from the store) are all released at the first edit.
func TestRelease_TC783_46_UpgradeFromThePreviousRelease(t *testing.T) {
	store, _ := seedOnlineApp(t, "n", delAppID, "immich")
	withSecrets(t, store, delAppID, composeNaming("a"), composeNaming("a"), "a", "old1", "old2")
	// The fake answers nil for old2, as secrets.Service.Delete does for an
	// entry already absent.
	del := &fakeSecretDeleter{}
	out, _, err := runRelease(store, DeleteSecretsDeps{Secrets: del, Store: &fakeStoreState{}, Log: discardLog()})
	if err != nil || string(out) != `{"names":["old1","old2"],"secrets":"released"}` {
		t.Fatalf("release = %s, %v", out, err)
	}
	if len(del.recorded()) != 2 || !slices.Equal(refsOf(t, store, delAppID), []string{"a"}) {
		t.Errorf("deletes = %d, refs = %v; want 2 and [a]", len(del.recorded()), refsOf(t, store, delAppID))
	}
}

// rowDeletingState reads Ready after deleting the app's row, as an app
// delete racing the release would.
type rowDeletingState struct {
	fakeStoreState
	store *Store
}

func (s *rowDeletingState) State(ctx context.Context) (storestate.State, error) {
	_, _ = s.store.db.ExecContext(ctx, `DELETE FROM apps WHERE id = ?`, delAppID)
	return s.fakeStoreState.State(ctx)
}

// TC-783-47 (F-783-26): an app deleted during the release leaves its secrets
// to its delete: no store call, and the step succeeds saying so.
func TestRelease_TC783_47_AppDeletedDuringTheRelease(t *testing.T) {
	t.Run("before the step", func(t *testing.T) {
		store, _ := seedOnlineApp(t, "n", delAppID, "immich")
		withSecrets(t, store, delAppID, composeNaming("a"), "", "a", "c")
		if err := store.Delete(context.Background(), delAppID); err != nil {
			t.Fatal(err)
		}
		st, del := &fakeStoreState{}, &fakeSecretDeleter{}
		out, _, err := runRelease(store, DeleteSecretsDeps{Secrets: del, Store: st, Log: discardLog()})
		if err != nil || string(out) != `{"secrets":"app-removed"}` || st.stateReads() != 0 || len(del.recorded()) != 0 {
			t.Errorf("release = %s, %v, %d reads, %d deletes; want app-removed and no store call", out, err, st.stateReads(), len(del.recorded()))
		}
	})
	t.Run("before the drop", func(t *testing.T) {
		store, _ := seedOnlineApp(t, "n", delAppID, "immich")
		withSecrets(t, store, delAppID, composeNaming("a"), "", "a", "c")
		del := &fakeSecretDeleter{}
		out, _, err := runRelease(store, DeleteSecretsDeps{Secrets: del, Store: &rowDeletingState{store: store}, Log: discardLog()})
		if err != nil || string(out) != `{"secrets":"app-removed"}` || len(del.recorded()) != 0 {
			t.Errorf("release = %s, %v, %d deletes; want app-removed and no delete", out, err, len(del.recorded()))
		}
	})
}

// TC-783-62 (F-783-29): an operator secret either manifest declares is in
// use whether or not a compose places it; one in neither manifest nor
// compose is released.
func TestRelease_TC783_62_OperatorSecretDeclarationsAreInUse(t *testing.T) {
	ctx := context.Background()
	store, _ := seedOnlineApp(t, "n", delAppID, "immich")
	decl := func(names ...string) []tileschema.OperatorSecret {
		var out []tileschema.OperatorSecret
		for _, n := range names {
			out = append(out, tileschema.OperatorSecret{Name: n, Label: n})
		}
		return out
	}
	upgrade := func(compose string, decls []tileschema.OperatorSecret) {
		t.Helper()
		row, err := store.Get(ctx, delAppID)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.UpgradeCompose(ctx, delAppID, row.ComposeSHA256, ComposeUpgrade{ComposeYAML: compose, OperatorSecrets: decls}, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	// Two versions back: all three declared.
	upgrade(composeNaming("ais-key"), decl("ais-key", "opt-key", "old-key"))
	for _, n := range []string{"ais-key", "opt-key", "old-key"} {
		if err := store.RecordSecretRef(ctx, delAppID, n); err != nil {
			t.Fatal(err)
		}
	}
	del := &fakeSecretDeleter{}
	// The compose places only ais-key from here on.
	upgrade("services:\n  web:\n    image: me/web:2\n    environment:\n      K: ${secret:ais-key}\n", decl("ais-key", "opt-key"))
	// old-key is still in the previous manifest: nothing is released.
	if out, _, err := runRelease(store, DeleteSecretsDeps{Secrets: del, Store: &fakeStoreState{}, Log: discardLog()}); err != nil || string(out) != `{"secrets":"none"}` {
		t.Fatalf("release with old-key in the previous manifest = %s, %v; want none", out, err)
	}
	// Current and previous manifests both declare ais-key and opt-key only.
	upgrade("services:\n  web:\n    image: me/web:3\n    environment:\n      K: ${secret:ais-key}\n", decl("ais-key", "opt-key"))
	out, _, err := runRelease(store, DeleteSecretsDeps{Secrets: del, Store: &fakeStoreState{}, Log: discardLog()})
	if err != nil || string(out) != `{"names":["old-key"],"secrets":"released"}` {
		t.Fatalf("release = %s, %v; want old-key released", out, err)
	}
	if calls := del.recorded(); len(calls) != 1 || calls[0].ref != mustRef(t, delAppID, "old-key") {
		t.Errorf("deletes = %+v; want old-key only", calls)
	}
	if refs := refsOf(t, store, delAppID); !slices.Equal(refs, []string{"ais-key", "opt-key"}) {
		t.Errorf("refs = %v; want ais-key and opt-key kept", refs)
	}
}
