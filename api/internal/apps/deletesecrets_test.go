package apps

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/nats-io/nats.go"
)

// fakeStoreState is SecretStoreState with a fixed answer. The zero value is a
// configured store reading Ready.
type fakeStoreState struct {
	unconfigured bool
	state        storestate.State
	err          error
	mu           sync.Mutex
	reads        int
}

func (f *fakeStoreState) Configured() bool { return !f.unconfigured }

func (f *fakeStoreState) State(context.Context) (storestate.State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.state == "" && f.err == nil {
		return storestate.Ready, nil
	}
	return f.state, f.err
}

func (f *fakeStoreState) stateReads() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads
}

// deleteCall is one call the fake deleter received.
type deleteCall struct {
	jobID string
	actor secrets.Actor
	ref   secrets.Ref
}

// fakeSecretDeleter records every Delete and fails the names in fail.
type fakeSecretDeleter struct {
	mu    sync.Mutex
	calls []deleteCall
	fail  map[string]error
}

func (f *fakeSecretDeleter) Delete(ctx context.Context, a secrets.Actor, r secrets.Ref) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, deleteCall{jobID: jobs.JobIDFromContext(ctx), actor: a, ref: r})
	for name, err := range f.fail {
		if ref, _ := secrets.AppSecret(delAppID, name); ref == r {
			return err
		}
	}
	return nil
}

func (f *fakeSecretDeleter) recorded() []deleteCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// stepLog collects a StepCtx's job log lines.
type stepLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *stepLog) log(level, msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, level+": "+msg)
}

func (l *stepLog) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// destroyCtx is a destroy_secrets StepCtx for spec whose remove step named
// names, submitted by createdBy.
func destroyCtx(t *testing.T, spec string, createdBy string, names ...string) (*jobs.StepCtx, *stepLog) {
	t.Helper()
	if names == nil {
		names = []string{}
	}
	raw, err := json.Marshal(removeResult{AppID: delAppID, Deleted: "true", SecretNames: names})
	if err != nil {
		t.Fatal(err)
	}
	l := &stepLog{}
	return &jobs.StepCtx{
		Ctx: context.Background(), JobID: "job-783", Spec: json.RawMessage(spec), CreatedBy: createdBy,
		PriorResults: map[string]json.RawMessage{"remove": raw}, Log: l.log,
	}, l
}

func mustRef(t *testing.T, appID, name string) secrets.Ref {
	t.Helper()
	r, err := secrets.AppSecret(appID, name)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// withSecrets sets the app's composes and records refs for it.
func withSecrets(t *testing.T, store *Store, appID, compose, previous string, refs ...string) {
	t.Helper()
	ctx := context.Background()
	if _, err := store.db.ExecContext(ctx, `UPDATE apps SET compose_yaml = ?, previous_compose_yaml = ? WHERE id = ?`, compose, previous, appID); err != nil {
		t.Fatal(err)
	}
	for _, r := range refs {
		if err := store.RecordSecretRef(ctx, appID, r); err != nil {
			t.Fatal(err)
		}
	}
}

func composeNaming(names ...string) string {
	var b strings.Builder
	b.WriteString("services:\n  web:\n    image: me/web:1\n    environment:\n")
	for i, n := range names {
		fmt.Fprintf(&b, "      V%d: ${secret:%s}\n", i, n)
	}
	return b.String()
}

// TC-783-06: a keep-volumes delete sends exactly one stop, with
// deleteVolumes false and removeCompose true.
func TestDelete_TC783_06_KeepVolumesStopRemovesCompose(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", delAppID, "immich")
	agent := fakeDeleteAgent(t, nc, "n")
	if _, err := deleteStop(store, inv, nc, &fakeStoreState{})(newStepCtxNATS(`{"appId":"`+delAppID+`"}`, nc)); err != nil {
		t.Fatalf("deleteStop: %v", err)
	}
	if got := agent.stops(); len(got) != 1 || got[0] {
		t.Fatalf("stops (deleteVolumes) = %v; want one, false", got)
	}
	if got := agent.removeComposes(); len(got) != 1 || !got[0] {
		t.Fatalf("stops (removeCompose) = %v; want one, true", got)
	}
}

// TC-783-07 (a): neither stop of a delete with volumes asks for the compose's
// removal; the agent removes the whole state directory there. (b) is in
// TestDelete_FlagNeverLeaksIntoOtherKinds.
func TestDelete_TC783_07_DeleteWithVolumesNeverSendsRemoveCompose(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", delAppID, "immich")
	agent := fakeDeleteAgent(t, nc, "n", delVolData)
	if _, err := deleteStop(store, inv, nc, &fakeStoreState{})(newStepCtxNATS(deleteSpecJSON(delVolData.Name), nc)); err != nil {
		t.Fatalf("deleteStop: %v", err)
	}
	if got := agent.removeComposes(); len(got) != 2 || got[0] || got[1] {
		t.Fatalf("stops (removeCompose) = %v; want two, both false", got)
	}
}

// TC-783-08: an agent that stopped the app but could not remove its compose
// fails a keep-volumes delete closed: the stop step fails with the detail, the
// row stays, failed, with that detail, and remove and destroy_secrets never run.
func TestDelete_TC783_08_ComposeRemovalFailureFailsClosed(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", delAppID, "immich")
	const detail = "Stopped, but the app's compose file could not be removed: permission denied."
	sub, err := nc.Subscribe(proto.AppStopSubject("n"), func(m *nats.Msg) {
		b, _ := json.Marshal(proto.AppStopAck{OK: false, Status: proto.AppStatusStopped, Detail: detail})
		_ = m.Respond(b)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	del := &fakeSecretDeleter{}
	w, err := DeleteWorkflow(store, inv, nc, nil, DeleteSecretsDeps{Secrets: del, Store: &fakeStoreState{}, Log: discardLog()})
	if err != nil {
		t.Fatal(err)
	}
	r, jst := realRunner(t, nc, w)
	j, err := r.Submit(ctx, "app.delete", DeleteSpec{AppID: delAppID}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	r.Wait()
	got, err := jst.GetJob(ctx, j.ID)
	if err != nil || got.Status != jobs.StatusFailed {
		t.Fatalf("job = %+v %v; want failed", got, err)
	}
	steps, err := jst.ListSteps(ctx, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range steps {
		switch st.Name {
		case "stop":
			if st.Status != jobs.StepFailed || st.Error != detail {
				t.Errorf("stop step = %s %q; want failed with the agent's detail", st.Status, st.Error)
			}
		case "remove", "destroy_secrets":
			t.Errorf("step %s ran after the stop failed", st.Name)
		}
	}
	row, err := store.Get(ctx, delAppID)
	if err != nil || row == nil {
		t.Fatalf("the row must stay: %v", err)
	}
	if row.LastStatus != proto.AppStatusFailed || row.LastDetail != detail {
		t.Errorf("row = %s %q; want failed with the detail", row.LastStatus, row.LastDetail)
	}
	if len(del.recorded()) != 0 {
		t.Error("a secret was deleted although the app was not removed")
	}
}

// TC-783-09: the row delete returns the union of the recorded refs and the
// compose's tokens, removes the row and its refs in one transaction, and the
// remove step's result lists those names; a missing row is ErrNoRows and
// "already removed" with an empty list.
func TestDelete_TC783_09_RowDeleteReturnsTheNames(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, _ := seedOnlineApp(t, "n", delAppID, "immich")
	withSecrets(t, store, delAppID, composeNaming("db-password", "api-key"), "", "db-password", "admin-token")

	out, err := deleteRemove(store, nc)(newStepCtxNATS(`{"appId":"`+delAppID+`"}`, nc))
	if err != nil {
		t.Fatalf("deleteRemove: %v", err)
	}
	var res removeResult
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatal(err)
	}
	if want := []string{"admin-token", "api-key", "db-password"}; !slices.Equal(res.SecretNames, want) || res.Deleted != "true" {
		t.Errorf("remove result = %+v; want names %v", res, want)
	}
	var apps, refs int
	_ = store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM apps WHERE id = ?`, delAppID).Scan(&apps)
	_ = store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM app_secret_refs WHERE app_id = ?`, delAppID).Scan(&refs)
	if apps != 0 || refs != 0 {
		t.Errorf("after delete: %d app rows, %d refs; want 0, 0", apps, refs)
	}

	if _, err := store.DeleteWithSecretNames(ctx, delAppID); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("DeleteWithSecretNames on a missing row = %v; want sql.ErrNoRows", err)
	}
	out, err = deleteRemove(store, nc)(newStepCtxNATS(`{"appId":"`+delAppID+`"}`, nc))
	if err != nil {
		t.Fatalf("deleteRemove again: %v", err)
	}
	if string(out) != `{"appId":"`+delAppID+`","deleted":"already-removed","secretNames":[]}` {
		t.Errorf("remove result on a missing row = %s", out)
	}
}

// A compose the scanner refuses rolls the row delete back.
func TestDeleteWithSecretNames_ScanErrorKeepsTheRow(t *testing.T) {
	ctx := context.Background()
	store, _ := seedOnlineApp(t, "n", delAppID, "immich")
	withSecrets(t, store, delAppID, "x: ${secret:Bad_Name}\n", "", "db-password")
	if _, err := store.DeleteWithSecretNames(ctx, delAppID); err == nil {
		t.Fatal("DeleteWithSecretNames accepted a compose the scanner refuses")
	}
	if row, _ := store.Get(ctx, delAppID); row == nil {
		t.Error("the row went although the names could not be read")
	}
	if names, _ := store.SecretRefNames(ctx, delAppID); !slices.Equal(names, []string{"db-password"}) {
		t.Errorf("refs = %v; want them kept", names)
	}
}

const withVolumesSpec = `{"appId":"` + delAppID + `","deleteVolumes":["rasp_` + delAppID + `_data"]}`

// TC-783-10: with the volumes deleted, every name is deleted with
// OperatorActor(createdBy) and the job's id in the context, and the job log
// says how many went, every version.
func TestDestroySecrets_TC783_10_DeletesEachNameAsTheOperator(t *testing.T) {
	del := &fakeSecretDeleter{}
	sc, l := destroyCtx(t, withVolumesSpec, "alice", "a", "b", "c")
	out, err := deleteDestroySecrets(DeleteSecretsDeps{Secrets: del, Store: &fakeStoreState{}, Log: discardLog()})(sc)
	if err != nil {
		t.Fatalf("destroy_secrets: %v", err)
	}
	calls := del.recorded()
	if len(calls) != 3 {
		t.Fatalf("deleter calls = %d; want 3", len(calls))
	}
	for i, name := range []string{"a", "b", "c"} {
		c := calls[i]
		if c.ref != mustRef(t, delAppID, name) || c.actor != secrets.OperatorActor("alice") || c.jobID != "job-783" {
			t.Errorf("call %d = %+v; want ref %s, operator alice, job job-783", i, c, name)
		}
	}
	if !strings.Contains(l.text(), "deleted the app's 3 secrets from the secret store, every version") {
		t.Errorf("job log = %q", l.text())
	}
	if string(out) != `{"count":3,"secrets":"deleted"}` {
		t.Errorf("result = %s", out)
	}
}

// TC-783-11: an app last deployed on v2026.10.2 has entries but no ref rows;
// the names in its compose and previous compose are deleted.
func TestDestroySecrets_TC783_11_UnrecordedEntriesAreDeleted(t *testing.T) {
	nc := startNATS(t)
	store, _ := seedOnlineApp(t, "n", delAppID, "immich")
	withSecrets(t, store, delAppID, composeNaming("a"), composeNaming("b"))
	out, err := deleteRemove(store, nc)(newStepCtxNATS(withVolumesSpec, nc))
	if err != nil {
		t.Fatalf("deleteRemove: %v", err)
	}
	del := &fakeSecretDeleter{}
	sc, _ := destroyCtx(t, withVolumesSpec, "alice")
	sc.PriorResults["remove"] = out
	if _, err := deleteDestroySecrets(DeleteSecretsDeps{Secrets: del, Store: &fakeStoreState{}, Log: discardLog()})(sc); err != nil {
		t.Fatalf("destroy_secrets: %v", err)
	}
	var got []secrets.Ref
	for _, c := range del.recorded() {
		got = append(got, c.ref)
	}
	if want := []secrets.Ref{mustRef(t, delAppID, "a"), mustRef(t, delAppID, "b")}; !slices.Equal(got, want) {
		t.Errorf("deleted = %v; want %v", got, want)
	}
}

// TC-783-12: a store failure on the middle of three names, one table row per
// outcome. The other two are still tried, the step fails naming the entry
// left, one ERROR record carries the fields and no value, and the job log
// names it.
func TestDestroySecrets_TC783_12_StoreFailuresFailTheJob(t *testing.T) {
	for name, storeErr := range map[string]error{
		"sealed":      fmt.Errorf("secrets: delete: %w", secretstore.ErrSealed),
		"unreachable": fmt.Errorf("secrets: delete: %w", secretstore.ErrUnreachable),
		"forbidden":   fmt.Errorf("%w: delete refused", secrets.ErrForbidden),
		"unexpected":  errors.New("something else went wrong"),
	} {
		t.Run(name, func(t *testing.T) {
			log, rec := logkittest.New()
			del := &fakeSecretDeleter{fail: map[string]error{"b": storeErr}}
			sc, l := destroyCtx(t, withVolumesSpec, "alice", "a", "b", "c")
			_, err := deleteDestroySecrets(DeleteSecretsDeps{Secrets: del, Store: &fakeStoreState{}, Log: log})(sc)
			want := "The app was removed, but 1 of its secrets could not be deleted from the secret store and are still in it: b."
			if err == nil || err.Error() != want {
				t.Fatalf("err = %v; want %q", err, want)
			}
			if got := len(del.recorded()); got != 3 {
				t.Errorf("deleter calls = %d; want all 3 tried", got)
			}
			errs := rec.AtLevel(slog.LevelError)
			if len(errs) != 1 {
				t.Fatalf("ERROR records = %d; want 1", len(errs))
			}
			for key, want := range map[string]string{
				"component": "apps", "event": "apps.secrets_destroy_failed", "app_id": delAppID,
				"job_id": "job-783", "user": "alice", "failed": "[b]",
			} {
				if v, _ := logkittest.Attr(errs[0], key); v != want {
					t.Errorf("%s = %q; want %q", key, v, want)
				}
			}
			if v, _ := logkittest.Attr(errs[0], "err"); !strings.Contains(v, storeErr.Error()) {
				t.Errorf("err = %q; want the store's text", v)
			}
			if !strings.Contains(l.text(), "error: "+want) {
				t.Errorf("job log = %q", l.text())
			}
			// The path holds names and store errors only; the record carries
			// exactly the listed fields, so there is no field a value could
			// ride in.
			var keys []string
			errs[0].Attrs(func(a slog.Attr) bool { keys = append(keys, a.Key); return true })
			slices.Sort(keys)
			if want := []string{"app_id", "component", "err", "event", "failed", "job_id", "user"}; !slices.Equal(keys, want) {
				t.Errorf("ERROR record fields = %v; want %v", keys, want)
			}
		})
	}
}

// TC-783-13: a keep-volumes delete destroys the entries (F-783-05 ruling):
// each name is deleted with OperatorActor(createdBy) and the job's id in the
// context, exactly as TC-783-10, and nothing says the secrets are kept.
func TestDestroySecrets_TC783_13_KeepVolumesDestroysTheEntries(t *testing.T) {
	del := &fakeSecretDeleter{}
	sc, l := destroyCtx(t, `{"appId":"`+delAppID+`"}`, "alice", "a", "b")
	out, err := deleteDestroySecrets(DeleteSecretsDeps{Secrets: del, Store: &fakeStoreState{}, Log: discardLog()})(sc)
	if err != nil {
		t.Fatalf("destroy_secrets: %v", err)
	}
	calls := del.recorded()
	if len(calls) != 2 {
		t.Fatalf("deleter calls = %d; want 2", len(calls))
	}
	for i, name := range []string{"a", "b"} {
		c := calls[i]
		if c.ref != mustRef(t, delAppID, name) || c.actor != secrets.OperatorActor("alice") || c.jobID != "job-783" {
			t.Errorf("call %d = %+v; want ref %s, operator alice, job job-783", i, c, name)
		}
	}
	if string(out) != `{"count":2,"secrets":"deleted"}` {
		t.Errorf("result = %s", out)
	}
	if strings.Contains(string(out), "kept") || strings.Contains(l.text(), "kept") {
		t.Errorf("a keep-volumes delete says the secrets are kept: result %s, job log %q", out, l.text())
	}
	if !strings.Contains(l.text(), "deleted the app's 2 secrets from the secret store, every version") {
		t.Errorf("job log = %q", l.text())
	}
}

// fakeRepo is a secrets.Repository that records whether it was called.
type fakeRepo struct{ calls int }

func (f *fakeRepo) Get(context.Context, secrets.Ref) (secrets.Secret, error) {
	f.calls++
	return secrets.Secret{}, nil
}
func (f *fakeRepo) Write(context.Context, secrets.Ref, secret.Value, int) (int, error) {
	f.calls++
	return 1, nil
}
func (f *fakeRepo) CurrentVersion(context.Context, secrets.Ref) (int, error) {
	f.calls++
	return 1, nil
}
func (f *fakeRepo) Delete(context.Context, secrets.Ref) error { f.calls++; return nil }

type noApps struct{}

func (noApps) TargetNode(context.Context, string) (string, bool, error) { return "", false, nil }

type noSwitch struct{}

func (noSwitch) MarkSwitched(context.Context) error { return nil }

// TC-783-14: a job with no operator fails closed. The deleter receives the
// zero actor, and the real service refuses it without a repository call.
func TestDestroySecrets_TC783_14_NoOperatorFailsClosed(t *testing.T) {
	rec := &fakeSecretDeleter{}
	sc, _ := destroyCtx(t, withVolumesSpec, "", "a")
	if _, err := deleteDestroySecrets(DeleteSecretsDeps{Secrets: rec, Store: &fakeStoreState{}, Log: discardLog()})(sc); err != nil {
		t.Fatalf("recording run: %v", err)
	}
	if calls := rec.recorded(); len(calls) != 1 || calls[0].actor != (secrets.Actor{}) {
		t.Fatalf("calls = %+v; want one with the zero actor", calls)
	}

	repo := &fakeRepo{}
	svc, err := secrets.NewService(secrets.Deps{Repo: repo, Apps: noApps{}, Switch: noSwitch{}, Log: discardLog()})
	if err != nil {
		t.Fatal(err)
	}
	sc, _ = destroyCtx(t, withVolumesSpec, "", "a")
	if _, err := deleteDestroySecrets(DeleteSecretsDeps{Secrets: svc, Store: &fakeStoreState{}, Log: discardLog()})(sc); err == nil {
		t.Fatal("destroy_secrets with no operator succeeded")
	}
	if repo.calls != 0 {
		t.Errorf("repository calls = %d; want none", repo.calls)
	}
}

// TC-783-15: DeleteWorkflow refuses each missing collaborator.
func TestDeleteWorkflow_TC783_15_RefusesMissingCollaborators(t *testing.T) {
	full := DeleteSecretsDeps{Secrets: &fakeSecretDeleter{}, Store: &fakeStoreState{}, Log: discardLog()}
	for name, d := range map[string]DeleteSecretsDeps{
		"nil deleter": {Store: full.Store, Log: full.Log},
		"nil store":   {Secrets: full.Secrets, Log: full.Log},
		"nil logger":  {Secrets: full.Secrets, Store: full.Store},
	} {
		w, err := DeleteWorkflow(nil, nil, nil, nil, d)
		if err == nil || w.Kind != "" {
			t.Errorf("%s: DeleteWorkflow = %+v, %v; want an error and no workflow", name, w.Kind, err)
		}
	}
	w, err := DeleteWorkflow(nil, nil, nil, nil, full)
	if err != nil || w.Kind != "app.delete" || w.Steps[len(w.Steps)-1].Name != "destroy_secrets" {
		t.Errorf("DeleteWorkflow(full) = %+v, %v", w, err)
	}
}

// destroy_secrets with no remove result fails rather than guessing.
func TestDestroySecrets_MissingRemoveResultFails(t *testing.T) {
	sc, _ := destroyCtx(t, withVolumesSpec, "alice")
	delete(sc.PriorResults, "remove")
	if _, err := deleteDestroySecrets(DeleteSecretsDeps{Secrets: &fakeSecretDeleter{}, Store: &fakeStoreState{}, Log: discardLog()})(sc); err == nil {
		t.Error("destroy_secrets ran without the remove step's names")
	}
	sc.PriorResults["remove"] = json.RawMessage(`not json`)
	if _, err := deleteDestroySecrets(DeleteSecretsDeps{Secrets: &fakeSecretDeleter{}, Store: &fakeStoreState{}, Log: discardLog()})(sc); err == nil {
		t.Error("destroy_secrets accepted an undecodable remove result")
	}
}

// A delete with volumes of an app with no secrets calls nothing.
func TestDestroySecrets_NoNamesCallsNothing(t *testing.T) {
	del := &fakeSecretDeleter{}
	sc, _ := destroyCtx(t, withVolumesSpec, "alice")
	out, err := deleteDestroySecrets(DeleteSecretsDeps{Secrets: del, Store: &fakeStoreState{}, Log: discardLog()})(sc)
	if err != nil || string(out) != `{"secrets":"none"}` || len(del.recorded()) != 0 {
		t.Errorf("destroy_secrets = %s, %v, %d calls", out, err, len(del.recorded()))
	}
}

// preflightFixture is an online app with secrets whose node answers every
// stop, recording it.
func preflightFixture(t *testing.T, compose string, refs ...string) (*Store, func(SecretStoreState) (json.RawMessage, error), *deleteAgent) {
	t.Helper()
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", delAppID, "immich")
	withSecrets(t, store, delAppID, compose, "", refs...)
	agent := fakeDeleteAgent(t, nc, "n", delVolData)
	return store, func(st SecretStoreState) (json.RawMessage, error) {
		return deleteStop(store, inv, nc, st)(newStepCtxNATS(deleteSpecJSON(delVolData.Name), nc))
	}, agent
}

// F-783-04: a delete with volumes of an app with secrets refuses before any
// stop RPC while the store is sealed, unreachable or quiesced, names the state
// and leaves the row unchanged.
func TestDelete_Preflight_F783_04_StoreNotReadyRefusesBeforeStop(t *testing.T) {
	for _, state := range []storestate.State{storestate.Sealed, storestate.Unreachable, storestate.Quiesced} {
		t.Run(string(state), func(t *testing.T) {
			ctx := context.Background()
			store, run, agent := preflightFixture(t, composeNaming("db-password"), "db-password")
			before, _ := store.Get(ctx, delAppID)
			_, err := run(&fakeStoreState{state: state})
			want := "The secret store " + storestate.Clause(state) + ", so the app's secrets could not be deleted; nothing was deleted. Retry when the store is ready."
			if err == nil || err.Error() != want {
				t.Fatalf("err = %v; want %q", err, want)
			}
			if len(agent.stops()) != 0 {
				t.Errorf("stops sent = %v; want none", agent.stops())
			}
			after, _ := store.Get(ctx, delAppID)
			if after == nil || after.LastStatus != before.LastStatus || after.LastDetail != before.LastDetail || !sameTime(after.LastStatusAt, before.LastStatusAt) {
				t.Errorf("row changed: before %+v after %+v", before, after)
			}
		})
	}
}

func sameTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

// F-783-04: a store whose state cannot be read refuses the same way, and the
// cause is kept.
func TestDelete_Preflight_F783_04_StateReadErrorRefuses(t *testing.T) {
	_, run, agent := preflightFixture(t, composeNaming("db-password"), "db-password")
	_, err := run(&fakeStoreState{err: context.Canceled})
	if err == nil || !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "nothing was deleted") {
		t.Fatalf("err = %v", err)
	}
	if len(agent.stops()) != 0 {
		t.Errorf("stops sent = %v; want none", agent.stops())
	}
}

// F-783-04: with no store configured and recorded refs, the stored entries
// cannot be deleted, so the delete refuses.
func TestDelete_Preflight_F783_04_UnconfiguredWithRefsRefuses(t *testing.T) {
	_, run, agent := preflightFixture(t, composeNaming("db-password"), "db-password", "admin-token")
	_, err := run(&fakeStoreState{unconfigured: true})
	want := "No secret store is configured, so the app's 2 stored secrets cannot be deleted; nothing was deleted."
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v; want %q", err, want)
	}
	if len(agent.stops()) != 0 {
		t.Errorf("stops sent = %v; want none", agent.stops())
	}
}

// F-783-04: with no store configured and scanned names only, the secrets were
// derived and never stored: the delete proceeds, and destroy_secrets returns
// none-stored without a deleter call.
func TestDelete_Preflight_F783_04_UnconfiguredScannedOnlyProceeds(t *testing.T) {
	st := &fakeStoreState{unconfigured: true}
	_, run, agent := preflightFixture(t, composeNaming("db-password"))
	if _, err := run(st); err != nil {
		t.Fatalf("deleteStop: %v", err)
	}
	if len(agent.stops()) != 2 || st.stateReads() != 0 {
		t.Errorf("stops = %v, state reads = %d; want two stops and no read", agent.stops(), st.stateReads())
	}
	del := &fakeSecretDeleter{}
	sc, _ := destroyCtx(t, withVolumesSpec, "alice", "db-password")
	out, err := deleteDestroySecrets(DeleteSecretsDeps{Secrets: del, Store: st, Log: discardLog()})(sc)
	if err != nil || string(out) != `{"secrets":"none-stored"}` || len(del.recorded()) != 0 {
		t.Errorf("destroy_secrets = %s, %v, %d calls; want none-stored and no call", out, err, len(del.recorded()))
	}
}

// F-783-04: an app with no secret names proceeds without reading the store.
func TestDelete_Preflight_F783_04_NoNamesSkipsTheStateRead(t *testing.T) {
	st := &fakeStoreState{state: storestate.Sealed}
	_, run, agent := preflightFixture(t, "services: {}\n")
	if _, err := run(st); err != nil {
		t.Fatalf("deleteStop: %v", err)
	}
	if st.stateReads() != 0 || len(agent.stops()) != 2 {
		t.Errorf("state reads = %d, stops = %v; want no read and two stops", st.stateReads(), agent.stops())
	}
}

// F-783-04: a compose the scanner refuses refuses the delete before any stop.
func TestDelete_Preflight_F783_04_ScanErrorRefusesBeforeStop(t *testing.T) {
	_, run, agent := preflightFixture(t, "x: ${secret:Bad_Name}\n")
	_, err := run(&fakeStoreState{})
	if err == nil || !strings.HasPrefix(err.Error(), "The app's compose could not be scanned for secrets, so nothing was deleted") {
		t.Fatalf("err = %v", err)
	}
	if len(agent.stops()) != 0 {
		t.Errorf("stops sent = %v; want none", agent.stops())
	}
}

// TC-783-35: a keep-volumes delete runs the same store preflight
// (F-783-05 ruling). With the store sealed the stop step fails with
// TC-783-28's sentence, sends no stop and leaves the row unchanged; with the
// store ready it sends its one stop.
func TestDelete_TC783_35_KeepVolumesRunsTheStorePreflight(t *testing.T) {
	for _, tc := range []struct {
		name    string
		state   storestate.State
		wantErr string
		stops   int
	}{
		{"sealed", storestate.Sealed, "The secret store " + storestate.Clause(storestate.Sealed) + ", so the app's secrets could not be deleted; nothing was deleted. Retry when the store is ready.", 0},
		{"ready", storestate.Ready, "", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			nc := startNATS(t)
			store, inv := seedOnlineApp(t, "n", delAppID, "immich")
			withSecrets(t, store, delAppID, composeNaming("db-password"), "", "db-password")
			agent := fakeDeleteAgent(t, nc, "n")
			before, _ := store.Get(ctx, delAppID)
			st := &fakeStoreState{state: tc.state}
			_, err := deleteStop(store, inv, nc, st)(newStepCtxNATS(`{"appId":"`+delAppID+`"}`, nc))
			if tc.wantErr == "" && err != nil {
				t.Fatalf("deleteStop: %v", err)
			}
			if tc.wantErr != "" && (err == nil || err.Error() != tc.wantErr) {
				t.Fatalf("err = %v; want %q", err, tc.wantErr)
			}
			if st.stateReads() != 1 || len(agent.stops()) != tc.stops {
				t.Errorf("state reads = %d, stops = %v; want one read and %d stops", st.stateReads(), agent.stops(), tc.stops)
			}
			if tc.wantErr != "" {
				after, _ := store.Get(ctx, delAppID)
				if after == nil || after.LastStatus != before.LastStatus || after.LastDetail != before.LastDetail || !sameTime(after.LastStatusAt, before.LastStatusAt) {
					t.Errorf("row changed: before %+v after %+v", before, after)
				}
			}
		})
	}
}
