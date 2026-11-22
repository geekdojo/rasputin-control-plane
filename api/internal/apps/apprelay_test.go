package apps

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/dbutil"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/nats-io/nats.go"
)

// geekdojo/geekdojo-brain#1081: the apps side of the app relay — the switch's
// constructor, the delete saga's relay teardown, and the runtime secret
// index through delete and node removal.

// TC-1081-06: NewAppIdentity refuses tiles with no issuer; no tiles and no
// issuer is the switch off; a custom app is never granted, even with "" in
// the list.
func TestNewAppIdentity_Contract(t *testing.T) {
	if _, err := NewAppIdentity([]string{"uptime-kuma"}, nil); err == nil {
		t.Error("tiles with a nil issuer were accepted")
	}
	off, err := NewAppIdentity(nil, nil)
	if err != nil {
		t.Fatalf("no tiles, no issuer: %v", err)
	}
	if off.Any() || off.Granted(&App{ID: testAppID, SourceTile: "uptime-kuma"}) {
		t.Error("the switch off grants something")
	}
	g, err := NewAppIdentity([]string{"", "uptime-kuma"}, &fakeIssuer{})
	if err != nil {
		t.Fatal(err)
	}
	if g.Granted(&App{ID: testAppID, Name: "mine"}) {
		t.Error("a custom app is granted by a list holding the empty tile id")
	}
	if !g.Granted(&App{ID: testAppID, SourceTile: "uptime-kuma"}) || !g.Any() {
		t.Error("the granted tile is not granted")
	}
}

func deleteSteps(t *testing.T, identity AppIdentity) []string {
	t.Helper()
	w, err := DeleteWorkflow(nil, nil, nil, nil, testSecretDeps(), identity)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range w.Steps {
		names = append(names, s.Name)
	}
	return names
}

// TC-1081-07: with no grant the delete saga keeps its four steps; with any,
// teardown_relay sits between teardown_leaf and remove.
func TestDeleteWorkflow_RelayStepOnlyWithAGrant(t *testing.T) {
	if got, want := deleteSteps(t, AppIdentity{}), []string{"stop", "teardown_leaf", "remove", "destroy_secrets"}; !slices.Equal(got, want) {
		t.Errorf("no grant: steps %v, want %v", got, want)
	}
	if got, want := deleteSteps(t, grant(&fakeIssuer{}, "uptime-kuma")), []string{"stop", "teardown_leaf", "teardown_relay", "remove", "destroy_secrets"}; !slices.Equal(got, want) {
		t.Errorf("a grant: steps %v, want %v", got, want)
	}
}

// TC-1081-08: with a grant, delete revokes once on the app's node; a failed
// revoke is a WARN line naming the app and the saga reaches remove; a node
// gone from inventory is a WARN skip.
func TestDelete_RevokesBestEffort(t *testing.T) {
	for _, tc := range []struct {
		name      string
		revokeErr error
		dropNode  bool
		wantCalls int
		wantWarn  string
	}{
		{name: "revoked", wantCalls: 1},
		{name: "no responder", revokeErr: nats.ErrNoResponders, wantCalls: 1, wantWarn: "relay teardown of " + delAppID + " on n failed"},
		{name: "refused", revokeErr: errors.New("node n refused to remove the relay socket"), wantCalls: 1, wantWarn: "relay teardown of " + delAppID + " on n failed"},
		{name: "node gone", dropNode: true, wantCalls: 0, wantWarn: "skip relay teardown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nc := startNATS(t)
			store, inv := seedOnlineApp(t, "n", delAppID, "immich")
			fakeDeleteAgent(t, nc, "n")
			issuer := &fakeIssuer{revokeErr: tc.revokeErr}
			w := wf(t)(DeleteWorkflow(store, inv, nc, nil, testSecretDeps(), grant(issuer, "uptime-kuma")))
			if tc.dropNode {
				if err := inv.Delete(context.Background(), "n"); err != nil {
					t.Fatal(err)
				}
			}
			run := runWorkflow(t, w, nc, `{"appId":"`+delAppID+`"}`, "job-del")
			if run.err != nil {
				t.Fatalf("failed at %s: %v", run.failedAt, run.err)
			}
			if _, ok := run.results["remove"]; !ok {
				t.Error("the saga did not reach remove")
			}
			if got := issuer.revokes(); len(got) != tc.wantCalls || (tc.wantCalls == 1 && got[0] != delAppID+"@n") {
				t.Errorf("revoked %v, want %d call(s) for %s@n", got, tc.wantCalls, delAppID)
			}
			if tc.wantWarn != "" && !slices.ContainsFunc(run.logs, func(l string) bool {
				return strings.HasPrefix(l, "warn: ") && strings.Contains(l, tc.wantWarn)
			}) {
				t.Errorf("no WARN line containing %q in %v", tc.wantWarn, run.logs)
			}
		})
	}
}

// TC-1081-09: runtime names come back from both delete transactions and
// cascade with the row; a row for a missing app fails; recording twice
// leaves one row.
func TestRuntimeIndex_CascadesAndIsReadAtomically(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	seedNodeApp(t, store, nodeAppP, "N", composeNaming("b"), "", "a")
	seedNodeApp(t, store, nodeAppQ, "N", "services: {}", "")
	seedNodeApp(t, store, delAppID, "M", composeNaming("p"), "", "p")
	for _, r := range []struct{ app, name string }{{nodeAppP, "k1"}, {nodeAppP, "k2"}, {nodeAppP, "k1"}, {delAppID, "rt"}} {
		if err := store.RecordRuntimeSecret(ctx, r.app, r.name); err != nil {
			t.Fatal(err)
		}
	}
	if got, _ := store.RuntimeSecretNames(ctx, nodeAppP); !slices.Equal(got, []string{"k1", "k2"}) {
		t.Errorf("names = %v, want [k1 k2]: recording twice must leave one row", got)
	}
	if err := store.RecordRuntimeSecret(ctx, "01J9ZK3Q0M8X7Y6W5V4T3S2R1Z", "k"); err == nil {
		t.Error("a runtime row for a missing app was recorded")
	}
	if err := store.RecordRuntimeSecret(ctx, nodeAppP, "gone"); err != nil {
		t.Fatal(err)
	}
	for range 2 { // forgetting an absent row is success
		if err := store.ForgetRuntimeSecret(ctx, nodeAppP, "gone"); err != nil {
			t.Fatalf("ForgetRuntimeSecret: %v", err)
		}
	}
	if got, _ := store.RuntimeSecretNames(ctx, nodeAppP); !slices.Equal(got, []string{"k1", "k2"}) {
		t.Errorf("after Forget, names = %v, want [k1 k2]", got)
	}

	names, runtime, _, err := store.DeleteWithSecretNames(ctx, delAppID)
	if err != nil || !slices.Equal(names, []string{"p"}) || !slices.Equal(runtime, []string{"rt"}) {
		t.Fatalf("DeleteWithSecretNames = %v, %v, %v; want [p] [rt]", names, runtime, err)
	}
	removed, err := store.DeleteByTargetNodeWithSecretNames(ctx, "N")
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 2 || !slices.Equal(removed[0].RuntimeNames, []string{"k1", "k2"}) || len(removed[1].RuntimeNames) != 0 {
		t.Errorf("removed = %+v, want P with [k1 k2] and Q with none", removed)
	}
	var n int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM app_runtime_secrets`).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d runtime rows left (%v), want 0", n, err)
	}
}

// TC-1081-10: runtime names count as recorded references in the delete
// preflight.
func TestDelete_PreflightCountsRuntimeNames(t *testing.T) {
	ctx := context.Background()
	runtimeOnly := func(t *testing.T) (*Store, func(SecretStoreState) (json.RawMessage, error), *deleteAgent) {
		store, run, agent := preflightFixture(t, "services: {}")
		for _, n := range []string{"k1", "k2"} {
			if err := store.RecordRuntimeSecret(ctx, delAppID, n); err != nil {
				t.Fatal(err)
			}
		}
		return store, run, agent
	}
	t.Run("store not ready", func(t *testing.T) {
		_, run, agent := runtimeOnly(t)
		_, err := run(&fakeStoreState{state: storestate.Sealed})
		want := "The secret store " + storestate.Clause(storestate.Sealed) + ", so the app's secrets could not be deleted; nothing was deleted. Retry when the store is ready."
		if err == nil || err.Error() != want || len(agent.stops()) != 0 {
			t.Fatalf("err = %v, stops %v; want %q and no stop", err, agent.stops(), want)
		}
	})
	t.Run("store unconfigured", func(t *testing.T) {
		_, run, agent := runtimeOnly(t)
		_, err := run(&fakeStoreState{unconfigured: true})
		want := "No secret store is configured, so the app's 2 stored secrets cannot be deleted; nothing was deleted."
		if err == nil || err.Error() != want || len(agent.stops()) != 0 {
			t.Fatalf("err = %v, stops %v; want %q and no stop", err, agent.stops(), want)
		}
	})
	t.Run("no runtime names", func(t *testing.T) {
		st := &fakeStoreState{state: storestate.Sealed}
		_, run, _ := preflightFixture(t, "services: {}")
		if _, err := run(st); err != nil || st.stateReads() != 0 {
			t.Fatalf("err = %v with %d state reads; want the preflight unchanged: no read, no refusal", err, st.stateReads())
		}
	})
}

// removedWith is a destroy_secrets StepCtx whose remove step named names and
// runtime.
func removedWith(t *testing.T, names, runtime []string) (*jobs.StepCtx, *stepLog) {
	t.Helper()
	sc, l := destroyCtx(t, withVolumesSpec, "alice", names...)
	raw, err := json.Marshal(removeResult{AppID: delAppID, Deleted: "true", SecretNames: append([]string{}, names...), RuntimeNames: runtime})
	if err != nil {
		t.Fatal(err)
	}
	sc.PriorResults["remove"] = raw
	return sc, l
}

func runtimeRefOf(t *testing.T, appID, name string) secrets.Ref {
	t.Helper()
	r, err := secrets.AppRuntimeSecret(appID, name)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TC-1081-11: destroy_secrets deletes each runtime entry as the operator; a
// failure fails the job naming it, with one ERROR; with no runtime names the
// remove result's bytes are unchanged.
func TestDestroySecrets_DeletesRuntimeEntries(t *testing.T) {
	t.Run("runtime only", func(t *testing.T) {
		del := &fakeSecretDeleter{}
		sc, _ := removedWith(t, nil, []string{"k1", "k2"})
		if _, err := deleteDestroySecrets(DeleteSecretsDeps{Secrets: del, Store: &fakeStoreState{}, Log: discardLog()})(sc); err != nil {
			t.Fatal(err)
		}
		got := del.recorded()
		if len(got) != 2 || got[0].ref != runtimeRefOf(t, delAppID, "k1") || got[1].ref != runtimeRefOf(t, delAppID, "k2") {
			t.Fatalf("deleted %+v, want the two runtime entries", got)
		}
		for _, c := range got {
			if c.actor != secrets.OperatorActor("alice") {
				t.Errorf("deleted as %+v, want the operator", c.actor)
			}
		}
	})
	t.Run("both kinds, one failing", func(t *testing.T) {
		log, rec := logkittest.New()
		failing := runtimeRefOf(t, delAppID, "k2")
		del := &fakeSecretDeleter{failRef: map[string]error{failing.String(): errors.New("store down")}}
		sc, _ := removedWith(t, []string{"db-password"}, []string{"k1", "k2"})
		_, err := deleteDestroySecrets(DeleteSecretsDeps{Secrets: del, Store: &fakeStoreState{}, Log: log})(sc)
		if err == nil || !strings.Contains(err.Error(), "_runtime/k2") || strings.Contains(err.Error(), "_runtime/k1") {
			t.Fatalf("err = %v, want it to name _runtime/k2 alone", err)
		}
		if got := del.recorded(); len(got) != 3 || got[0].ref != mustRef(t, delAppID, "db-password") {
			t.Errorf("deleted %+v, want the pushed secret and both runtime entries", got)
		}
		if errs := rec.Matching(slog.LevelError, "not deleted"); len(errs) != 1 {
			t.Errorf("%d ERROR records, want 1", len(errs))
		} else if ev, _ := logkittest.Attr(errs[0], "event"); ev != "apps.secrets_destroy_failed" {
			t.Errorf("event %q", ev)
		}
	})
	t.Run("no runtime names keeps the remove result's bytes", func(t *testing.T) {
		nc := startNATS(t)
		store, _ := seedOnlineApp(t, "n", delAppID, "immich")
		out, err := deleteRemove(store, nc)(newStepCtxNATS(`{"appId":"`+delAppID+`"}`, nc))
		if err != nil {
			t.Fatal(err)
		}
		if want := `{"appId":"` + delAppID + `","deleted":"true","secretNames":[]}`; string(out) != want {
			t.Errorf("remove result = %s, want %s", out, want)
		}
	})
}

// TC-1081-12: node removal checks and deletes runtime entries.
func TestNodeApps_RuntimeEntries(t *testing.T) {
	ctx := context.Background()
	seed := func(t *testing.T) *Store {
		store := newStore(t)
		seedNodeApp(t, store, nodeAppP, "N", "services: {}", "")
		seedNodeApp(t, store, nodeAppQ, "N", "services: {}", "")
		for _, r := range []struct{ app, name string }{{nodeAppP, "k1"}, {nodeAppQ, "k2"}} {
			if err := store.RecordRuntimeSecret(ctx, r.app, r.name); err != nil {
				t.Fatal(err)
			}
		}
		return store
	}
	t.Run("check refuses a store that is not ready", func(t *testing.T) {
		n := newNodeApps(t, seed(t), DeleteSecretsDeps{Secrets: &fakeSecretDeleter{}, Store: &fakeStoreState{state: storestate.Sealed}, Log: discardLog()})
		if err := n.CheckSecrets(ctx, "N"); !errors.Is(err, ErrNodeSecretsUnavailable) {
			t.Fatalf("CheckSecrets = %v, want ErrNodeSecretsUnavailable", err)
		}
	})
	t.Run("remove deletes each and names each failure", func(t *testing.T) {
		del := &fakeSecretDeleter{failRef: map[string]error{runtimeRefOf(t, nodeAppQ, "k2").String(): errors.New("store down")}}
		n := newNodeApps(t, seed(t), DeleteSecretsDeps{Secrets: del, Store: &fakeStoreState{}, Log: discardLog()})
		ids, err := n.Remove(ctx, "alice", "N")
		var nse *NodeSecretsError
		if !errors.As(err, &nse) || !errors.Is(err, ErrSecretsLeft) || !strings.Contains(nse.Sentence, nodeAppQ+"/_runtime/k2") {
			t.Fatalf("Remove = %v, want ErrSecretsLeft naming %s/_runtime/k2", err, nodeAppQ)
		}
		if len(ids) != 2 {
			t.Errorf("removed %v", ids)
		}
		var refs []secrets.Ref
		for _, c := range del.recorded() {
			refs = append(refs, c.ref)
		}
		if !slices.Contains(refs, runtimeRefOf(t, nodeAppP, "k1")) || !slices.Contains(refs, runtimeRefOf(t, nodeAppQ, "k2")) {
			t.Errorf("deleted %v, want both runtime entries", refs)
		}
	})
}

// TC-1081-26 (store half): an apps database the previous release created,
// without app_runtime_secrets, opens, gains the table, and its apps delete
// as before.
func TestOpenStore_UpgradesAPreviousReleaseDatabase(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "apps.db")
	i := strings.Index(schema, "-- app_runtime_secrets")
	if i < 0 {
		t.Fatal("the schema no longer marks the runtime table")
	}
	db, err := dbutil.Open(ctx, path, schema[:i], "apps")
	if err != nil {
		t.Fatal(err)
	}
	applyMigrations(ctx, db)
	old := &Store{db: db}
	app := makeApp(delAppID, "old")
	app.ComposeYAML = composeNaming("p")
	if err := old.Create(ctx, app); err != nil {
		t.Fatal(err)
	}
	var tables int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = 'app_runtime_secrets'`).Scan(&tables); err != nil || tables != 0 {
		t.Fatalf("the previous schema already has the table (%d, %v)", tables, err)
	}
	_ = db.Close()

	store, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.RecordRuntimeSecret(ctx, delAppID, "k"); err != nil {
		t.Fatalf("the upgraded database has no runtime table: %v", err)
	}
	names, runtime, _, err := store.DeleteWithSecretNames(ctx, delAppID)
	if err != nil || !slices.Equal(names, []string{"p"}) || !slices.Equal(runtime, []string{"k"}) {
		t.Fatalf("delete = %v %v %v", names, runtime, err)
	}
}

// The deploy command carries Relay exactly when the app was issued.
func TestDeployCommand_Relay(t *testing.T) {
	var cmd proto.AppDeployCmd
	b, err := deployCommand(&App{ID: testAppID, Name: "x"}, secret.New([]byte("services: {}\n")), nil, true)
	if err != nil || json.Unmarshal(b, &cmd) != nil || !cmd.Relay {
		t.Fatalf("deployCommand(relay) = %s, %v", b, err)
	}
}
