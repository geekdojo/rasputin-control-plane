package apps

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/dbutil"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
)

// geekdojo/geekdojo-brain#1084: an app's Transit keys in the apps store and
// through every path that destroys, or keeps, an app's secrets.

func keyRefOf(t *testing.T, appID, name string) secrets.Ref {
	t.Helper()
	r, err := secrets.AppKey(appID, name)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func recordKeys(t *testing.T, store *Store, appID string, names ...string) {
	t.Helper()
	for _, n := range names {
		if err := store.RecordTransitKey(context.Background(), appID, n); err != nil {
			t.Fatal(err)
		}
	}
}

func countKeyRows(t *testing.T, store *Store) int {
	t.Helper()
	var n int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM app_transit_keys`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TC-1084-18: a rasputin.db the previous release created opens and gains
// app_transit_keys; recording is idempotent, forgetting an absent row
// succeeds, a row for a missing app fails on the foreign key, HasTransitKey
// reads the row, and deleting the app removes its key rows.
func TestTransitKeyIndex_UpgradeAndCascade(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "apps.db")
	i := strings.Index(schema, "-- app_transit_keys")
	if i < 0 {
		t.Fatal("the schema no longer marks the key table")
	}
	db, err := dbutil.Open(ctx, path, schema[:i], "apps")
	if err != nil {
		t.Fatal(err)
	}
	applyMigrations(ctx, db)
	old := &Store{db: db}
	if err := old.Create(ctx, makeApp(delAppID, "old")); err != nil {
		t.Fatal(err)
	}
	var tables int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = 'app_transit_keys'`).Scan(&tables); err != nil || tables != 0 {
		t.Fatalf("the previous schema already has the table (%d, %v)", tables, err)
	}
	_ = db.Close()

	store, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	recordKeys(t, store, delAppID, "wrap", "wrap", "sign")
	if got, _ := store.TransitKeyNames(ctx, delAppID); !slices.Equal(got, []string{"sign", "wrap"}) {
		t.Errorf("names = %v, want [sign wrap]: recording twice must leave one row", got)
	}
	if ok, err := store.HasTransitKey(ctx, delAppID, "wrap"); !ok || err != nil {
		t.Errorf("HasTransitKey(wrap) = %t, %v", ok, err)
	}
	if ok, err := store.HasTransitKey(ctx, delAppID, "ghost"); ok || err != nil {
		t.Errorf("HasTransitKey(ghost) = %t, %v", ok, err)
	}
	for range 2 {
		if err := store.ForgetTransitKey(ctx, delAppID, "ghost"); err != nil {
			t.Errorf("forgetting an absent row = %v", err)
		}
	}
	if err := store.RecordTransitKey(ctx, "01J9ZK3Q0M8X7Y6W5V4T3S2R1Z", "k"); err == nil {
		t.Error("a key row for a missing app was recorded")
	}
	_, _, keys, err := store.DeleteWithSecretNames(ctx, delAppID)
	if err != nil || !slices.Equal(keys, []string{"sign", "wrap"}) {
		t.Fatalf("DeleteWithSecretNames keys = %v, %v; want [sign wrap]", keys, err)
	}
	if n := countKeyRows(t, store); n != 0 {
		t.Errorf("%d key rows left after the app's delete", n)
	}
}

// TC-1084-19: an app whose only store entries are two keys is refused by the
// delete preflight and by node removal's check while the store is not ready,
// before anything is stopped or removed, with the sentence counting 2; with
// no store configured and keys recorded, both are refused.
func TestPreflights_CountKeys(t *testing.T) {
	ctx := context.Background()
	keysOnly := func(t *testing.T) (*Store, func(SecretStoreState) (json.RawMessage, error), *deleteAgent) {
		store, run, agent := preflightFixture(t, "services: {}")
		recordKeys(t, store, delAppID, "a", "b")
		return store, run, agent
	}
	t.Run("delete, store not ready", func(t *testing.T) {
		store, run, agent := keysOnly(t)
		_, err := run(&fakeStoreState{state: storestate.Sealed})
		want := "The secret store " + storestate.Clause(storestate.Sealed) + ", so the app's secrets could not be deleted; nothing was deleted. Retry when the store is ready."
		if err == nil || err.Error() != want || len(agent.stops()) != 0 {
			t.Fatalf("err = %v, stops %v; want %q and no stop", err, agent.stops(), want)
		}
		if app, _ := store.Get(ctx, delAppID); app == nil {
			t.Error("the app row is gone")
		}
	})
	t.Run("delete, no store", func(t *testing.T) {
		_, run, agent := keysOnly(t)
		_, err := run(&fakeStoreState{unconfigured: true})
		want := "No secret store is configured, so the app's 2 stored secrets cannot be deleted; nothing was deleted."
		if err == nil || err.Error() != want || len(agent.stops()) != 0 {
			t.Fatalf("err = %v, stops %v; want %q and no stop", err, agent.stops(), want)
		}
	})
	seedNode := func(t *testing.T) *Store {
		store := newStore(t)
		seedNodeApp(t, store, nodeAppP, "N", "services: {}", "")
		recordKeys(t, store, nodeAppP, "a", "b")
		return store
	}
	t.Run("node removal, store not ready", func(t *testing.T) {
		store := seedNode(t)
		n := newNodeApps(t, store, DeleteSecretsDeps{Secrets: &fakeSecretDeleter{}, Store: &fakeStoreState{state: storestate.Sealed}, Log: discardLog()})
		if err := n.CheckSecrets(ctx, "N"); !errors.Is(err, ErrNodeSecretsUnavailable) {
			t.Fatalf("CheckSecrets = %v, want ErrNodeSecretsUnavailable", err)
		}
		if app, _ := store.Get(ctx, nodeAppP); app == nil {
			t.Error("the app row is gone")
		}
	})
	t.Run("node removal, no store", func(t *testing.T) {
		n := newNodeApps(t, seedNode(t), DeleteSecretsDeps{Secrets: &fakeSecretDeleter{}, Store: &fakeStoreState{unconfigured: true}, Log: discardLog()})
		err := n.CheckSecrets(ctx, "N")
		var nse *NodeSecretsError
		if !errors.As(err, &nse) || !strings.Contains(nse.Sentence, "the 2 stored secrets of the node's apps") {
			t.Fatalf("CheckSecrets = %v, want a refusal counting 2", err)
		}
	})
}

// TC-1084-20: app delete and node removal destroy every key as the operator;
// a key the store no longer has counts as done (secrets.Service.DestroyKey
// returns nil for it, so the deleter here answers nil); a store failure on
// one key fails the step and names that key; the remove result of an app
// with no keys is byte-identical to the result before the change.
func TestDeleteAndNodeRemoval_DestroyKeys(t *testing.T) {
	ctx := context.Background()
	t.Run("remove carries the keys; destroy_secrets destroys each", func(t *testing.T) {
		nc := startNATS(t)
		store, _ := seedOnlineApp(t, "n", delAppID, "immich")
		recordKeys(t, store, delAppID, "wrap", "gone")
		out, err := deleteRemove(store, nc)(newStepCtxNATS(`{"appId":"`+delAppID+`"}`, nc))
		if err != nil {
			t.Fatal(err)
		}
		if want := `{"appId":"` + delAppID + `","deleted":"true","secretNames":[],"transitKeys":["gone","wrap"]}`; string(out) != want {
			t.Fatalf("remove result = %s, want %s", out, want)
		}
		sc, l := destroyCtx(t, withVolumesSpec, "alice")
		sc.PriorResults["remove"] = out
		del := &fakeSecretDeleter{}
		if _, err := deleteDestroySecrets(DeleteSecretsDeps{Secrets: del, Store: &fakeStoreState{}, Log: discardLog()})(sc); err != nil {
			t.Fatal(err)
		}
		got := del.recorded()
		if len(got) != 2 || got[0].ref != keyRefOf(t, delAppID, "gone") || got[1].ref != keyRefOf(t, delAppID, "wrap") {
			t.Fatalf("destroyed %+v, want both keys", got)
		}
		for _, c := range got {
			if c.actor != secrets.OperatorActor("alice") {
				t.Errorf("destroyed as %+v, want the operator", c.actor)
			}
		}
		if !strings.Contains(l.text(), "deleted the app's 2 secrets") {
			t.Errorf("job log %q", l.text())
		}
	})
	t.Run("a failing key fails the step naming it", func(t *testing.T) {
		del := &fakeSecretDeleter{failRef: map[string]error{keyRefOf(t, delAppID, "wrap").String(): errors.New("store down")}}
		sc, _ := destroyCtx(t, withVolumesSpec, "alice")
		raw, _ := json.Marshal(removeResult{AppID: delAppID, Deleted: "true", SecretNames: []string{}, TransitKeys: []string{"gone", "wrap"}})
		sc.PriorResults["remove"] = raw
		_, err := deleteDestroySecrets(DeleteSecretsDeps{Secrets: del, Store: &fakeStoreState{}, Log: discardLog()})(sc)
		if err == nil || !strings.Contains(err.Error(), "key wrap") || strings.Contains(err.Error(), "key gone") {
			t.Fatalf("err = %v, want it to name key wrap alone", err)
		}
	})
	t.Run("node removal destroys each key and names a failure", func(t *testing.T) {
		store := newStore(t)
		seedNodeApp(t, store, nodeAppP, "N", "services: {}", "")
		seedNodeApp(t, store, nodeAppQ, "N", "services: {}", "")
		recordKeys(t, store, nodeAppP, "wrap")
		recordKeys(t, store, nodeAppQ, "wrap")
		del := &fakeSecretDeleter{failRef: map[string]error{keyRefOf(t, nodeAppQ, "wrap").String(): errors.New("store down")}}
		ids, err := newNodeApps(t, store, DeleteSecretsDeps{Secrets: del, Store: &fakeStoreState{}, Log: discardLog()}).Remove(ctx, "alice", "N")
		var nse *NodeSecretsError
		if !errors.As(err, &nse) || !errors.Is(err, ErrSecretsLeft) || !strings.Contains(nse.Sentence, nodeAppQ+"/key wrap") {
			t.Fatalf("Remove = %v, want ErrSecretsLeft naming %s/key wrap", err, nodeAppQ)
		}
		if len(ids) != 2 {
			t.Errorf("removed %v", ids)
		}
		var refs []secrets.Ref
		for _, c := range del.recorded() {
			refs = append(refs, c.ref)
		}
		if !slices.Equal(refs, []secrets.Ref{keyRefOf(t, nodeAppP, "wrap"), keyRefOf(t, nodeAppQ, "wrap")}) {
			t.Errorf("destroyed %v, want both apps' keys", refs)
		}
		if n := countKeyRows(t, store); n != 0 {
			t.Errorf("%d key rows left", n)
		}
	})
	t.Run("no keys keeps the remove result's bytes", func(t *testing.T) {
		nc := startNATS(t)
		store, _ := seedOnlineApp(t, "n", delAppID, "immich")
		out, err := deleteRemove(store, nc)(newStepCtxNATS(`{"appId":"`+delAppID+`"}`, nc))
		if err != nil {
			t.Fatal(err)
		}
		// The golden captured on origin/main 0bd7b3b5, before #1084.
		if want := `{"appId":"` + delAppID + `","deleted":"true","secretNames":[]}`; string(out) != want {
			t.Errorf("remove result = %s, want %s", out, want)
		}
	})
}

// TC-1084-21: app.upgrade's and app.edit's release step (release_secrets),
// with refs to release, destroys no key and leaves the key rows; a revert
// takes no secret deleter at all (RevertWorkflow), and the compose swap it
// makes leaves the key rows.
func TestUpgradeEditRevert_KeepKeys(t *testing.T) {
	ctx := context.Background()
	store, _ := seedOnlineApp(t, "n", delAppID, "immich")
	withSecrets(t, store, delAppID, composeNaming("a"), composeNaming("b"), "a", "b", "c")
	recordKeys(t, store, delAppID, "wrap", "sign")
	del := &fakeSecretDeleter{}
	if _, _, err := runRelease(store, DeleteSecretsDeps{Secrets: del, Store: &fakeStoreState{}, Log: discardLog()}); err != nil {
		t.Fatal(err)
	}
	for _, c := range del.recorded() {
		if c.ref == keyRefOf(t, delAppID, "wrap") || c.ref == keyRefOf(t, delAppID, "sign") {
			t.Errorf("the release step destroyed %s", c.ref)
		}
	}
	if len(del.recorded()) != 1 || del.recorded()[0].ref != mustRef(t, delAppID, "c") {
		t.Errorf("released %+v, want only the unused ref c", del.recorded())
	}
	app, err := store.Get(ctx, delAppID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RevertCompose(ctx, delAppID, app.ComposeSHA256, app.PreviousComposeYAML, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.TransitKeyNames(ctx, delAppID); !slices.Equal(got, []string{"sign", "wrap"}) {
		t.Errorf("key rows after release and revert = %v, want [sign wrap]", got)
	}
}
