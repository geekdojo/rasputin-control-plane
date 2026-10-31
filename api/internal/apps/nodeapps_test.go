package apps

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"slices"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// geekdojo/geekdojo-brain#783, F-783-06: a removed node's apps and their
// secrets.

const (
	nodeAppP = "01J9ZK3Q0M8X7Y6W5V4T3S2R1P"
	nodeAppQ = "01J9ZK3Q0M8X7Y6W5V4T3S2R1Q"
	nodeAppR = "01J9ZK3Q0M8X7Y6W5V4T3S2R1R"
	nodeAppS = "01J9ZK3Q0M8X7Y6W5V4T3S2R1S"
)

// seedNodeApp creates app id on node with its composes and refs.
func seedNodeApp(t *testing.T, store *Store, id, node, compose, previous string, refs ...string) {
	t.Helper()
	a := makeApp(id, "app-"+id[len(id)-1:])
	a.TargetNode = node
	if err := store.Create(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	withSecrets(t, store, id, compose, previous, refs...)
}

func countApps(t *testing.T, store *Store) int {
	t.Helper()
	var n int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM apps`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TC-783-48: DeleteByTargetNodeWithSecretNames returns refs ∪ scanned names
// per app (a refused compose naming nothing), deletes the node's rows and
// refs, and leaves another node's app alone; a node with no apps writes
// nothing.
func TestNodeApps_TC783_48_DeleteByTargetNodeWithSecretNames(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	seedNodeApp(t, store, nodeAppP, "N", composeNaming("b"), composeNaming("c"), "a")
	seedNodeApp(t, store, nodeAppQ, "N", "services: {}", "")
	seedNodeApp(t, store, nodeAppR, "N", refusedCompose, "", "r")
	seedNodeApp(t, store, nodeAppS, "M", composeNaming("s"), "", "s")

	got, err := store.DeleteByTargetNodeWithSecretNames(ctx, "N")
	if err != nil {
		t.Fatal(err)
	}
	want := []AppSecretNames{
		{AppID: nodeAppP, Names: []string{"a", "b", "c"}, RecordedRefs: 1},
		{AppID: nodeAppQ, Names: nil, RecordedRefs: 0},
		{AppID: nodeAppR, Names: []string{"r"}, RecordedRefs: 1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v; want %+v", got, want)
	}
	for _, id := range []string{nodeAppP, nodeAppQ, nodeAppR} {
		if row, _ := store.Get(ctx, id); row != nil {
			t.Errorf("%s survived", id)
		}
	}
	if row, _ := store.Get(ctx, nodeAppS); row == nil || !slices.Equal(refsOf(t, store, nodeAppS), []string{"s"}) {
		t.Error("the other node's app or its ref was touched")
	}
	if countRefs(t, store) != 1 {
		t.Errorf("%d refs; want only S's", countRefs(t, store))
	}

	empty, err := store.DeleteByTargetNodeWithSecretNames(ctx, "empty")
	if err != nil || len(empty) != 0 || countApps(t, store) != 1 {
		t.Errorf("empty node = %v, %v, %d apps; want nothing", empty, err, countApps(t, store))
	}
}

func newNodeApps(t *testing.T, store *Store, d DeleteSecretsDeps) *NodeApps {
	t.Helper()
	n, err := NewNodeApps(store, d)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TC-783-49: CheckSecrets refuses with the node sentence when the store
// cannot take the deletes, passes without reading the state when there is
// nothing to delete, refuses as unreadable when the refs cannot be read, and
// never writes.
func TestNodeApps_TC783_49_CheckSecrets(t *testing.T) {
	ctx := context.Background()
	readErr := errors.New("monitor: read failed")
	notReady := func(st storestate.State) string {
		return "The secret store " + storestate.Clause(st) + ", so the secrets of the node's apps could not be deleted; the node was not removed. Retry when the store is ready."
	}
	for _, tc := range []struct {
		name      string
		st        *fakeStoreState
		compose   string
		refs      []string
		want      string
		kind      error
		cause     error
		wantReads int
	}{
		{"sealed", &fakeStoreState{state: storestate.Sealed}, composeNaming("a"), []string{"a"}, notReady(storestate.Sealed), ErrNodeSecretsUnavailable, nil, 1},
		{"unreachable", &fakeStoreState{state: storestate.Unreachable}, composeNaming("a"), []string{"a"}, notReady(storestate.Unreachable), ErrNodeSecretsUnavailable, nil, 1},
		{"quiesced", &fakeStoreState{state: storestate.Quiesced}, composeNaming("a"), []string{"a"}, notReady(storestate.Quiesced), ErrNodeSecretsUnavailable, nil, 1},
		{"state read fails", &fakeStoreState{err: readErr}, composeNaming("a"), []string{"a"}, notReady(""), ErrNodeSecretsUnavailable, readErr, 1},
		{"not configured with refs", &fakeStoreState{unconfigured: true}, composeNaming("a"), []string{"a"},
			"No secret store is configured, so the 1 stored secret of the node's apps cannot be deleted; the node was not removed.", ErrNodeSecretsUnavailable, nil, 0},
		{"no names", &fakeStoreState{state: storestate.Sealed}, "services: {}", nil, "", nil, nil, 0},
		{"no store, scanned names only", &fakeStoreState{unconfigured: true}, composeNaming("a"), nil, "", nil, nil, 0},
		{"ready", &fakeStoreState{}, composeNaming("a"), []string{"a"}, "", nil, nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newStore(t)
			seedNodeApp(t, store, nodeAppP, "N", tc.compose, "", tc.refs...)
			refsBefore := countRefs(t, store)
			err := newNodeApps(t, store, DeleteSecretsDeps{Secrets: &fakeSecretDeleter{}, Store: tc.st, Log: discardLog()}).CheckSecrets(ctx, "N")
			if tc.want == "" && err != nil {
				t.Fatalf("CheckSecrets: %v", err)
			}
			if tc.want != "" {
				var nse *NodeSecretsError
				if !errors.As(err, &nse) || nse.Sentence != tc.want || !errors.Is(err, tc.kind) {
					t.Fatalf("err = %v; want %q of kind %v", err, tc.want, tc.kind)
				}
				if tc.cause != nil && !errors.Is(err, tc.cause) {
					t.Errorf("err does not wrap its cause")
				}
			}
			if tc.st.stateReads() != tc.wantReads {
				t.Errorf("state reads = %d; want %d", tc.st.stateReads(), tc.wantReads)
			}
			if countApps(t, store) != 1 || countRefs(t, store) != refsBefore {
				t.Error("a row or ref was written")
			}
		})
	}
	t.Run("refs unreadable", func(t *testing.T) {
		store := newStore(t)
		seedNodeApp(t, store, nodeAppP, "N", composeNaming("a"), "", "a")
		if _, err := store.db.Exec(`DROP TABLE app_secret_refs`); err != nil {
			t.Fatal(err)
		}
		err := newNodeApps(t, store, DeleteSecretsDeps{Secrets: &fakeSecretDeleter{}, Store: &fakeStoreState{}, Log: discardLog()}).CheckSecrets(ctx, "N")
		var nse *NodeSecretsError
		if !errors.As(err, &nse) || !errors.Is(err, ErrNodeSecretsUnreadable) ||
			nse.Sentence != "The recorded secrets of the node's apps could not be read, so the node was not removed." {
			t.Fatalf("err = %v; want the unreadable refusal", err)
		}
		if countApps(t, store) != 1 {
			t.Error("the app row went")
		}
	})
}

// TC-783-50: Remove deletes one entry per app and name as the user; a failed
// delete is ErrSecretsLeft naming app/name with one ERROR record; a database
// error is returned with no delete; with no store and no refs nothing is
// deleted (F-783-20).
func TestNodeApps_TC783_50_Remove(t *testing.T) {
	ctx := context.Background()
	seed := func(t *testing.T) *Store {
		store := newStore(t)
		seedNodeApp(t, store, nodeAppP, "N", composeNaming("a", "b"), "", "a", "b")
		seedNodeApp(t, store, nodeAppR, "N", composeNaming("r"), "", "r")
		return store
	}
	t.Run("every entry, as the user", func(t *testing.T) {
		store := seed(t)
		del := &fakeSecretDeleter{}
		ids, err := newNodeApps(t, store, DeleteSecretsDeps{Secrets: del, Store: &fakeStoreState{}, Log: discardLog()}).Remove(ctx, "alice", "N")
		if err != nil || !slices.Equal(ids, []string{nodeAppP, nodeAppR}) {
			t.Fatalf("Remove = %v, %v", ids, err)
		}
		want := []secrets.Ref{mustRef(t, nodeAppP, "a"), mustRef(t, nodeAppP, "b"), mustRef(t, nodeAppR, "r")}
		calls := del.recorded()
		if len(calls) != len(want) {
			t.Fatalf("deletes = %+v; want %v", calls, want)
		}
		for i, c := range calls {
			if c.ref != want[i] || c.actor != secrets.OperatorActor("alice") {
				t.Errorf("delete %d = %+v; want %v as alice", i, c, want[i])
			}
		}
	})
	t.Run("a delete fails", func(t *testing.T) {
		store := seed(t)
		log, rec := logkittest.New()
		del := &fakeSecretDeleter{failRef: map[string]error{mustRef(t, nodeAppP, "b").String(): secretstore.ErrSealed}}
		ids, err := newNodeApps(t, store, DeleteSecretsDeps{Secrets: del, Store: &fakeStoreState{}, Log: log}).Remove(ctx, "alice", "N")
		var nse *NodeSecretsError
		want := "The node was removed, but 1 secret of its apps could not be deleted from the secret store and is still in it: " + nodeAppP + "/b."
		if !errors.Is(err, ErrSecretsLeft) || !errors.As(err, &nse) || nse.Sentence != want || err.Error() != want {
			t.Fatalf("err = %v; want %q", err, want)
		}
		if !slices.Equal(ids, []string{nodeAppP, nodeAppR}) || len(del.recorded()) != 3 {
			t.Errorf("ids = %v, deletes = %d; want both ids and every delete tried", ids, len(del.recorded()))
		}
		recs := rec.AtLevel(slog.LevelError)
		if len(recs) != 1 {
			t.Fatalf("%d ERROR records; want 1", len(recs))
		}
		for k, v := range map[string]string{"component": "apps", "event": "apps.node_secrets_destroy_failed", "node_id": "N",
			"user": "alice", "failed": "[" + nodeAppP + "/b]", "err": nodeAppP + "/b: " + secretstore.ErrSealed.Error()} {
			if got, _ := logkittest.Attr(recs[0], k); got != v {
				t.Errorf("%s = %q; want %q", k, got, v)
			}
		}
	})
	t.Run("the database fails", func(t *testing.T) {
		store := seed(t)
		if _, err := store.db.Exec(`DROP TABLE app_secret_refs`); err != nil {
			t.Fatal(err)
		}
		del := &fakeSecretDeleter{}
		ids, err := newNodeApps(t, store, DeleteSecretsDeps{Secrets: del, Store: &fakeStoreState{}, Log: discardLog()}).Remove(ctx, "alice", "N")
		if err == nil || errors.Is(err, ErrSecretsLeft) || ids != nil || len(del.recorded()) != 0 {
			t.Errorf("Remove = %v, %v, %d deletes; want the database error and no delete", ids, err, len(del.recorded()))
		}
	})
	t.Run("no store and no refs", func(t *testing.T) {
		store := newStore(t)
		seedNodeApp(t, store, nodeAppP, "N", composeNaming("a"), "")
		del := &fakeSecretDeleter{}
		ids, err := newNodeApps(t, store, DeleteSecretsDeps{Secrets: del, Store: &fakeStoreState{unconfigured: true}, Log: discardLog()}).Remove(ctx, "alice", "N")
		if err != nil || !slices.Equal(ids, []string{nodeAppP}) || len(del.recorded()) != 0 {
			t.Errorf("Remove = %v, %v, %d deletes; want the id and no delete", ids, err, len(del.recorded()))
		}
	})
}

// TC-783-51: NewNodeApps refuses a nil store and a nil dependency.
func TestNodeApps_TC783_51_NewNodeAppsRefusesNil(t *testing.T) {
	store := newStore(t)
	ok := testSecretDeps()
	for name, tc := range map[string]struct {
		store *Store
		d     DeleteSecretsDeps
	}{
		"nil store":   {nil, ok},
		"nil Secrets": {store, DeleteSecretsDeps{Store: ok.Store, Log: ok.Log}},
		"nil Store":   {store, DeleteSecretsDeps{Secrets: ok.Secrets, Log: ok.Log}},
		"nil Log":     {store, DeleteSecretsDeps{Secrets: ok.Secrets, Store: ok.Store}},
	} {
		if n, err := NewNodeApps(tc.store, tc.d); err == nil || n != nil {
			t.Errorf("%s: NewNodeApps = %v, %v; want a refusal", name, n, err)
		}
	}
}
