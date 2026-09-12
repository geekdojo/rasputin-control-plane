package apps

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// invalidAppIDs are appId values that are not shaped like an app id: too
// short, the wrong alphabet, and ids carrying path separators or dot
// segments, including ones padded to an app id's length.
var invalidAppIDs = []string{
	"a",
	"not-an-app-id",
	".",
	"..",
	"x/y",
	"../x",
	"x/../y",
	"/x",
	`x\y`,
	"01J8Z3K5QW6X7Y8Z9A0B1C/../",
	"01J8Z3K5QW6X7Y8Z9A0B1C2D..",
	"01J8Z3K5QW6X7Y8Z9A0B1C2D3/",
	"01J8Z3K5QW6X7Y8Z9A0B1C2D3",   // 25 characters
	"01J8Z3K5QW6X7Y8Z9A0B1C2D3EF", // 27 characters
	"01J8Z3K5QW6X7Y8Z9A0B1C2D3U",  // U is outside the alphabet
}

func deleteSpecFor(t *testing.T, appID string) string {
	t.Helper()
	b, err := json.Marshal(DeleteSpec{AppID: appID})
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	return string(b)
}

func TestParseDeleteSpec_RejectsInvalidAppID(t *testing.T) {
	for _, id := range invalidAppIDs {
		if _, err := parseDeleteSpec(json.RawMessage(deleteSpecFor(t, id))); err == nil {
			t.Errorf("parseDeleteSpec accepted appId %q", id)
		}
	}
	if _, err := parseDeleteSpec(json.RawMessage(`{}`)); err == nil {
		t.Error("parseDeleteSpec accepted a spec with no appId")
	}
	// Either case is an app id.
	for _, id := range []string{delAppID, strings.ToLower(delAppID)} {
		spec, err := parseDeleteSpec(json.RawMessage(deleteSpecFor(t, id)))
		if err != nil || spec.AppID != id {
			t.Errorf("parseDeleteSpec(%q) = %+v, %v; want accepted", id, spec, err)
		}
	}
}

// Every step of the delete saga refuses a spec whose appId is not an app id:
// no leaf removal, no row removed, no change event.
func TestDeleteWorkflow_InvalidAppIDRemovesNothing(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", delAppID, "immich")

	events, err := nc.SubscribeSync(">")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer func() { _ = events.Unsubscribe() }()

	var removed []string
	rm := func(appID string) error { removed = append(removed, appID); return nil }

	for _, id := range invalidAppIDs {
		spec := deleteSpecFor(t, id)
		if _, err := deleteStop(store, inv, nc)(newStepCtxNATS(spec, nc)); err == nil {
			t.Errorf("stop step accepted appId %q", id)
		}
		if _, err := deleteLeaf(store, inv, nc, rm)(newStepCtxNATS(spec, nc)); err == nil {
			t.Errorf("teardown_leaf step accepted appId %q", id)
		}
		if _, err := deleteRemove(store, nc)(newStepCtxNATS(spec, nc)); err == nil {
			t.Errorf("remove step accepted appId %q", id)
		}
	}

	if len(removed) != 0 {
		t.Errorf("leaf removal ran for %q", removed)
	}
	if got, _ := store.Get(ctx, delAppID); got == nil {
		t.Error("an unrelated app row was removed")
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if msg, err := events.NextMsg(200 * time.Millisecond); err == nil {
		t.Errorf("a refused spec published %q", msg.Subject)
	}
}

// A well-formed id with no app row owns no leaf material: the leaf step
// succeeds, so a retried delete still completes, and removes nothing.
func TestDeleteLeaf_UnknownAppRemovesNothing(t *testing.T) {
	nc := startNATS(t)
	store := newStore(t)
	inv := newInventory(t)

	called := false
	rm := func(string) error { called = true; return nil }
	if _, err := deleteLeaf(store, inv, nc, rm)(newStepCtxNATS(deleteSpecFor(t, missingAppID), nc)); err != nil {
		t.Fatalf("deleteLeaf on an unknown app should succeed: %v", err)
	}
	if called {
		t.Error("leaf removal ran for an app with no row")
	}
}

// An app whose node is gone or de-registered has nothing to tear down on the
// node, but its control-plane leaf directory is still removed, by the row's id.
func TestDeleteLeaf_GoneNodeStillRemovesAppLeaf(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStore(t)
	inv := newInventory(t)
	a := makeApp(delAppID, "jellyfin")
	a.TargetNode = "gone"
	if err := store.Create(ctx, a); err != nil {
		t.Fatalf("Create app: %v", err)
	}

	var removed []string
	rm := func(appID string) error { removed = append(removed, appID); return nil }
	if _, err := deleteLeaf(store, inv, nc, rm)(newStepCtxNATS(deleteSpecFor(t, delAppID), nc)); err != nil {
		t.Fatalf("deleteLeaf with the node gone should succeed: %v", err)
	}
	if len(removed) != 1 || removed[0] != delAppID {
		t.Errorf("leaf removal ran for %q, want exactly [%q]", removed, delAppID)
	}

	// Registered but no longer a compute node: the same cleanup applies.
	if err := inv.Insert(ctx, &proto.Node{
		ID: "gone", Role: proto.RoleStorage, Hostname: "gone.test",
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("inv insert: %v", err)
	}
	removed = nil
	if _, err := deleteLeaf(store, inv, nc, rm)(newStepCtxNATS(deleteSpecFor(t, delAppID), nc)); err != nil {
		t.Fatalf("deleteLeaf with a non-compute node should succeed: %v", err)
	}
	if len(removed) != 1 || removed[0] != delAppID {
		t.Errorf("leaf removal ran for %q, want exactly [%q]", removed, delAppID)
	}
}
