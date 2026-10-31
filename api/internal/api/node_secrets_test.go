package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/console"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/oklog/ulid/v2"
)

// geekdojo/geekdojo-brain#783: DELETE /api/nodes/{id} removes the node's apps
// and every secret they had in the store, or refuses with nothing changed.

// fakeAppStoreState is apps.SecretStoreState with a fixed answer. The zero
// value is a configured store reading Ready.
type fakeAppStoreState struct {
	mu           sync.Mutex
	unconfigured bool
	state        storestate.State
	reads        int
}

func (f *fakeAppStoreState) Configured() bool { return !f.unconfigured }

func (f *fakeAppStoreState) State(context.Context) (storestate.State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.state == "" {
		return storestate.Ready, nil
	}
	return f.state, nil
}

func (f *fakeAppStoreState) set(st storestate.State) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state = st
}

func (f *fakeAppStoreState) stateReads() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads
}

// fakeAppSecretDeleter records every Delete; onDelete, when set, runs first.
type fakeAppSecretDeleter struct {
	mu       sync.Mutex
	refs     []secrets.Ref
	onDelete func(ctx context.Context)
}

func (f *fakeAppSecretDeleter) Delete(ctx context.Context, _ secrets.Actor, r secrets.Ref) error {
	if f.onDelete != nil {
		f.onDelete(ctx)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refs = append(f.refs, r)
	return nil
}

func (f *fakeAppSecretDeleter) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.refs)
}

// testAppSecretDeps is a DeleteSecretsDeps over a ready store and a deleter
// that succeeds.
func testAppSecretDeps() apps.DeleteSecretsDeps {
	return apps.DeleteSecretsDeps{Secrets: &fakeAppSecretDeleter{}, Store: &fakeAppStoreState{}, Log: slog.New(slog.DiscardHandler)}
}

// fakeRemover is a nodeAppRemover with fixed answers.
type fakeRemover struct {
	checkErr  error
	removeIDs []string
	removeErr error
}

func (f *fakeRemover) CheckSecrets(context.Context, string) error { return f.checkErr }
func (f *fakeRemover) Remove(context.Context, string, string) ([]string, error) {
	return f.removeIDs, f.removeErr
}

// seedSecretApp adds an app on nodeID whose compose names db-password, with
// its ref recorded, and a bound bus token for the node.
func seedSecretApp(t *testing.T, f *apiFixture, nodeID string) string {
	t.Helper()
	now := time.Now().UTC()
	id := ulid.Make().String()
	if err := f.appsStore.Create(f.ctx, &apps.App{
		ID: id, Name: "secret-" + nodeID, TargetNode: nodeID, LastStatus: proto.AppStatusRunning, CreatedAt: now, UpdatedAt: now,
		ComposeYAML: "services:\n  web:\n    image: me/web:1\n    environment:\n      P: ${secret:db-password}\n",
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.appsStore.RecordSecretRef(f.ctx, id, "db-password"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.srv.busTokens.MintBound(f.ctx, "compute", nodeID, proto.RoleCompute); err != nil {
		t.Fatal(err)
	}
	return id
}

// assertNodeUntouched checks a refused removal changed nothing.
func assertNodeUntouched(t *testing.T, f *apiFixture, nodeID, hsID string, appIDs ...string) {
	t.Helper()
	if _, ok := f.meshFake.nodes[hsID]; !ok {
		t.Error("Headscale was asked to delete the node")
	}
	if n, err := f.inv.Get(f.ctx, nodeID); err != nil || n == nil {
		t.Errorf("inventory row gone: %v", err)
	}
	for _, id := range appIDs {
		if a, err := f.appsStore.Get(f.ctx, id); err != nil || a == nil {
			t.Errorf("app %s gone: %v", id, err)
		}
	}
	if ns, err := f.fw.GetNodeState(f.ctx, nodeID); err != nil || ns == nil || ns.NodeID == "" {
		t.Errorf("firewall state gone: %v", err)
	}
	if live, err := f.srv.busTokens.NodeHasLiveToken(f.ctx, nodeID); err != nil || !live {
		t.Errorf("bus token revoked: live=%v err=%v", live, err)
	}
}

// TC-783-52: with the store sealed, removing a node with a secret-bearing app
// answers 503 node_secrets_unavailable with the sentence and a correlation
// id, and nothing is removed or revoked.
func TestDeleteNode_TC783_52_StoreNotReadyRefusesWithNothingChanged(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	plainID, hsID := seedNodeWithCascade(t, f, "node-s")
	secretID := seedSecretApp(t, f, "node-s")
	f.secretState.set(storestate.Sealed)

	w := f.do(t, http.MethodDelete, "/api/nodes/node-s", "", c)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d %s", w.Code, w.Body.String())
	}
	body := decodeBody[codedError](t, w.Body.String())
	want := "The secret store " + storestate.Clause(storestate.Sealed) + ", so the secrets of the node's apps could not be deleted; the node was not removed. Retry when the store is ready."
	if body.Code != codeNodeSecretsUnavailable || body.Error != want || body.CorrelationID == "" {
		t.Errorf("body = %+v; want code %s, %q and a correlation id", body, codeNodeSecretsUnavailable, want)
	}
	assertNodeUntouched(t, f, "node-s", hsID, plainID, secretID)
	if refs, _ := f.appsStore.SecretRefNames(f.ctx, secretID); len(refs) != 1 {
		t.Errorf("refs = %v; want kept", refs)
	}
	if f.secretDeleter.calls() != 0 {
		t.Error("a secret was deleted")
	}
}

// TC-783-57: a ref read that fails refuses the removal with 500
// node_secrets_unreadable and the sentence, and nothing is removed.
func TestDeleteNode_TC783_57_UnreadableRefsRefuse(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	appID, hsID := seedNodeWithCascade(t, f, "node-u")
	if _, _, err := f.srv.busTokens.MintBound(f.ctx, "compute", "node-u", proto.RoleCompute); err != nil {
		t.Fatal(err)
	}
	const sentence = "The recorded secrets of the node's apps could not be read, so the node was not removed."
	f.srv.nodeApps = &fakeRemover{checkErr: &apps.NodeSecretsError{Kind: apps.ErrNodeSecretsUnreadable, Sentence: sentence, Cause: errors.New("disk I/O error")}}

	w := f.do(t, http.MethodDelete, "/api/nodes/node-u", "", c)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d %s", w.Code, w.Body.String())
	}
	body := decodeBody[codedError](t, w.Body.String())
	if body.Code != codeNodeSecretsUnreadable || body.Error != sentence || strings.Contains(w.Body.String(), "disk I/O") {
		t.Errorf("body = %s; want the code and the sentence, without the cause", w.Body.String())
	}
	assertNodeUntouched(t, f, "node-u", hsID, appID)
}

// TC-783-53: when only secret deletes fail, the removal completes (events,
// firewall state, tokens, inventory, console record) and answers 500
// node_secrets_left with the sentence.
func TestDeleteNode_TC783_53_RemovalCompletesWhenDeletesFail(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	appID, _ := seedNodeWithCascade(t, f, "node-l")
	if _, _, err := f.srv.busTokens.MintBound(f.ctx, "compute", "node-l", proto.RoleCompute); err != nil {
		t.Fatal(err)
	}
	if err := f.console.RecordNode(f.ctx, console.NodeState{NodeID: "node-l", Status: console.NodeApplied, UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	const sentence = "The node was removed, but 1 secret of its apps could not be deleted from the secret store and is still in it: P/b."
	f.srv.nodeApps = &fakeRemover{removeIDs: []string{appID, "other-app"}, removeErr: &apps.NodeSecretsError{Kind: apps.ErrSecretsLeft, Sentence: sentence}}
	subA := subscribeOne(t, f.nc, proto.AppChangeSubject(appID, proto.AppDeleted))
	subB := subscribeOne(t, f.nc, proto.AppChangeSubject("other-app", proto.AppDeleted))

	w := f.do(t, http.MethodDelete, "/api/nodes/node-l", "", c)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d %s", w.Code, w.Body.String())
	}
	body := decodeBody[codedError](t, w.Body.String())
	if body.Code != codeNodeSecretsLeft || body.Error != sentence {
		t.Errorf("body = %+v; want %s and the sentence", body, codeNodeSecretsLeft)
	}
	if !subA.wait(2*time.Second) || !subB.wait(2*time.Second) {
		t.Error("an app-deleted event is missing")
	}
	if n, _ := f.inv.Get(f.ctx, "node-l"); n != nil {
		t.Error("inventory row survived")
	}
	if ns, _ := f.fw.GetNodeState(f.ctx, "node-l"); ns != nil && ns.NodeID != "" {
		t.Error("firewall state survived")
	}
	if live, _ := f.srv.busTokens.NodeHasLiveToken(f.ctx, "node-l"); live {
		t.Error("bus token not revoked")
	}
	st, err := f.console.Status(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range st.Nodes {
		if n.NodeID == "node-l" {
			t.Error("console record not forgotten")
		}
	}
}

// TC-783-54: a node whose apps name no secret is removed as before, with the
// store sealed, and the store's state is never read.
func TestDeleteNode_TC783_54_NoSecretsNeverReadsTheStore(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	appID, _ := seedNodeWithCascade(t, f, "node-p")
	f.secretState.set(storestate.Sealed)

	w := f.do(t, http.MethodDelete, "/api/nodes/node-p", "", c)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d %s", w.Code, w.Body.String())
	}
	impact := decodeBody[nodeRemovalImpact](t, w.Body.String())
	if impact.NodeID != "node-p" || len(impact.AppIDs) != 1 || impact.AppIDs[0] != appID {
		t.Errorf("impact = %+v", impact)
	}
	if f.secretState.stateReads() != 0 || f.secretDeleter.calls() != 0 {
		t.Errorf("state reads = %d, deletes = %d; want none", f.secretState.stateReads(), f.secretDeleter.calls())
	}
}

// TC-783-61 (F-783-22 ruling): the Headscale delete, the bus-token revoke
// and the inventory removal all happen before the first store delete, and
// the deletes outlive a cancelled request.
func TestDeleteNode_TC783_61_RevokeFirstDeletesOutliveTheRequest(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	_, hsID := seedNodeWithCascade(t, f, "node-r")
	secretID := seedSecretApp(t, f, "node-r")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	var meshGone, tokensRevoked, inventoryGone bool
	var deleteCtxErr error
	first := true
	f.secretDeleter.onDelete = func(dctx context.Context) {
		if !first {
			return
		}
		first = false
		_, inMesh := f.meshFake.nodes[hsID]
		meshGone = !inMesh
		live, _ := f.srv.busTokens.NodeHasLiveToken(context.Background(), "node-r")
		tokensRevoked = !live
		n, _ := f.inv.Get(context.Background(), "node-r")
		inventoryGone = n == nil
		close(entered)
		<-release
		deleteCtxErr = dctx.Err()
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/nodes/node-r", nil).WithContext(ctx)
	req.AddCookie(c)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.handler.ServeHTTP(w, req)
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the store delete never started")
	}
	cancel()
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the removal never finished")
	}
	if !meshGone || !tokensRevoked || !inventoryGone {
		t.Errorf("at the first store delete: headscale deleted=%v, tokens revoked=%v, inventory removed=%v; want all", meshGone, tokensRevoked, inventoryGone)
	}
	if deleteCtxErr != nil {
		t.Errorf("the delete's context was cancelled with the request: %v", deleteCtxErr)
	}
	if f.secretDeleter.calls() != 1 {
		t.Errorf("deletes = %d; want 1", f.secretDeleter.calls())
	}
	if a, _ := f.appsStore.Get(context.Background(), secretID); a != nil {
		t.Error("the secret-bearing app survived")
	}
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d %s", w.Code, w.Body.String())
	}
}

// TC-783-55: a compose change records the session user as the job's
// created_by, for an upgrade, an edit and a revert.
func TestAppsCompose_TC783_55_RecordsTheOperator(t *testing.T) {
	f, cookie, _, _ := upgradeFixture(t)
	seedUpgradeApp(t, f, "cat", "vw", "vaultwarden", "services: {old: {}}\n", 3)
	seedUpgradeApp(t, f, "custom", "mine", "", customOld, 0)
	seedUpgradeApp(t, f, "back", "back", "", customOld, 0)
	if err := f.appsStore.EditCompose(f.ctx, "back", apps.ComposeHash(customOld), "services:\n  web:\n    image: me/web:3\n", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ kind, id, body string }{
		{"app.upgrade", "cat", catalogBody},
		{"app.edit", "custom", composeYAMLBody(t, "services:\n  web:\n    image: me/web:2\n")},
		{"app.revert", "back", shaBody(customOld)},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			w := f.do(t, http.MethodPut, "/api/apps/"+tc.id+"/compose", tc.body, cookie)
			if w.Code != http.StatusAccepted {
				t.Fatalf("want 202, got %d %s", w.Code, w.Body.String())
			}
			job := decodeBody[jobs.Job](t, w.Body.String())
			got, err := f.jobsStore.GetJob(f.ctx, job.ID)
			if err != nil || got == nil || got.Kind != tc.kind || got.CreatedBy != "alice" {
				t.Errorf("job = %+v, %v; want %s created by alice", got, err, tc.kind)
			}
		})
	}
	waitForJobs(t, f.runner)
}
