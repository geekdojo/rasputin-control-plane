package apps

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// The app-identity switch (geekdojo/geekdojo-brain#1080): off, nothing an
// agent receives changes (appidentity_golden_test.go); granted, the push step
// issues the app its identity once, before the deploy command leaves, and a
// failed issue sends nothing to the node.

// fakeIssuer counts its calls and records the apps it was asked to issue.
// onIssue, when set, runs inside each call, to observe what had already
// happened when the push reached the issuer.
type fakeIssuer struct {
	mu      sync.Mutex
	ids     []string
	err     error
	onIssue func(app *App)
	// revoked records the apps Revoke was asked about, each as id@node;
	// revokeErr fails it.
	revoked   []string
	revokeErr error
}

func (f *fakeIssuer) Revoke(_ context.Context, app *App) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, app.ID+"@"+app.TargetNode)
	return f.revokeErr
}

func (f *fakeIssuer) revokes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.revoked...)
}

func (f *fakeIssuer) Issue(_ context.Context, app *App) error {
	if f.onIssue != nil {
		f.onIssue(app)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ids = append(f.ids, app.ID)
	return f.err
}

func (f *fakeIssuer) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.ids)
}

func (f *fakeIssuer) issued() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ids...)
}

// grant is an AppIdentity with the given tiles granted, calling issuer.
func grant(issuer AppIdentityIssuer, tiles ...string) AppIdentity {
	g := AppIdentity{tiles: map[string]bool{}, issuer: issuer}
	for _, t := range tiles {
		g.tiles[t] = true
	}
	return g
}

// countingDeployAgent answers both deploy subjects on node n with an OK ack,
// and records, for each command, the issuer's call count at the moment it
// arrived.
func countingDeployAgent(t *testing.T, nc *nats.Conn, issuer *fakeIssuer) <-chan int {
	t.Helper()
	seen := make(chan int, 4)
	for _, subject := range []string{proto.AppDeploySubject("n"), proto.AppDeploySecretsSubject("n")} {
		sub, err := nc.Subscribe(subject, func(m *nats.Msg) {
			seen <- issuer.calls()
			b, _ := json.Marshal(proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
			_ = m.Respond(b)
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = sub.Unsubscribe() })
	}
	return seen
}

// TC-1080-03, as #1081 changes it: nothing outside the package can grant a
// tile or set an issuer except through NewAppIdentity, which refuses a grant
// with no issuer (TC-1081-06). AppIdentity exposes no field, and its only
// exported methods read the switch: Granted and Any.
func TestAppIdentity_ExposesNothingThatCouldGrant(t *testing.T) {
	typ := reflect.TypeOf(AppIdentity{})
	for i := range typ.NumField() {
		if f := typ.Field(i); f.IsExported() {
			t.Errorf("AppIdentity exports field %s", f.Name)
		}
	}
	for _, ty := range []reflect.Type{typ, reflect.PointerTo(typ)} {
		var names []string
		for i := range ty.NumMethod() {
			names = append(names, ty.Method(i).Name)
		}
		if !reflect.DeepEqual(names, []string{"Any", "Granted"}) {
			t.Errorf("%s exports methods %v, want only the readers [Any Granted]", ty, names)
		}
	}
}

// TC-1080-04: with an issuer present and no tile granted, neither a catalog
// app nor a custom app is issued, and the agent receives the same bytes as
// the goldens recorded before the switch existed.
func TestAppIdentity_NothingGrantedIssuesNothingAndChangesNoBytes(t *testing.T) {
	issuer := &fakeIssuer{}
	build := func(store *Store, inv *inventory.Store, nc *nats.Conn, secrets SecretSource) (jobs.Workflow, error) {
		return DeployWorkflow(store, inv, nc, nil, secrets, AppIdentity{issuer: issuer})
	}
	for _, c := range deployGoldenCases() {
		if c.name != "plain-tile" && c.name != "custom-app" {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			got, data := deployGoldenWire(t, build, c)
			want, err := os.ReadFile(filepath.Join(deployGoldenDir, c.name+".golden"))
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Errorf("the agent received different bytes with an issuer present: %s", data)
			}
		})
	}
	if n := issuer.calls(); n != 0 {
		t.Errorf("Issue called %d times with no tile granted", n)
	}
}

// TC-1080-05: the zero value (no tile set, no issuer) pushes a catalog app
// without reaching the nil issuer.
func TestAppIdentity_ZeroValuePushesWithoutAnIssuer(t *testing.T) {
	build := func(store *Store, inv *inventory.Store, nc *nats.Conn, secrets SecretSource) (jobs.Workflow, error) {
		return DeployWorkflow(store, inv, nc, nil, secrets, AppIdentity{})
	}
	// deployGoldenWire fails the test if the push returns an error or the
	// agent never acks; a nil issuer reached would panic.
	deployGoldenWire(t, build, deployGoldenCases()[0])
	if granted, err := (AppIdentity{}).issue(context.Background(), &App{ID: testAppID, SourceTile: "minecraft"}); err != nil || granted {
		t.Errorf("the zero value issued: granted=%v err=%v", granted, err)
	}
}

// TC-1080-06: a granted tile is issued exactly once per push, with the pushed
// app, in every saga that can carry a catalog app, and before its deploy
// command reaches the agent. For the deploy saga, also before DEPLOYING is
// recorded and announced; revert and upgrade have marked it in their pull.
func TestAppIdentity_GrantedTileIsIssuedOnceBeforeThePush(t *testing.T) {
	sagas := []struct {
		name string
		seed func(t *testing.T) (*Store, *inventory.Store)
		run  func(t *testing.T, store *Store, inv *inventory.Store, nc *nats.Conn, identity AppIdentity) (string, error)
	}{
		{"deploy",
			func(t *testing.T) (*Store, *inventory.Store) { return seedUpgradeApp(t, testAppID) },
			func(t *testing.T, store *Store, inv *inventory.Store, nc *nats.Conn, identity AppIdentity) (string, error) {
				return runSteps(t, wf(t)(DeployWorkflow(store, inv, nc, nil, testSource(t), identity)), nc, testAppID)
			}},
		{"revert",
			func(t *testing.T) (*Store, *inventory.Store) {
				store, inv, _, _ := upgradedToV2(t)
				return store, inv
			},
			func(t *testing.T, store *Store, inv *inventory.Store, nc *nats.Conn, identity AppIdentity) (string, error) {
				fakePullAgent(t, nc, proto.AppPullAck{OK: true}, nil)
				r := runWorkflow(t, wf(t)(RevertWorkflow(store, inv, nc, nil, testSource(t), identity)), nc, revertSpec(testAppID, composeV1), "job-test")
				return r.failedAt, r.err
			}},
		{"upgrade",
			func(t *testing.T) (*Store, *inventory.Store) { return seedUpgradeApp(t, testAppID) },
			func(t *testing.T, store *Store, inv *inventory.Store, nc *nats.Conn, identity AppIdentity) (string, error) {
				fakePullAgent(t, nc, proto.AppPullAck{OK: true}, nil)
				w := wf(t)(UpgradeWorkflow(store, inv, nc, nil, lookupOf(upgradeTile(composeV2), 2), testSource(t), testSecretDeps(), identity))
				return runSteps(t, w, nc, testAppID)
			}},
	}
	for _, s := range sagas {
		t.Run(s.name, func(t *testing.T) {
			nc := startNATS(t)
			store, inv := s.seed(t)
			issuer := &fakeIssuer{}
			seen := countingDeployAgent(t, nc, issuer)

			// The deploy saga's DEPLOYING mark is its status write and its change
			// event. Both are read from inside the issuer, so they are what had
			// happened when the push reached it. The flush makes any change
			// event already published on this connection land in the pending
			// count first.
			changes, err := nc.SubscribeSync(proto.AppChangeSubject(testAppID, proto.AppDeploying))
			if err != nil {
				t.Fatal(err)
			}
			var statusAtIssue proto.AppStatus
			announcedAtIssue := -1
			issuer.onIssue = func(app *App) {
				if row, err := store.Get(context.Background(), app.ID); err == nil && row != nil {
					statusAtIssue = row.LastStatus
				}
				if err := nc.Flush(); err != nil {
					t.Error(err)
				}
				announcedAtIssue, _, _ = changes.Pending()
			}

			if step, err := s.run(t, store, inv, nc, grant(issuer, "uptime-kuma")); err != nil {
				t.Fatalf("failed at %s: %v", step, err)
			}
			if got := issuer.issued(); len(got) != 1 || got[0] != testAppID {
				t.Fatalf("issued %v, want exactly [%s]", got, testAppID)
			}
			if n := receiveWithin(t, seen, "the agent never received a deploy command"); n != 1 {
				t.Errorf("the agent received the deploy command when Issue had been called %d times, want 1", n)
			}
			if s.name == "deploy" {
				if statusAtIssue != proto.AppStatusRunning {
					t.Errorf("status when issued = %q, want the seeded running: DEPLOYING was recorded first", statusAtIssue)
				}
				if announcedAtIssue != 0 {
					t.Errorf("%d DEPLOYING change events were published before the app was issued its identity", announcedAtIssue)
				}
			}
		})
	}
}

// TC-1080-07: edit is a custom-app saga, so it never issues, even with a
// tile granted whose id is the custom app's name.
func TestAppIdentity_EditNeverIssues(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedCustomApp(t, testAppID)
	fakePullAgent(t, nc, proto.AppPullAck{OK: true}, nil)
	deploys := fakeDeployAgent(t, nc, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
	issuer := &fakeIssuer{}
	stash := NewComposeStash()
	const jobID = "01JOBEDIT0000000000000000A"
	if err := stash.Put(jobID, customV2); err != nil {
		t.Fatal(err)
	}
	w := wf(t)(EditWorkflow(store, inv, nc, nil, stash, testSource(t), testSecretDeps(), grant(issuer, "mine")))
	run := runWorkflow(t, w, nc, `{"appId":"`+testAppID+`"}`, jobID)
	if run.err != nil {
		t.Fatalf("edit failed at %s: %v", run.failedAt, run.err)
	}
	if _, ok := run.results["push"]; !ok {
		t.Error("the edit's push step recorded no ack")
	}
	if cmd := receiveWithin(t, deploys, "the edit's deploy never reached the agent"); cmd.ComposeYAML != customV2 {
		t.Errorf("pushed %q, want the edited compose", cmd.ComposeYAML)
	}
	if n := issuer.calls(); n != 0 {
		t.Errorf("Issue called %d times for an edit", n)
	}
}

// TC-1080-08: a custom app is never granted, even when a granted tile id
// equals its name: not on deploy, and not on a re-apply.
func TestAppIdentity_CustomAppIsNeverGranted(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedCustomApp(t, testAppID)
	fakePullAgent(t, nc, proto.AppPullAck{OK: true}, nil)
	deploys := fakeDeployAgent(t, nc, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
	issuer := &fakeIssuer{}
	identity := grant(issuer, "mine")

	if step, err := runSteps(t, wf(t)(DeployWorkflow(store, inv, nc, nil, testSource(t), identity)), nc, testAppID); err != nil {
		t.Fatalf("deploy failed at %s: %v", step, err)
	}
	receiveWithin(t, deploys, "the deploy never reached the agent")

	if err := store.EditCompose(ctx, testAppID, ComposeHash(customV1), customV2, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	r := runWorkflow(t, wf(t)(RevertWorkflow(store, inv, nc, nil, testSource(t), identity)), nc, revertSpec(testAppID, customV1), "job-test")
	if r.err != nil {
		t.Fatalf("re-apply failed at %s: %v", r.failedAt, r.err)
	}
	receiveWithin(t, deploys, "the re-apply never reached the agent")

	if n := issuer.calls(); n != 0 {
		t.Errorf("Issue called %d times for a custom app", n)
	} // Not even by a grant of the empty tile id, which is what a custom app's
	// row carries.
	if grant(issuer, "").Granted(&App{ID: testAppID, Name: "mine"}) {
		t.Error("a grant of the empty tile id grants a custom app")
	}
}

// TC-1080-09: only the granted tile is issued.
func TestAppIdentity_OnlyTheGrantedTileIsIssued(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedUpgradeApp(t, testAppID) // installed from uptime-kuma
	fakeDeployAgent(t, nc, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
	issuer := &fakeIssuer{}
	if step, err := runSteps(t, wf(t)(DeployWorkflow(store, inv, nc, nil, testSource(t), grant(issuer, "pi-hole"))), nc, testAppID); err != nil {
		t.Fatalf("deploy failed at %s: %v", step, err)
	}
	if n := issuer.calls(); n != 0 {
		t.Errorf("Issue called %d times for an app from a tile that is not granted", n)
	}
}

var errIssuerDown = errors.New("issuer unreachable")

// silentDeployAgent subscribes to both deploy subjects of node n and answers
// nothing: a test that expects no command counts what arrived.
func silentDeployAgent(t *testing.T, nc *nats.Conn) []*nats.Subscription {
	t.Helper()
	var subs []*nats.Subscription
	for _, subject := range []string{proto.AppDeploySubject("n"), proto.AppDeploySecretsSubject("n")} {
		sub, err := nc.SubscribeSync(subject)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = sub.Unsubscribe() })
		subs = append(subs, sub)
	}
	return subs
}

// receivedBy is how many messages subs hold once everything published on nc
// has been delivered.
func receivedBy(t *testing.T, nc *nats.Conn, subs []*nats.Subscription) int {
	t.Helper()
	n := 0
	for _, sub := range subs {
		n += pendingAfterFlush(t, nc, sub)
	}
	return n
}

// pendingAfterFlush is sub's pending message count once everything published
// on nc has been delivered.
func pendingAfterFlush(t *testing.T, nc *nats.Conn, sub *nats.Subscription) int {
	t.Helper()
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	n, _, err := sub.Pending()
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TC-1080-10: a failed issue refuses the deploy closed. The error is wrapped
// with the app, nothing reaches the node, and the app is left where it was:
// its status unchanged and no DEPLOYING announced.
func TestAppIdentity_AFailedIssueRefusesTheDeploy(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedUpgradeApp(t, testAppID)
	before, err := store.Get(ctx, testAppID)
	if err != nil {
		t.Fatal(err)
	}
	agent := silentDeployAgent(t, nc)
	changes, err := nc.SubscribeSync(proto.AppChangeSubject(testAppID, proto.AppDeploying))
	if err != nil {
		t.Fatal(err)
	}
	issuer := &fakeIssuer{err: errIssuerDown}
	w := wf(t)(DeployWorkflow(store, inv, nc, nil, testSource(t), grant(issuer, "uptime-kuma")))

	_, err = workflowStep(t, w, "push")(newStepCtxNATS(`{"appId":"`+testAppID+`"}`, nc))
	if err == nil {
		t.Fatal("the deploy went ahead although the issuer failed")
	}
	if !errors.Is(err, errIssuerDown) {
		t.Errorf("error %v does not wrap the issuer's", err)
	}
	if want := "apps: issue the identity of " + testAppID + ": "; !strings.HasPrefix(err.Error(), want) {
		t.Errorf("error %q, want it to start %q", err, want)
	}
	after, err := store.Get(ctx, testAppID)
	if err != nil {
		t.Fatal(err)
	}
	if after.LastStatus != before.LastStatus {
		t.Errorf("status = %s, want %s left as it was", after.LastStatus, before.LastStatus)
	}
	if n := receivedBy(t, nc, agent); n != 0 {
		t.Errorf("the agent received %d messages", n)
	}
	if n := pendingAfterFlush(t, nc, changes); n != 0 {
		t.Errorf("%d DEPLOYING change events were published", n)
	}
}

// TC-1080-11: in a compose-change saga a failed issue fails the push, and
// nothing reaches the node. The status the pull's DEPLOYING mark leaves is
// not asserted (F-1080-01, left to #1081).
func TestAppIdentity_AFailedIssueSendsTheUpgradeNothing(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedUpgradeApp(t, testAppID)
	fakePullAgent(t, nc, proto.AppPullAck{OK: true}, nil)
	agent := silentDeployAgent(t, nc)
	issuer := &fakeIssuer{err: errIssuerDown}
	w := wf(t)(UpgradeWorkflow(store, inv, nc, nil, lookupOf(upgradeTile(composeV2), 2), testSource(t), testSecretDeps(), grant(issuer, "uptime-kuma")))

	step, err := runSteps(t, w, nc, testAppID)
	if step != "push" || !errors.Is(err, errIssuerDown) {
		t.Fatalf("want the push to fail with the issuer's error, got step=%q err=%v", step, err)
	}
	if n := receivedBy(t, nc, agent); n != 0 {
		t.Errorf("the agent received %d deploy commands", n)
	}
}
