package apprelay_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apprelay"
	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bustls/bustlstest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storepolicy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storesession"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstoretest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/nats-io/nats.go"
)

// The functional switch and binary are the secret store smoke test's
// (docs/testing-secret-store.md); this test is documented in
// docs/testing-app-relay.md.
const (
	binEnv    = "RASPUTIN_SECRETSTORE_BIN"
	switchEnv = "RASPUTIN_SECRETSTORE_FUNCTIONAL"
)

const (
	fnAppA  = "01J9ZK3Q0M8X7Y6W5V4T3S2R1A"
	fnAppB  = "01J9ZK3Q0M8X7Y6W5V4T3S2R1B"
	fnNodeN = "nodea"
	fnNodeM = "nodeb"
	fnTile  = "relay-tile"
	// The values the test writes; the log and job scans search for each.
	fnValue1 = "sentinel-relay-value-one-1081"
	fnValue2 = "sentinel-relay-value-two-1081"
	fnPushed = "sentinel-pushed-value-1081"
)

// appNodes is secrets.AppTargets over the apps store, as main's is.
type appNodes struct{ s *apps.Store }

func (a appNodes) TargetNode(ctx context.Context, id string) (string, bool, error) {
	app, err := a.s.Get(ctx, id)
	if err != nil || app == nil {
		return "", false, err
	}
	return app.TargetNode, true, nil
}

// noSwitch is a secrets.Switch: only operator writes set the marker, and the
// test's one operator write does not need it recorded.
type noSwitch struct{}

func (noSwitch) MarkSwitched(context.Context) error { return nil }

// readyStore is apps.SecretStoreState for a store that is configured and
// ready.
type readyStore struct{}

func (readyStore) Configured() bool { return true }
func (readyStore) State(context.Context) (storestate.State, error) {
	return storestate.Ready, nil
}

// busHost is a non-loopback IPv4 address, where the auth callout checks the
// join token; loopback mints the same scope without checking it.
func busHost() string {
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if ip4 := ipn.IP.To4(); ip4 != nil && !ip4.IsLoopback() && !ip4.IsLinkLocalUnicast() {
					return ip4.String()
				}
			}
		}
	}
	return "127.0.0.1"
}

// TC-1081-27: the scope rule end to end. A bus enforcing the auth callout
// with credentials minted for nodes N and M; the real secrets service on the
// real chain against the pinned OpenBao under the shipped rasputin-api
// policy; the relay endpoint and service as main wires them; and the real
// delete saga.
func TestAppRelay_ScopeRuleAgainstTheRealStore(t *testing.T) {
	bin := os.Getenv(binEnv)
	if bin == "" {
		functest.SkipOrFail(t, switchEnv, "%s is not set, so there is no secret store binary to run", binEnv)
		return
	}
	if _, err := os.Stat(bin); err != nil {
		functest.SkipOrFail(t, switchEnv, "%s=%s: no secret store binary there: %v", binEnv, bin, err)
		return
	}
	ctx := context.Background()
	log, rec := logkittest.New()
	dir := t.TempDir()

	// The real store chain, as the secrets functional test builds it.
	apiPolicy, err := storepolicy.Text(storepolicy.APIPolicy)
	if err != nil {
		t.Fatal(err)
	}
	h, err := secretstoretest.New(secretstoretest.Config{BinaryPath: bin, TempParent: t.TempDir(), Logger: slog.New(slog.DiscardHandler), Now: time.Now, Rand: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	st, err := h.StartWith(t.Context(), secretstoretest.Bootstrap{Mount: storepolicy.Mount, Roles: []secretstoretest.Role{
		{Name: storepolicy.APIPolicy, Policy: storepolicy.APIPolicy, PolicyText: apiPolicy},
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close(context.Background()) })
	sess := realSession(t, st, log)
	repo, err := secrets.NewRepository(sess)
	if err != nil {
		t.Fatal(err)
	}

	// The apps and inventory stores: A granted on N, B granted on M.
	appStore, err := apps.OpenStore(ctx, filepath.Join(dir, "apps.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = appStore.Close() })
	inv, err := inventory.OpenStore(ctx, filepath.Join(dir, "inv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inv.Close() })
	now := time.Now().UTC()
	for _, n := range []string{fnNodeN, fnNodeM} {
		if err := inv.Insert(ctx, &proto.Node{ID: n, Role: proto.RoleCompute, Hostname: n + ".test", FirstSeen: now, LastSeen: now}); err != nil {
			t.Fatal(err)
		}
	}
	for id, node := range map[string]string{fnAppA: fnNodeN, fnAppB: fnNodeM} {
		if err := appStore.Create(ctx, &apps.App{ID: id, Name: "app-" + id[len(id)-1:], ComposeYAML: "services: {}\n", TargetNode: node,
			SourceTile: fnTile, LastStatus: proto.AppStatusRunning, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	svc, err := secrets.NewService(secrets.Deps{Repo: repo, Apps: appNodes{s: appStore}, Switch: noSwitch{}, Log: log})
	if err != nil {
		t.Fatal(err)
	}

	// The bus, enforcing the callout, with tokens bound to N and M.
	issuer, err := busauth.EnsureIssuer(filepath.Join(dir, "bus"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "nats"), 0o755); err != nil {
		t.Fatal(err)
	}
	tokens, err := busauth.OpenStore(ctx, filepath.Join(dir, "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tokens.Close() })
	kit := bustlstest.Bus(t)
	srv, err := bus.Start(ctx, bus.Config{Host: busHost(), Port: -1, StoreDir: filepath.Join(dir, "nats"), AuthEnforce: true,
		IssuerPublicKey: issuer.PublicKey(), APIUser: "rasputin-api", APIPass: "test-secret", TLS: kit.Server})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Stop)
	if err := tokens.SetNodeRegistry(ctx, inv.Registry()); err != nil {
		t.Fatal(err)
	}
	resp := busauth.NewResponder(srv.Conn(), issuer, tokens)
	if err := resp.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resp.Stop)
	clientURL, _ := srv.ClientURL()
	permErrs := map[string]chan error{}
	connect := func(node string) *nats.Conn {
		t.Helper()
		tok, _, err := tokens.MintBound(ctx, node, node, "compute")
		if err != nil {
			t.Fatal(err)
		}
		errs := make(chan error, 8)
		permErrs[node] = errs
		nc, err := nats.Connect(clientURL, kit.Option, nats.UserInfo(node, tok), nats.MaxReconnects(0),
			nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, e error) { errs <- e }))
		if err != nil {
			t.Fatalf("connect as %s: %v", node, err)
		}
		t.Cleanup(nc.Close)
		return nc
	}
	ncN, ncM := connect(fnNodeN), connect(fnNodeM)

	// The api side, as main wires it.
	ca := tlscatest.Controlplane(t, filepath.Join(dir, "trust"))
	iss, err := apprelay.NewIssuer(apprelay.IssuerDeps{Bus: srv.Conn(), Signer: ca, CACert: ca.Cert, CAPEM: ca.CertPEM, Silence: inv})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := apps.NewAppIdentity([]string{fnTile}, iss)
	if err != nil {
		t.Fatal(err)
	}
	relaySvc, err := apprelay.NewService(apprelay.ServiceDeps{Apps: appStore, Grants: identity, Index: appStore, Secrets: svc})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := apprelay.NewHandler(apprelay.HandlerDeps{Service: relaySvc, Log: log, IDs: rand.Text})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handler.Subscribe(srv.Conn()); err != nil {
		t.Fatal(err)
	}
	if err := srv.Conn().Flush(); err != nil {
		t.Fatal(err)
	}

	// N's agent, for the delete saga: it stops, drops the leaf and removes
	// the relay socket when asked.
	for subj, ack := range map[string]any{
		proto.AppStopSubject(fnNodeN):  proto.AppStopAck{OK: true, Status: proto.AppStatusStopped},
		proto.AppLeafSubject(fnNodeN):  proto.AppLeafAck{OK: true},
		proto.AppRelaySubject(fnNodeN): proto.AppRelayAck{OK: true},
	} {
		b, _ := json.Marshal(ack)
		if _, err := ncN.Subscribe(subj, func(m *nats.Msg) { _ = m.Respond(b) }); err != nil {
			t.Fatal(err)
		}
	}
	if err := ncN.Flush(); err != nil {
		t.Fatal(err)
	}

	// call publishes c as node's agent does and waits for the api's reply.
	call := func(t *testing.T, nc *nats.Conn, node string, c proto.AppSecretCall) proto.AppSecretReply {
		t.Helper()
		reply := proto.AppSecretReplyPrefix(node) + rand.Text()
		sub, err := nc.SubscribeSync(reply)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = sub.Unsubscribe() }()
		b, _ := json.Marshal(c)
		if err := nc.PublishRequest(proto.AppSecretCallSubject(node), reply, b); err != nil {
			t.Fatal(err)
		}
		m, err := sub.NextMsg(10 * time.Second)
		if err != nil {
			t.Fatalf("no reply: %v", err)
		}
		var r proto.AppSecretReply
		if err := json.Unmarshal(m.Data, &r); err != nil {
			t.Fatal(err)
		}
		if r.CorrelationID == "" || r.Message == "" {
			t.Errorf("reply %+v has no correlation id or message", r)
		}
		return r
	}
	asA := func(op, name, value string) proto.AppSecretCall {
		return proto.AppSecretCall{AppID: fnAppA, Op: op, Name: name, Value: value}
	}
	runtimePath := func(appID, name string) secretstore.KVPath {
		r, err := secrets.AppRuntimeSecret(appID, name)
		if err != nil {
			t.Fatal(err)
		}
		p, err := secretstore.NewKVPath(storepolicy.Mount, r.String())
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("A creates, reads, replaces and deletes its own", func(t *testing.T) {
		for _, step := range []struct {
			c    proto.AppSecretCall
			code string
			val  string
		}{
			{asA(proto.AppSecretCreate, "session-key", fnValue1), proto.AppSecretOK, ""},
			{asA(proto.AppSecretRead, "session-key", ""), proto.AppSecretOK, fnValue1},
			{asA(proto.AppSecretCreate, "session-key", fnValue2), proto.AppSecretExists, ""},
			{asA(proto.AppSecretReplace, "session-key", fnValue2), proto.AppSecretOK, ""},
			{asA(proto.AppSecretRead, "session-key", ""), proto.AppSecretOK, fnValue2},
			{asA(proto.AppSecretCreate, "keep-me", fnValue1), proto.AppSecretOK, ""},
			{asA(proto.AppSecretDelete, "session-key", ""), proto.AppSecretOK, ""},
			{asA(proto.AppSecretRead, "session-key", ""), proto.AppSecretNotFound, ""},
		} {
			if r := call(t, ncN, fnNodeN, step.c); r.Code != step.code || r.Value != step.val {
				t.Fatalf("%s %s = %s (value %d bytes); want %s", step.c.Op, step.c.Name, r.Code, len(r.Value), step.code)
			}
		}
		if names, err := appStore.RuntimeSecretNames(ctx, fnAppA); err != nil || len(names) != 1 || names[0] != "keep-me" {
			t.Errorf("index = %v, %v; want [keep-me]", names, err)
		}
	})

	t.Run("refusals", func(t *testing.T) {
		// A's pushed value is not in A's runtime tree: a runtime read of its
		// name finds nothing, and the pushed value is untouched.
		pushed, _ := secrets.AppSecret(fnAppA, "db-password")
		if _, err := svc.Create(ctx, secrets.OperatorActor("alice"), pushed, secret.New([]byte(fnPushed))); err != nil {
			t.Fatal(err)
		}
		if r := call(t, ncN, fnNodeN, asA(proto.AppSecretRead, "db-password", "")); r.Code != proto.AppSecretNotFound || r.Value != "" {
			t.Errorf("a runtime read of the pushed name = %+v; want not_found", r)
		}
		// A name cannot climb into another app's tree.
		if r := call(t, ncN, fnNodeN, asA(proto.AppSecretRead, "../"+fnAppB+"/_runtime/k", "")); r.Code != proto.AppSecretInvalid {
			t.Errorf("a name reaching B's tree = %s; want invalid", r.Code)
		}
		// N cannot act as B, which is on M.
		if r := call(t, ncN, fnNodeN, proto.AppSecretCall{AppID: fnAppB, Op: proto.AppSecretCreate, Name: "k", Value: fnValue1}); r.Code != proto.AppSecretForbidden {
			t.Errorf("N acting as B = %s; want forbidden", r.Code)
		}
		// M cannot act as A, which is on N.
		if r := call(t, ncM, fnNodeM, asA(proto.AppSecretRead, "keep-me", "")); r.Code != proto.AppSecretForbidden || r.Value != "" {
			t.Errorf("M acting as A = %+v; want forbidden", r)
		}
		// M cannot publish on N's relay subject or read N's reply lane: the
		// broker refuses both.
		_ = ncM.Publish(proto.AppSecretCallSubject(fnNodeN), []byte("{}"))
		_, _ = ncM.SubscribeSync(proto.AppSecretReplyPrefix(fnNodeN) + "x")
		_ = ncM.Flush()
		violations := 0
		deadline := time.After(5 * time.Second)
		for violations < 2 {
			select {
			case e := <-permErrs[fnNodeM]:
				if errors.Is(e, nats.ErrPermissionViolation) || strings.Contains(strings.ToLower(e.Error()), "permissions violation") {
					violations++
				}
			case <-deadline:
				t.Fatalf("%d permission violations for M on N's subjects, want 2", violations)
			}
		}
	})

	t.Run("after A's delete saga", func(t *testing.T) {
		jst, err := jobs.OpenStore(ctx, filepath.Join(dir, "jobs.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = jst.Close() })
		w, err := apps.DeleteWorkflow(appStore, inv, srv.Conn(), nil, apps.DeleteSecretsDeps{Secrets: svc, Store: readyStore{}, Log: log}, identity)
		if err != nil {
			t.Fatal(err)
		}
		runner := jobs.NewRunner(jst, srv.Conn())
		runner.Register(w)
		j, err := runner.Submit(ctx, "app.delete", apps.DeleteSpec{AppID: fnAppA}, "alice")
		if err != nil {
			t.Fatal(err)
		}
		runner.Wait()
		got, _ := jst.GetJob(ctx, j.ID)
		if got == nil || got.Status != jobs.StatusSucceeded {
			t.Fatalf("app.delete = %+v", got)
		}
		if r := call(t, ncN, fnNodeN, asA(proto.AppSecretRead, "keep-me", "")); r.Code != proto.AppSecretForbidden {
			t.Errorf("A's call after its delete = %s; want forbidden", r.Code)
		}
		for _, name := range []string{"keep-me", "session-key"} {
			if _, err := sess.Versions(ctx, runtimePath(fnAppA, name)); !errors.Is(err, secretstore.ErrNotFound) {
				t.Errorf("apps/A/_runtime/%s metadata after delete: %v; want 404", name, err)
			}
		}

		// No value in any api log record, job log line or step result.
		var texts []string
		steps, _ := jst.ListSteps(ctx, j.ID)
		for _, s := range steps {
			texts = append(texts, string(s.Result), s.Error)
		}
		events, _ := jst.ListEvents(ctx, j.ID)
		for _, e := range events {
			texts = append(texts, string(e.Data))
		}
		texts = append(texts, rec.Text())
		if len(rec.Records()) == 0 || len(events) == 0 {
			t.Fatal("nothing was captured, so the scan would read nothing")
		}
		for _, v := range []string{fnValue1, fnValue2, fnPushed} {
			for _, s := range texts {
				if strings.Contains(s, v) {
					t.Errorf("a value reached a log or the job: %.200s", s)
				}
			}
		}
	})
}

// realSession is the api's login session over the production client, a real
// readiness Monitor and its ObservedStore, for the rasputin-api role.
func realSession(t *testing.T, s *secretstoretest.Store, logger *slog.Logger) *storesession.Session {
	t.Helper()
	tc, err := s.ClientTLSFor(storepolicy.APIPolicy)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(s.URL())
	if err != nil {
		t.Fatal(err)
	}
	client, err := secretstore.New(secretstore.Config{Addr: u, TLS: tc, CallTimeout: 10 * time.Second, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	monitor, err := storestate.New(storestate.Deps{
		Store: client, Now: time.Now, Log: logger,
		JobRunning: func(context.Context, string) (bool, error) { return false, nil },
		Blank:      func(context.Context) (bool, error) { return false, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	observed, err := storestate.NewObservedStore(client, monitor)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := storesession.New(storesession.Config{Role: storepolicy.APIPolicy, Login: client, Store: observed, Observer: monitor, Log: logger})
	if err != nil {
		t.Fatal(err)
	}
	return sess
}
