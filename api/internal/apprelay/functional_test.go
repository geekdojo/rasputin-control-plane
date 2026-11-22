package apprelay_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
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
	// fnKeyPlain is the plaintext the apps encrypt (TC-1084-24).
	fnKeyPlain = "sentinel-key-plaintext-1084"
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

// relayRig is the relay as main wires it, on a bus enforcing the auth
// callout with credentials minted for nodes N and M, the real secrets service
// on the real chain against the pinned OpenBao, the apps and inventory stores
// with app A granted on N and B granted on M, and N's agent answering the
// delete saga's calls.
type relayRig struct {
	ctx      context.Context
	dir      string
	log      *slog.Logger
	rec      *logkittest.Recorder
	store    *secretstoretest.Store
	sess     *storesession.Session
	keySess  *storesession.Session
	keyCalls *countingTransit
	monitor  *storestate.Monitor
	appStore *apps.Store
	inv      *inventory.Store
	svc      *secrets.Service
	srv      *bus.Server
	identity apps.AppIdentity
	ncN, ncM *nats.Conn
	permErrs map[string]chan error
}

// newRelayRig starts the store with b, then runs provision (nil for none)
// before anything logs in.
func newRelayRig(t *testing.T, b secretstoretest.Bootstrap, provision func(*secretstoretest.Store)) (*relayRig, bool) {
	t.Helper()
	bin := os.Getenv(binEnv)
	if bin == "" {
		functest.SkipOrFail(t, switchEnv, "%s is not set, so there is no secret store binary to run", binEnv)
		return nil, false
	}
	if _, err := os.Stat(bin); err != nil {
		functest.SkipOrFail(t, switchEnv, "%s=%s: no secret store binary there: %v", binEnv, bin, err)
		return nil, false
	}
	r := &relayRig{ctx: context.Background(), dir: t.TempDir(), permErrs: map[string]chan error{}}
	ctx, dir := r.ctx, r.dir
	r.log, r.rec = logkittest.New()
	log := r.log

	h, err := secretstoretest.New(secretstoretest.Config{BinaryPath: bin, TempParent: t.TempDir(), Logger: slog.New(slog.DiscardHandler), Now: time.Now, Rand: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	st, err := h.StartWith(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close(context.Background()) })
	r.store = st
	if provision != nil {
		provision(st)
	}
	r.sess, r.monitor = realSession(t, st, log)
	r.keySess, r.keyCalls = realKeySession(t, st, log)
	repo, err := secrets.NewRepository(r.sess)
	if err != nil {
		t.Fatal(err)
	}

	// The apps and inventory stores: A granted on N, B granted on M.
	r.appStore, err = apps.OpenStore(ctx, filepath.Join(dir, "apps.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.appStore.Close() })
	r.inv, err = inventory.OpenStore(ctx, filepath.Join(dir, "inv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.inv.Close() })
	now := time.Now().UTC()
	for _, n := range []string{fnNodeN, fnNodeM} {
		if err := r.inv.Insert(ctx, &proto.Node{ID: n, Role: proto.RoleCompute, Hostname: n + ".test", FirstSeen: now, LastSeen: now}); err != nil {
			t.Fatal(err)
		}
	}
	for id, node := range map[string]string{fnAppA: fnNodeN, fnAppB: fnNodeM} {
		if err := r.appStore.Create(ctx, &apps.App{ID: id, Name: "app-" + id[len(id)-1:], ComposeYAML: "services: {}\n", TargetNode: node,
			SourceTile: fnTile, LastStatus: proto.AppStatusRunning, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	r.svc, err = secrets.NewService(secrets.Deps{Repo: repo, Transit: r.keySess, Apps: appNodes{s: r.appStore}, Switch: noSwitch{}, Log: log})
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
	r.srv, err = bus.Start(ctx, bus.Config{Host: busHost(), Port: -1, StoreDir: filepath.Join(dir, "nats"), AuthEnforce: true,
		IssuerPublicKey: issuer.PublicKey(), APIUser: "rasputin-api", APIPass: "test-secret", TLS: kit.Server})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.srv.Stop)
	if err := tokens.SetNodeRegistry(ctx, r.inv.Registry()); err != nil {
		t.Fatal(err)
	}
	resp := busauth.NewResponder(r.srv.Conn(), issuer, tokens)
	if err := resp.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resp.Stop)
	clientURL, _ := r.srv.ClientURL()
	connect := func(node string) *nats.Conn {
		t.Helper()
		tok, _, err := tokens.MintBound(ctx, node, node, "compute")
		if err != nil {
			t.Fatal(err)
		}
		errs := make(chan error, 8)
		r.permErrs[node] = errs
		nc, err := nats.Connect(clientURL, kit.Option, nats.UserInfo(node, tok), nats.MaxReconnects(0),
			nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, e error) { errs <- e }))
		if err != nil {
			t.Fatalf("connect as %s: %v", node, err)
		}
		t.Cleanup(nc.Close)
		return nc
	}
	r.ncN, r.ncM = connect(fnNodeN), connect(fnNodeM)

	// The api side, as main wires it.
	ca := tlscatest.Controlplane(t, filepath.Join(dir, "trust"))
	iss, err := apprelay.NewIssuer(apprelay.IssuerDeps{Bus: r.srv.Conn(), Signer: ca, CACert: ca.Cert, CAPEM: ca.CertPEM, Silence: r.inv})
	if err != nil {
		t.Fatal(err)
	}
	r.identity, err = apps.NewAppIdentity([]string{fnTile}, iss)
	if err != nil {
		t.Fatal(err)
	}
	relaySvc, err := apprelay.NewService(apprelay.ServiceDeps{Apps: r.appStore, Grants: r.identity, Index: r.appStore, Secrets: r.svc})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := apprelay.NewHandler(apprelay.HandlerDeps{Service: relaySvc, Log: log, IDs: rand.Text})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handler.Subscribe(r.srv.Conn()); err != nil {
		t.Fatal(err)
	}
	if err := r.srv.Conn().Flush(); err != nil {
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
		if _, err := r.ncN.Subscribe(subj, func(m *nats.Msg) { _ = m.Respond(b) }); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.ncN.Flush(); err != nil {
		t.Fatal(err)
	}
	return r, true
}

// call publishes c as node's agent does and waits for the api's reply.
func (r *relayRig) call(t *testing.T, nc *nats.Conn, node string, c proto.AppSecretCall) proto.AppSecretReply {
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
	var rep proto.AppSecretReply
	if err := json.Unmarshal(m.Data, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.CorrelationID == "" || rep.Message == "" {
		t.Errorf("reply %+v has no correlation id or message", rep)
	}
	return rep
}

// authorProvisioned is the store PR 2's release makes: the production role
// set, rasputin-author admitting the provisioner's leaf, and the author
// path's engine, policy and role (geekdojo/geekdojo-brain#1084, TC-1084-28).
func authorProvisioned(t *testing.T) (secretstoretest.Bootstrap, func(*secretstoretest.Store)) {
	t.Helper()
	b := previousRelease(t)
	b.Roles = append(b.Roles, secretstoretest.Role{Name: storepolicy.AuthorPolicy, CommonName: "rasputin-provisioner",
		Policy: storepolicy.AuthorPolicy, PolicyText: policyText(t, storepolicy.AuthorPolicy)})
	return b, func(st *secretstoretest.Store) {
		v, err := st.Login(t.Context(), "rasputin-provisioner", storepolicy.AuthorPolicy)
		if err != nil {
			t.Fatal(err)
		}
		defer v.Destroy()
		tc, err := st.ClientTLSFor("rasputin-provisioner")
		if err != nil {
			t.Fatal(err)
		}
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: tc}}
		defer c.CloseIdleConnections()
		for _, w := range []struct {
			method, path string
			body         any
		}{
			{http.MethodPost, "sys/mounts/" + storepolicy.AppKeysMount, map[string]string{"type": "transit"}},
			{http.MethodPut, "sys/policies/acl/" + storepolicy.AppKeysPolicy, map[string]string{"policy": string(policyText(t, storepolicy.AppKeysPolicy))}},
			{http.MethodPost, "auth/cert/certs/" + storepolicy.AppKeysPolicy, map[string]string{"certificate": string(st.StoreCA().CertPEM),
				"allowed_common_names": storepolicy.AppKeysPolicy, "token_policies": storepolicy.AppKeysPolicy,
				"token_no_default_policy": "true", "token_ttl": "1h"}},
		} {
			b, _ := json.Marshal(w.body)
			req, _ := http.NewRequestWithContext(t.Context(), w.method, st.URL()+"/v1/"+w.path, bytes.NewReader(b))
			req.Header.Set("X-Vault-Token", string(v.Reveal()))
			resp, err := c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("author %s %s = %d", w.method, w.path, resp.StatusCode)
			}
		}
	}
}

// previousRelease is the store the previous release's init.json makes: the
// fixed policies and roles, rasputin-bindable, and no author, Transit mount
// or key role (TC-1084-06).
func previousRelease(t *testing.T) secretstoretest.Bootstrap {
	t.Helper()
	role := func(name string) secretstoretest.Role {
		return secretstoretest.Role{Name: name, Policy: name, PolicyText: policyText(t, name)}
	}
	return secretstoretest.Bootstrap{Mount: storepolicy.Mount,
		Roles:    []secretstoretest.Role{role(storepolicy.APIPolicy), role(storepolicy.SealRotatePolicy), role(storepolicy.ProvisionerPolicy)},
		Policies: []secretstoretest.Policy{{Name: storepolicy.BindablePolicy, Text: policyText(t, storepolicy.BindablePolicy)}},
	}
}

func policyText(t *testing.T, name string) []byte {
	t.Helper()
	b, err := storepolicy.Text(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TC-1081-27: the scope rule end to end. A bus enforcing the auth callout
// with credentials minted for nodes N and M; the real secrets service on the
// real chain against the pinned OpenBao under the shipped rasputin-api
// policy; the relay endpoint and service as main wires them; and the real
// delete saga. TC-1084-24 extends it to keys, on a store the author path
// provisioned, with the api's kv leaf for kv and its key leaf for keys.
func TestAppRelay_ScopeRuleAgainstTheRealStore(t *testing.T) {
	b, provision := authorProvisioned(t)
	rg, ok := newRelayRig(t, b, provision)
	if !ok {
		return
	}
	ctx, log, rec, sess, svc, appStore, inv, srv := rg.ctx, rg.log, rg.rec, rg.sess, rg.svc, rg.appStore, rg.inv, rg.srv
	ncN, ncM, identity, permErrs, dir := rg.ncN, rg.ncM, rg.identity, rg.permErrs, rg.dir
	call := rg.call
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

	// TC-1084-24: keys, end to end. A and B each create wrap and encrypt the
	// same plaintext; each round-trips its own; A decrypting B's ciphertext
	// is invalid and never B's plaintext; A's key ops under its kv entries'
	// names change no kv version; a destroyed and re-created wrap no longer
	// decrypts A's old ciphertext.
	keyPlain := base64.StdEncoding.EncodeToString([]byte(fnKeyPlain))
	var bCipher string
	t.Run("TC-1084-24 keys: each app its own", func(t *testing.T) {
		asB := func(op, name, value string) proto.AppSecretCall {
			return proto.AppSecretCall{AppID: fnAppB, Op: op, Name: name, Value: value}
		}
		cipher := map[string]string{}
		for _, side := range []struct {
			app  string
			nc   *nats.Conn
			node string
			as   func(op, name, value string) proto.AppSecretCall
		}{{fnAppA, ncN, fnNodeN, asA}, {fnAppB, ncM, fnNodeM, asB}} {
			if r := call(t, side.nc, side.node, side.as(proto.AppKeyCreate, "wrap", "")); r.Code != proto.AppSecretOK {
				t.Fatalf("%s create wrap = %+v", side.app, r)
			}
			r := call(t, side.nc, side.node, side.as(proto.AppKeyEncrypt, "wrap", keyPlain))
			if r.Code != proto.AppSecretOK || !strings.HasPrefix(r.Value, "vault:v1:") {
				t.Fatalf("%s encrypt = %+v", side.app, r)
			}
			cipher[side.app] = r.Value
			if r := call(t, side.nc, side.node, side.as(proto.AppKeyDecrypt, "wrap", cipher[side.app])); r.Code != proto.AppSecretOK || r.Value != keyPlain {
				t.Errorf("%s round trip = %s (%d bytes)", side.app, r.Code, len(r.Value))
			}
		}
		bCipher = cipher[fnAppB]
		if r := call(t, ncN, fnNodeN, asA(proto.AppKeyDecrypt, "wrap", cipher[fnAppB])); r.Code != proto.AppSecretInvalid || r.Value != "" {
			t.Errorf("A decrypting B's ciphertext = %+v; want invalid and no plaintext", r)
		}
		before, err := sess.Versions(ctx, runtimePath(fnAppA, "keep-me"))
		if err != nil {
			t.Fatal(err)
		}
		// A key never reaches a kv entry: with no key row, encrypt and
		// decrypt are not_found; a destroy of a key that does not exist is
		// done, and touches no entry.
		for _, k := range []struct {
			c    proto.AppSecretCall
			code string
		}{
			{asA(proto.AppKeyEncrypt, "keep-me", keyPlain), proto.AppSecretNotFound},
			{asA(proto.AppKeyDecrypt, "keep-me", cipher[fnAppA]), proto.AppSecretNotFound},
			{asA(proto.AppKeyDestroy, "keep-me", ""), proto.AppSecretOK},
			{asA(proto.AppKeyEncrypt, "db-password", keyPlain), proto.AppSecretNotFound},
		} {
			if r := call(t, ncN, fnNodeN, k.c); r.Code != k.code || r.Value != "" {
				t.Errorf("A %s %s = %+v; want %s", k.c.Op, k.c.Name, r, k.code)
			}
		}
		after, err := sess.Versions(ctx, runtimePath(fnAppA, "keep-me"))
		if err != nil || after.CurrentVersion != before.CurrentVersion {
			t.Errorf("keep-me's version %d -> %d (%v): a key op changed a kv entry", before.CurrentVersion, after.CurrentVersion, err)
		}
		if r := call(t, ncN, fnNodeN, asA(proto.AppSecretRead, "keep-me", "")); r.Code != proto.AppSecretOK || r.Value != fnValue1 {
			t.Errorf("keep-me after the key ops = %s", r.Code)
		}
		for _, op := range []string{proto.AppKeyDestroy, proto.AppKeyCreate} {
			if r := call(t, ncN, fnNodeN, asA(op, "wrap", "")); r.Code != proto.AppSecretOK {
				t.Fatalf("A %s wrap = %+v", op, r)
			}
		}
		if r := call(t, ncN, fnNodeN, asA(proto.AppKeyDecrypt, "wrap", cipher[fnAppA])); r.Code != proto.AppSecretInvalid || r.Value != "" {
			t.Errorf("A's old ciphertext under the re-created wrap = %+v; want invalid", r)
		}
		if names, err := appStore.TransitKeyNames(ctx, fnAppA); err != nil || !slices.Equal(names, []string{"wrap"}) {
			t.Errorf("A's key rows = %v, %v; want [wrap]", names, err)
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
		// TC-1084-24: A's key rows and store keys are gone; B's key still
		// decrypts.
		if names, err := appStore.TransitKeyNames(ctx, fnAppA); err != nil || len(names) != 0 {
			t.Errorf("A's key rows after delete = %v, %v; want none", names, err)
		}
		wrapA, _ := secretstore.NewTransitKey(storepolicy.AppKeysMount, "app-"+fnAppA+"-wrap")
		if _, err := rg.keySess.TransitDecrypt(ctx, wrapA, secret.New([]byte(bCipher))); !errors.Is(err, secretstore.ErrNotFound) {
			t.Errorf("A's wrap in the store after delete: %v; want not found", err)
		}
		asB := proto.AppSecretCall{AppID: fnAppB, Op: proto.AppKeyDecrypt, Name: "wrap", Value: bCipher}
		if r := call(t, ncM, fnNodeM, asB); r.Code != proto.AppSecretOK || r.Value != keyPlain {
			t.Errorf("B's decrypt after A's delete = %s", r.Code)
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
		for _, v := range []string{fnValue1, fnValue2, fnPushed, fnKeyPlain, keyPlain, bCipher} {
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
func realSession(t *testing.T, s *secretstoretest.Store, logger *slog.Logger) (*storesession.Session, *storestate.Monitor) {
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
	return sess, monitor
}

// countingTransit counts the Transit calls and logins that reach the key
// client.
type countingTransit struct {
	c      *secretstore.Client
	logins atomic.Int32
	calls  atomic.Int32
}

func (c *countingTransit) CertLogin(ctx context.Context, role string) (secret.Value, error) {
	c.logins.Add(1)
	return c.c.CertLogin(ctx, role)
}

func (c *countingTransit) TransitCreateKey(ctx context.Context, tok secret.Value, k secretstore.TransitKey) error {
	c.calls.Add(1)
	return c.c.TransitCreateKey(ctx, tok, k)
}

func (c *countingTransit) TransitEncrypt(ctx context.Context, tok secret.Value, k secretstore.TransitKey, v secret.Value) (secret.Value, error) {
	c.calls.Add(1)
	return c.c.TransitEncrypt(ctx, tok, k, v)
}

func (c *countingTransit) TransitDecrypt(ctx context.Context, tok secret.Value, k secretstore.TransitKey, v secret.Value) (secret.Value, error) {
	c.calls.Add(1)
	return c.c.TransitDecrypt(ctx, tok, k, v)
}

func (c *countingTransit) TransitDestroyKey(ctx context.Context, tok secret.Value, k secretstore.TransitKey) error {
	c.calls.Add(1)
	return c.c.TransitDestroyKey(ctx, tok, k)
}

// realKeySession is the api's key session as main wires it
// (geekdojo/geekdojo-brain#1084): the production client presenting the key
// leaf, CN rasputin-app-keys, logging in as rasputin-app-keys, with no
// readiness observer.
func realKeySession(t *testing.T, s *secretstoretest.Store, logger *slog.Logger) (*storesession.Session, *countingTransit) {
	t.Helper()
	tc, err := s.ClientTLSFor(storepolicy.AppKeysPolicy)
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
	ct := &countingTransit{c: client}
	sess, err := storesession.New(storesession.Config{Role: storepolicy.AppKeysPolicy, Login: ct, Transit: ct,
		Observer: noObserver{}, Log: logger})
	if err != nil {
		t.Fatal(err)
	}
	return sess, ct
}

// noObserver is main's noAuditObserver: the key session reports to no one.
type noObserver struct{}

func (noObserver) ObserveAudited(context.Context, error) {}

// TC-1084-06: a store initialised by the previous release (no author, no
// Transit mount, no key role). A granted app holding one runtime secret: its
// key create answers unavailable with one ERROR apprelay.store_failed naming
// the refused rasputin-app-keys login, and forgets the row it added
// (F-1084-22); an encrypt or decrypt under a never-created name, wrap
// included, answers not_found at WARN with no store call (F-1084-02); a
// destroy of wrap answers unavailable; the runtime secret reads back
// unchanged; the kv readiness is untouched: no secret-store alert, and the
// monitor reads ready; and the app's delete succeeds (F-1084-22).
func TestAppRelay_KeysOnAPreviousReleaseStore(t *testing.T) {
	rg, ok := newRelayRig(t, previousRelease(t), nil)
	if !ok {
		return
	}
	ctx, rec := rg.ctx, rg.rec
	as := func(op, name, value string) proto.AppSecretCall {
		return proto.AppSecretCall{AppID: fnAppA, Op: op, Name: name, Value: value}
	}
	if r := rg.call(t, rg.ncN, fnNodeN, as(proto.AppSecretCreate, "session-key", fnValue1)); r.Code != proto.AppSecretOK {
		t.Fatalf("runtime create = %+v", r)
	}
	r, err := secrets.AppRuntimeSecret(fnAppA, "session-key")
	if err != nil {
		t.Fatal(err)
	}
	p, _ := secretstore.NewKVPath(storepolicy.Mount, r.String())
	before, err := rg.sess.Versions(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	plain := base64.StdEncoding.EncodeToString([]byte(fnKeyPlain))

	// since is the records written after the first n, at level.
	since := func(n int, level slog.Level) []slog.Record {
		var out []slog.Record
		for _, r := range rec.Records()[n:] {
			if r.Level == level {
				out = append(out, r)
			}
		}
		return out
	}
	mark := len(rec.Records())
	create := rg.call(t, rg.ncN, fnNodeN, as(proto.AppKeyCreate, "wrap", ""))
	if create.Code != proto.AppSecretUnavailable {
		t.Fatalf("create on a previous-release store = %+v; want unavailable", create)
	}
	var failed []slog.Record
	for _, e := range since(mark, slog.LevelError) {
		if ev, _ := logkittest.Attr(e, "event"); ev == "apprelay.store_failed" {
			failed = append(failed, e)
		}
	}
	if len(failed) != 1 {
		t.Fatalf("%d apprelay.store_failed records, want 1:\n%s", len(failed), rec.Text())
	}
	for k, want := range map[string]string{"component": "apprelay", "node": fnNodeN, "app_id": fnAppA, "op": proto.AppKeyCreate,
		"name": "wrap", "correlation_id": create.CorrelationID} {
		if got, _ := logkittest.Attr(failed[0], k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if e, _ := logkittest.Attr(failed[0], "err"); !strings.Contains(e, "log in as "+storepolicy.AppKeysPolicy) {
		t.Errorf("err = %q, want it to name the refused %s login", e, storepolicy.AppKeysPolicy)
	}
	if ok, err := rg.appStore.HasTransitKey(ctx, fnAppA, "wrap"); ok || err != nil {
		t.Errorf("the wrap row after the refused create = %t, %v; want forgotten (F-1084-22)", ok, err)
	}

	logins, calls := rg.keyCalls.logins.Load(), rg.keyCalls.calls.Load()
	for _, c := range []proto.AppSecretCall{as(proto.AppKeyEncrypt, "ghost", plain), as(proto.AppKeyDecrypt, "ghost", "vault:v1:"+plain), as(proto.AppKeyEncrypt, "wrap", plain)} {
		mark := len(rec.Records())
		r := rg.call(t, rg.ncN, fnNodeN, c)
		if r.Code != proto.AppSecretNotFound {
			t.Errorf("%s %s = %+v; want not_found", c.Op, c.Name, r)
		}
		if len(since(mark, slog.LevelError)) != 0 || len(since(mark, slog.LevelWarn)) != 1 {
			t.Errorf("%s %s: want one WARN refusal and no ERROR:\n%s", c.Op, c.Name, rec.Text())
		}
	}
	if rg.keyCalls.logins.Load() != logins || rg.keyCalls.calls.Load() != calls {
		t.Errorf("the never-created key calls reached the store: %d logins, %d calls more", rg.keyCalls.logins.Load()-logins, rg.keyCalls.calls.Load()-calls)
	}
	if r := rg.call(t, rg.ncN, fnNodeN, as(proto.AppKeyDestroy, "wrap", "")); r.Code != proto.AppSecretUnavailable {
		t.Errorf("destroy wrap = %+v; want unavailable", r)
	}

	if r := rg.call(t, rg.ncN, fnNodeN, as(proto.AppSecretRead, "session-key", "")); r.Code != proto.AppSecretOK || r.Value != fnValue1 {
		t.Errorf("the runtime secret after the key calls = %s", r.Code)
	}
	after, err := rg.sess.Versions(ctx, p)
	if err != nil || after.CurrentVersion != before.CurrentVersion {
		t.Errorf("the runtime secret's version %d -> %d (%v)", before.CurrentVersion, after.CurrentVersion, err)
	}
	if st, err := rg.monitor.State(ctx); err != nil || st != storestate.Ready {
		t.Errorf("readiness = %s, %v; want ready", st, err)
	}
	for _, a := range rg.monitor.Alerts(ctx, time.Now()) {
		if strings.HasPrefix(a.ID, "secret-store:") {
			t.Errorf("alert %s raised", a.ID)
		}
	}
	if strings.Contains(rec.Text(), fnKeyPlain) || strings.Contains(rec.Text(), plain) || strings.Contains(rec.Text(), fnValue1) {
		t.Error("a value reached a log record")
	}

	// F-1084-22: the app's delete succeeds: it has no key to destroy, and
	// its runtime secret is deleted.
	jst, err := jobs.OpenStore(ctx, filepath.Join(rg.dir, "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = jst.Close() })
	w, err := apps.DeleteWorkflow(rg.appStore, rg.inv, rg.srv.Conn(), nil, apps.DeleteSecretsDeps{Secrets: rg.svc, Store: readyStore{}, Log: rg.log}, rg.identity)
	if err != nil {
		t.Fatal(err)
	}
	runner := jobs.NewRunner(jst, rg.srv.Conn())
	runner.Register(w)
	j, err := runner.Submit(ctx, "app.delete", apps.DeleteSpec{AppID: fnAppA}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	runner.Wait()
	if got, _ := jst.GetJob(ctx, j.ID); got == nil || got.Status != jobs.StatusSucceeded {
		t.Fatalf("app.delete = %+v; want succeeded", got)
	}
	if names, err := rg.appStore.TransitKeyNames(ctx, fnAppA); err != nil || len(names) != 0 {
		t.Errorf("A's key rows after delete = %v, %v; want none", names, err)
	}
	if _, err := rg.sess.Versions(ctx, p); !errors.Is(err, secretstore.ErrNotFound) {
		t.Errorf("the runtime secret after delete: %v; want not found", err)
	}
}
