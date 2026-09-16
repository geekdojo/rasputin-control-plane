package busauth

// Node id validation on the bus. The NATS username a client presents is its
// node id, and the credential the callout mints scopes it to subjects built
// from that id ("rasputin.node.<id>.>"). nats-server hands the username to the
// callout as-is, so these tests pin that the callout, the credential minter and
// the token store all require the id to be a single lowercase DNS label — one
// literal subject token — on every path, loopback included.

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bus"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

// enforcedBus is the embedded server with AuthEnforce on and the real callout
// responder, bound to host, wired as main.go wires it (sessions tracked).
type enforcedBus struct {
	srv    *bus.Server
	tokens *Store
	url    string
}

func startEnforcedBus(t *testing.T, host string) *enforcedBus {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()

	issuer, err := EnsureIssuer(filepath.Join(dir, "bus"))
	if err != nil {
		t.Fatalf("EnsureIssuer: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "nats"), 0o755); err != nil {
		t.Fatalf("mkdir nats: %v", err)
	}
	tokens, err := OpenStore(ctx, filepath.Join(dir, "bus.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = tokens.Close() })

	srv, err := bus.Start(ctx, bus.Config{
		Host: host, Port: -1,
		StoreDir:        filepath.Join(dir, "nats"),
		AuthEnforce:     true,
		IssuerPublicKey: issuer.PublicKey(),
		APIUser:         "rasputin-api",
		APIPass:         "test-secret",
	})
	if err != nil {
		t.Fatalf("bus.Start(host=%s): %v", host, err)
	}
	t.Cleanup(srv.Stop)

	tokens.TrackSessions(srv) // as main.go does, before the responder starts
	resp := NewResponder(srv.Conn(), issuer, tokens)
	if err := resp.Start(); err != nil {
		t.Fatalf("responder.Start: %v", err)
	}
	t.Cleanup(resp.Stop)

	return &enforcedBus{srv: srv, tokens: tokens, url: srv.ClientURL()}
}

// nonLoopbackIPv4 returns an up, non-loopback IPv4 address of this machine so
// the server can be bound somewhere the callout does NOT treat as trusted
// loopback. Empty when the machine has none.
func nonLoopbackIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ip4 := ipn.IP.To4(); ip4 != nil && !ip4.IsLoopback() && !ip4.IsLinkLocalUnicast() {
				return ip4.String()
			}
		}
	}
	return ""
}

func connect(url, username, token string, opts ...nats.Option) (*nats.Conn, error) {
	all := append([]nats.Option{
		nats.UserInfo(username, token), // token "" = tokenless
		nats.MaxReconnects(0),
		nats.Timeout(3 * time.Second),
	}, opts...)
	return nats.Connect(url, all...)
}

// nonLiteralNodeIDs are usernames that are not a single literal subject token.
// "beta.evt" spans two tokens, so a grant built from it would land inside node
// beta's event subjects.
var nonLiteralNodeIDs = []string{"*", ">", "beta.evt"}

// assertNodeIDRejected requires the connection to be refused. If it is not, it
// goes on to check the cross-node reach the grant must never give — reading
// node beta's commands and publishing its events — so a failure shows exactly
// what the credential covered.
func assertNodeIDRejected(t *testing.T, eb *enforcedBus, username, token string) {
	t.Helper()
	nc, err := connect(eb.url, username, token)
	if err != nil {
		t.Logf("username %q: connection rejected: %v", username, err)
		return
	}
	defer nc.Close()
	t.Errorf("username %q: connection was authorized; want it rejected", username)

	api := eb.srv.Conn()

	cmdSub, err := nc.SubscribeSync("rasputin.node.beta.cmd.>")
	if err != nil {
		t.Fatalf("subscribe call: %v", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	// Let the server process the SUB (and any permissions violation).
	time.Sleep(100 * time.Millisecond)
	if err := api.Publish("rasputin.node.beta.cmd.system.reboot", []byte("for beta")); err != nil {
		t.Fatalf("api publish: %v", err)
	}
	if err := api.Flush(); err != nil {
		t.Fatalf("api flush: %v", err)
	}
	if m, err := cmdSub.NextMsg(time.Second); err == nil {
		t.Errorf("username %q received node beta's command on %s", username, m.Subject)
	}

	evtSub, err := api.SubscribeSync("rasputin.node.beta.evt.registered")
	if err != nil {
		t.Fatalf("api subscribe: %v", err)
	}
	defer func() { _ = evtSub.Unsubscribe() }()
	if err := api.Flush(); err != nil {
		t.Fatalf("api flush: %v", err)
	}
	if err := nc.Publish("rasputin.node.beta.evt.registered", []byte(`{"nodeId":"beta"}`)); err != nil {
		t.Fatalf("publish call: %v", err)
	}
	_ = nc.Flush()
	if m, err := evtSub.NextMsg(time.Second); err == nil {
		t.Errorf("username %q published %s and the api received it", username, m.Subject)
	}
}

// An unbound token (Store.Mint — POST /api/bus/tokens with no nodeId) presented
// from a non-loopback address, so the token really is validated.
func TestCallout_RejectsNonLiteralNodeID_UnboundToken_NonLoopback(t *testing.T) {
	ip := nonLoopbackIPv4()
	if ip == "" {
		t.Skip("no non-loopback IPv4 interface on this machine; see the loopback variant")
	}
	eb := startEnforcedBus(t, ip)
	if strings.HasPrefix(eb.url, "nats://127.") {
		t.Fatalf("server URL %s is loopback; the test would not exercise token validation", eb.url)
	}
	token, _, err := eb.tokens.Mint(context.Background(), "unbound")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	// Control: the same token under a valid node id is accepted.
	nc, err := connect(eb.url, "alpha", token)
	if err != nil {
		t.Fatalf("unbound token under a valid node id should connect: %v", err)
	}
	nc.Close()

	for _, u := range nonLiteralNodeIDs {
		t.Run("username="+u, func(t *testing.T) {
			assertNodeIDRejected(t, eb, u, token)
		})
	}
}

// Loopback, no token: the path authorize trusts without a token.
func TestCallout_RejectsNonLiteralNodeID_LoopbackTokenless(t *testing.T) {
	eb := startEnforcedBus(t, "127.0.0.1")
	// Control: a valid node id on loopback is still trusted.
	nc, err := connect(eb.url, "alpha", "")
	if err != nil {
		t.Fatalf("tokenless loopback connection with a valid node id should connect: %v", err)
	}
	nc.Close()

	for _, u := range nonLiteralNodeIDs {
		t.Run("username="+u, func(t *testing.T) {
			assertNodeIDRejected(t, eb, u, "")
		})
	}
}

// A token BOUND to alpha is only accepted as alpha; Validate compares the bound
// id to the presented username literally.
func TestCallout_BoundTokenRejectedUnderNonLiteralNodeID(t *testing.T) {
	ip := nonLoopbackIPv4()
	if ip == "" {
		t.Skip("no non-loopback IPv4 interface; loopback would bypass the token check entirely")
	}
	eb := startEnforcedBus(t, ip)
	token, _, err := eb.tokens.MintBound(context.Background(), "alpha", "alpha")
	if err != nil {
		t.Fatalf("MintBound: %v", err)
	}

	nc, err := connect(eb.url, "alpha", token)
	if err != nil {
		t.Fatalf("bound token as its own node should connect: %v", err)
	}
	nc.Close()

	for _, u := range nonLiteralNodeIDs {
		t.Run("username="+u, func(t *testing.T) {
			nc, err := connect(eb.url, u, token)
			if err == nil {
				nc.Close()
				t.Fatalf("token bound to alpha was accepted under username %q", u)
			}
		})
	}
}

// A connection under a non-literal node id must not be able to deliver a
// command to another node's command subjects — neither fire-and-forget nor
// request-reply. Node beta is a real, correctly bound node subscribed to its
// own commands.
func assertNoCrossNodeCommand(t *testing.T, host string, useToken bool) {
	t.Helper()
	eb := startEnforcedBus(t, host)
	ctx := context.Background()

	var token string
	if useToken {
		tok, _, err := eb.tokens.Mint(ctx, "unbound")
		if err != nil {
			t.Fatalf("Mint unbound: %v", err)
		}
		token = tok
	}

	betaTok, _, err := eb.tokens.MintBound(ctx, "beta", "beta")
	if err != nil {
		t.Fatalf("MintBound beta: %v", err)
	}
	beta, err := connect(eb.url, "beta", betaTok)
	if err != nil {
		t.Fatalf("beta connect: %v", err)
	}
	defer beta.Close()

	pingSub, err := beta.SubscribeSync("rasputin.node.beta.cmd.diag.ping")
	if err != nil {
		t.Fatalf("beta subscribe diag.ping: %v", err)
	}
	if _, err := beta.Subscribe("rasputin.node.beta.cmd.system.reboot", func(m *nats.Msg) {
		_ = m.Respond([]byte(`{"ok":true}`))
	}); err != nil {
		t.Fatalf("beta subscribe system.reboot: %v", err)
	}
	if err := beta.Flush(); err != nil {
		t.Fatalf("beta flush: %v", err)
	}

	nc, err := connect(eb.url, "*", token)
	if err != nil {
		t.Logf("username \"*\": connection rejected: %v", err)
		return
	}
	defer nc.Close()
	t.Errorf("username \"*\": connection was authorized; want it rejected")

	if err := nc.Publish("rasputin.node.beta.cmd.diag.ping", []byte(`{"jobId":"x"}`)); err != nil {
		t.Fatalf("publish diag.ping: %v", err)
	}
	_ = nc.Flush()
	if _, err := pingSub.NextMsg(time.Second); err == nil {
		t.Error("node beta received a diag.ping published under username \"*\"")
	}

	if reply, err := nc.Request("rasputin.node.beta.cmd.system.reboot", []byte(`{"delaySeconds":1}`), 2*time.Second); err == nil {
		t.Errorf("a system.reboot request under username \"*\" reached node beta and was answered (%q)", reply.Data)
	}
}

func TestCallout_NoCrossNodeCommand_UnboundToken_NonLoopback(t *testing.T) {
	ip := nonLoopbackIPv4()
	if ip == "" {
		t.Skip("no non-loopback IPv4 interface on this machine")
	}
	assertNoCrossNodeCommand(t, ip, true)
}

func TestCallout_NoCrossNodeCommand_LoopbackTokenless(t *testing.T) {
	assertNoCrossNodeCommand(t, "127.0.0.1", false)
}

// invalidNodeIDs fail the node id rule; each is a shape that is not one
// lowercase DNS label.
var invalidNodeIDs = []string{
	"*", ">", "a.b", "a b", "a\tb", "Alpha", "node_1", "-alpha", "alpha-",
	strings.Repeat("a", 64),
}

func TestResponder_AuthorizeRejectsInvalidNodeID(t *testing.T) {
	ctx := context.Background()
	store := newTokenStore(t)
	unbound, _, err := store.Mint(ctx, "unbound")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	r := &Responder{tokens: store}

	for _, id := range invalidNodeIDs {
		for _, host := range []string{"127.0.0.1", "::1", "192.168.1.50"} {
			if ok, _ := r.authorize(1, id, unbound, host); ok {
				t.Errorf("authorize(%q, unbound token, %s) = true; want denied", id, host)
			}
			if ok, _ := r.authorize(1, id, "", host); ok {
				t.Errorf("authorize(%q, no token, %s) = true; want denied", id, host)
			}
		}
	}
	// Valid ids still pass on both paths.
	if ok, reason := r.authorize(1, "alpha", "", "127.0.0.1"); !ok {
		t.Errorf("loopback alpha denied: %s", reason)
	}
	if ok, reason := r.authorize(2, "alpha", unbound, "192.168.1.50"); !ok {
		t.Errorf("remote alpha with unbound token denied: %s", reason)
	}
}

// Defence in depth: mintUserJWT itself refuses any node id that is not a single
// literal subject token, and whatever it does mint scopes exactly one token
// after "rasputin.node.".
func TestMintUserJWT_NodeIDIsASingleLiteralSubjectToken(t *testing.T) {
	issuer, err := EnsureIssuer(t.TempDir())
	if err != nil {
		t.Fatalf("EnsureIssuer: %v", err)
	}
	ukp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	upub, _ := ukp.PublicKey()
	r := NewResponder(nil, issuer, nil)

	cases := append([]string{""}, invalidNodeIDs...)
	for _, nodeID := range cases {
		t.Run("nodeID="+nodeID, func(t *testing.T) {
			tok, err := r.mintUserJWT(upub, nodeID)
			if err != nil {
				return // refused: the required outcome
			}
			t.Errorf("mintUserJWT(%q) minted a credential; want an error", nodeID)
			uc, err := jwt.DecodeUserClaims(tok)
			if err != nil {
				t.Fatalf("DecodeUserClaims: %v", err)
			}
			check := func(kind string, subjects jwt.StringList, wantTail string) {
				for _, s := range subjects {
					rest, ok := strings.CutPrefix(s, "rasputin.node.")
					if !ok {
						continue // _INBOX.> etc.
					}
					tokens := strings.Split(rest, ".")
					first := tokens[0]
					if first == "" || first == "*" || first == ">" ||
						strings.IndexFunc(first, unicode.IsSpace) >= 0 ||
						strings.Join(tokens[1:], ".") != wantTail {
						t.Errorf("node id %q minted %s grant %q — not exactly one literal token after rasputin.node.",
							nodeID, kind, s)
					}
				}
			}
			check("pub", uc.Permissions.Pub.Allow, ">")
			check("sub", uc.Permissions.Sub.Allow, "cmd.>")
		})
	}

	if _, err := r.mintUserJWT(upub, "e3bench-controlplane1"); err != nil {
		t.Errorf("mintUserJWT with a valid node id: %v", err)
	}
}

// A bound token for an id the callout would never accept can never
// authenticate, so the store refuses to create one.
func TestStore_MintBoundRejectsInvalidNodeID(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	for _, id := range invalidNodeIDs {
		if _, _, err := s.MintBound(ctx, "t", id); err == nil {
			t.Errorf("MintBound(%q) succeeded; want an error", id)
		}
	}
	infos, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(infos) != 0 {
		t.Errorf("rejected mints left %d token rows; want 0", len(infos))
	}
	if _, _, err := s.MintBound(ctx, "t", "alpha"); err != nil {
		t.Errorf("MintBound(alpha): %v", err)
	}
}

// One invalid binding fails the whole preseed load, and nothing is stored —
// not even the valid entries alongside it.
func TestStore_PreloadHashesRejectsInvalidNodeID(t *testing.T) {
	ctx := context.Background()
	for _, id := range invalidNodeIDs {
		t.Run("nodeID="+id, func(t *testing.T) {
			s := newTokenStore(t)
			_, h1, _ := GenerateToken()
			_, h2, _ := GenerateToken()
			n, err := s.PreloadHashes(ctx, []PreseedToken{
				{Hash: h1, NodeID: "alpha", Label: "compute"},
				{Hash: h2, NodeID: id, Label: "compute"},
			})
			if err == nil {
				t.Fatalf("PreloadHashes with node id %q succeeded (inserted %d); want an error", id, n)
			}
			if n != 0 {
				t.Errorf("PreloadHashes reported %d inserted alongside its error; want 0", n)
			}
			infos, err := s.List(ctx)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(infos) != 0 {
				t.Errorf("a rejected preseed stored %d rows; want 0", len(infos))
			}
		})
	}
}
