package busauth

import (
	"context"
	"log"
	"sync/atomic"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
)

const (
	// authCalloutSubject is where the embedded server publishes auth requests
	// (nats-server constant $SYS.REQ.USER.AUTH).
	authCalloutSubject = "$SYS.REQ.USER.AUTH"

	// globalAccount is NATS's DEFAULT_GLOBAL_ACCOUNT. In non-operator mode the
	// server places a callout-minted user into the account named by the user
	// JWT's Audience (verified: auth_callout.go assignAccountAndPermissions →
	// placement = arc.Audience). We place agents in $G — the same account the
	// api operates and JetStream lives in — so subject-scoped permissions
	// gate them while they share the bus.
	globalAccount = "$G"

	// mintedTTL bounds an authorized connection. When it lapses the server
	// closes the connection ("User Authentication Expired") and the agent's
	// reconnect re-authenticates through the callout, so a token revoked while
	// a kick was somehow missed stops working within this bound (the backstop
	// to revoke's force-disconnect; see sessions.go). A short-ish TTL caps the
	// blast radius of a minted JWT while not generating churn.
	mintedTTL = 24 * time.Hour

	validateTimeout = 3 * time.Second
)

// Validator is the subset of *Store the responder needs (eases testing).
// Admit validates a join token for the connection conn names and, on success,
// records the grant so revoking the token closes that connection — and
// disconnects the token's previous session, because a token holds one
// (sessions.go).
type Validator interface {
	Admit(ctx context.Context, conn Conn, plaintext, presentedNodeID string) (bool, error)
}

// Responder handles NATS auth-callout requests on the in-process connection:
// it validates the presented join token, then mints a per-node subject-scoped
// user JWT signed by the issuer account key.
type Responder struct {
	nc     *nats.Conn
	issuer *Issuer
	tokens Validator
	sub    *nats.Subscription

	// hold, when set and answering true, refuses every connection with the
	// reason it gives (SetHold).
	hold atomic.Pointer[HoldFunc]

	// replyTTL is the lifetime stamped into every minted credential's dynamic
	// response permission. Production is always proto.BusReplyGrantTTL; the
	// integration test shortens it so the expiry path runs in milliseconds
	// instead of forty-five minutes.
	replyTTL time.Duration

	// userTTL is the lifetime of every minted user JWT. Production is always
	// mintedTTL; the expiry integration test shortens it so the server's
	// expiry disconnect runs in seconds instead of a day.
	userTTL time.Duration
}

func NewResponder(nc *nats.Conn, issuer *Issuer, tokens Validator) *Responder {
	return &Responder{nc: nc, issuer: issuer, tokens: tokens, replyTTL: proto.BusReplyGrantTTL, userTTL: mintedTTL}
}

// Start subscribes to the auth-callout subject. The connection MUST be the
// api's in-process AuthUser connection (which bypasses the callout itself).
func (r *Responder) Start() error {
	sub, err := r.nc.Subscribe(authCalloutSubject, r.handle)
	if err != nil {
		return err
	}
	r.sub = sub
	log.Printf("busauth: auth-callout responder active (issuer=%s)", r.issuer.PublicKey())
	return nil
}

// HoldFunc reports whether the responder should refuse every connection for
// now, and the reason it gives the client.
type HoldFunc func() (held bool, reason string)

// SetHold makes the responder refuse every connection, the controlplane's own
// agent's included, while hold answers true. Safe to call at any time.
//
// The one use: while the api replaces its embedded server to refuse plaintext
// (bus.Server.SetAllowNonTLS), job intake is closed, and it reopens only after
// the api's own connection is back on the new server. That connection carries
// this responder, so a node could otherwise be admitted — and register, and
// have a registration hook submit a job — in the moment between the two, and
// that job would be refused with nobody to retry it. Held, the node is refused
// and retries on its own reconnect loop, after intake has reopened.
func (r *Responder) SetHold(hold HoldFunc) {
	if hold == nil {
		r.hold.Store(nil)
		return
	}
	r.hold.Store(&hold)
}

func (r *Responder) Stop() {
	if r.sub != nil {
		_ = r.sub.Unsubscribe()
	}
}

func (r *Responder) handle(m *nats.Msg) {
	arc, err := jwt.DecodeAuthorizationRequestClaims(string(m.Data))
	if err != nil {
		log.Printf("busauth: undecodable auth request: %v", err)
		return // can't form a signed response without the server id; drop → server times out → deny
	}
	serverID := arc.Server.ID
	userNkey := arc.UserNkey
	nodeID := arc.ConnectOptions.Username
	token := arc.ConnectOptions.Password
	host := arc.ClientInformation.Host
	cid := arc.ClientInformation.ID // server connection id; what a revoke closes

	if hold := r.hold.Load(); hold != nil {
		if held, why := (*hold)(); held {
			log.Printf("busauth: hold node=%q host=%q: %s", nodeID, host, why)
			r.respond(m, userNkey, serverID, "", why)
			return
		}
	}
	ok, reason := r.authorize(Conn{ServerID: serverID, CID: cid, Host: host}, nodeID, token)
	if !ok {
		log.Printf("busauth: deny node=%q host=%q: %s", nodeID, host, reason)
		r.respond(m, userNkey, serverID, "", reason)
		return
	}

	userJWT, err := r.mintUserJWT(userNkey, nodeID)
	if err != nil {
		log.Printf("busauth: mint failed for node=%q: %v", nodeID, err)
		r.respond(m, userNkey, serverID, "", "internal error minting credentials")
		return
	}
	r.respond(m, userNkey, serverID, userJWT, "")
}

// authorize implements the trust model: every connection presents a valid node
// id (it scopes the grant) and a live join token bound to that id. conn names
// the connection (the asking server's id, its id for the connection, and the
// host it came from), recorded on the grant so revoking the token can close
// it and so a takeover names both presenters.
//
// Where a connection comes from earns it nothing. The bus used to trust any
// loopback connection without a token, for the controlplane's co-located
// agent; that let any local user on the controlplane claim any node's id, and
// bus TLS authenticates the server, never the client. That agent now holds a
// token the api mints for it (Store.EnsureAgentToken), and loopback clients
// authenticate like everyone else (geekdojo/geekdojo-brain#140, decided
// 2026-09-17). Do not reintroduce a source-address exemption.
//
// The node id is checked first: it becomes one token of every subject in the
// minted credential, and nats-server passes the username through to the
// callout unvalidated.
func (r *Responder) authorize(conn Conn, nodeID, token string) (bool, string) {
	if nodeID == "" {
		return false, "missing node id (NATS username)"
	}
	if !ValidNodeID(nodeID) {
		return false, "invalid node id (NATS username): " + NodeIDRule
	}
	if token == "" {
		return false, "missing join token"
	}
	ctx, cancel := context.WithTimeout(context.Background(), validateTimeout)
	defer cancel()
	// Pass the presented node id: a token bound to a different node is rejected
	// here, so a leaked token can't be replayed as another node.
	valid, err := r.tokens.Admit(ctx, conn, token, nodeID)
	if err != nil {
		return false, "token validation error"
	}
	if !valid {
		return false, "invalid, revoked, or wrong-node join token"
	}
	return true, ""
}

// mintUserJWT builds the per-node scoped user credential, signed by the issuer
// account key. Permissions are the documented starting set; widen here if the
// enforce-on-bench step shows an agent denied a subject it needs.
//
// It re-checks the node id itself (defence in depth): the id is spliced into
// the permission subjects below, so a caller that skipped authorize must still
// never get a credential scoped to anything but one literal subject token.
func (r *Responder) mintUserJWT(userNkey, nodeID string) (string, error) {
	if err := checkNodeID(nodeID); err != nil {
		return "", err
	}
	uc := jwt.NewUserClaims(userNkey)
	uc.Name = nodeID
	uc.Audience = globalAccount // placement (non-operator mode)

	// A zero-value Responder must still mint a bounded credential: a zero
	// Expires is read by nats-server as "never expires".
	userTTL := r.userTTL
	if userTTL <= 0 {
		userTTL = mintedTTL
	}
	uc.Expires = time.Now().Add(userTTL).Unix()

	// A Responder built as a zero value (tests, a future constructor that
	// forgets the field) must not fall back to the server's two-minute default
	// — that is the bug this constant exists to close.
	replyTTL := r.replyTTL
	if replyTTL <= 0 {
		replyTTL = proto.BusReplyGrantTTL
	}

	scope := "rasputin.node." + nodeID
	uc.Permissions.Pub.Allow.Add(scope + ".>") // events, heartbeat, logs
	// ...but NOT its own command lane. `rasputin.node.<id>.cmd.>` is the
	// control plane's direction of travel (proto/subjects.go): the api
	// publishes commands there and the agent subscribes, so a node that can
	// publish there can issue itself every verb the agent implements —
	// firewall.apply, storage.claim, update.install, app.leaf — with no api
	// decision in front of it. The broker is the only thing that separates the
	// two directions on a shared subject tree, so it has to say so. Deny wins
	// over Allow in nats-server, and the deny is one subtree of the allow above
	// (jwt v2 Permission.Deny; geekdojo/geekdojo-brain#500).
	//
	// This costs a real agent nothing: every agent publish is an evt.*,
	// heartbeat or log subject (agent/…: NodeEvtSubject, NodeHeartbeatSubject,
	// the log subjects), and replies to the api's commands go to the reply
	// subject through the Resp grant below, never to a cmd subject. The api's
	// own connection is not callout-minted (it is the in-process AuthUser), so
	// CP→node commands are untouched.
	uc.Permissions.Pub.Deny.Add(proto.NodeCmdFilter(nodeID))
	// A node subscribes to its own commands and NOTHING else — in particular
	// not _INBOX.>. Inbox subscriptions exist only to receive replies to
	// requests a connection makes, and the agent makes none: it only answers,
	// through the Resp grant below. The api's requests to every node use
	// nats.go's shared _INBOX. prefix, so an _INBOX.> subscribe grant let any
	// node read every other node's replies to the api — the PPPoE WAN password
	// in firewall.get, the passphrase-sealed backup key in storage.* (geekdojo/
	// geekdojo-brain#451). If the agent ever needs to make a request, give it a
	// per-node inbox prefix; do not re-add the shared one.
	uc.Permissions.Sub.Allow.Add(scope + ".cmd.>")
	// Let the agent answer request-reply (api → agent commands) by publishing
	// to the reply subject it received, without granting blanket pub. Both
	// bounds are set EXPLICITLY because nats-server fills a zero with its own
	// default, and both of its defaults are wrong for us:
	//
	//   MaxMsgs -1 — unlimited. The default is 1.
	//   Expires    — proto.BusReplyGrantTTL. The default is two minutes, which
	//                is shorter than every agent work budget we hand out, so a
	//                slow handler lost the right to answer mid-flight and the
	//                operator saw only "context deadline exceeded".
	//
	// This bounds a LIFETIME, not a subject space: the grant still covers only
	// the one literal reply subject the server just delivered to this
	// connection, and only because the connection cannot already publish there.
	// See proto/busreply.go for the full derivation. Do NOT "fix" this by
	// adding _INBOX.> to Pub.Allow — that would let any compromised node forge
	// acks for requests addressed to other nodes.
	uc.Permissions.Resp = &jwt.ResponsePermission{
		MaxMsgs: -1,
		Expires: replyTTL,
	}

	return uc.Encode(r.issuer.KeyPair())
}

func (r *Responder) respond(m *nats.Msg, userNkey, serverID, userJWT, errMsg string) {
	rc := jwt.NewAuthorizationResponseClaims(userNkey)
	rc.Audience = serverID
	if errMsg != "" {
		rc.Error = errMsg
	} else {
		rc.Jwt = userJWT
	}
	tok, err := rc.Encode(r.issuer.KeyPair())
	if err != nil {
		log.Printf("busauth: encode response failed: %v", err)
		return
	}
	_ = m.Respond([]byte(tok))
}
