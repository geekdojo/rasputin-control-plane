package busauth

import (
	"context"
	"log"
	"net"
	"time"

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

	// mintedTTL bounds an authorized connection. Agents reconnect (and re-auth)
	// well within this; a short-ish TTL caps the blast radius of a minted JWT
	// while not generating churn.
	mintedTTL = 24 * time.Hour

	validateTimeout = 3 * time.Second
)

// Validator is the subset of *Store the responder needs (eases testing).
type Validator interface {
	Validate(ctx context.Context, plaintext string) (bool, error)
}

// Responder handles NATS auth-callout requests on the in-process connection:
// it validates the presented join token (or trusts loopback), then mints a
// per-node subject-scoped user JWT signed by the issuer account key.
type Responder struct {
	nc     *nats.Conn
	issuer *Issuer
	tokens Validator
	sub    *nats.Subscription
}

func NewResponder(nc *nats.Conn, issuer *Issuer, tokens Validator) *Responder {
	return &Responder{nc: nc, issuer: issuer, tokens: tokens}
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

	ok, reason := r.authorize(nodeID, token, host)
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

// authorize implements the trust model: a node id is always required (it scopes
// the grant); loopback connections are trusted same-box-as-the-authority (the
// controlplane's co-located agent, which carries no join token); every other
// connection must present a live token.
func (r *Responder) authorize(nodeID, token, host string) (bool, string) {
	if nodeID == "" {
		return false, "missing node id (NATS username)"
	}
	if isLoopback(host) {
		return true, ""
	}
	if token == "" {
		return false, "missing join token"
	}
	ctx, cancel := context.WithTimeout(context.Background(), validateTimeout)
	defer cancel()
	valid, err := r.tokens.Validate(ctx, token)
	if err != nil {
		return false, "token validation error"
	}
	if !valid {
		return false, "invalid or revoked join token"
	}
	return true, ""
}

// mintUserJWT builds the per-node scoped user credential, signed by the issuer
// account key. Permissions are the documented starting set; widen here if the
// enforce-on-bench step shows an agent denied a subject it needs.
func (r *Responder) mintUserJWT(userNkey, nodeID string) (string, error) {
	uc := jwt.NewUserClaims(userNkey)
	uc.Name = nodeID
	uc.Audience = globalAccount // placement (non-operator mode)
	uc.Expires = time.Now().Add(mintedTTL).Unix()

	scope := "rasputin.node." + nodeID
	uc.Permissions.Pub.Allow.Add(scope + ".>") // events, heartbeat, logs
	uc.Permissions.Sub.Allow.Add(scope + ".cmd.>")
	uc.Permissions.Sub.Allow.Add("_INBOX.>") // replies to requests the agent makes
	// Let the agent answer request-reply (api → agent commands) by publishing
	// to the reply subject it received, without granting blanket pub.
	uc.Permissions.Resp = &jwt.ResponsePermission{MaxMsgs: -1}

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

func isLoopback(host string) bool {
	if host == "" {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
