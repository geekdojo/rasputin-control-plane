package bus

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/mdns"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// ErrNotConnected is what Publish returns before the first successful Dial.
// After that, a publish on a dead connection returns nats.go's own
// nats.ErrConnectionClosed (the client keeps the last conn until the re-dial
// replaces it, so callers see the same error the nats client gives).
var ErrNotConnected = errors.New("agent/bus: not connected")

// Publisher is the one bus verb the agent's periodic publishers (heartbeat,
// metrics, IDS alerts) need. Both *Client and *nats.Conn satisfy it; the
// agent hands them the Client so a publish always lands on the CURRENT
// connection, and tests hand them a bare conn.
type Publisher interface {
	Publish(subj string, data []byte) error
}

// mdnsDialer resolves *.local hostnames via multicast DNS before dialing, so a
// node can reach the control plane at rasputin.local on a LAN whose OS has no
// .local resolver (notably the OpenWrt firewall image). nats calls Dial on every
// (re)connect, so address churn is handled transparently — each reconnect
// re-resolves. Non-.local hosts and bare IPs dial normally.
//
// TRIP-WIRE: this only ever sees a hostname because the options in dial() set
// nats.SkipHostLookup(). Remove that option and nats.go resolves the name
// itself first, this function is handed an IP literal, the guard below stops
// matching, and mDNS silently stops being consulted — which is exactly how a
// control plane that moved became unreachable forever (geekdojo-brain#547).
// TestDial_CustomDialerReceivesHostnameNotResolvedIP is the guard.
type mdnsDialer struct {
	resolveTimeout time.Duration
	dialTimeout    time.Duration
	log            *slog.Logger
}

func (d *mdnsDialer) Dial(network, address string) (net.Conn, error) {
	if host, port, err := net.SplitHostPort(address); err == nil &&
		strings.HasSuffix(strings.ToLower(host), ".local") {
		if ip, rerr := mdns.Resolve(host, d.resolveTimeout); rerr == nil && ip != "" {
			address = net.JoinHostPort(ip, port)
		} else if rerr != nil {
			d.log.Warn("agent/bus: mDNS resolve failed; using the OS resolver",
				"host", host, "err", rerr.Error())
		}
	}
	return net.DialTimeout(network, address, d.dialTimeout)
}

// Client owns the agent's bus connection for the life of the process.
//
// A *nats.Conn is not for life. nats.go reconnects on its own through
// ordinary network loss, but it CLOSES the connection — for good, whatever
// MaxReconnects says — once it decides the failure is permanent, and a closed
// conn can never be reopened: its subscriptions die with it. The Client is the
// layer above that: when the conn reaches the closed state it dials a brand
// new one, forever, with bounded backoff, and re-runs the agent's subscription
// setup (onConn) and registration (onConnected) on it. Everything in the agent
// that publishes goes through the Client rather than holding a conn, so a
// publish always lands on the current connection.
//
// The case this exists for (e3bench, 2026-09-04): the controlplane was wiped
// and came back accepting TCP before its bus credentials were seeded. Every
// agent's reconnect got "authorization violation" twice, nats.go closed the
// conn, and five nodes sat off the bus for 17 hours logging "connection
// closed" every 10s until a human restarted them. See doc.go.
type Client struct {
	url, nodeID string
	// token yields the join token for each connection attempt (Config.Token).
	// It is asked on EVERY connect and reconnect, so a token file the
	// controlplane's api re-mints reaches this client on its next attempt.
	token TokenSource
	// pin is the bus key pin (proto.ParseBusPin form) every conn is dialed
	// with, and pinDigest its parsed digest. Fixed at New: nothing on a node
	// can change the pin a running agent trusts.
	pin       string
	pinDigest [sha256.Size]byte
	log       *slog.Logger
	// onConn runs on every NEW conn — the first Dial and each re-dial from
	// the closed state — before onConnected. Subscriptions live on the conn,
	// so this is where the agent (re-)registers every handler. A non-nil
	// error rejects the conn: it is closed and the attempt counts as failed.
	onConn func(*nats.Conn) error
	// onConnected runs after every successful connect: the first Dial, each
	// nats-level reconnect (same conn, subscriptions intact) and each
	// re-dial. The agent (re-)publishes its registration here.
	onConnected func(*nats.Conn)
	// onLost runs whenever the current connection is lost: nats.go reports a
	// disconnect it will reconnect from, or closes the conn for good. The
	// agent re-verifies its cluster-DNS pin from here — on the event, rather
	// than on a clock (see internal/clusterdns).
	onLost func()

	reconnectWait time.Duration
	backoff       Backoff
	// extraOpts are appended after the client's own options. Tests use them
	// to put nats.go back into its default auth-abort mode so the closed
	// path can be driven with real authorization violations.
	extraOpts []nats.Option

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu        sync.Mutex
	conn      *nats.Conn
	closed    bool // Close was called; never re-dial again
	redialing bool
	// lastRefusal is the last handshake refusal logged, so a server that
	// keeps failing the pin the same way is one entry, not one per attempt.
	// A successful connect or reconnect clears it.
	lastRefusal string

	// redials counts successful re-dials from the closed state.
	redials atomic.Int64
}

// defaultReconnectWait is nats.go's own reconnect wait when Config leaves it
// zero.
const defaultReconnectWait = 2 * time.Second

// Config is everything a Client is given. The agent's composition root
// (cmd/rasputin-agent) builds it; the Client reaches for no collaborator of its
// own.
type Config struct {
	// URL is the bus to dial; "" means nats.DefaultURL.
	URL string
	// NodeID is presented as the NATS username.
	NodeID string
	// Pin is the bus key pin (proto.ParseBusPin form). Required: the bus
	// accepts only TLS, and the pin is the one check on the server's key
	// (geekdojo/geekdojo-brain#517).
	Pin string
	// Token yields the node's bus join credential for each connection
	// attempt. It is presented as NATS username=NodeID, password=token, which
	// the api's auth-callout responder validates to mint a per-node scoped
	// JWT. Every node carries a token, the controlplane's own agent included
	// (geekdojo/geekdojo-brain#140): see ResolveTokenSource. nil presents no
	// token, which an enforcing bus refuses.
	Token TokenSource
	// OnConn, OnConnected and OnLost: see the fields of Client.
	OnConn      func(*nats.Conn) error
	OnConnected func(*nats.Conn)
	OnLost      func()
	// Backoff is the re-dial schedule from the closed state; zero means
	// DefaultBackoff.
	Backoff Backoff
	// ReconnectWait is nats.go's own wait between nats-level reconnect
	// attempts; zero means 2s.
	ReconnectWait time.Duration
	// Log receives every entry the Client writes. Required.
	Log *slog.Logger
}

// New builds a Client that is not yet connected; call Dial. It dials nothing.
// It refuses a Config with no usable pin — there is no plaintext bus to fall
// back to — and one with no logger.
func New(cfg Config) (*Client, error) {
	if cfg.Log == nil {
		return nil, errors.New("agent/bus: Config.Log is required")
	}
	pin := strings.TrimSpace(cfg.Pin)
	digest, err := proto.ParseBusPin(pin)
	if err != nil {
		return nil, fmt.Errorf("agent/bus: the bus accepts only TLS, so a bus pin is required: %w", err)
	}
	url := cfg.URL
	if url == "" {
		url = nats.DefaultURL
	}
	token := cfg.Token
	if token == nil {
		token = StaticToken("")
	}
	backoff := cfg.Backoff
	if backoff == (Backoff{}) {
		backoff = DefaultBackoff
	}
	reconnectWait := cfg.ReconnectWait
	if reconnectWait == 0 {
		reconnectWait = defaultReconnectWait
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		url:           url,
		nodeID:        cfg.NodeID,
		token:         token,
		pin:           pin,
		pinDigest:     digest,
		log:           cfg.Log,
		onConn:        cfg.OnConn,
		onConnected:   cfg.OnConnected,
		onLost:        cfg.OnLost,
		reconnectWait: reconnectWait,
		backoff:       backoff,
		ctx:           ctx,
		cancel:        cancel,
	}, nil
}

// userInfo is the nats UserInfoHandler: nats.go calls it while writing the
// CONNECT of every connection attempt, the first and each reconnect, so the
// token is read fresh each time.
func (c *Client) userInfo() (string, string) {
	tok, err := c.token()
	if err != nil {
		c.log.Warn("agent/bus: no join token for this connection attempt; the bus refuses it and the next attempt reads the token again",
			"node_id", c.nodeID, "err", err.Error())
		return c.nodeID, ""
	}
	return c.nodeID, tok
}

// Dial makes ONE connection attempt: connect, run onConn, run onConnected.
// It does not retry — the caller decides what a failed first dial means (the
// agent loops with its own backoff because the firewall boots before the
// control plane it is dialing). Once Dial has succeeded the Client keeps the
// connection alive on its own for the rest of the process.
func (c *Client) Dial() error {
	nc, err := c.dial()
	if err != nil {
		return err
	}
	c.install(nc, false)
	return nil
}

// dial connects and runs onConn. The returned conn is not yet the Client's
// current conn — install does that — so a ClosedHandler firing on it before
// install is ignored, and a rejected conn is closed without a re-dial.
func (c *Client) dial() (*nats.Conn, error) {
	connOpts := []nats.Option{
		nats.Name(fmt.Sprintf("rasputin-agent/%s", c.nodeID)),
		// Resolve rasputin.local via mDNS on every (re)connect (see mdnsDialer).
		nats.SetCustomDialer(&mdnsDialer{resolveTimeout: 2 * time.Second, dialTimeout: 5 * time.Second, log: c.log}),
		// SkipHostLookup is what makes the dialer above reachable at all.
		// Without it, createConn resolves the URL's hostname through the OS
		// resolver BEFORE calling the dialer (nats.go v1.53.1, nats.go:2454)
		// and hands it the resulting A record. The dialer then receives an IP
		// literal, its ".local" guard never matches, and mdns.Resolve is never
		// called — the mDNS path has been dead since the custom dialer was
		// introduced. With this option createConn falls through to
		// `hosts = append(hosts, u.Host)` and the dialer gets the NAME.
		//
		// This is not cosmetic. On the firewall the OS resolver IS dnsmasq
		// answering from the hosts file hostsync publishes, so when the
		// control plane takes a new DHCP lease the lookup does not fail — it
		// SUCCEEDS with the old address, and the agent dials a host that is no
		// longer there, forever. hostsync deliberately keeps its stale entry
		// while the bus is down (it publishes only what an authenticated bus
		// connection reported), so nothing else breaks the loop: re-resolving
		// the name on the wire, on every reconnect, is the rescue path.
		//
		// What is given up is only nats.go's own multi-A expansion and
		// randomization across them, which a single-control-plane cluster has
		// no use for. A bare IP in the URL is unaffected (net.ParseIP already
		// short-circuited the lookup), and a non-.local hostname still
		// resolves — the dialer passes the name to net.DialTimeout.
		nats.SkipHostLookup(),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(c.reconnectWait),
		nats.PingInterval(20 * time.Second),
		nats.MaxPingsOutstanding(3),
		// nats.go's default is to give up — close the conn, MaxReconnects
		// notwithstanding — the second time the same server answers with the
		// same auth error (Conn.processAuthError, nats.go v1.51.0). That
		// default is for a client whose credentials will never change. Ours
		// change under us: a rebuilt controlplane rejects every node until
		// its token store is seeded, and the tokens are valid again minutes
		// later. Keep reconnecting through it. The re-dial below still
		// covers every other route to the closed state.
		nats.IgnoreAuthErrorAbort(),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				c.log.Warn("agent/bus: disconnected", "node_id", c.nodeID, "err", err.Error())
			}
			c.lost()
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			c.mu.Lock()
			c.lastRefusal = ""
			c.mu.Unlock()
			c.log.Info("agent/bus: reconnected", "node_id", c.nodeID, "url", nc.ConnectedUrl(), "transport", "tls-pinned")
			if c.onConnected != nil {
				c.onConnected(nc)
			}
		}),
		nats.ClosedHandler(c.onClosed),
		// Without this, nats.go installs its own default handler and the only
		// trace of an async failure is a bare, unprefixed line nobody greps for.
		// That matters most for permissions violations: Msg.Respond is an
		// ASYNCHRONOUS publish that returns nil, so an agent whose reply is
		// denied by the bus sees no error at all on the calling goroutine — the
		// denial arrives here, later, or nowhere. A dropped reply then surfaces
		// only on the api as "rpc: context deadline exceeded", which names the
		// wrong side of the connection. Say it loudly, with the fix.
		nats.ErrorHandler(func(_ *nats.Conn, sub *nats.Subscription, err error) {
			subject := "(no subscription)"
			if sub != nil {
				subject = sub.Subject
			}
			if errors.Is(err, nats.ErrPermissionViolation) {
				c.log.Error("agent/bus: permissions violation: this node's minted credential does not allow that subject",
					"node_id", c.nodeID, "subject", subject, "err", err.Error(),
					"fix", "an _INBOX subject means a reply outlived its response grant (see proto.BusReplyGrantTTL); "+
						"any other subject is a publish outside rasputin.node."+c.nodeID+".>")
				return
			}
			if errors.Is(err, nats.ErrAuthorization) {
				c.log.Warn("agent/bus: the control plane does not accept this node's join token; retrying "+
					"(a rebuilt controlplane whose token store is not seeded yet looks exactly like this)",
					"node_id", c.nodeID, "err", err.Error())
				return
			}
			c.log.Error("agent/bus: async error", "node_id", c.nodeID, "subject", subject, "err", err.Error())
		}),
	}
	// Always present the node id as the NATS username and the join token as
	// the password. The callout needs the id to scope the grant and a token
	// bound to that id to admit the connection at all — from any address,
	// loopback included (geekdojo/geekdojo-brain#140). Asked per attempt
	// (userInfo), never captured here, so a re-minted token file is picked up
	// by the next reconnect. Harmless when the server has no auth — NATS
	// ignores creds it doesn't require.
	connOpts = append(connOpts, nats.UserInfoHandler(c.userInfo))
	// nats.Secure sets Opts.Secure, so a server whose INFO offers no TLS is
	// refused with ErrSecureConnWanted BEFORE the CONNECT carrying the join
	// token is written: the agent never speaks plaintext, and a man in the
	// middle cannot talk it down to it. The verification is the pin and
	// nothing else — see pinnedTLSConfig.
	connOpts = append(connOpts, nats.Secure(c.tlsConfig()))
	connOpts = append(connOpts, c.extraOpts...)
	nc, err := nats.Connect(c.url, connOpts...)
	if err != nil {
		return nil, fmt.Errorf("agent/bus: connect %s (TLS, pinned %s): %w", c.url, c.pin, err)
	}
	if c.onConn != nil {
		if err := c.onConn(nc); err != nil {
			nc.Close()
			return nil, fmt.Errorf("agent/bus: set up %s: %w", c.url, err)
		}
	}
	return nc, nil
}

// errPinMismatch is what the TLS handshake fails with when the server's key is
// not the pinned one.
var errPinMismatch = errors.New("the bus server's key does not match RASPUTIN_BUS_PIN — refusing the connection (a controlplane with a different bus key: reflashed without restoring its identity, or not this cluster's)")

// pinnedTLSConfig verifies the server by the SHA-256 of its leaf certificate's
// SubjectPublicKeyInfo, and by nothing else: no CA chain, no hostname, no
// validity dates (geekdojo/geekdojo-brain#448 — a chain would lock the fleet
// out on a CA change, dates would make bus membership depend on a Pi's clock
// at boot, before NTP).
//
// CodeQL/gosec flag InsecureSkipVerify, and here it is the opposite of
// insecure: the chain check it skips would accept any certificate a trusted
// CA signed, while VerifyConnection accepts exactly one public key.
//
// TRIP-WIRE: the safety of the InsecureSkipVerify line lives in the
// VerifyConnection assignment beside it. VerifyConnection — not
// VerifyPeerCertificate — because it runs on EVERY handshake, resumed ones
// included; if it is removed, made conditional, or swapped for a check that
// does not compare the full digest, this config accepts any server at all.
func pinnedTLSConfig(want [sha256.Size]byte) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // verified by pin in VerifyConnection, below — see the doc comment
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("the bus server presented no certificate")
			}
			if !proto.BusPinMatchesSPKI(want, cs.PeerCertificates[0].RawSubjectPublicKeyInfo) {
				return errPinMismatch
			}
			return nil
		},
	}
}

// install makes nc the current conn, announces it, and runs onConnected.
// redialed says whether this is the first Dial or a re-dial from the closed
// state — the log line and the counter differ, the rest is identical.
func (c *Client) install(nc *nats.Conn, redialed bool) {
	c.mu.Lock()
	c.conn = nc
	c.redialing = false
	c.lastRefusal = ""
	c.mu.Unlock()
	if redialed {
		c.redials.Add(1)
		c.log.Info("agent/bus: re-dialed; new connection, handlers re-subscribed",
			"node_id", c.nodeID, "url", nc.ConnectedUrl(), "transport", "tls-pinned")
	} else {
		c.log.Info("agent/bus: connected", "node_id", c.nodeID, "url", nc.ConnectedUrl(), "transport", "tls-pinned")
	}
	if c.onConnected != nil {
		c.onConnected(nc)
	}
	// The conn can close between onConn and the assignment above, in which
	// case its ClosedHandler already fired and was ignored (nc was not yet
	// the current conn). Re-check now that it is; onClosed is idempotent.
	if nc.IsClosed() {
		c.onClosed(nc)
	}
}

// onClosed is the nats ClosedHandler. nats.go has given up on this conn for
// good; unless the agent itself is shutting down, dial a new one.
func (c *Client) onClosed(nc *nats.Conn) {
	c.mu.Lock()
	if nc != c.conn || c.closed || c.redialing {
		c.mu.Unlock()
		return
	}
	c.redialing = true
	c.wg.Add(1)
	c.mu.Unlock()
	reason := "no error recorded"
	if err := nc.LastError(); err != nil {
		reason = err.Error()
	}
	c.log.Warn("agent/bus: connection closed for good; re-dialing from scratch",
		"node_id", c.nodeID, "reason", reason, "url", c.url)
	c.lost()
	go c.redial()
}

// tlsConfig is pinnedTLSConfig for this Client's pin, with every handshake the
// pin check refuses reported through handshakeRefused. nats.go reports no
// error for a nats-level reconnect whose TLS handshake fails, so without this
// a running node refused by a controlplane restored onto a different key would
// sit off the bus with nothing in its journal saying why
// (docs/bus-tls-contract.md).
func (c *Client) tlsConfig() *tls.Config {
	cfg := pinnedTLSConfig(c.pinDigest)
	check := cfg.VerifyConnection
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		err := check(cs)
		if err != nil {
			c.handshakeRefused(err)
		}
		return err
	}
	return cfg
}

// handshakeRefused logs a handshake the pin check refused, at WARN, once per
// distinct error until the next successful connect.
func (c *Client) handshakeRefused(err error) {
	msg := err.Error()
	c.mu.Lock()
	same := msg == c.lastRefusal
	c.lastRefusal = msg
	c.mu.Unlock()
	if same {
		return
	}
	c.log.Warn("agent/bus: refused the bus server's key; retrying", "node_id", c.nodeID, "url", c.url, "pin", c.pin, "err", msg)
}

// lost runs the OnLost hook unless the Client itself is closing: the agent's
// own shutdown drains the conn through the same handlers, and that is not a
// loss anyone needs to react to.
func (c *Client) lost() {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed || c.onLost == nil {
		return
	}
	c.onLost()
}

// redial dials until it succeeds or the Client is closed. Each failure is
// logged with its reason and the next delay; the schedule is Backoff.
func (c *Client) redial() {
	defer c.wg.Done()
	for attempt := 1; ; attempt++ {
		nc, err := c.dial()
		if err == nil {
			c.install(nc, true)
			return
		}
		wait := c.backoff.Delay(attempt)
		c.log.Warn("agent/bus: re-dial attempt failed",
			"node_id", c.nodeID, "attempt", attempt, "err", err.Error(), "next", wait.Round(time.Millisecond))
		select {
		case <-c.ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// Conn returns the current connection: nil before the first successful Dial,
// and the last conn (possibly closed) while a re-dial is in progress. Hold it
// only for the duration of one operation — the next re-dial replaces it.
func (c *Client) Conn() *nats.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn
}

// Publish publishes on the current connection.
func (c *Client) Publish(subj string, data []byte) error {
	nc := c.Conn()
	if nc == nil {
		return ErrNotConnected
	}
	return nc.Publish(subj, data)
}

// ConnectedAddr is the peer address of the current connection, or "" when
// there is none or it is not currently connected.
func (c *Client) ConnectedAddr() string {
	nc := c.Conn()
	if nc == nil {
		return ""
	}
	return nc.ConnectedAddr()
}

// Redials reports how many times the Client has re-dialed from the closed
// state.
func (c *Client) Redials() int64 { return c.redials.Load() }

// Close stops re-dialing and drains the current connection. Safe to call more
// than once.
func (c *Client) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	nc := c.conn
	c.mu.Unlock()
	c.cancel()
	c.wg.Wait()
	// A re-dial that raced Close may have installed a newer conn.
	if cur := c.Conn(); cur != nil {
		nc = cur
	}
	if nc != nil && !nc.IsClosed() {
		_ = nc.Drain()
	}
}
