package bus

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/mdns"
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
type mdnsDialer struct {
	resolveTimeout time.Duration
	dialTimeout    time.Duration
}

func (d *mdnsDialer) Dial(network, address string) (net.Conn, error) {
	if host, port, err := net.SplitHostPort(address); err == nil &&
		strings.HasSuffix(strings.ToLower(host), ".local") {
		if ip, rerr := mdns.Resolve(host, d.resolveTimeout); rerr == nil && ip != "" {
			address = net.JoinHostPort(ip, port)
		} else if rerr != nil {
			log.Printf("agent/bus: mDNS resolve %s failed (%v); falling back to OS resolver", host, rerr)
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
	url, nodeID, token string
	// onConn runs on every NEW conn — the first Dial and each re-dial from
	// the closed state — before onConnected. Subscriptions live on the conn,
	// so this is where the agent (re-)registers every handler. A non-nil
	// error rejects the conn: it is closed and the attempt counts as failed.
	onConn func(*nats.Conn) error
	// onConnected runs after every successful connect: the first Dial, each
	// nats-level reconnect (same conn, subscriptions intact) and each
	// re-dial. The agent (re-)publishes its registration here.
	onConnected func(*nats.Conn)

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

	// redials counts successful re-dials from the closed state.
	redials atomic.Int64
}

// New builds a Client that is not yet connected; call Dial. url "" means
// nats.DefaultURL. See Client for what onConn and onConnected are for.
//
// token is the node's bus join credential (RASPUTIN_CP_JOIN_TOKEN). It is
// presented as NATS username=nodeID, password=token, which the api's
// auth-callout responder validates to mint a per-node scoped JWT. It is
// harmless to pass when the server has no auth enabled (NATS ignores creds it
// doesn't require), so the agent always passes it; only the SERVER's
// RASPUTIN_BUS_AUTH flag gates enforcement. A controlplane's co-located agent
// has no token and is trusted via loopback.
func New(url, nodeID, token string, onConn func(*nats.Conn) error, onConnected func(*nats.Conn)) *Client {
	if url == "" {
		url = nats.DefaultURL
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		url:           url,
		nodeID:        nodeID,
		token:         token,
		onConn:        onConn,
		onConnected:   onConnected,
		reconnectWait: 2 * time.Second,
		backoff:       DefaultBackoff,
		ctx:           ctx,
		cancel:        cancel,
	}
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
		nats.SetCustomDialer(&mdnsDialer{resolveTimeout: 2 * time.Second, dialTimeout: 5 * time.Second}),
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
				log.Printf("agent/bus: disconnected: %v", err)
			}
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			log.Printf("agent/bus: reconnected to %s", nc.ConnectedUrl())
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
				log.Printf("rasputin-agent: bus: PERMISSIONS VIOLATION on %s: %v — "+
					"this node's minted credential does not allow that subject. If it "+
					"names an _INBOX subject, a reply outlived its response grant "+
					"(see proto.BusReplyGrantTTL); otherwise the publish is outside "+
					"rasputin.node.%s.>", subject, err, c.nodeID)
				return
			}
			if errors.Is(err, nats.ErrAuthorization) {
				log.Printf("rasputin-agent: bus: %v — the control plane is up but does not "+
					"accept this node's join token (a rebuilt controlplane whose token store "+
					"is not seeded yet looks exactly like this); the client keeps retrying", err)
				return
			}
			log.Printf("rasputin-agent: bus: async error on %s: %v", subject, err)
		}),
	}
	// Always present the node id as the NATS username (token as password, which
	// may be empty). The callout needs the id to scope the grant and to apply
	// loopback trust for a tokenless controlplane agent; an empty token from a
	// non-loopback node is correctly denied. Harmless when the server has no
	// auth — NATS ignores creds it doesn't require.
	connOpts = append(connOpts, nats.UserInfo(c.nodeID, c.token))
	connOpts = append(connOpts, c.extraOpts...)
	nc, err := nats.Connect(c.url, connOpts...)
	if err != nil {
		return nil, fmt.Errorf("agent/bus: connect %s: %w", c.url, err)
	}
	if c.onConn != nil {
		if err := c.onConn(nc); err != nil {
			nc.Close()
			return nil, fmt.Errorf("agent/bus: set up %s: %w", c.url, err)
		}
	}
	return nc, nil
}

// install makes nc the current conn, announces it, and runs onConnected.
// redialed says whether this is the first Dial or a re-dial from the closed
// state — the log line and the counter differ, the rest is identical.
func (c *Client) install(nc *nats.Conn, redialed bool) {
	c.mu.Lock()
	c.conn = nc
	c.redialing = false
	c.mu.Unlock()
	if redialed {
		c.redials.Add(1)
		log.Printf("agent/bus: re-dialed %s as %s — new connection, handlers re-subscribed", nc.ConnectedUrl(), c.nodeID)
	} else {
		log.Printf("agent/bus: connected to %s as %s", nc.ConnectedUrl(), c.nodeID)
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
	log.Printf("agent/bus: connection CLOSED (%s) — the nats client will not reconnect this one; re-dialing %s from scratch", reason, c.url)
	go c.redial()
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
		log.Printf("agent/bus: re-dial attempt %d failed: %v; next attempt in %s", attempt, err, wait.Round(time.Millisecond))
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
