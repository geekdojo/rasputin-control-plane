package api

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
)

// The collector ingress admits a node only while it holds a live join token,
// and it decides that per CONNECTION, never per request: the check runs once,
// in the TLS handshake, against the token store's in-memory live-node set
// (busauth livenodes.go) — no database read on the connection or request path.
// A node that loses its last live token (revoke, or node removal, which
// revokes every token) has its open ingress connections closed at once, the
// same way a revoke drops its bus sessions, so a kept-alive connection cannot
// outlive the revocation.

// IngestLiveness is what the ingress needs from the token store: the in-memory
// live-node set, and the event that a node left it. *busauth.Store implements
// it.
type IngestLiveness interface {
	// NodeLive reports, from memory, whether nodeID holds a live token.
	NodeLive(nodeID string) bool
	// OnNodeRevoked registers fn to run each time a node leaves the set.
	OnNodeRevoked(fn func(nodeID string))
}

// ingestConns tracks the ingress's admitted connections by node id.
type ingestConns struct {
	gate IngestLiveness

	mu     sync.Mutex
	byNode map[string]map[net.Conn]struct{}
	nodeOf map[net.Conn]string
}

// WireObsIngest installs the per-connection liveness gate on the ingress
// server: a VerifyConnection (through GetConfigForClient, which is what hands
// it the connection) that refuses the handshake of a node not in the
// live-node set and records the connection under its node id, a ConnState that
// forgets closed connections, and an OnNodeRevoked hook that closes a node's
// connections when it leaves the set. hs.TLSConfig must already carry the
// listener's client-certificate verification; call before the server starts.
func (s *Server) WireObsIngest(hs *http.Server, gate IngestLiveness) error {
	if hs == nil || hs.TLSConfig == nil {
		return errors.New("obs ingress: no TLS config to install the liveness gate on")
	}
	if gate == nil {
		return errors.New("obs ingress: no token store to check node liveness against")
	}
	c := &ingestConns{gate: gate, byNode: map[string]map[net.Conn]struct{}{}, nodeOf: map[net.Conn]string{}}
	base := hs.TLSConfig.Clone()
	hs.TLSConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		cfg := base.Clone()
		raw := hello.Conn
		cfg.VerifyConnection = func(cs tls.ConnectionState) error { return c.admit(raw, cs) }
		return cfg, nil
	}
	prev := hs.ConnState
	hs.ConnState = func(conn net.Conn, st http.ConnState) {
		if st == http.StateClosed || st == http.StateHijacked {
			c.forget(conn)
		}
		if prev != nil {
			prev(conn, st)
		}
	}
	gate.OnNodeRevoked(c.closeNode)
	return nil
}

// admit runs once per handshake, after the client chain has verified. The
// check and the record happen under one lock, and closeNode takes the same
// lock after the live-node set has changed, so a connection is either refused
// here or recorded in time to be closed there.
func (c *ingestConns) admit(raw net.Conn, cs tls.ConnectionState) error {
	nodeID, err := nodeIDFromClientCert(&cs)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.gate.NodeLive(nodeID) {
		log.Printf("obs ingest: refusing a handshake from %q — the node holds no live join token (none minted, or all revoked)", nodeID)
		return fmt.Errorf("node %q holds no live join token", nodeID)
	}
	if c.byNode[nodeID] == nil {
		c.byNode[nodeID] = map[net.Conn]struct{}{}
	}
	c.byNode[nodeID][raw] = struct{}{}
	c.nodeOf[raw] = nodeID
	return nil
}

// forget drops a closed connection. The server reports the *tls.Conn; the
// record is keyed by the connection underneath it, which is what the
// handshake saw.
func (c *ingestConns) forget(conn net.Conn) {
	if tc, ok := conn.(*tls.Conn); ok {
		conn = tc.NetConn()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	node, ok := c.nodeOf[conn]
	if !ok {
		return
	}
	delete(c.nodeOf, conn)
	delete(c.byNode[node], conn)
	if len(c.byNode[node]) == 0 {
		delete(c.byNode, node)
	}
}

// closeNode closes every admitted connection of nodeID. The server then sees
// each one close and forgets it.
func (c *ingestConns) closeNode(nodeID string) {
	c.mu.Lock()
	conns := make([]net.Conn, 0, len(c.byNode[nodeID]))
	for conn := range c.byNode[nodeID] {
		conns = append(conns, conn)
	}
	c.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	if len(conns) > 0 {
		log.Printf("obs ingest: closed %d connection(s) of %q — its join token was revoked", len(conns), nodeID)
	}
}
