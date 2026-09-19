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

// The collector ingress admits a node only while it is a current inventory
// member holding a live join token, and it decides that per CONNECTION, never
// per request: the check runs once, in the TLS handshake, against the api's
// one in-memory node registry (inventory.Registry) — no database read on the
// connection or request path. A node that stops qualifying (removed from
// inventory, or its last token revoked) has its open ingress connections
// closed at once, the same way a revoke drops its bus sessions, so a
// kept-alive connection cannot outlive the decision.

// IngestRegistry is what the ingress needs from the node registry.
// *inventory.Registry implements it.
type IngestRegistry interface {
	// Admitted reports, from memory, whether nodeID is a current member
	// holding a live token.
	Admitted(nodeID string) bool
	// OnNodeExcluded registers fn to run each time a node stops being
	// admitted.
	OnNodeExcluded(fn func(nodeID string))
}

// ingestConns tracks the ingress's admitted connections by node id.
type ingestConns struct {
	gate IngestRegistry

	mu     sync.Mutex
	byNode map[string]map[net.Conn]struct{}
	nodeOf map[net.Conn]string
}

// WireObsIngest installs the per-connection liveness gate on the ingress
// server: a VerifyConnection (through GetConfigForClient, which is what hands
// it the connection) that refuses the handshake of a node the registry does
// not admit and records the connection under its node id, a ConnState that
// forgets closed connections, and an OnNodeExcluded hook that closes a node's
// connections when it stops being admitted. hs.TLSConfig must already carry the
// listener's client-certificate verification; call before the server starts.
func (s *Server) WireObsIngest(hs *http.Server, gate IngestRegistry) error {
	if hs == nil || hs.TLSConfig == nil {
		return errors.New("obs ingress: no TLS config to install the liveness gate on")
	}
	if gate == nil {
		return errors.New("obs ingress: no node registry to check admission against")
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
	gate.OnNodeExcluded(c.closeNode)
	s.ingestGated = true
	return nil
}

// admit runs once per handshake, after the client chain has verified. The
// check and the record happen under one lock, and closeNode takes the same
// lock after the registry has changed, so a connection is either refused
// here or recorded in time to be closed there.
func (c *ingestConns) admit(raw net.Conn, cs tls.ConnectionState) error {
	nodeID, err := nodeIDFromClientCert(&cs)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.gate.Admitted(nodeID) {
		log.Printf("obs ingest: refusing a handshake from %q — not a current member holding a live join token (removed, never registered, or its tokens revoked)", nodeID)
		return fmt.Errorf("node %q is not admitted", nodeID)
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
		log.Printf("obs ingest: closed %d connection(s) of %q — it was removed or its join token revoked", len(conns), nodeID)
	}
}
