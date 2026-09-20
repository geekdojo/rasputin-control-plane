package api

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The api's node listener admits a node by the KEY it presents, and it decides
// that per CONNECTION: the check runs once, in the TLS handshake, against the
// api's one in-memory node registry (inventory.Registry) — no database read on
// the connection or the request path.
//
// Two ways to be admitted, for as long as both kinds of client are in the
// fleet (geekdojo/geekdojo-brain#513):
//
//   - A REGISTERED KEY. The node generated it, reported its SPKI hash over a
//     pinned bus connection, and the api recorded it (#514). The listener runs
//     ClientAuth=RequireAnyClientCert and compares the peer's SubjectPublicKeyInfo
//     against the registry: no chain, no name, no dates, for the same reasons
//     the bus pins a key rather than trusting a CA (proto.BusPinPrefix). The
//     certificate around the key is the node's own, self-signed, and nothing
//     issues it.
//   - THE MESH CHAIN, for a collector deployed before the keys existed. Because
//     RequireAnyClientCert does not verify anything, the chain is verified here,
//     explicitly, against the mesh CA, and the identity is the leaf's
//     CommonName — which is what this listener has always done.
//
// Either way the node must also be a current inventory member holding a live
// join token, and a node that stops qualifying has its open connections closed
// at once, the same way a revoke drops its bus sessions. A key that stops being
// registered — replaced after a reflash, or cleared by a removal — closes the
// connections held under THAT key, so a replaced key stops working without
// disturbing the new one.

// IngestRegistry is what the listener needs from the node registry.
// *inventory.Registry implements it.
type IngestRegistry interface {
	// Admitted reports, from memory, whether nodeID is a current member
	// holding a live token.
	Admitted(nodeID string) bool
	// AdmitKey reports, from memory, which node registered the key with
	// this SPKI hash and what the key is for — and answers only while that
	// node is admitted.
	AdmitKey(spki string) (inventory.KeyOwner, bool)
	// OnNodeExcluded registers fn to run each time a node stops being
	// admitted.
	OnNodeExcluded(fn func(nodeID string))
	// OnKeysRetired registers fn to run each time SPKI hashes stop being
	// registered for a node.
	OnKeysRetired(fn func(nodeID string, retired []string))
}

// nodeIdentity is who the handshake decided the peer is.
type nodeIdentity struct {
	nodeID string
	// purpose is what the presented key is registered for, empty for a
	// client admitted by the mesh chain. A route that is only for one
	// purpose checks it; a legacy client has none to check.
	purpose proto.NodeKeyPurpose
	// spki is the presented key's hash, empty for a mesh-chain client.
	spki string
}

// ingestConns tracks the listener's admitted connections by node id and by the
// key they were admitted under.
type ingestConns struct {
	gate IngestRegistry
	// meshClients verifies a legacy collector's chain; nil once there are
	// no legacy clients left, which refuses everything but a registered key.
	meshClients *x509.CertPool

	mu     sync.Mutex
	byNode map[string]map[net.Conn]struct{}
	byKey  map[string]map[net.Conn]struct{}
	nodeOf map[net.Conn]nodeIdentity
}

// WireObsIngest installs the per-connection admission gate on the node
// listener: a VerifyConnection (through GetConfigForClient, which is what hands
// it the connection) that refuses the handshake of a peer the registry does not
// admit and records the connection under its node id and key, a ConnState that
// forgets closed connections, and hooks that close a node's connections when it
// stops being admitted or when a key it held stops being registered.
//
// meshClients is the pool a legacy collector's chain is verified against — the
// mesh CA. Passing nil admits registered keys only.
//
// hs.TLSConfig must already carry the listener's certificate selection; call
// before the server starts.
func (s *Server) WireObsIngest(hs *http.Server, gate IngestRegistry, meshClients *x509.CertPool) error {
	if hs == nil || hs.TLSConfig == nil {
		return errors.New("obs ingress: no TLS config to install the admission gate on")
	}
	if gate == nil {
		return errors.New("obs ingress: no node registry to check admission against")
	}
	c := newIngestConns(gate, meshClients)
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
	gate.OnKeysRetired(c.closeKeys)
	s.nodeGate = c
	return nil
}

// newIngestConns builds the gate. Separate from WireObsIngest so the handler
// tests can build one without a listener.
func newIngestConns(gate IngestRegistry, meshClients *x509.CertPool) *ingestConns {
	return &ingestConns{
		gate:        gate,
		meshClients: meshClients,
		byNode:      map[string]map[net.Conn]struct{}{},
		byKey:       map[string]map[net.Conn]struct{}{},
		nodeOf:      map[net.Conn]nodeIdentity{},
	}
}

// identify decides who a peer is, from memory. It is the whole admission rule,
// and it is the same function the handshake and every request run, so the two
// cannot drift.
func (c *ingestConns) identify(cs *tls.ConnectionState) (nodeIdentity, error) {
	if cs == nil {
		return nodeIdentity{}, errors.New("no TLS connection state (non-TLS request)")
	}
	if len(cs.PeerCertificates) == 0 {
		return nodeIdentity{}, errors.New("no client certificate presented")
	}
	leaf := cs.PeerCertificates[0]

	// A registered key first. The certificate around it is not examined at
	// all: this is a key check, and a node's own self-signed wrapper has
	// nothing else worth reading.
	spki := proto.NodeKeySPKIHashForDER(leaf.RawSubjectPublicKeyInfo)
	if owner, ok := c.gate.AdmitKey(spki); ok {
		return nodeIdentity{nodeID: owner.NodeID, purpose: owner.Purpose, spki: spki}, nil
	}

	// Otherwise the legacy path: a mesh-CA-signed client leaf whose
	// CommonName is the node id. RequireAnyClientCert verified nothing, so
	// the chain is verified here or not at all.
	if c.meshClients == nil {
		return nodeIdentity{}, errors.New("the presented key is not registered to any node")
	}
	inter := x509.NewCertPool()
	for _, cert := range cs.PeerCertificates[1:] {
		inter.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         c.meshClients,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nodeIdentity{}, fmt.Errorf("the presented key is not registered, and its certificate does not chain to the mesh CA: %w", err)
	}
	nodeID, err := nodeIDFromClientCert(cs)
	if err != nil {
		return nodeIdentity{}, err
	}
	if !c.gate.Admitted(nodeID) {
		return nodeIdentity{}, fmt.Errorf("node %q is not admitted", nodeID)
	}
	return nodeIdentity{nodeID: nodeID}, nil
}

// admit runs once per handshake. The check and the record happen under one
// lock, and the close hooks take the same lock after the registry has changed,
// so a connection is either refused here or recorded in time to be closed
// there.
func (c *ingestConns) admit(raw net.Conn, cs tls.ConnectionState) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	id, err := c.identify(&cs)
	if err != nil {
		log.Printf("obs ingest: refusing a handshake: %v", err)
		return err
	}
	if c.byNode[id.nodeID] == nil {
		c.byNode[id.nodeID] = map[net.Conn]struct{}{}
	}
	c.byNode[id.nodeID][raw] = struct{}{}
	if id.spki != "" {
		if c.byKey[id.spki] == nil {
			c.byKey[id.spki] = map[net.Conn]struct{}{}
		}
		c.byKey[id.spki][raw] = struct{}{}
	}
	c.nodeOf[raw] = id
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
	id, ok := c.nodeOf[conn]
	if !ok {
		return
	}
	delete(c.nodeOf, conn)
	delete(c.byNode[id.nodeID], conn)
	if len(c.byNode[id.nodeID]) == 0 {
		delete(c.byNode, id.nodeID)
	}
	if id.spki == "" {
		return
	}
	delete(c.byKey[id.spki], conn)
	if len(c.byKey[id.spki]) == 0 {
		delete(c.byKey, id.spki)
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
	closeAll(conns)
	if len(conns) > 0 {
		log.Printf("obs ingest: closed %d connection(s) of %q — it was removed or its join token revoked", len(conns), nodeID)
	}
}

// closeKeys closes every connection held under a key that is no longer
// registered for nodeID — a key replaced after a reflash, or cleared by a
// removal. Connections the node holds under its CURRENT key are left alone,
// so a key change ends the old sessions and nothing else.
func (c *ingestConns) closeKeys(nodeID string, retired []string) {
	var conns []net.Conn
	c.mu.Lock()
	for _, spki := range retired {
		for conn := range c.byKey[spki] {
			conns = append(conns, conn)
		}
	}
	c.mu.Unlock()
	closeAll(conns)
	if len(conns) > 0 {
		log.Printf("obs ingest: closed %d connection(s) held under %d retired key(s) of %q", len(conns), len(retired), nodeID)
	}
}

func closeAll(conns []net.Conn) {
	for _, conn := range conns {
		_ = conn.Close()
	}
}
