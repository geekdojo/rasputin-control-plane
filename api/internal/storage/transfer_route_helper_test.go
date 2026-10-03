package storage

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Test doubles for key-bound transfer in this package's harnesses.

// fakeRouteNodes is the router's view of inventory. A node it was not told
// about reads as a registered node whose agent predates key-bound transfer,
// so every harness that is not about routing routes by bearer, as before.
// getErr and keysErr inject read errors; calls counts Get per node.
type fakeRouteNodes struct {
	mu      sync.Mutex
	nodes   map[string]*proto.Node
	absent  map[string]bool
	keys    map[string]proto.NodeKeys
	getErr  error
	keysErr error
	calls   map[string]int
}

// capable marks id as advertising key-bound transfer with keys registered.
func (f *fakeRouteNodes) capable(id string, keys proto.NodeKeys) *fakeRouteNodes {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.nodes == nil {
		f.nodes, f.keys = map[string]*proto.Node{}, map[string]proto.NodeKeys{}
	}
	f.nodes[id] = &proto.Node{ID: id, Capabilities: []string{proto.CapabilityKeyBoundTransfer}}
	f.keys[id] = keys
	return f
}

func (f *fakeRouteNodes) Get(_ context.Context, id string) (*proto.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[id]++
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.absent[id] {
		return nil, nil
	}
	if n, ok := f.nodes[id]; ok {
		return n, nil
	}
	return &proto.Node{ID: id}, nil
}

func (f *fakeRouteNodes) NodeKeys(_ context.Context, id string) (proto.NodeKeys, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.keysErr != nil {
		return nil, f.keysErr
	}
	return f.keys[id], nil
}

func (f *fakeRouteNodes) getCalls(id string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[id]
}

// agentKeys is a key set holding an agent key.
func agentKeys() proto.NodeKeys {
	return proto.NodeKeys{proto.NodeKeyAgent: "spki-agent", proto.NodeKeyCollector: "spki-collector"}
}

// testKeyOwnerHeader stands in, in this package's harnesses, for the node
// listener's TLS client authentication: the fake agents name their node in
// it, and the stand-in listener passes it to ServeNode as the key owner. The
// real listener and real keys are exercised in the api package
// (node_backup_test.go); here only what the api mints and routes is under
// test.
const testKeyOwnerHeader = "X-Test-Key-Owner"

// standInNodeListener mounts the node-listener entries of the ingest and the
// restore egress, with the key owner taken from testKeyOwnerHeader.
func standInNodeListener(ing *backupxfer.Ingest, eg *RestoreEgress) http.Handler {
	mux := http.NewServeMux()
	if ing != nil {
		mux.HandleFunc("PUT "+backupxfer.IngestPathPrefix, func(w http.ResponseWriter, r *http.Request) {
			ing.ServeNode(w, r, r.Header.Get(testKeyOwnerHeader))
		})
	}
	if eg != nil {
		mux.HandleFunc("GET "+backupxfer.EgressPathPrefix, func(w http.ResponseWriter, r *http.Request) {
			eg.ServeNode(w, r, r.Header.Get(testKeyOwnerHeader))
		})
	}
	return mux
}

// ownerClient is an HTTP client for the fake agent on node: every request
// names node in testKeyOwnerHeader. Its transport keeps the shipping
// client's 100-continue wait and one connection per request.
func ownerClient(node string) *http.Client {
	return &http.Client{Transport: ownerHeader{node: node, next: &http.Transport{
		ExpectContinueTimeout: 5 * time.Second, DisableKeepAlives: true,
	}}}
}

type ownerHeader struct {
	node string
	next http.RoundTripper
}

func (o ownerHeader) RoundTrip(r *http.Request) (*http.Response, error) {
	c := r.Clone(r.Context())
	// The trailer map is shared, not copied: the shipping client fills the
	// sealed digest into it after the body has been read.
	c.Trailer = r.Trailer
	c.Header.Set(testKeyOwnerHeader, o.node)
	return o.next.RoundTrip(c)
}
