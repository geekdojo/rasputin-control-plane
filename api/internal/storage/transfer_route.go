package storage

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Where one node's backup transfers go, decided by the api before any of the
// node's apps is stopped.
//
// There is one route: the api's node listener, which admits a connection by
// the node's registered agent key, and on which a credential is honoured only
// from the node it names (backupxfer.CheckPresenter). A node that cannot take
// that route is refused by name, never sent anywhere else:
//
//   - an api with no node listener (RASPUTIN_HTTPS_ADDR unset) has no route
//     for any node;
//   - a node whose agent does not advertise proto.CapabilityKeyBoundTransfer
//     would not present its key, so it must be updated first;
//   - a capable node with no registered agent key had its key report refused
//     (a copied key is one cause; the inventory log says which).

// nodeRouteReader is the two inventory questions the router asks.
// *inventory.Store answers both.
type nodeRouteReader interface {
	Get(ctx context.Context, id string) (*proto.Node, error)
	NodeKeys(ctx context.Context, nodeID string) (proto.NodeKeys, error)
}

// ErrNoNodeListener is the route error of an api that runs no node listener.
var ErrNoNodeListener = errors.New("this api has no node listener (RASPUTIN_HTTPS_ADDR is unset), so no node has a backup transfer route")

// ErrAgentPredatesKeyBoundTransfer wraps the route error of a node whose agent
// does not advertise proto.CapabilityKeyBoundTransfer.
var ErrAgentPredatesKeyBoundTransfer = errors.New("agent predates key-bound transfer")

// TransferRouter decides each node's transfer route.
type TransferRouter struct {
	nodes nodeRouteReader
	// ingest and egress are the node listener's upload and restore-fetch
	// URLs, "" when the api runs no node listener.
	ingest, egress string
}

// NewTransferRouter builds the router over inventory and the api's
// node-listener base URL. An empty base is an api with no node listener (the
// HTTPS-off dev stack): the router is built, and every route call errors. A
// non-empty base is turned into URLs here, so an unparseable one is refused
// at start rather than discovered per node.
func NewTransferRouter(nodes nodeRouteReader, nodeListenerBaseURL string) (*TransferRouter, error) {
	if nodes == nil {
		return nil, errors.New("storage: the transfer router needs the node inventory")
	}
	t := &TransferRouter{nodes: nodes}
	if strings.TrimSpace(nodeListenerBaseURL) == "" {
		return t, nil
	}
	var err error
	if t.ingest, err = backupxfer.IngestDestination(nodeListenerBaseURL); err != nil {
		return nil, fmt.Errorf("storage: the transfer router's node-listener base: %w", err)
	}
	if t.egress, err = backupxfer.EgressDestination(nodeListenerBaseURL); err != nil {
		return nil, fmt.Errorf("storage: the transfer router's node-listener base: %w", err)
	}
	return t, nil
}

// Ingest is the URL nodeID uploads backup members to.
func (t *TransferRouter) Ingest(ctx context.Context, nodeID string) (string, error) {
	return t.route(ctx, nodeID, t.ingest)
}

// Egress is the URL nodeID fetches restore streams from.
func (t *TransferRouter) Egress(ctx context.Context, nodeID string) (string, error) {
	return t.route(ctx, nodeID, t.egress)
}

// route applies the rule, in order: the node must be readable and present;
// the api must run a node listener; the node's agent must advertise the
// capability; its keys must be readable and hold an agent key. Then dest.
func (t *TransferRouter) route(ctx context.Context, nodeID, dest string) (string, error) {
	n, err := t.nodes.Get(ctx, nodeID)
	if err != nil {
		return "", fmt.Errorf("node %s: reading it from inventory to route its backup transfer: %w", nodeID, err)
	}
	if n == nil {
		return "", fmt.Errorf("node %s is not in inventory, so there is no route for its backup transfer", nodeID)
	}
	if dest == "" {
		return "", fmt.Errorf("node %s: %w", nodeID, ErrNoNodeListener)
	}
	if !slices.Contains(n.Capabilities, proto.CapabilityKeyBoundTransfer) {
		return "", fmt.Errorf("node %s runs agent %s: its %w; update the node", nodeID, agentVersionOf(n), ErrAgentPredatesKeyBoundTransfer)
	}
	keys, err := t.nodes.NodeKeys(ctx, nodeID)
	if err != nil {
		return "", fmt.Errorf("node %s: reading its registered keys to route its backup transfer: %w", nodeID, err)
	}
	if keys[proto.NodeKeyAgent] == "" {
		return "", fmt.Errorf("node %s advertises key-bound transfer but has no registered agent key; see the inventory log for why its key report was refused", nodeID)
	}
	return dest, nil
}

// agentVersionOf is n's agent version for an error, saying so when the node
// reported none.
func agentVersionOf(n *proto.Node) string {
	if v := strings.TrimSpace(n.AgentVersion); v != "" {
		return v
	}
	return "(version not reported)"
}
