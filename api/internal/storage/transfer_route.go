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

// The route one node's backup transfers take, decided by the api at mint time
// and recorded in the signed grant (backupxfer.Grant.KeyBound).
//
// A node whose agent advertises proto.CapabilityKeyBoundTransfer presents its
// registered agent key, so it is sent to the api's node listener and handed a
// key-bound credential: one that the bearer-only routes refuse and that the
// node listener honours only from that node's key. A node whose agent predates
// the capability is sent to the legacy bearer-only routes on the public base,
// as before (register row E12, deleted by geekdojo/geekdojo-brain#516 once
// every node advertises it).
//
// A capable node with no registered agent key is an error, never a bearer
// fallback: its key report was refused (a copied key is one cause), and
// handing it a bearer route would be a downgrade on exactly the node the key
// check exists for.

// nodeRouteReader is the two inventory questions the router asks.
// *inventory.Store answers both.
type nodeRouteReader interface {
	Get(ctx context.Context, id string) (*proto.Node, error)
	NodeKeys(ctx context.Context, nodeID string) (proto.NodeKeys, error)
}

// TransferRoute is where one node is told to upload to or fetch from, and
// whether the credential it is handed is key-bound. Why says why a route is
// the bearer one; it is empty on the node-key route.
type TransferRoute struct {
	Destination string
	KeyBound    bool
	Why         string
}

// Why a node is routed by bearer credential.
const (
	whyNoNodeListener = "this api has no node listener"
	whyAgentPredates  = "agent predates key-bound transfer"
)

// TransferRouter decides each node's transfer route.
type TransferRouter struct {
	nodes        nodeRouteReader
	publicBase   string
	nodeListener string
}

// NewTransferRouter builds the router over inventory, the api's public base
// URL (the legacy bearer route) and its node-listener base URL ("" when the
// api runs no node listener). An unparseable base is refused here, so a run
// never discovers it per node.
func NewTransferRouter(nodes nodeRouteReader, publicBaseURL, nodeListenerBaseURL string) (*TransferRouter, error) {
	if nodes == nil {
		return nil, errors.New("storage: the transfer router needs the node inventory")
	}
	if _, err := backupxfer.IngestDestination(publicBaseURL); err != nil {
		return nil, fmt.Errorf("storage: the transfer router's public base: %w", err)
	}
	if strings.TrimSpace(nodeListenerBaseURL) != "" {
		if _, err := backupxfer.IngestDestination(nodeListenerBaseURL); err != nil {
			return nil, fmt.Errorf("storage: the transfer router's node-listener base: %w", err)
		}
	}
	return &TransferRouter{nodes: nodes, publicBase: publicBaseURL, nodeListener: strings.TrimSpace(nodeListenerBaseURL)}, nil
}

// Ingest is nodeID's route for uploading backup members.
func (t *TransferRouter) Ingest(ctx context.Context, nodeID string) (TransferRoute, error) {
	return t.route(ctx, nodeID, backupxfer.IngestDestination)
}

// Egress is nodeID's route for fetching restore streams.
func (t *TransferRouter) Egress(ctx context.Context, nodeID string) (TransferRoute, error) {
	return t.route(ctx, nodeID, backupxfer.EgressDestination)
}

// route applies the rule, in order: the node must be readable and present; a
// capable node on an api with a node listener must have a registered agent
// key and goes key-bound; anything else goes by bearer, saying why.
func (t *TransferRouter) route(ctx context.Context, nodeID string, dest func(string) (string, error)) (TransferRoute, error) {
	n, err := t.nodes.Get(ctx, nodeID)
	if err != nil {
		return TransferRoute{}, fmt.Errorf("node %s: reading it from inventory to route its backup transfer: %w", nodeID, err)
	}
	if n == nil {
		return TransferRoute{}, fmt.Errorf("node %s is not in inventory, so there is no route for its backup transfer", nodeID)
	}
	capable := slices.Contains(n.Capabilities, proto.CapabilityKeyBoundTransfer)
	if capable && t.nodeListener != "" {
		keys, err := t.nodes.NodeKeys(ctx, nodeID)
		if err != nil {
			return TransferRoute{}, fmt.Errorf("node %s: reading its registered keys to route its backup transfer: %w", nodeID, err)
		}
		if keys[proto.NodeKeyAgent] == "" {
			return TransferRoute{}, fmt.Errorf("node %s advertises key-bound transfer but has no registered agent key; see the inventory log for why its key report was refused", nodeID)
		}
		d, err := dest(t.nodeListener)
		if err != nil {
			return TransferRoute{}, err
		}
		return TransferRoute{Destination: d, KeyBound: true}, nil
	}
	why := whyAgentPredates
	if capable {
		why = whyNoNodeListener
	}
	d, err := dest(t.publicBase)
	if err != nil {
		return TransferRoute{}, err
	}
	return TransferRoute{Destination: d, Why: why}, nil
}
