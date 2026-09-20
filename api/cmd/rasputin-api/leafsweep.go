package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
)

// collectorLeafSpec is the per-node collector's client-auth leaf. CN = node_id
// is what the mTLS ingress reads back as the caller's identity; the DNS SAN is
// cosmetic for a client leaf (the server verifies the chain and the clientAuth
// EKU, not SANs). One definition, used by the deploy's mint and by the leaf
// sweep's renewal check — a spec those two disagreed on would have the sweep
// re-minting a leaf the deploy is happy with, on every sweep, forever.
func collectorLeafSpec(nodeID string) mesh.LeafSpec {
	return mesh.LeafSpec{CommonName: nodeID, DNSNames: []string{nodeID}, ClientAuth: true}
}

// collectorLeafSource lists the per-node collector leaves for the sweep.
//
// It reports only leaves that ALREADY exist under root and whose node is still
// in inventory. Both halves matter:
//
//   - existing only, so the sweep never mints a leaf for a node that has no
//     collector — deciding which nodes should have one is the collector
//     reconcile's job, and doing it in two places is how the two drift;
//   - in inventory only, so a removed node's leaf stops being renewed the
//     moment it leaves (§5.2 revocation). The files it leaves behind are not
//     deleted here.
//
// redeploy is the reload hook: a collector's leaf is delivered inside its
// compose, so the node serves a renewed one only after a redeploy. The deploy
// re-mints idempotently and will find the fresh leaf the sweep just wrote.
func collectorLeafSource(root string, inv *inventory.Store, redeploy func(ctx context.Context, nodeID string) error) mesh.LeafSource {
	return func(ctx context.Context) ([]mesh.LeafConsumer, error) {
		entries, err := os.ReadDir(root)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, nil // no collector has ever been deployed
			}
			return nil, fmt.Errorf("read collector leaf dir: %w", err)
		}
		nodes, err := inv.List(ctx)
		if err != nil {
			return nil, fmt.Errorf("list inventory: %w", err)
		}
		known := make(map[string]bool, len(nodes))
		for _, n := range nodes {
			known[n.ID] = true
		}
		var out []mesh.LeafConsumer
		for _, e := range entries {
			if !e.IsDir() || !known[e.Name()] {
				continue
			}
			nodeID := e.Name()
			out = append(out, mesh.LeafConsumer{
				Name: "collector/" + nodeID,
				Dir:  filepath.Join(root, nodeID),
				Spec: func() (mesh.LeafSpec, error) { return collectorLeafSpec(nodeID), nil },
				Reload: func(ctx context.Context, _ mesh.LeafPaths) error {
					if redeploy == nil {
						return nil
					}
					return redeploy(ctx, nodeID)
				},
			})
		}
		return out, nil
	}
}
