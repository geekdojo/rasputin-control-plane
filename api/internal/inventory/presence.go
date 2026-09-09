package inventory

import (
	"context"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Presence: the heartbeat status joined with mesh membership.
//
// The nodes page had one word for a node the api cannot hear — OFFLINE — and
// it could not tell "the machine is down" from "the machine is up and only its
// agent has dropped off the bus". On e3bench 2026-09-04, after a controlplane
// wipe, five nodes' agents had their NATS connection permanently closed while
// tailscaled stayed enrolled: the nodes page said OFFLINE, /mesh said live
// with a recent last-seen, and the operator was left to cross-reference the
// two (geekdojo/geekdojo-brain#401). The join between the two lives here so
// every reader of a node's status — the handlers, the transition ticker, the
// alerts aggregator, ExplainNoResponder — derives it the same way.
//
// This package cannot import mesh (mesh imports inventory), so the mesh side
// of the join arrives through a hook: MeshLookup is mesh.Service.Membership,
// wired by main. Unwired (dev, tests), mesh stays undetermined and status is
// the heartbeat alone — exactly what it was before this file existed.

// MeshLookup returns nodeID → tailnet membership, or nil when membership
// cannot be determined at all (no mesh service, no reconcile yet). It must be
// cheap and must never block on the network: it is called on every node
// listing and every transition scan.
type MeshLookup func(ctx context.Context) map[string]*proto.MeshMembership

// SetMeshLookup wires the mesh side of the presence join. Set before the
// inventory Service starts; nil leaves mesh undetermined.
func (s *Store) SetMeshLookup(fn MeshLookup) { s.meshLookup = fn }

// mesh runs the lookup if one is wired.
func (s *Store) mesh(ctx context.Context) map[string]*proto.MeshMembership {
	if s.meshLookup == nil {
		return nil
	}
	return s.meshLookup(ctx)
}

// DeriveStatus is the node's presence: ComputeStatus on the heartbeat, with
// one refinement — a node whose heartbeat has lapsed to offline but whose mesh
// device is online (bounded by the mesh service's staleness rule, see
// proto.MeshMembership.Online) is StatusOffBus instead. The machine is
// reachable; its agent is not on the bus.
//
// The rule, in full:
//
//	heartbeat online            → online   (mesh state is irrelevant)
//	heartbeat stale             → stale    (the intermediate state stays as is)
//	heartbeat offline, mesh on  → off-bus
//	heartbeat offline, mesh off → offline
//	heartbeat offline, mesh nil → offline  (undetermined never upgrades)
//
// StatusOffBus is deliberately reached only from the offline tier, never from
// stale: three missed heartbeats is too little evidence to name a cause, and
// a live mesh device says nothing about whether the next heartbeat is on its
// way. Twelve missed is when the flat OFFLINE used to appear, and that is the
// word being replaced.
func DeriveStatus(lastSeen time.Time, mesh *proto.MeshMembership) proto.NodeStatus {
	st := ComputeStatus(lastSeen)
	if st == proto.StatusOffline && mesh != nil && mesh.Online {
		return proto.StatusOffBus
	}
	return st
}

// ApplyMesh annotates nodes in place with membership AND the status derived
// from it. A nil byNode means we could not determine membership, so every
// node keeps Mesh == nil (undetermined) and its status is the heartbeat alone.
// A node absent from a non-nil map has genuinely never enrolled — we looked,
// and it was not there.
func ApplyMesh(nodes []*proto.Node, byNode map[string]*proto.MeshMembership) {
	for _, n := range nodes {
		if n == nil {
			continue
		}
		if byNode != nil {
			if m, ok := byNode[n.ID]; ok {
				n.Mesh = m
			} else {
				n.Mesh = &proto.MeshMembership{State: proto.MeshAbsent}
			}
		}
		n.Status = DeriveStatus(n.LastSeen, n.Mesh)
	}
}

// Presence annotates nodes with mesh membership and derived status through
// the wired lookup — what a handler or a refusal wants after a List or Get.
func (s *Store) Presence(ctx context.Context, nodes []*proto.Node) {
	ApplyMesh(nodes, s.mesh(ctx))
}
