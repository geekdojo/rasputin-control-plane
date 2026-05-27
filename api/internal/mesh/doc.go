// Package mesh integrates Headscale as a managed sidecar and surfaces a
// narrow intent model on top of it. Rasputin owns the lifecycle of every
// node's tailnet membership and a small set of intent shapes (pre-auth
// keys, subnet routes). The rest of Headscale's policy surface — ACL
// HuJSON, DNS overrides, exit nodes — passes through to Headplane.
//
// Components:
//   - Store: SQLite ledger for mesh_intents + a singleton mesh_state row
//     tracking the last-applied and last-reconciled hashes.
//   - Headscale client: talks to Headscale's HTTP API. In v0 we ship a
//     MockClient that file-backs the state for dev; the real client wraps
//     the headscale binary's REST surface.
//   - Supervisor: manages the Headscale container lifecycle (in mock mode
//     it just records desired state — see TODOs below).
//   - Workflows: mesh.apply, mesh.reconcile, mesh.enroll_node.
//
// TODO(v1): real Docker container supervision. The supervisor interface is
// here so the wiring can swap to a real backend without restructuring.
//
// See projects/rasputin/design/control-plane/mesh.md in the geekdojo-wiki.
package mesh
