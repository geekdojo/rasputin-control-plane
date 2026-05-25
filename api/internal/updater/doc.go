// Package updater hosts signed RAUC bundles in the JetStream object store
// and orchestrates the per-node update saga: stage → switch slot → reboot →
// health-check → commit or rollback.
//
// See projects/rasputin/design/control-plane/architecture.md §11
// in the geekdojo-wiki.
package updater
