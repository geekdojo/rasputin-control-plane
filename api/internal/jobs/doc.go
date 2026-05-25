// Package jobs implements the universal Job model: SQLite-backed ledger,
// linear-saga executor, retry policies, and restart/replay recovery.
//
// Every state-changing operation in the control plane is a Job. There is
// no other way to mutate state.
//
// See projects/rasputin/design/control-plane/architecture.md §6
// in the geekdojo-wiki.
package jobs
