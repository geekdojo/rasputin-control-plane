// Package bus is the agent's NATS client: outbound-only connection, subject
// dispatch to subsystem handlers, ack/dedup using JetStream message IDs.
//
// See projects/rasputin/design/control-plane/architecture.md §5
// in the geekdojo-wiki.
package bus
