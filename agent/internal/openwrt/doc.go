// Package openwrt is the firewall-node ubus / UCI client. Applies config
// deltas, computes state hashes, returns drift telemetry.
//
// Only compiled in on firewall nodes (build tag: firewall).
//
// See projects/rasputin/design/control-plane/architecture.md §8
// in the geekdojo-brain.
package openwrt
