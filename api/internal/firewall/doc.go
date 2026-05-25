// Package firewall translates user intents (port-forward, VLAN, WG peer, rule)
// into OpenWrt UCI deltas, ships them to the firewall agent via a Job, and
// reconciles observed state against intent on a periodic timer.
//
// See projects/rasputin/design/control-plane/architecture.md §8
// in the geekdojo-wiki.
package firewall
