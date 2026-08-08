// Package nameserver is the control plane's authoritative DNS responder for the
// per-installation internal zone (<cluster-id>.internal) — the "CP nameserver"
// of ADR-0004 §3/§8. It is an embedded miekg/dns responder, not a sidecar:
// records are a live projection of state the api already owns (Decision 8),
// answered from memory on every query with no zone-file reload.
//
// This is the LAN authority. It answers with LAN IPs only (split-horizon by IP
// class — the tailnet view is MagicDNS's job, ADR-0004 §3); it is not a
// recursive resolver (that is the separate AA-8/AA-9 feature) and it never
// recurses off-zone.
//
// # Slice 1 (this package, initially)
//
// The responder, the constrained LAN-interface bind, and the CP-self answers —
// the zone apex <cluster-id>.internal and the unicast <cluster>.local name, both
// resolving to the control plane's own LAN IP (which the api already knows via a
// default-route lookup). These need no node/app data, so they build and prove
// the whole novel path — authoritative semantics, the bind, resolved
// coexistence — ahead of the node-IP plumbing. The <cluster>.local answer
// retires the E2 .local reach stopgaps.
//
// # Slice 2 (later)
//
// Node and app A records, projected from the inventory + apps tables. Node LAN
// IP is agent-reported on NodeRegisteredEvt (no DHCP MAC reservations, so a
// node's IP churns on reboot); agent reconnect fires a reconcile job that
// resyncs the node's record and every app on it. Slice 2 supplies an additional
// [Source]; the responder is unchanged.
//
// # Bind
//
// The responder binds UDP+TCP on the control plane's LAN IP (by value, not
// 0.0.0.0:53) and must never displace systemd-resolved's 127.0.0.53:53 stub —
// resolved also publishes the cluster's mDNS <cluster>.local (ADR-0003), so
// freeing port 53 by disabling resolved would break cluster discovery. Because
// the LAN IP moves per DHCP lease, it is re-resolved at Start.
package nameserver
