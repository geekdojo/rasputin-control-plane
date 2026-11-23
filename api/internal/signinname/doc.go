// Package signinname publishes the home sign-in door's name, sso-<cid>.local,
// over multicast DNS on the control plane's LAN link, beside systemd-resolved
// (geekdojo/geekdojo-brain#995; Bryce's ruling D25; signin-origin.md §3.3).
//
// systemd-resolved publishes exactly one name, the hostname <cid>.local, so the
// second name needs its own responder. D25 rules that it is this small one
// inside the api, never Avahi. It answers only sso-<cid>.local, and never
// answers or probes <cid>.local, which stays resolved's.
//
// The protocol is RFC 6762's, and only the parts the name needs:
//
//   - Probing (§8.1): three probes 250 ms apart. The name is ours when 250 ms
//     pass after the third with no conflicting response.
//   - Announcing (§8.3, §8.4): two announcements 1 s apart, again after a
//     change of address on the same link.
//   - Answering (§6): A and ANY questions for the name, multicast, at most once
//     a second, or 250 ms after the last multicast for a probe (§6.2).
//   - Conflict (§9): another host's record for the name with different data
//     stops every answer. The responder never renames. It tracks the other
//     host's record and re-probes once that record is gone: on its goodbye, or
//     when it expires unanswered after the §5.2 cache-maintenance queries.
//   - Goodbye (§10.1): a TTL-0 announcement when the api stops.
//
// The socket is bound to the group address 224.0.0.251:5353 with SO_REUSEADDR,
// so it co-binds beside resolved in either start order and never receives a
// host-unicast datagram (SP-6 cell 1). No common Go mDNS library probes before
// it answers (signin-origin.md §3.3), so the protocol code is ours, held by the
// unit tests here, by FuzzParse, and by CI SO-19 in functional_linux_test.go.
//
// The state is computed when read: [Responder.State] classifies the current
// facts as ok, conflict or unpublished, as the agent's nameguard does. A fault
// in the responder (a panic or a read error) leaves it unpublished, "stopped",
// and alerting; it never takes the api down and never stalls the address
// watcher.
package signinname
