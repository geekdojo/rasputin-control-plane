package openwrt

import (
	"context"
)

// UCIClient is the contract the firewall agent uses to talk to OpenWrt.
//
// Two implementations:
//
//   - mock.go: file-backed, used everywhere except real OpenWrt hardware. The
//     "state" is just a JSON document on disk; the hash is its SHA-256.
//   - uci.go (OpenWrt only): real uci / ubus calls — uci set + commit +
//     /etc/init.d/firewall reload on apply, `ubus call uci get` read-back.
//
// Both must return identical hashes for identical state so the api's drift
// detection is comparable across them.
type UCIClient interface {
	// Apply replaces the firewall configuration with the supplied state and
	// returns the resulting state hash.
	Apply(ctx context.Context, state map[string]any) (hash string, err error)

	// Get returns the currently-observed state and its hash. Used by the
	// reconcile workflow.
	Get(ctx context.Context) (state map[string]any, hash string, err error)

	// SetActive toggles the firewall node's base services for the deployment
	// mode. active=false (LAN-peer — the box is idle) turns the LAN DHCP
	// server off so it can't clash with the operator's existing router, and
	// stops snort; active=true restores both. Idempotent. Independent of the
	// intent Apply path (which governs port-forwards/rules, not whether the
	// box has a firewall job at all).
	SetActive(ctx context.Context, active bool) error
}
