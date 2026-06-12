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
}
