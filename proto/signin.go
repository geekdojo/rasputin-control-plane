package proto

import (
	"errors"
	"strings"
)

// The sign-in doors' names (geekdojo/geekdojo-brain#983, signin-origin.md §6).
//
// The agent and the api both need these strings: the api serves the doors and
// answers their DNS records, and the agent routes the app door's name at the
// control plane's nameserver. They are defined here, once, so the leaf, the
// records, the routing domain and the reserved-label check can never disagree.
const (
	// SignInLabel is the app door's first label: signin.<cid>.internal.
	SignInLabel = "signin"
	// RadiusLabel is reserved for the network-access server's name. Nothing
	// answers it yet; it is reserved so no app or device takes it first.
	RadiusLabel = "radius"
	// SignInHomePrefix prefixes the cluster id in the home door's name:
	// sso-<cid>.local.
	SignInHomePrefix = "sso-"
)

// BaseDomain is the cluster's private DNS base domain, "<cluster-id>.internal":
// the MagicDNS base domain, the control-plane nameserver's zone, and the parent
// of every app's tailnet name. `.internal` is the ICANN-reserved private-use
// TLD, so it can never collide with a public zone. The id is trimmed, and an
// empty id gives the dev fallback "rasputin.internal". The cluster id is
// already a single DNS-safe label (ADR-0003), so nothing else is sanitised.
func BaseDomain(clusterID string) string {
	id := strings.TrimSpace(clusterID)
	if id == "" {
		id = "rasputin"
	}
	return id + ".internal"
}

// SignInFQDN is the app door's host, signin.<cid>.internal.
func SignInFQDN(clusterID string) string {
	return SignInLabel + "." + BaseDomain(clusterID)
}

// SignInHomeFQDN is the home door's host, sso-<cid>.local (D25).
func SignInHomeFQDN(clusterID string) string {
	return SignInHomePrefix + strings.TrimSpace(clusterID) + ".local"
}

// IsReservedLabel reports whether s is a label the sign-in doors keep for
// themselves, so no app, catalog tile, node or tailnet device may take it.
func IsReservedLabel(s string) bool {
	return s == SignInLabel || s == RadiusLabel
}

// ClusterIDMaxLen is the longest cluster id: sso-<cid> must still fit in one
// 63-character DNS label (D25), so the prefix's length comes off the label's.
const ClusterIDMaxLen = 63 - len(SignInHomePrefix)

// The two rules only a cluster id has, beyond being a DNS label
// (geekdojo/geekdojo-brain#995, D25). CheckClusterID returns one of them.
var (
	// ErrClusterIDTooLong: the id is longer than ClusterIDMaxLen.
	ErrClusterIDTooLong = errors.New("proto: cluster id is longer than 59 characters")
	// ErrClusterIDReservedPrefix: the id starts with SignInHomePrefix, so its
	// own name would be another cluster's sign-in name.
	ErrClusterIDReservedPrefix = errors.New("proto: cluster id starts with the reserved prefix sso-")
)

// CheckClusterID applies the cluster-id rules the sign-in name needs: at most
// ClusterIDMaxLen characters, and no SignInHomePrefix. The length is checked
// first. It does not check that id is a DNS label; its callers do that. This
// is the one copy of the rule: the provisioner and the door table both call
// it.
func CheckClusterID(id string) error {
	if len(id) > ClusterIDMaxLen {
		return ErrClusterIDTooLong
	}
	if strings.HasPrefix(id, SignInHomePrefix) {
		return ErrClusterIDReservedPrefix
	}
	return nil
}
