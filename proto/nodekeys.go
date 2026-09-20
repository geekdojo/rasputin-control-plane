package proto

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
)

// A node's own long-lived TLS keys, and how it tells the control plane about
// them (geekdojo/geekdojo-brain#514, auth-methodology §5.2 "node→CP client
// auth, HTTPS").
//
// The agent generates two keys, once, and keeps them in its state directory:
// one it uses itself and one it hands to the per-node observability collector.
// Neither key ever leaves the node. What the node reports — here, in
// registration metadata, exactly as it reports the mesh CA fingerprint
// (MetadataMeshCAFingerprint) — is the SHA-256 of each key's DER
// SubjectPublicKeyInfo. That is the same value, in the same encoding, as a bus
// pin (BusPinForPublicKey), because it answers the same question: which key is
// this, ignoring whatever certificate happens to be wrapped around it.
//
// The control plane records the hashes and admits a node's HTTPS connection by
// comparing the peer's SPKI against them. No chain, no name, no dates — see
// the comment on BusPinPrefix for why a key rather than a chain, which applies
// unchanged in this direction.

// NodeKeyPurpose names what one registered key is for. A key is admitted only
// on the routes its purpose covers, so a collector key cannot be used as the
// agent and vice versa.
type NodeKeyPurpose string

const (
	// NodeKeyAgent is the key the node's own agent presents to the api.
	NodeKeyAgent NodeKeyPurpose = "agent"
	// NodeKeyCollector is the key the node's observability collector
	// (Grafana Alloy) presents to the obs ingress.
	NodeKeyCollector NodeKeyPurpose = "collector"
)

// NodeKeyPurposes is every purpose this release knows, in a stable order.
// A report may carry purposes not in this list — a newer agent — and those
// are ignored rather than refused, the same way an unknown metadata key is.
func NodeKeyPurposes() []NodeKeyPurpose {
	return []NodeKeyPurpose{NodeKeyAgent, NodeKeyCollector}
}

// ValidNodeKeyPurpose reports whether p is a purpose this release knows.
func ValidNodeKeyPurpose(p NodeKeyPurpose) bool {
	for _, k := range NodeKeyPurposes() {
		if k == p {
			return true
		}
	}
	return false
}

// MetadataNodeKeys is the registration-metadata key under which an agent
// reports its node keys: an object of purpose → SPKI hash, e.g.
//
//	"nodeKeys": {"agent": "sha256/…", "collector": "sha256/…"}
//
// Absent from an agent that predates the keys (MetadataMinAgentVersion tells
// that apart from "should report and did not"), and absent — deliberately —
// from any registration the agent did not make over a pinned TLS bus
// connection. See NodeKeysAcceptable.
const MetadataNodeKeys = "nodeKeys"

// NodeKeySPKIHash is the canonical hash of a node key's public half: the same
// encoding as a bus pin, "sha256/" plus the standard base64 of the SHA-256 of
// the DER SubjectPublicKeyInfo. One encoding for "which key is this" across
// the product, so an operator who can read a pin can read this.
func NodeKeySPKIHash(pub any) (string, error) {
	return BusPinForPublicKey(pub)
}

// NodeKeySPKIHashForDER is NodeKeySPKIHash for an already-marshalled SPKI —
// what a TLS peer certificate carries (x509.Certificate.RawSubjectPublicKeyInfo).
func NodeKeySPKIHashForDER(spkiDER []byte) string { return BusPinForSPKI(spkiDER) }

// ParseNodeKeySPKIHash validates a reported hash and returns its digest.
// Same strictness as ParseBusPin: the exact canonical form or nothing, because
// a value "repaired" into a different digest is a node that can never connect
// with nothing saying why.
func ParseNodeKeySPKIHash(s string) ([sha256.Size]byte, error) {
	return ParseBusPin(s)
}

// NodeKeys is a node's reported keys, purpose → SPKI hash, with every value
// already validated.
type NodeKeys map[NodeKeyPurpose]string

// Purposes returns the purposes present, sorted, so logs and comparisons are
// deterministic.
func (k NodeKeys) Purposes() []NodeKeyPurpose {
	out := make([]NodeKeyPurpose, 0, len(k))
	for p := range k {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Equal reports whether two key sets are the same set of purposes with the
// same hash under each. nil and empty are equal: neither records a key.
func (k NodeKeys) Equal(other NodeKeys) bool {
	if len(k) != len(other) {
		return false
	}
	for p, h := range k {
		if other[p] != h {
			return false
		}
	}
	return true
}

// Clone returns an independent copy; nil stays nil.
func (k NodeKeys) Clone() NodeKeys {
	if k == nil {
		return nil
	}
	out := make(NodeKeys, len(k))
	for p, h := range k {
		out[p] = h
	}
	return out
}

// String renders the set for a log line, short-form hashes only.
func (k NodeKeys) String() string {
	var b strings.Builder
	for i, p := range k.Purposes() {
		if i > 0 {
			b.WriteString(" ")
		}
		fmt.Fprintf(&b, "%s=%s", p, ShortFingerprint(strings.TrimPrefix(k[p], BusPinPrefix)))
	}
	return b.String()
}

// DecodeNodeKeys reads the MetadataNodeKeys value out of a registration's
// metadata map. It returns the keys for the purposes this release knows, with
// every hash validated.
//
// It fails closed on a malformed report: a value that is not an object, or a
// known purpose whose hash does not parse, is an error and the WHOLE report is
// refused — a node that half-reports its identity is not a node whose identity
// the api should half-record. A purpose this release does not know is skipped
// silently; that is a newer agent, not a broken one.
//
// ok is false with no error when the key is simply absent, which is what a
// pre-key agent and a plaintext-bus registration both look like.
func DecodeNodeKeys(metadata map[string]any) (keys NodeKeys, ok bool, err error) {
	v, present := metadata[MetadataNodeKeys]
	if !present || v == nil {
		return nil, false, nil
	}
	// JSON round-trips the object as map[string]any; a Go caller that built
	// the event in memory may hand over the typed form.
	var raw map[string]any
	switch t := v.(type) {
	case map[string]any:
		raw = t
	case NodeKeys:
		raw = make(map[string]any, len(t))
		for p, h := range t {
			raw[string(p)] = h
		}
	default:
		return nil, false, fmt.Errorf("proto: metadata %s is %T, want an object of purpose to SPKI hash", MetadataNodeKeys, v)
	}
	out := NodeKeys{}
	for name, hv := range raw {
		purpose := NodeKeyPurpose(name)
		if !ValidNodeKeyPurpose(purpose) {
			continue
		}
		h, isString := hv.(string)
		if !isString {
			return nil, false, fmt.Errorf("proto: metadata %s[%s] is %T, want a string", MetadataNodeKeys, name, hv)
		}
		if _, perr := ParseNodeKeySPKIHash(h); perr != nil {
			return nil, false, fmt.Errorf("proto: metadata %s[%s]: %w", MetadataNodeKeys, name, perr)
		}
		out[purpose] = h
	}
	if len(out) == 0 {
		return nil, false, nil
	}
	return out, true, nil
}

// NodeKeysAcceptable reports whether a registration carrying these metadata
// may register or replace keys: only when the agent says the connection it
// registered over is TLS with the bus pin verified (MetadataBusTLS true).
//
// This is the same rule successor bus pins follow (auth-methodology §5.1). On
// an unpinned link the key grants nothing the join token does not already
// grant, but a man-in-the-middle holding a sniffed token could register a key
// of its own — so the key is taken only where the node has proven it is
// talking to this control plane.
func NodeKeysAcceptable(metadata map[string]any) bool {
	v, ok := metadata[MetadataBusTLS]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}
