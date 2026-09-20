package proto

import "strings"

// Registration-metadata keys that exist so a CUTOVER can wait on a fact.
//
// A migration step that tightens a rule on the server — "stop reading the
// token out of the environment", "refuse an unpinned HTTPS client" — must not
// fire on a date or on someone's belief about the fleet. It fires when every
// registered node has REPORTED the capability, which means every node needs a
// way to say it. That is what these keys are: one fact each, reported on every
// registration, with a metadataMinAgentVersion floor beside it so that "should
// report and did not" is a different reading from "predates the key".
//
// They follow MetadataMeshCAFingerprint's pattern exactly (meshtrust.go): the
// agent puts the value in NodeRegisteredEvt.Metadata, the api records it on
// the node row, and a consumer reads it back through the decoder here rather
// than indexing the map itself — one place that knows the key's name, its
// value shape, and what an absent key means.
//
// The decoders answer (value, reported). Absent is never an error and never a
// value: a consumer that treats "cannot say" as "said no" is fail-closed by
// construction, which is the direction every one of these cutovers runs in.

// MetadataTokenSource is the registration-metadata key under which an agent
// reports WHERE it read the bus join token it presented on this connection
// (§7 4.1). One of TokenSourceFile, TokenSourceEnv or TokenSourceNone.
//
// The cutover it gates is the deletion of the agent's environment fallback:
// RASPUTIN_CP_JOIN_TOKEN goes away once every registered node reports
// TokenSourceFile, and not before — an image whose firstboot or init.d still
// writes only the variable would otherwise stop joining at its next agent
// update, with the credential it needs sitting in a place nothing reads.
//
// Reported on EVERY registration, TokenSourceEnv and TokenSourceNone
// included: the point of the key is to name the nodes that are not on the
// file yet, so a node that says "env" is as much a report as one that says
// "file". Absent from a pre-key agent's registration.
const MetadataTokenSource = "tokenSource"

// The values MetadataTokenSource takes. A node reports exactly one.
const (
	// TokenSourceFile: read from the file named by
	// RASPUTIN_CP_JOIN_TOKEN_FILE, or from the controlplane default
	// (BusAgentTokenPath), on every connect. The canonical source.
	TokenSourceFile = "file"
	// TokenSourceEnv: read once from RASPUTIN_CP_JOIN_TOKEN. The legacy
	// source, kept only while older images are in the fleet.
	TokenSourceEnv = "env"
	// TokenSourceNone: no token at all. The bus refuses such a connection
	// when it enforces auth, so this is reported by a node that is failing
	// to join — which is exactly a node an operator should be told about.
	TokenSourceNone = "none"
)

// MetadataHTTPSPinned is the registration-metadata key under which an agent
// reports whether its HTTPS clients to the control plane verify the api by the
// BUS KEY PIN it already holds, rather than by a certificate chain (§7 6.2).
// A bool, reported on every registration, false included.
//
// The cutover it gates is the last one in the ladder (§7 6.5): the plaintext
// and chain-verified routes are deleted once every registered node reports
// true. False is the honest answer from an agent that still trusts a CA
// bundle, and it is REPORTED rather than omitted so the api can tell a node
// that has not moved yet from one that cannot say either way.
const MetadataHTTPSPinned = "httpsPinned"

// TokenSourceOf reads a node's MetadataTokenSource report out of its
// registration metadata. reported is false when the key is absent or carries
// anything but one of the three values above — an unknown value is not a
// report, because a cutover that accepted it would be gating on a string it
// does not understand.
func TokenSourceOf(metadata map[string]any) (source string, reported bool) {
	if metadata == nil {
		return "", false
	}
	v, ok := metadata[MetadataTokenSource]
	if !ok {
		return "", false
	}
	s, isString := v.(string)
	if !isString {
		return "", false
	}
	switch strings.TrimSpace(s) {
	case TokenSourceFile:
		return TokenSourceFile, true
	case TokenSourceEnv:
		return TokenSourceEnv, true
	case TokenSourceNone:
		return TokenSourceNone, true
	}
	return "", false
}

// HTTPSPinnedOf reads a node's MetadataHTTPSPinned report out of its
// registration metadata. reported is false when the key is absent or is not a
// bool; pinned is true only for a reported true.
func HTTPSPinnedOf(metadata map[string]any) (pinned, reported bool) {
	if metadata == nil {
		return false, false
	}
	v, ok := metadata[MetadataHTTPSPinned]
	if !ok {
		return false, false
	}
	b, isBool := v.(bool)
	if !isBool {
		return false, false
	}
	return b, true
}
