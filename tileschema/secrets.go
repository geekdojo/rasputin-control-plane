package tileschema

import (
	"fmt"
	"strings"
)

// CapabilityTileSecrets is the Requires capability a tile names when its
// compose carries ${secret:<name>} tokens (ADR-0006 Decision 11a,
// geekdojo/geekdojo-brain#520).
//
// It is what makes the channel additive without a schemaVersion major, and the
// reason it is not optional: the token is a syntactically ordinary string, so a
// control plane that does not resolve it has no way to notice it should have.
// That build would deploy the tile and hand the app the LITERAL
// `${secret:db-password}` as its database password — a credential published in
// the catalog repository, which is the exact shape of the finding this channel
// exists to close (F29). Refusing the tile is worse product and strictly
// better security, and Decision 7's must-understand rule is the mechanism that
// makes the older build choose it.
const CapabilityTileSecrets = "tile.secrets"

// SecretTokenPrefix opens a secret token. A whole token is
// SecretTokenPrefix + <name> + "}".
const SecretTokenPrefix = "${secret:"

// SecretToken is one ${secret:<name>} occurrence in a compose string, located
// by byte offsets into it: compose[Start:End] is the whole token, braces
// included, so a caller can rewrite it without re-finding it.
type SecretToken struct {
	Start int
	End   int
	Name  string
}

// ScanSecretTokens returns every secret token in compose in the order they
// appear, and refuses a malformed one.
//
// ONE scanner, three callers, which is ADR-0006 Decision 8 applied to the one
// rule in this channel an author can get wrong: the catalog publisher runs it
// through ValidateTile before signing, the control plane runs it through the
// same ValidateTile at catalog load, and the control plane's resolver runs it
// again on the way out to a node. A second scan in the api would be a second
// definition of what a token is, and the two would diverge silently — each
// side staying internally green is exactly how that failure hides.
//
// It is a TEXTUAL scan over the compose string. ADR-0006 Decision 4 holds
// unchanged: no YAML parser enters the control plane, so this deliberately
// does not know a key from a value from a comment. A token in a comment
// resolves like any other, which is the honest consequence of the constraint
// and not a gap — the alternative is a YAML parser in the path between an
// attacker-supplied bundle and the cluster.
func ScanSecretTokens(compose string) ([]SecretToken, error) {
	var out []SecretToken
	for i := 0; ; {
		rel := strings.Index(compose[i:], SecretTokenPrefix)
		if rel < 0 {
			return out, nil
		}
		start := i + rel
		nameStart := start + len(SecretTokenPrefix)

		// `$${secret:x}` is the ESCAPED form, and a tile must never author it.
		// The control plane emits it itself on the two node-bound paths that
		// must not resolve a secret (the image pull and the volume check),
		// because Docker Compose reads `$$` as a literal `$` and so emits the
		// token unexpanded. A tile carrying it would therefore ask for exactly
		// what this whole channel exists to prevent: the literal string
		// `${secret:x}` delivered to the container as a credential, and
		// delivered silently, because nothing downstream would see a token to
		// resolve. Refused here, out loud, at publish and at load.
		if start > 0 && compose[start-1] == '$' {
			return nil, fmt.Errorf("byte %d: %q is escaped with %q, which is the form the control plane emits for a path that must NOT resolve it — a tile writes %s<name>} and nothing else",
				start, "$"+SecretTokenPrefix, "$$", SecretTokenPrefix)
		}

		// Bounded to the line the token opened on, so an unterminated token
		// is reported as one rather than swallowing every byte up to some
		// closing brace pages later and then failing as a bad name.
		end := strings.IndexAny(compose[nameStart:], "}\n")
		if end < 0 || compose[nameStart+end] != '}' {
			return nil, fmt.Errorf("byte %d: %s has no closing brace on its line", start, SecretTokenPrefix)
		}
		name := compose[nameStart : nameStart+end]
		if !ValidSecretName(name) {
			return nil, fmt.Errorf("byte %d: secret name %q must be a DNS-1123 label (1-63 chars, [a-z0-9-], no leading/trailing hyphen)", start, name)
		}
		out = append(out, SecretToken{Start: start, End: nameStart + end + 1, Name: name})
		i = nameStart + end + 1
	}
}

// ValidSecretName reports whether s is usable as a ${secret:<name>} name.
//
// It is ValidDNSLabel, and deliberately nothing more: ADR-0006 Decision 11a
// puts the secret name under "the same guard the tile id already carries".
// Bounding it to a lowercase DNS label is what kills the injection at the
// source rather than downstream — the name is the only author-supplied
// component of the derivation's info string, so an unbounded one is the only
// way an author could reach for another tuple's value.
//
// Named separately from ValidDNSLabel although it delegates to it, because the
// two answer different questions and the call sites should say which they are
// asking. One implementation, so the rules cannot drift apart while looking
// like they agree.
func ValidSecretName(s string) bool { return ValidDNSLabel(s) }
