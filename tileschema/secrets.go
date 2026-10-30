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

// CapabilityOperatorSecrets is the Requires capability a tile names when it
// declares operator-supplied secrets in Tile.OperatorSecrets
// (geekdojo/geekdojo-brain#780, S20 option A).
//
// It is must-understand for the same reason tile.secrets is, one step further
// along. A control plane that knows tile.secrets but not this capability would
// ignore the unknown operatorSecrets field (Decision 7's tolerance), see an
// ordinary ${secret:<name>} token, DERIVE a random value for it, store it, and
// hand it to the app as the owner's API key. Nothing would show that it went
// wrong: the app would start, and fail against the third-party service much
// later, with a key nobody chose. Naming the capability makes that older
// reader refuse the tile instead.
const CapabilityOperatorSecrets = "tile.operator-secrets"

// OperatorSecret declares one secret the app's OWNER supplies, rather than one
// the control plane derives. It is a name and the label the owner is shown;
// never a value. The value is set by the owner, write-only, and lives only in
// the secret store.
//
// A declared operator secret is required unless it carries `required: false`
// (geekdojo/geekdojo-brain#604): a deploy is refused while a required one the
// compose uses is unset. An optional one that is unset reaches the app as an
// empty string, and is never derived. The field is additive: a reader from
// before it ignores it, and so fails closed on an optional secret, refusing
// the deploy until the value is set.
type OperatorSecret struct {
	// Name is the ${secret:<name>} name the compose uses for this value. It is
	// held to ValidSecretName, like every other secret name.
	Name string `json:"name"`
	// Label is what the owner is shown when asked for the value, for example
	// "Feed API key".
	Label string `json:"label"`
	// Required is false only for a secret the app can run without. Absent
	// means required, which is how every declaration before the field read.
	Required *bool `json:"required,omitempty"`
}

// IsRequired reports whether a deploy must refuse while the value is unset:
// true unless the declaration says `required: false`.
func (s OperatorSecret) IsRequired() bool { return s.Required == nil || *s.Required }

// OperatorSecretByName is the declaration in decls named name, and whether
// there is one. It is the one lookup the deploy gate, the operator secret
// service and the store source share.
func OperatorSecretByName(decls []OperatorSecret, name string) (OperatorSecret, bool) {
	for _, d := range decls {
		if d.Name == name {
			return d, true
		}
	}
	return OperatorSecret{}, false
}

// validateOperatorSecrets checks a tile's operator-secret declarations against
// its Requires and against the ${secret:} tokens its compose uses. tokens is
// the scan ValidateTile has already made, passed in rather than re-scanned.
//
// Each refusal is one sentence an author reads in CI, naming the declaration
// it is about.
func validateOperatorSecrets(t Tile, tokens []SecretToken) error {
	if len(t.OperatorSecrets) == 0 {
		return nil
	}
	if !requires(t, CapabilityOperatorSecrets) {
		return fmt.Errorf("the tile declares operatorSecrets but does not list %q in requires — a control plane that does not know operator secrets would derive a random value for the name and hand it to the app as the owner's key, so it must refuse this tile instead",
			CapabilityOperatorSecrets)
	}

	used := make(map[string]bool, len(tokens))
	for _, tok := range tokens {
		used[tok.Name] = true
	}
	hasCompose := strings.TrimSpace(t.ComposeYAML) != ""

	seen := make(map[string]bool, len(t.OperatorSecrets))
	for i, s := range t.OperatorSecrets {
		if !ValidSecretName(s.Name) {
			return fmt.Errorf("operatorSecrets[%d]: name %q must be a DNS-1123 label (1-63 chars, [a-z0-9-], no leading/trailing hyphen)", i, s.Name)
		}
		if seen[s.Name] {
			return fmt.Errorf("operatorSecrets[%d] %q: duplicate name — each operator secret is declared once", i, s.Name)
		}
		seen[s.Name] = true
		if strings.TrimSpace(s.Label) == "" {
			return fmt.Errorf("operatorSecrets[%d] %q: label is required — it is what the owner is shown when asked for the value", i, s.Name)
		}
		// A declared name the compose never uses asks the owner for a value
		// that goes nowhere, and usually means a typo: the compose's token then
		// names a DIFFERENT secret, which the control plane derives at random.
		// A preview tile with no compose has nothing to check this against.
		if hasCompose && !used[s.Name] {
			return fmt.Errorf("operatorSecrets[%d] %q: the compose never uses %s%s} — the owner would be asked for a value that reaches no container",
				i, s.Name, SecretTokenPrefix, s.Name)
		}
	}
	return nil
}
