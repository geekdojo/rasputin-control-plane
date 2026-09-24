package appsecret

import (
	"fmt"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// Resolve returns compose with every ${secret:<name>} token replaced by its
// derived value for appID at this rotation version.
//
// PURE, and takes the compose as a STRING. ADR-0006 Decision 4 holds unchanged:
// the substitution is a textual scan against a token and no YAML parser enters
// the control plane. gopkg.in/yaml.v3 is in api/go.mod and is imported by test
// files only; this path keeps it that way.
//
// A compose with no token is returned unchanged — the same string, not a
// re-rendered copy — because the install path's contract is that what the
// database holds is what a node gets, byte for byte, and every app in the field
// today has no tokens. A rewriter that normalised whitespace on the way past
// would change every one of their composes for no reason and break the compose
// hash that the revert path matches on.
//
// The caller is the point where the compose is marshalled into
// proto.AppDeployCmd, and nowhere else. Resolving anywhere upstream of that —
// in the install handler, in the store — writes plaintext credentials into a
// database with no encryption at rest, permanently, and shows them in the UI's
// compose preview.
func Resolve(compose, appID string, seed *Seed, version uint32) (string, error) {
	tokens, err := tileschema.ScanSecretTokens(compose)
	if err != nil {
		return "", fmt.Errorf("appsecret: resolve %s: %w", appID, err)
	}
	if len(tokens) == 0 {
		return compose, nil
	}
	if seed == nil {
		// Refused, not skipped. Passing the token through would deploy the
		// literal string `${secret:db-password}` as a credential, which is
		// precisely the failure this channel exists to remove — and it would do
		// it silently, with a container that came up and a job that succeeded.
		return "", fmt.Errorf("appsecret: %s declares %d ${secret:} token(s) but no app-secret seed is loaded, so the deploy is refused rather than sending the literal placeholder as a credential", appID, len(tokens))
	}

	var b strings.Builder
	b.Grow(len(compose))
	at := 0
	for _, tok := range tokens {
		value, derr := seed.Derive(appID, tok.Name, version)
		if derr != nil {
			return "", derr
		}
		b.WriteString(compose[at:tok.Start])
		b.WriteString(value)
		at = tok.End
	}
	b.WriteString(compose[at:])
	return b.String(), nil
}

// Escape rewrites every ${secret:<name>} token to $${secret:<name>} so Docker
// Compose treats it as a literal instead of one of its own variables.
//
// It exists because of a MEASURED collision, not a theoretical one. Docker
// Compose 29.1.3, 2026-09-23: a compose containing `${secret:name}` makes
// Compose hard-fail with "invalid interpolation format" and refuse the whole
// file — including on `docker compose config --volumes`, which is what the
// volume check runs. `$${secret:name}` parses cleanly and Compose emits the
// token literally.
//
// So the token shape is not inert on the node. The api sends the same compose
// string to an agent from three places and only ONE of them may see a real
// secret:
//
//   - the deploy (proto.AppDeployCmd) resolves — that is the path the container
//     is started from, and the only one that needs the value;
//   - the image pull (proto.AppPullCmd) escapes — it fetches images and has no
//     use for a credential, so sending one would widen the blast radius of a
//     compromised node for nothing;
//   - the volume check (proto.AppVolumesCheckCmd) escapes — it stages the
//     compose on the node and asks Docker Compose ITSELF to resolve volumes, so
//     an unescaped token does not merely leak nothing, it fails the check
//     outright and the compose change is refused with an error about
//     interpolation.
//
// It takes and returns a string and cannot fail: its whole job is to neutralise
// a token shape, so it matches on the prefix and never needs the token to be
// well-formed or the name to be valid. A malformed token is refused where
// malformed tokens belong — at publish and at catalog load, by
// tileschema.ValidateTile, and again by Resolve on the deploy path.
func Escape(compose string) string {
	if !strings.Contains(compose, tileschema.SecretTokenPrefix) {
		return compose
	}
	var b strings.Builder
	b.Grow(len(compose) + 16)
	for i := 0; ; {
		rel := strings.Index(compose[i:], tileschema.SecretTokenPrefix)
		if rel < 0 {
			b.WriteString(compose[i:])
			return b.String()
		}
		at := i + rel
		b.WriteString(compose[i:at])
		// Idempotent: an occurrence already preceded by `$` is already the
		// literal form, and a second `$` would make Compose emit `$${secret:x}`
		// instead of `${secret:x}`. A stored compose cannot legitimately contain
		// the escaped form — ScanSecretTokens refuses it at publish and at load
		// — so this is defence against a future caller escaping twice rather
		// than against a tile, and it costs two lines.
		if at == 0 || compose[at-1] != '$' {
			b.WriteByte('$')
		}
		b.WriteString(tileschema.SecretTokenPrefix)
		i = at + len(tileschema.SecretTokenPrefix)
	}
}
