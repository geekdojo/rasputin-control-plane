package bus

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Where a node's bus join token comes from.
//
// Every connection to the bus presents a join token bound to the node id it
// claims — the controlplane's own agent included. The bus once trusted any
// connection from loopback instead, which let any local user on a
// controlplane claim any node's id (geekdojo/geekdojo-brain#140, decided
// 2026-09-17).
//
//  1. RASPUTIN_CP_JOIN_TOKEN_FILE — a file holding the token, read again on
//     EVERY connect attempt. This is the canonical source on every node and
//     every role (geekdojo/geekdojo-brain#537, methodology §5.2 and §7 4.1).
//     The token is a secret, so it belongs in one file the owner alone can
//     read, not in an environment block that every child process inherits and
//     that /proc exposes to anything that can read the process. Re-reading is
//     the other half: the controlplane's api mints its own agent's token into
//     such a file at start (proto.BusAgentTokenFileName) and re-mints it when
//     it stops validating (an identity restore, a revoke), and a node's token
//     can be replaced under a running agent the same way, so the agent must
//     pick a new one up on its next reconnect rather than at its next
//     restart. An environment variable cannot change under a running process,
//     which is why this is a file.
//  2. Otherwise RASPUTIN_CP_JOIN_TOKEN — the token itself, from the node's
//     seed. The legacy source, still honoured so that a NEW agent on an OLD
//     image — whose firstboot or init.d writes only this variable — keeps
//     joining. Read once: nothing rewrites a seeded token while the agent
//     runs. It is deleted once every node reports tokenSource=file (§7 4.1).
//  3. Otherwise, on a controlplane, proto.BusAgentTokenPath. A controlplane
//     whose node.env was written before the file existed has neither
//     variable, and firstboot never runs again to add one; this default is
//     what keeps an updated controlplane's agent on the bus.
//  4. Otherwise no token. The bus refuses the connection, as it always has
//     for a node that carries none.
//
// The FILE wins when both are set. That is the direction of the migration:
// whatever wrote the file wrote it later than the seed did, and it is the only
// one of the two that can be re-read. The reverse order (env first, which is
// what shipped in 2026.09.4-dev.167) meant that a node carrying a seeded token
// could never be moved to the file without an agent restart, because the file
// was never read while the variable was set.

// EnvJoinToken is the node's seeded join token. Legacy: superseded by
// EnvJoinTokenFile, and honoured only while older images are in the fleet.
const EnvJoinToken = "RASPUTIN_CP_JOIN_TOKEN"

// EnvJoinTokenFile names a file holding the join token, read on every connect.
// This is the canonical source; it wins over EnvJoinToken.
const EnvJoinTokenFile = "RASPUTIN_CP_JOIN_TOKEN_FILE"

// TokenSource returns the join token for one connection attempt. An error
// means there is no usable token for this attempt; the caller connects without
// one, the bus refuses it, and the next attempt asks again.
type TokenSource func() (string, error)

// StaticToken is a TokenSource that always answers token ("" for none).
func StaticToken(token string) TokenSource {
	return func() (string, error) { return token, nil }
}

// TokenFile is a TokenSource that reads path on every call. Surrounding
// whitespace is trimmed; a missing, unreadable or empty file is an error.
func TokenFile(path string) TokenSource {
	return func() (string, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return "", fmt.Errorf("the join token file %s does not exist yet", path)
			}
			return "", fmt.Errorf("the join token file %s cannot be read: %w", path, err)
		}
		tok := strings.TrimSpace(string(b))
		if tok == "" {
			return "", fmt.Errorf("the join token file %s is empty", path)
		}
		return tok, nil
	}
}

// ResolveTokenSource picks the token source from the agent's environment
// values and role, in the order documented above, and describes the choice
// for the startup log (never the token itself). defaultFile is the
// controlplane default, proto.BusAgentTokenPath outside tests.
func ResolveTokenSource(token, tokenFile string, role proto.NodeRole, defaultFile string) (TokenSource, string) {
	// The token is used exactly as given, as it always has been; only the
	// file path is trimmed.
	tokenFile = strings.TrimSpace(tokenFile)
	switch {
	case tokenFile != "" && token != "":
		return TokenFile(tokenFile), fmt.Sprintf("the file %s (%s), read on every connect (%s is set too, and ignored)", tokenFile, EnvJoinTokenFile, EnvJoinToken)
	case tokenFile != "":
		return TokenFile(tokenFile), fmt.Sprintf("the file %s (%s), read on every connect", tokenFile, EnvJoinTokenFile)
	case token != "":
		return StaticToken(token), EnvJoinToken
	case role == proto.RoleControlPlane:
		return TokenFile(defaultFile), fmt.Sprintf("the file %s (the controlplane default; the api mints it), read on every connect", defaultFile)
	default:
		return StaticToken(""), fmt.Sprintf("none — neither %s nor %s is set, and a bus that enforces auth refuses a node without one", EnvJoinToken, EnvJoinTokenFile)
	}
}
