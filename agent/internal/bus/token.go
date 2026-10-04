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
// A token has exactly one storage form: a file. The order is
//
//  1. RASPUTIN_CP_JOIN_TOKEN_FILE — a file holding the token, read again on
//     EVERY connect attempt. This is the source on every node and every role
//     (geekdojo/geekdojo-brain#537, methodology §5.2 and §7 4.1). The token
//     is a secret, so it belongs in one file the owner alone can read, not in
//     an environment block that every child process inherits and that /proc
//     exposes to anything that can read the process. Re-reading is the other
//     half: the controlplane's api mints its own agent's token into such a
//     file at start (proto.BusAgentTokenFileName) and re-mints it when it
//     stops validating (an identity restore, a revoke), and a node's token
//     can be replaced under a running agent the same way, so the agent picks
//     a new one up on its next reconnect rather than at its next restart.
//  2. Otherwise, on a controlplane, proto.BusAgentTokenPath. A controlplane
//     whose node.env was written before the file variable existed names no
//     file, and firstboot never runs again to add one; this default is what
//     keeps an updated controlplane's agent on the bus.
//  3. Otherwise no token. The bus refuses the connection, as it always has
//     for a node that carries none.
//
// RASPUTIN_CP_JOIN_TOKEN, the inline form older images wrote, is retired
// (geekdojo/geekdojo-brain#539): it is never read as a credential. Its
// presence is diagnosed, so a node still carrying only it is told why it is
// refused rather than going offline unexplained. The deletion waited on every
// node in the field reporting that it read its token from a file.

// EnvJoinToken is retired; never read as a credential; its presence is
// diagnosed. The agent's main only asks whether it is set, and passes that to
// ResolveTokenSource, so its value cannot reach a log line.
const EnvJoinToken = "RASPUTIN_CP_JOIN_TOKEN"

// EnvJoinTokenFile names a file holding the join token, read on every connect.
// It is the only place a node's token is read from.
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

// ResolveTokenSource picks the token source from the agent's role and the
// file its environment names, in the order documented above. It returns the
// source itself; a sentence describing the choice for the startup log (never
// the token itself); and none, true when this node presents no token at all.
//
// legacySet says whether the retired EnvJoinToken is set. It changes only the
// description, never the source: the function takes no token value, so the
// retired variable cannot become a credential here. defaultFile is the
// controlplane default, proto.BusAgentTokenPath outside tests.
func ResolveTokenSource(tokenFile string, legacySet bool, role proto.NodeRole, defaultFile string) (src TokenSource, describe string, none bool) {
	tokenFile = strings.TrimSpace(tokenFile)
	var retired string
	if legacySet {
		retired = fmt.Sprintf("; %s is set and not read", EnvJoinToken)
	}
	switch {
	case tokenFile != "":
		return TokenFile(tokenFile), fmt.Sprintf("the file %s (%s), read on every connect%s", tokenFile, EnvJoinTokenFile, retired), false
	case role == proto.RoleControlPlane:
		return TokenFile(defaultFile), fmt.Sprintf("the file %s (the controlplane default; the api mints it), read on every connect%s", defaultFile, retired), false
	case legacySet:
		return StaticToken(""), fmt.Sprintf("none — %s is set but is no longer read (geekdojo/geekdojo-brain#539), and %s is not set", EnvJoinToken, EnvJoinTokenFile), true
	default:
		return StaticToken(""), fmt.Sprintf("none — %s is not set", EnvJoinTokenFile), true
	}
}
