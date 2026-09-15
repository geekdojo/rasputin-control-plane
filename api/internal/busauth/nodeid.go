package busauth

import (
	"errors"
	"fmt"

	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// ErrInvalidNodeID is returned (wrapped) wherever a node id that fails
// ValidNodeID is refused, so callers can map it to a client error.
var ErrInvalidNodeID = errors.New("invalid node id")

// NodeIDRule is the human-readable form of ValidNodeID, for error messages.
const NodeIDRule = "a node id must be 1-63 characters of lowercase letters, digits and hyphens, and must not start or end with a hyphen"

// ValidNodeID reports whether id is an acceptable node id: a lowercase RFC 1123
// DNS label (1-63 characters of a-z, 0-9 and '-', no leading or trailing
// hyphen). A node id is the first label of the node's FQDN and its mDNS
// hostname, and it is also spliced into bus subjects as exactly one token
// ("rasputin.node.<id>.…"), so it must never contain a subject separator,
// wildcard or whitespace. The label rule excludes all of those.
//
// Ids are rejected, never normalized: the id a node presents on the bus must be
// byte-identical to the id its token was bound to.
func ValidNodeID(id string) bool {
	return tileschema.ValidDNSLabel(id)
}

// checkNodeID returns a wrapped ErrInvalidNodeID when id fails ValidNodeID.
func checkNodeID(id string) error {
	if !ValidNodeID(id) {
		return fmt.Errorf("%w %q: %s", ErrInvalidNodeID, id, NodeIDRule)
	}
	return nil
}
