package secrets

import (
	"bytes"
	"fmt"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The value rule (geekdojo/geekdojo-brain#779). A stored app secret never
// enters compose text: the compose holds only ${RASPUTIN_SECRET_<NAME>}, and
// the value travels beside it and reaches Compose verbatim as a process
// environment variable (geekdojo/geekdojo-brain#776). Compose interpolates
// that value once into a scalar it has already parsed and never re-reads it,
// so a value cannot change the compose it is placed in.
//
// The value must therefore be bytes that channel carries exactly:
//
//   - valid UTF-8, which secretstore's write check already enforces (JSON
//     would rewrite anything else to U+FFFD);
//   - no NUL byte, enforced here: JSON carries one to the store, but no
//     process environment can, so every later deploy would fail at the node.
//
// Everything else is accepted and stored unchanged: "$", "${...}", "$$",
// newlines, quotes and YAML indicators are not encoded, since any encoding
// would reach the app as part of its credential.

// checkDeliverable refuses a value the environment channel cannot carry. The
// error names r and never the value.
func checkDeliverable(r Ref, v secret.Value) error {
	if bytes.IndexByte(v.Reveal(), 0) >= 0 {
		return fmt.Errorf("%w: %s: the value contains a NUL byte, which an environment variable cannot carry",
			secretstore.ErrInvalidValue, r)
	}
	return nil
}
