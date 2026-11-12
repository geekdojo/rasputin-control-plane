package identitytest

import "github.com/geekdojo/rasputin-control-plane/secret"

// DBPassword is the database password, for the self-test's scan of every
// recorded record (TC-966-20). It exists only in this package's tests.
func (e *Env) DBPassword() secret.Value { return e.dbPassword }
