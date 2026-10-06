// Package functest holds the one copy of the "required" switch that the api's
// functional tests share. Tests import it; nothing in a shipped binary does.
//
// A functional test that needs a real dependency (docker, Compose, Grafana)
// skips when that dependency is missing, so it costs nothing on a laptop
// without it. A skip is invisible in CI, though: a job that lost its docker
// would go green having tested nothing. Setting the test's switch variable to
// Required turns each of those skips into a failure, which is how a CI job
// makes the test an enforced gate (geekdojo/geekdojo-brain#695).
package functest

import "os"

// Required is the switch value that turns a skip into a failure.
const Required = "required"

// TB is the slice of testing.TB that SkipOrFail uses, declared here by its
// consumer so a unit test can supply a recording stub. *testing.T satisfies it.
type TB interface {
	Helper()
	Fatalf(format string, args ...any)
	Skipf(format string, args ...any)
}

// SkipOrFail skips t with the formatted reason, or, when the variable env is
// set to exactly Required, fails it with a message naming the variable. Only
// the variable it is given is read.
func SkipOrFail(t TB, env, format string, args ...any) {
	t.Helper()
	if os.Getenv(env) == Required {
		t.Fatalf(env+"="+Required+" but "+format, args...)
	} else {
		t.Skipf(format, args...)
	}
}
