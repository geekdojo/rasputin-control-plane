//go:build !darwin

package proctest

// allExiting is false off darwin: Linux's kill(2) succeeds on a zombie and on
// an exiting process, so an EPERM there is always a real permission error.
func allExiting(int) (bool, error) { return false, nil }
