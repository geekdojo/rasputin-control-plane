//go:build !darwin

package proctest

import "testing"

// F-966-17: off darwin no EPERM is excused: Linux kill(2) succeeds on a
// zombie or an exiting process, so its EPERM is a real permission error.
func TestAllExiting_NeverOffDarwin(t *testing.T) {
	if got, err := allExiting(1); got || err != nil {
		t.Fatalf("allExiting = %v, %v; want false, nil", got, err)
	}
}
