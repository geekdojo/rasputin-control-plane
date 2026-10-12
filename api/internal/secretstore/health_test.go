package secretstore_test

import (
	"errors"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
)

// InactiveReason is the one reading of a Health answer, shared by the audit
// rotator and the readiness monitor (geekdojo/geekdojo-brain#760, F-760-05).
func TestInactiveReason(t *testing.T) {
	up := secretstore.Health{Initialized: true}
	for _, tc := range []struct {
		h    secretstore.Health
		err  error
		want string
	}{
		{up, nil, ""},
		{secretstore.Health{Initialized: true, Sealed: true}, nil, "sealed"},
		{secretstore.Health{}, nil, "uninitialised"},
		{up, &secretstore.Error{Kind: secretstore.ErrSealed}, "sealed"},
		{up, &secretstore.Error{Kind: secretstore.ErrUninitialised}, "uninitialised"},
		{up, &secretstore.Error{Kind: secretstore.ErrUnreachable}, "unreachable"},
		{up, &secretstore.Error{Kind: secretstore.ErrDisabled}, "disabled"},
		{up, &secretstore.Error{Kind: secretstore.ErrProtocol}, "error"},
		{up, errors.New("other"), "error"},
	} {
		if got := secretstore.InactiveReason(tc.h, tc.err); got != tc.want {
			t.Errorf("InactiveReason(%+v, %v) = %q, want %q", tc.h, tc.err, got, tc.want)
		}
	}
}
