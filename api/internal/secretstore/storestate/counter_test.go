package storestate

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
)

// TC-939-01: the counting observer's rules, one outcome at a time from zero.
// The store answered (nil, not found, CAS mismatch): a request. Any other
// failure that reached the store: a request and an error. No request reached
// a store (invalid value, disabled), or the caller's ctx ended: nothing.
func TestCounter_TC_939_01_CountingRules(t *testing.T) {
	live := context.Background()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name string
		ctx  context.Context
		err  error
		want Counts
	}{
		{"nil", live, nil, Counts{Requests: 1}},
		{"not found", live, &secretstore.Error{Op: "read", Kind: secretstore.ErrNotFound}, Counts{Requests: 1}},
		{"cas mismatch", live, &secretstore.Error{Op: "write", Kind: secretstore.ErrCASMismatch}, Counts{Requests: 1}},
		{"denied", live, &secretstore.Error{Op: "read", Kind: secretstore.ErrDenied}, Counts{Requests: 1, Errors: 1}},
		{"client timeout", live, clientTimeout("read"), Counts{Requests: 1, Errors: 1}},
		{"sealed", live, &secretstore.Error{Op: "read", Kind: secretstore.ErrSealed}, Counts{Requests: 1, Errors: 1}},
		{"protocol", live, &secretstore.Error{Op: "read", Kind: secretstore.ErrProtocol}, Counts{Requests: 1, Errors: 1}},
		{"unreachable", live, &secretstore.Error{Op: "read", Kind: secretstore.ErrUnreachable}, Counts{Requests: 1, Errors: 1}},
		{"invalid value", live, fmt.Errorf("write: %w", secretstore.ErrInvalidValue), Counts{}},
		{"disabled", live, &secretstore.Error{Op: "read", Kind: secretstore.ErrDisabled}, Counts{}},
		{"cancelled ctx", cancelled, nil, Counts{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c Counter
			c.ObserveAudited(tc.ctx, tc.err)
			if got := c.Counts(); got != tc.want {
				t.Errorf("Counts() = %+v, want %+v", got, tc.want)
			}
		})
	}

	t.Run("accumulates", func(t *testing.T) {
		var c Counter
		c.ObserveAudited(live, nil)
		c.ObserveAudited(live, errors.New("anything else"))
		c.ObserveAudited(live, nil)
		if got := c.Counts(); got != (Counts{Requests: 3, Errors: 1}) {
			t.Errorf("Counts() = %+v, want {3 1}", got)
		}
	})
}

// TC-939-01 (tee): Tee tells every observer each outcome, so the Monitor's
// audit-blocked handling and the counts see the same calls.
func TestTee_TC_939_01_TellsEveryObserver(t *testing.T) {
	var a, b Counter
	o := Tee(&a, &b)
	o.ObserveAudited(context.Background(), nil)
	o.ObserveAudited(context.Background(), &secretstore.Error{Op: "read", Kind: secretstore.ErrDenied})
	want := Counts{Requests: 2, Errors: 1}
	if a.Counts() != want || b.Counts() != want {
		t.Errorf("counts = %+v, %+v; want both %+v", a.Counts(), b.Counts(), want)
	}
}

// TC-939-03: State.Sealed for all seven states.
func TestState_TC_939_03_Sealed(t *testing.T) {
	for _, tc := range []struct {
		st            State
		sealed, known bool
	}{
		{Sealed, true, true},
		{Ready, false, true},
		{AuditBlocked, false, true},
		{Blank, false, true},
		{Uninitialised, false, false},
		{Unreachable, false, false},
		{Quiesced, false, false},
	} {
		sealed, known := tc.st.Sealed()
		if sealed != tc.sealed || known != tc.known {
			t.Errorf("%s.Sealed() = (%v, %v), want (%v, %v)", tc.st, sealed, known, tc.sealed, tc.known)
		}
	}
}
