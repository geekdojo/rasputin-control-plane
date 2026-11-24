package auth

import (
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
)

// Principal.Submitter is authz.Person over the principal's Sub and Roles: the
// job records the sub, never the name, and an empty Sub is the zero
// Submitter, which every rule refuses (geekdojo/geekdojo-brain#1001).
func TestPrincipal_Submitter(t *testing.T) {
	p := Principal{Sub: "s-1", Name: "maya", Roles: []string{"viewer"}}
	if got := p.Submitter(); got != authz.Person(authz.Subject{Sub: "s-1", Roles: []string{"viewer"}}) {
		t.Errorf("Submitter = %+v, want authz.Person over the sub and roles", got)
	}
	if got := p.Submitter().CreatedBy(); got != "s-1" {
		t.Errorf("CreatedBy = %q, want the sub s-1", got)
	}
	if p.Submitter().IsSystem() {
		t.Error("a person's Submitter is the system")
	}
	if got := (Principal{Name: "maya", Roles: []string{"admin"}}).Submitter(); got != (authz.Submitter{}) {
		t.Errorf("a principal with no Sub = %+v, want the zero Submitter", got)
	}
}
