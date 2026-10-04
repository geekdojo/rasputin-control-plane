package backupxfer

import (
	"net/http"
	"testing"
)

// TC-514-01: CheckPresenter is the whole rule between a credential and the
// connection that presents it, asserted exactly for the four shapes.
func TestCheckPresenter(t *testing.T) {
	bound := testGrant()
	bound.KeyBound = true
	unbound := testGrant()
	owner := bound.NodeID

	cases := []struct {
		name     string
		g        Grant
		keyOwner string
		want     *Problem // nil means admitted
	}{
		{"(a) key-bound on the bearer route", bound, "", &Problem{Status: http.StatusForbidden, Code: CodeKeyRequired}},
		{"(b) unbound on the bearer route", unbound, "", nil},
		{"(c) key-bound, presented by its own node", bound, owner, nil},
		{"(d) key-bound, presented by another node", bound, "e3bench-compute2", &Problem{Status: http.StatusForbidden, Code: CodeCredentialScope}},
		{"(d) unbound, presented by another node", unbound, "e3bench-compute2", &Problem{Status: http.StatusForbidden, Code: CodeCredentialScope}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckPresenter(c.g, c.keyOwner)
			switch {
			case c.want == nil && got != nil:
				t.Fatalf("CheckPresenter = %+v, want nil", got)
			case c.want != nil && got == nil:
				t.Fatalf("CheckPresenter = nil, want %d %s", c.want.Status, c.want.Code)
			case c.want != nil && (got.Status != c.want.Status || got.Code != c.want.Code):
				t.Fatalf("CheckPresenter = %d %s, want %d %s", got.Status, got.Code, c.want.Status, c.want.Code)
			case got != nil && got.Detail == "":
				t.Fatal("a refusal carries no detail")
			}
		})
	}
}

// TC-514-02: KeyBound is signed scope: it survives Mint and Verify, and a
// grant minted without it verifies unbound.
func TestKeyBoundIsSignedScope(t *testing.T) {
	a, err := NewAuthority()
	if err != nil {
		t.Fatal(err)
	}
	bound := testGrant()
	bound.KeyBound = true
	for _, c := range []struct {
		g    Grant
		want bool
	}{{bound, true}, {testGrant(), false}} {
		tok, err := a.Mint(c.g, CredentialTTL)
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		got, err := a.Verify(tok)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if got.KeyBound != c.want {
			t.Errorf("verified KeyBound = %v, want %v", got.KeyBound, c.want)
		}
	}
}
