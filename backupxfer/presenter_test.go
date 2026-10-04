package backupxfer

import (
	"net/http"
	"testing"
)

// TC-514-01, TC-516-01: CheckPresenter is one rule between a credential and
// the connection that presents it: the grant's node must be the presenting
// key's owner. An empty owner owns no grant.
func TestCheckPresenter(t *testing.T) {
	g := testGrant()
	owner := g.NodeID

	cases := []struct {
		name     string
		keyOwner string
		want     *Problem // nil means admitted
	}{
		{"presented by its own node", owner, nil},
		{"presented by another node", "e3bench-compute2", &Problem{Status: http.StatusForbidden, Code: CodeCredentialScope}},
		{"presented with no owner", "", &Problem{Status: http.StatusForbidden, Code: CodeCredentialScope}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckPresenter(g, c.keyOwner)
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
