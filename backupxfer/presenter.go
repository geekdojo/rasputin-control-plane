package backupxfer

import "net/http"

// CheckPresenter is the whole authorization rule between a credential and the
// connection that presents it (auth-methodology §5.2, "authorization on top";
// register row C18). keyOwner is the node whose registered agent key the node
// listener authenticated the request with.
//
// The grant's node must be the key's owner: a node cannot spend another
// node's credential, whatever it holds. An empty owner is no node, so it owns
// no grant and is refused too.
//
// A refusal is 403. A nil result means the presenter may use the grant; its
// per-object scope (member, generation, run, use) is still checked by the
// endpoint.
func CheckPresenter(g Grant, keyOwner string) *Problem {
	if keyOwner == "" || g.NodeID != keyOwner {
		return &Problem{Status: http.StatusForbidden, Code: CodeCredentialScope,
			Detail: "the credential was issued to another node"}
	}
	return nil
}
