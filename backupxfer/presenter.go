package backupxfer

import "net/http"

// CheckPresenter is the whole authorization rule between a credential and the
// connection that presents it (auth-methodology §5.2, "authorization on top";
// register row C18). keyOwner is the node whose registered agent key the
// endpoint authenticated the request with, or "" on the bearer-only route,
// where nothing but the credential is presented.
//
//   - A key-bound grant is refused on the bearer-only route: the api minted it
//     for a node it routed to the node listener, so a copy presented anywhere
//     else is not that node.
//   - On the node listener, the grant's node must be the key's owner: a node
//     cannot spend another node's credential, whatever it holds.
//
// Every refusal is 403. A nil result means the presenter may use the grant;
// its per-object scope (member, generation, run, use) is still checked by the
// endpoint.
func CheckPresenter(g Grant, keyOwner string) *Problem {
	switch {
	case keyOwner == "" && g.KeyBound:
		return &Problem{Status: http.StatusForbidden, Code: CodeKeyRequired,
			Detail: "this credential is honoured only from its node's registered agent key, on the api's node listener"}
	case keyOwner != "" && g.NodeID != keyOwner:
		return &Problem{Status: http.StatusForbidden, Code: CodeCredentialScope,
			Detail: "the credential was issued to another node"}
	}
	return nil
}
