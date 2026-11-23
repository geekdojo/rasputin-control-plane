package door

import (
	"net/http"
	"net/netip"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door/policy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/adminguard"
)

// The path shape refusals' sentences (SEC-INPUT, ERR-MESSAGE).
const (
	sentenceAbsoluteForm = "This request named a whole address where only a path belongs, so it was refused. Start signing in again."
	sentenceBadCharacter = "This address holds characters the sign-in pages never use, so it was refused. Start signing in again."
	sentenceBadSegment   = "This address holds an empty or relative part, so it was refused. Start signing in again."
)

// shapeError is the path shape check's refusal: its log reason and sentence.
type shapeError struct{ reason, sentence string }

// checkShape reads the raw request target before anything decodes it: an
// absolute-form target, and in the path a %, ;, backslash, empty segment or
// dot segment, are each refused. "/" alone is a path (the 404 page).
func checkShape(requestURI string) *shapeError {
	if !strings.HasPrefix(requestURI, "/") {
		return &shapeError{"absolute_form", sentenceAbsoluteForm}
	}
	p, _, _ := strings.Cut(requestURI, "?")
	if strings.ContainsAny(p, "%;\\") {
		return &shapeError{"path_character", sentenceBadCharacter}
	}
	if p == "/" {
		return nil
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "" || seg == "." || seg == ".." {
			return &shapeError{"path_segment", sentenceBadSegment}
		}
	}
	return nil
}

// credentialFields are the form fields that carry a password, an
// authenticator code or a recovery code (a passkey's fields are none of
// these: ui/identity-theme/src/login/passkeys.ftl).
var credentialFields = []string{"password", "otp", "recoveryCodeInput"}

// parse turns r into the policy's typed request: the guard's reading of it,
// the client ids, the Basic user, each filtered parameter's values, whether a
// request object or a credential field is present, and the peer. A request
// the guard cannot read is still parsed, with GuardErr set, so the policy
// refuses it with its reason.
func parse(r *http.Request, door Kind, route policy.RouteKind) policy.Request {
	req := policy.Request{Door: door, Route: route, Method: r.Method, Params: map[string][]string{}}
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		req.Peer = ap.Addr()
	}
	in, err := adminguard.FromRequest(r)
	req.Guard, req.GuardErr = in, err
	if err != nil {
		return req
	}
	values := func(name string) []string {
		return append(append([]string(nil), in.Query[name]...), in.Form[name]...)
	}
	req.ClientIDs = values("client_id")
	for _, name := range policy.Filtered {
		if v := values(name); len(v) > 0 {
			req.Params[name] = v
		}
	}
	req.RequestObject = len(values("request")) > 0 || len(values("request_uri")) > 0
	for _, f := range credentialFields {
		if _, ok := in.Form[f]; ok {
			req.Credential = true
		}
	}
	user, ok, err := adminguard.BasicUser(in.Authorization)
	if err != nil {
		req.GuardErr = err
		return req
	}
	req.BasicUser, req.HasBasic = user, ok
	return req
}
