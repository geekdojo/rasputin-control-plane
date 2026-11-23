// Package policy is the sign-in doors' business service
// (geekdojo/geekdojo-brain#985, Identity 4.3; signin-origin.md §5.2): it
// decides, from a request the door endpoint has already parsed into typed
// values, whether that request may reach the identity service, and if not,
// with what status and sentence it is refused. It also owns the per-source
// throttle on credential posts, fed from the drained sign-in events.
//
// It sees no *http.Request and no raw input (SEC-INPUT): the endpoint parses,
// this decides (ARCH-BL). Every check that cannot finish refuses
// (ERR-CLOSED).
package policy

import (
	"net/netip"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/adminguard"
)

// Kind is which door a request arrived at.
type Kind int

// The two doors.
const (
	Home Kind = iota + 1
	App
)

// String is the door's name in logs and metrics.
func (k Kind) String() string {
	switch k {
	case Home:
		return "home"
	case App:
		return "app"
	}
	return "unknown"
}

// RouteKind is what an allowlisted route is, which decides the checks it
// gets.
type RouteKind string

// The route kinds. Each door route has one.
const (
	RouteAuth            RouteKind = "auth"
	RouteRegistrations   RouteKind = "registrations"
	RouteToken           RouteKind = "token"
	RouteCerts           RouteKind = "certs"
	RouteUserinfo        RouteKind = "userinfo"
	RouteLogout          RouteKind = "logout"
	RouteLogoutConfirm   RouteKind = "logout-confirm"
	RouteDiscovery       RouteKind = "discovery"
	RouteAuthenticate    RouteKind = "login-actions/authenticate"
	RouteRequiredAction  RouteKind = "login-actions/required-action"
	RouteRestart         RouteKind = "login-actions/restart"
	RouteDetachedInfo    RouteKind = "login-actions/detached-info"
	RouteResetCredential RouteKind = "login-actions/reset-credentials"
	RouteRegistration    RouteKind = "login-actions/registration"
	RouteSAML            RouteKind = "saml"
	RouteSAMLDescriptor  RouteKind = "saml/descriptor"
	RouteTheme           RouteKind = "theme"
	RouteSignin          RouteKind = "signin"
)

// Page reports whether the route serves a sign-in page or takes a credential,
// so it needs the identity service ready (F-985-18): theme files, the door's
// own files, discovery, certs and userinfo do not.
func (r RouteKind) Page() bool {
	switch r {
	case RouteTheme, RouteSignin, RouteDiscovery, RouteCerts, RouteUserinfo, RouteSAMLDescriptor:
		return false
	}
	return true
}

// EventProducing reports whether forwarding the route can make the identity
// service store a user or admin event, so the drain is marked dirty after it.
func (r RouteKind) EventProducing() bool { return r.Page() }

// Filtered are the parameters the door filters on, each counted across the
// query and the form.
var Filtered = []string{"grant_type", "response_type", "response_mode", "prompt", "kc_action", "state"}

// Request is a door request as the endpoint parsed it.
type Request struct {
	Door   Kind
	Route  RouteKind
	Method string
	// ClientIDs are every client_id value, query and form together.
	ClientIDs []string
	// BasicUser is the Basic Authorization's user, when HasBasic.
	BasicUser string
	HasBasic  bool
	// Params holds every value of each Filtered parameter, query and form
	// together.
	Params map[string][]string
	// RequestObject is a request or request_uri parameter being present.
	RequestObject bool
	// Credential is a credential field (password, otp, recoveryCodeInput)
	// being present in the form.
	Credential bool
	// Peer is the TCP peer's address; the zero Addr when it did not parse.
	Peer netip.Addr
	// Guard is the request as adminguard reads it, and GuardErr what its
	// FromRequest returned.
	Guard    adminguard.Input
	GuardErr error
}

// param is the one value of a filtered parameter, "" when absent. A repeated
// one is refused before any check reads it.
func (r Request) param(name string) string {
	if v := r.Params[name]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// CredentialPost reports whether r is a credential post: a POST to
// login-actions/authenticate carrying a password, an authenticator code or a
// recovery code. Only these are held one at a time and waited per source.
func (r Request) CredentialPost() bool {
	return r.Route == RouteAuthenticate && r.Method == "POST" && r.Credential
}
