package door

import (
	"slices"

	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door/policy"
)

// Kind is which door a handler is: policy's, re-exported so a caller names
// door.Home.
type Kind = policy.Kind

// The two doors.
const (
	Home = policy.Home
	App  = policy.App
)

// realmPrefix is the one realm the doors serve.
const realmPrefix = "/realms/rasputin/"

// Route is one allowlisted path (signin-origin.md §5.2). Every request a
// door serves matches exactly one; everything else is the 404 door page.
// Each is an open route with its reason, beside the console's openRoutes:
// a door request carries no Rasputin session.
type Route struct {
	// Pattern is the ServeMux path pattern, with no method and no host.
	Pattern string
	// Methods are the methods it is forwarded with; any other gets the door
	// page, never the mux's 405.
	Methods []string
	// Doors are the doors that serve it.
	Doors []Kind
	// Kind decides the checks it gets, the client rule among them
	// (policy.RouteKind).
	Kind policy.RouteKind
	// Reason is why it answers without a session, in one line.
	Reason string
}

var (
	both     = []Kind{Home, App}
	homeOnly = []Kind{Home}
	appOnly  = []Kind{App}
	get      = []string{"GET"}
	post     = []string{"POST"}
	getPost  = []string{"GET", "POST"}
)

// oidc is a path under the realm's openid-connect protocol.
func oidc(p string) string { return realmPrefix + "protocol/openid-connect/" + p }

// actions is a login-actions path.
func actions(p string) string { return realmPrefix + "login-actions/" + p }

// routes is the allowlist, as data.
var routes = []Route{
	{oidc("auth"), getPost, both, policy.RouteAuth, "the authorization request: the sign-in page a person reaches from an app"},
	{oidc("token"), post, both, policy.RouteToken, "an app exchanges its code or refreshes its token; the client authenticates itself"},
	{oidc("certs"), get, both, policy.RouteCerts, "the realm's public signing keys, which every app verifies tokens with"},
	{oidc("userinfo"), getPost, both, policy.RouteUserinfo, "an app reads the signed-in person's claims with its access token"},
	{oidc("logout"), getPost, both, policy.RouteLogout, "sign-out from an app, which asks the person first"},
	{oidc("logout/logout-confirm"), getPost, both, policy.RouteLogoutConfirm, "the sign-out confirmation the logout page posts"},
	{realmPrefix + ".well-known/openid-configuration", get, both, policy.RouteDiscovery, "the realm's discovery document, which every app reads its endpoints from"},
	{actions("authenticate"), getPost, both, policy.RouteAuthenticate, "the sign-in form's own steps: the password, the second step, a passkey"},
	{actions("required-action"), getPost, both, policy.RouteRequiredAction, "a required step after sign-in, such as a new password or a passkey"},
	{actions("restart"), get, both, policy.RouteRestart, "starts the sign-in again from its first page"},
	{actions("detached-info"), get, both, policy.RouteDetachedInfo, "an information page shown after a sign-in step ends the flow"},
	{actions("reset-credentials"), getPost, both, policy.RouteResetCredential, "a password reset, only for the door's own reset client"},
	{oidc("registrations"), get, homeOnly, policy.RouteRegistrations, "account creation on the home network, only for the console"},
	{actions("registration"), getPost, homeOnly, policy.RouteRegistration, "the account creation form's own step, only for the console"},
	{realmPrefix + "protocol/saml", getPost, appOnly, policy.RouteSAML, "a SAML device's sign-in, at the app door only"},
	{realmPrefix + "protocol/saml/descriptor", get, appOnly, policy.RouteSAMLDescriptor, "the realm's SAML metadata a device is set up from, at the app door only"},
	{"/resources/{v}/login/rasputin/{file...}", get, both, policy.RouteTheme, "Rasputin's login theme files the theme build lists, at the resource version learned from the running service only"},
	{"/resources/{v}/common/keycloak/{file...}", get, both, policy.RouteTheme, "the shared theme files the login theme build lists, at the resource version learned from the running service only"},
	{signinPrefix + "{file...}", get, both, policy.RouteSignin, "the door's own page styles and images, served from memory and never forwarded"},
	{"/api/auth/reset-done", get, appOnly, policy.RouteResetDone, "the app door's reset client returns here; it ends the person's sessions and mints none"},
}

// Routes are the routes door serves.
func Routes(door Kind) []Route {
	var out []Route
	for _, r := range routes {
		if slices.Contains(r.Doors, door) {
			out = append(out, r)
		}
	}
	return out
}
