// Package converge holds the identity realm's api-owned fields to the state
// Rasputin wants, on facts (geekdojo/geekdojo-brain#981, Identity 3.5;
// lifecycle.md §5, testing.md CI TS-17).
//
// Converger reads the realm, its clients and its key providers, writes only
// what drifted, reads everything back and records the desired state's hash.
// FeatureCheck compares the running service's features with the shipped
// build. Armer records the realm's id and the armed marker. Trigger decides,
// on the scheduler's check, when each of their jobs is due: identity.converge,
// identity.migrate (package migrations) and identity.arm.
package converge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
)

// storedEventsExpiry is how long the identity service keeps stored user and
// admin events: the buffer the sign-in history drain reads (lifecycle.md
// §5.4). It is data retention and decides no state (timer-audit row L27).
const storedEventsExpiry = 30 * 24 * time.Hour

// AuditEventTypes are the user events the realm stores: lifecycle.md §5.4's
// sign-in, failure, sign-out, registration, credential changes, lockout and
// session ended, as Keycloak's EventType names them.
var AuditEventTypes = []string{
	"LOGIN", "LOGIN_ERROR", "LOGOUT", "REGISTER",
	"UPDATE_PASSWORD", "RESET_PASSWORD", "UPDATE_TOTP", "REMOVE_TOTP", "UPDATE_CREDENTIAL", "REMOVE_CREDENTIAL",
	"USER_DISABLED_BY_TEMPORARY_LOCKOUT", "USER_DISABLED_BY_PERMANENT_LOCKOUT", "USER_SESSION_DELETED",
}

// DefaultClients are the clients the identity service creates in every realm.
// Converge holds them disabled.
var DefaultClients = []string{"account", "account-console", "admin-cli", "broker", "security-admin-console"}

// RasputinClients are the baseline's own clients, whose redirect URIs
// converge owns.
var RasputinClients = []string{"rasputin-account", "rasputin-admin", "rasputin-console", "rasputin-mesh", "rasputin-reset-app", "rasputin-reset-home"}

// KeyProviders are the baseline's four key providers. Each must be present;
// re-creating one would mint a new signing key (Identity 7.9), so converge
// never does.
var KeyProviders = []string{"aes-generated", "hmac-generated-hs512", "rsa-enc-generated", "rsa-generated"}

// fallbackPrefix starts the name of a key provider the identity service
// makes for itself when an algorithm has no key. Converge deletes each.
const fallbackPrefix = "fallback-"

// Inputs are the facts the desired state is built from, read on each check.
type Inputs struct {
	// InstallName is setup.install_name: the realm's display name.
	InstallName string
	// RedirectURIs are each rasputin-* client's redirect URIs, by client id.
	// A client it does not name gets none.
	RedirectURIs map[string][]string
	// ClockSynced is the clock-sync fact: the authenticator app is offered
	// only while it holds (geekdojo/geekdojo-brain#987).
	ClockSynced bool
	// AppBindings are the app clients' sign-in variants, by client id: nil
	// until Identity 7.3 registers app clients.
	AppBindings map[string]flows.Variant
	// BackchannelLogoutURLs are each rasputin-* client's back-channel logout
	// URL, by client id (geekdojo/geekdojo-brain#989). A client it does not
	// name has the attribute held absent.
	BackchannelLogoutURLs map[string]string
}

// The client attributes converge owns: the back-channel logout URL, and,
// while one is set, the session id it requires in every logout token.
const (
	AttrBackchannelURL     = "backchannel.logout.url"
	AttrBackchannelSession = "backchannel.logout.session.required"
)

// Desired is every field converge owns, with its value. Its JSON is
// canonical (sorted lists, maps in key order), so Hash changes exactly when a
// value does.
type Desired struct {
	DisplayName               string              `json:"displayName"`
	DisplayNameHTML           string              `json:"displayNameHtml"`
	EventsEnabled             bool                `json:"eventsEnabled"`
	EventsListeners           []string            `json:"eventsListeners"`
	EnabledEventTypes         []string            `json:"enabledEventTypes"`
	EventsExpirySeconds       int                 `json:"eventsExpiration"`
	AdminEventsEnabled        bool                `json:"adminEventsEnabled"`
	AdminEventsDetailsEnabled bool                `json:"adminEventsDetailsEnabled"`
	AdminEventsExpirySeconds  string              `json:"adminEventsExpiration"`
	SMTPServer                map[string]string   `json:"smtpServer"`
	WebAuthnRPID              string              `json:"webAuthnPolicyRpId"`
	WebAuthnPasswordlessRPID  string              `json:"webAuthnPolicyPasswordlessRpId"`
	DisabledClients           []string            `json:"disabledClients"`
	RedirectURIs              map[string][]string `json:"redirectUris"`
	KeyProviders              []string            `json:"keyProviders"`
	// ConsoleURL is the realm attribute rasputin.console-url: the console's
	// origin, which the sign-in pages link to (geekdojo/geekdojo-brain#988).
	// "" holds the attribute absent.
	ConsoleURL string `json:"consoleUrl"`
	// ClientAttributes are the client attributes converge owns, by client id
	// and then attribute: "" holds an attribute absent. Every other
	// attribute a client carries is kept as read.
	ClientAttributes map[string]map[string]string `json:"clientAttributes"`
	// Rules are the sign-in rules (geekdojo/geekdojo-brain#987): the seven
	// flows, the realm's session, password, brute-force and passkey rules,
	// the required actions, the profile, roles, scopes and bindings.
	Rules flows.Rules `json:"rules"`
	// flowsIn are the inputs Rules was rendered from, for the parts that
	// also read the server (the required actions it lists).
	flowsIn flows.Inputs
}

// NewDesired is the desired state for in.
func NewDesired(in Inputs) Desired {
	expiry := int(storedEventsExpiry / time.Second)
	d := Desired{
		DisplayName:               in.InstallName,
		EventsEnabled:             true,
		EventsListeners:           []string{},
		EnabledEventTypes:         sorted(AuditEventTypes),
		EventsExpirySeconds:       expiry,
		AdminEventsEnabled:        true,
		AdminEventsDetailsEnabled: false,
		AdminEventsExpirySeconds:  strconv.Itoa(expiry),
		SMTPServer:                map[string]string{},
		DisabledClients:           sorted(DefaultClients),
		RedirectURIs:              map[string][]string{},
		KeyProviders:              sorted(KeyProviders),
	}
	for _, c := range RasputinClients {
		d.RedirectURIs[c] = sorted(in.RedirectURIs[c])
	}
	d.ConsoleURL = consoleOrigin(in.RedirectURIs["rasputin-console"])
	d.ClientAttributes = map[string]map[string]string{}
	for _, c := range RasputinClients {
		d.ClientAttributes[c] = clientAttributes(in.BackchannelLogoutURLs[c])
	}
	d.flowsIn = flows.Inputs{InstallName: in.InstallName, ClockSynced: in.ClockSynced, AppBindings: in.AppBindings}
	d.Rules = flows.Render(d.flowsIn)
	return d
}

// clientAttributes are a client's owned attributes for its back-channel
// logout URL u. Without one the URL is held absent and the session flag is
// left as the identity service has it (its own default, which only matters
// once a URL is set).
func clientAttributes(u string) map[string]string {
	if u == "" {
		return map[string]string{AttrBackchannelURL: ""}
	}
	return map[string]string{AttrBackchannelURL: u, AttrBackchannelSession: "true"}
}

// consoleOrigin is the one https origin the console's redirect URIs share,
// "https://<host>", or "" when there are none, one is not an absolute https
// URL, or they name more than one origin. The sign-in pages leave a link out
// rather than guess which address is the console.
func consoleOrigin(uris []string) string {
	origin := ""
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return ""
		}
		o := "https://" + u.Host
		if origin != "" && o != origin {
			return ""
		}
		origin = o
	}
	return origin
}

// Hash is the sha256 of d's canonical JSON, in hex.
func (d Desired) Hash() string {
	// Desired holds strings, bools, ints, and slices and maps of them,
	// which always encode.
	b, _ := json.Marshal(d)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// sorted is a sorted copy of s, never nil.
func sorted(s []string) []string {
	out := append([]string{}, s...)
	slices.Sort(out)
	return out
}
