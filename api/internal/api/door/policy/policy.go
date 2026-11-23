package policy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/adminguard"
)

// The clients the policy names: the console, whose account creation the
// home door admits, and each door's own reset client (Identity 4.10).
const (
	ConsoleClient   = "rasputin-console"
	ResetHomeClient = "rasputin-reset-home"
	ResetAppClient  = "rasputin-reset-app"
)

// Readiness is the identity service's readiness: *identitystate.Monitor.
type Readiness interface {
	Ready(ctx context.Context) error
}

// AppClient is what an app's tile declares about its sign-in client.
type AppClient struct {
	FormPost       bool
	RequestObjects bool
}

// AppClients are the app clients the api registered (Identity 7.3).
type AppClients interface {
	AppClient(ctx context.Context, clientID string) (AppClient, bool, error)
}

// ActionRequest is a kc_action the door was asked to forward, with the
// authorization request it came in.
type ActionRequest struct {
	Client, Action, State string
}

// Actions answers whether the api's own launcher issued an action for this
// authorization request.
type Actions interface {
	Issued(ctx context.Context, a ActionRequest) (bool, error)
}

// Network gives the facts the registration source rule reads (Identity 4.8).
type Network interface {
	Facts(ctx context.Context) (NetworkFacts, error)
}

// Waiting reports whether the accounts waiting for access are at their cap
// (Identity 4.8).
type Waiting interface {
	Full(ctx context.Context) (bool, error)
}

// Throttler is the per-source throttle Check consults last.
type Throttler interface {
	Admit(door Kind, addr netip.Addr, now time.Time) Admission
}

// Bindings answers whether a client's sign-in is paused: its binding is
// stricter than the realm default and the sign-in rules are not intact
// (*converge.Converger, geekdojo/geekdojo-brain#987; row B90).
type Bindings interface {
	ClientPaused(clientID string) bool
}

// Deps are the service's collaborators. New refuses a missing one; Bindings
// is optional.
type Deps struct {
	Table      doors.Table
	Readiness  Readiness
	Throttle   Throttler
	AppClients AppClients
	Actions    Actions
	Network    Network
	Waiting    Waiting
	Now        func() time.Time
	// Bindings pauses clients bound stricter than the realm default while
	// the rules differ. Nil pauses no client: until Identity 7.3 registers
	// app clients, no client is bound stricter than the realm default, and
	// 7.3 wires the converger here when it does.
	Bindings Bindings
}

// Service is the door policy.
type Service struct{ d Deps }

// New checks d and returns the service.
func New(d Deps) (*Service, error) {
	missing := ""
	switch {
	case len(d.Table.Home.Clients) == 0 || len(d.Table.App.Clients) == 0:
		missing = "Table"
	case d.Readiness == nil:
		missing = "Readiness"
	case d.Throttle == nil:
		missing = "Throttle"
	case d.AppClients == nil:
		missing = "AppClients"
	case d.Actions == nil:
		missing = "Actions"
	case d.Network == nil:
		missing = "Network"
	case d.Waiting == nil:
		missing = "Waiting"
	case d.Now == nil:
		missing = "Now"
	}
	if missing != "" {
		return nil, errors.New("policy: Deps." + missing + " is missing")
	}
	if d.Bindings == nil {
		d.Bindings = noneBound{}
	}
	return &Service{d: d}, nil
}

// noneBound pauses no client.
type noneBound struct{}

func (noneBound) ClientPaused(string) bool { return false }

// Decision is Check's answer.
type Decision struct {
	Allow bool
	// Status, Sentence and Reason describe a refusal: the HTTP status, the
	// sentence the person reads, and the log's refused= value.
	Status   int
	Sentence string
	Reason   string
	// NotReady is a refusal because the identity service is not ready; the
	// door renders its not-ready page for it.
	NotReady bool
	// RetryAfter is a throttle refusal's wait.
	RetryAfter time.Duration
	// BackLink is a registration refusal, which links back to the form.
	BackLink bool
	// Held is an admitted credential post's throttle slot; the endpoint
	// reports Answered on it once the identity service has answered.
	Held    bool
	HeldKey Key
}

// The log reasons that are WARN rather than INFO.
const (
	ReasonAdminAccount = "admin_account"
	ReasonUnreadable   = "unreadable"
)

// The sentences (ERR-MESSAGE).
const (
	sentenceClientMissing   = "This sign-in request names no app, so it was refused. Start signing in again from the app."
	sentenceClientRepeated  = "This sign-in request names its app more than once, so it was refused. Start signing in again from the app."
	sentenceClientConflict  = "This sign-in request names two different apps, so it was refused. Start signing in again from the app."
	sentenceClientWrongDoor = "This app doesn't sign in here. Start signing in again from the app."
	sentenceRepeated        = "This sign-in request repeats a setting, so it was refused. Start signing in again."
	sentenceGrantType       = "This kind of sign-in isn't allowed here."
	sentenceResponseType    = "This sign-in request asks for an answer this door doesn't give, so it was refused. Start signing in again from the app."
	sentenceResponseMode    = "This sign-in request asks for its answer in a way this door doesn't allow, so it was refused. Start signing in again from the app."
	sentenceRequestObject   = "This sign-in request carries settings this door doesn't accept, so it was refused. Start signing in again from the app."
	sentencePrompt          = "This sign-in request doesn't ask you to sign in afresh, so it was refused. Start signing in again from the app."
	sentenceAction          = "This sign-in step wasn't started by Rasputin, so it was refused. Start again from Rasputin."
	sentenceReset           = "Resetting a password isn't available for this app here. Start again from the sign-in page."
	sentenceRegisterDoor    = "Accounts can only be created on your home network, at the Rasputin console."
	sentenceRegisterSource  = "Accounts can only be created from a device on your home network."
	sentenceRegisterFull    = "Too many accounts are waiting for access. Ask an administrator to give access to the ones waiting, then try again."
	sentenceRegisterUnknown = "Creating an account isn't available right now. Ask whoever runs this cluster to add you."
	sentenceBusy            = "Another sign-in from this device is still being checked. Try again in a moment."
	sentenceClientPaused    = "Signing in to this app is paused because its sign-in settings changed. An administrator can see why in Rasputin's alerts."
)

// ReasonClientPaused is a paused client's refusal reason.
const ReasonClientPaused = "client_paused"

func refuse(status int, reason, sentence string) Decision {
	return Decision{Status: status, Reason: reason, Sentence: sentence}
}

func badRequest(reason, sentence string) Decision {
	return refuse(http.StatusBadRequest, reason, sentence)
}

// Check decides r, in signin-origin.md §5.2's order: readiness on page and
// credential routes, the admin-account guard, the client rule, repeated
// parameters, the grant, the response shape and prompt, kc_action, reset,
// registration, and last the throttle.
func (s *Service) Check(ctx context.Context, r Request) Decision {
	if r.Route.Page() {
		if err := s.d.Readiness.Ready(ctx); err != nil {
			return Decision{Status: http.StatusServiceUnavailable, Reason: "not_ready", NotReady: true}
		}
	}
	if err := guard(r); err != nil {
		reason := ReasonUnreadable
		if errors.Is(err, adminguard.ErrAdminAccount) {
			reason = ReasonAdminAccount
		}
		return badRequest(reason, adminguard.Sentence(err))
	}
	client, d, ok := s.client(ctx, r)
	if !ok {
		return d
	}
	if r.Route == RouteAuth && s.d.Bindings.ClientPaused(client) {
		return refuse(http.StatusServiceUnavailable, ReasonClientPaused, sentenceClientPaused)
	}
	for _, name := range Filtered {
		if len(r.Params[name]) > 1 {
			return badRequest("repeated_"+name, sentenceRepeated)
		}
	}
	if g, present := r.Params["grant_type"]; r.Route == RouteToken || present {
		if len(g) != 1 || (g[0] != "authorization_code" && g[0] != "refresh_token") {
			return badRequest("grant", sentenceGrantType)
		}
	}
	if d, ok := s.shape(ctx, r, client); !ok {
		return d
	}
	if d, ok := s.action(ctx, r, client); !ok {
		return d
	}
	if d, ok := s.registration(ctx, r, client); !ok {
		return d
	}
	if r.CredentialPost() {
		a := s.d.Throttle.Admit(r.Door, r.Peer, s.d.Now())
		if !a.OK {
			d := Decision{Status: http.StatusTooManyRequests, Reason: "throttled", Sentence: a.Sentence, RetryAfter: a.RetryAfter}
			if a.Busy {
				d.Reason, d.Sentence = "busy", sentenceBusy
			}
			return d
		}
		return Decision{Allow: true, Held: true, HeldKey: a.Key}
	}
	return Decision{Allow: true}
}

// guard is the admin-account guard over the parsed request.
func guard(r Request) error {
	if r.GuardErr != nil {
		return r.GuardErr
	}
	return adminguard.Check(r.Guard)
}

// clientRule is how a route kind treats the client (F-985-04).
type clientRule int

const (
	clientNone clientRule = iota
	clientOptional
	clientRequired
)

func ruleFor(k RouteKind) clientRule {
	switch k {
	case RouteAuth, RouteRegistrations, RouteToken, RouteAuthenticate, RouteRequiredAction,
		RouteResetCredential, RouteRegistration:
		return clientRequired
	case RouteRestart, RouteDetachedInfo, RouteLogout, RouteLogoutConfirm:
		return clientOptional
	}
	return clientNone
}

// client applies the route's client rule and returns the client, "" when the
// route reads none or an optional one is absent.
func (s *Service) client(ctx context.Context, r Request) (string, Decision, bool) {
	rule := ruleFor(r.Route)
	if rule == clientNone {
		return "", Decision{}, true
	}
	if len(r.ClientIDs) > 1 {
		return "", badRequest("client_repeated", sentenceClientRepeated), false
	}
	client := ""
	if len(r.ClientIDs) == 1 {
		client = r.ClientIDs[0]
	}
	if r.HasBasic {
		if client != "" && client != r.BasicUser {
			return "", badRequest("client_conflict", sentenceClientConflict), false
		}
		client = r.BasicUser
	}
	switch {
	case client == "" && rule == clientRequired:
		return "", badRequest("client_missing", sentenceClientMissing), false
	case client == "":
		return "", Decision{}, true
	}
	ok, err := s.belongs(ctx, r.Door, client)
	if err != nil || !ok {
		return "", badRequest("client_door", sentenceClientWrongDoor), false
	}
	switch r.Route {
	case RouteResetCredential:
		if client != resetClient(r.Door) {
			return "", badRequest("reset_client", sentenceReset), false
		}
	case RouteRegistrations, RouteRegistration:
		if r.Door != Home || client != ConsoleClient {
			return "", badRequest("registration_client", sentenceRegisterDoor), false
		}
	}
	return client, Decision{}, true
}

// belongs reports whether client is one of door's: the door table's, and at
// the app door every app client the api registered.
func (s *Service) belongs(ctx context.Context, door Kind, client string) (bool, error) {
	switch door {
	case Home:
		return slices.Contains(s.d.Table.Home.Clients, client), nil
	case App:
		if slices.Contains(s.d.Table.App.Clients, client) {
			return true, nil
		}
		_, ok, err := s.d.AppClients.AppClient(ctx, client)
		return ok, err
	}
	return false, fmt.Errorf("policy: unknown door %d", door)
}

func resetClient(door Kind) string {
	if door == Home {
		return ResetHomeClient
	}
	return ResetAppClient
}

// shape is the response shape on an authorization request: at the home door
// query only, code only, no request objects, and prompt=login (or
// prompt=create for the console's account creation); at the app door
// form_post and request objects only for a client that declares them.
func (s *Service) shape(ctx context.Context, r Request, client string) (Decision, bool) {
	if r.Route != RouteAuth && r.Route != RouteRegistrations {
		return Decision{}, true
	}
	mode, prompt := r.param("response_mode"), r.param("prompt")
	if r.Door == Home {
		switch {
		case r.param("response_type") != "code":
			return badRequest("response_type", sentenceResponseType), false
		case mode != "" && mode != "query":
			return badRequest("response_mode", sentenceResponseMode), false
		case r.RequestObject:
			return badRequest("request_object", sentenceRequestObject), false
		}
		promptOK := prompt == "login" || (prompt == "create" && client == ConsoleClient) ||
			(r.Route == RouteRegistrations && prompt == "")
		if !promptOK {
			return badRequest("prompt", sentencePrompt), false
		}
		return Decision{}, true
	}
	if mode != "form_post" && !r.RequestObject {
		return Decision{}, true
	}
	app, ok, err := s.d.AppClients.AppClient(ctx, client)
	if err != nil {
		ok = false
	}
	switch {
	case mode == "form_post" && (!ok || !app.FormPost):
		return badRequest("response_mode", sentenceResponseMode), false
	case r.RequestObject && (!ok || !app.RequestObjects):
		return badRequest("request_object", sentenceRequestObject), false
	}
	return Decision{}, true
}

// action forwards a kc_action only when the api's own launcher issued it for
// this authorization request; delete_credential, in any form, never.
func (s *Service) action(ctx context.Context, r Request, client string) (Decision, bool) {
	a, present := r.Params["kc_action"]
	if !present {
		return Decision{}, true
	}
	name, _, _ := strings.Cut(a[0], ":")
	if strings.EqualFold(strings.TrimSpace(name), "delete_credential") {
		return badRequest("kc_action", sentenceAction), false
	}
	ok, err := s.d.Actions.Issued(ctx, ActionRequest{Client: client, Action: a[0], State: r.param("state")})
	if err != nil || !ok {
		return badRequest("kc_action", sentenceAction), false
	}
	return Decision{}, true
}

// registration admits account creation only from an address on the home
// network's subnets that is neither a tailnet address nor a node's, while
// the waiting cap is not reached. Account creation is the two registration
// routes, whose client and door the client rule checked, and an
// authorization request with prompt=create, which opens the registration
// form too: only the console's, only at the home door.
func (s *Service) registration(ctx context.Context, r Request, client string) (Decision, bool) {
	creates := r.Route == RouteAuth && slices.Contains(strings.Fields(r.param("prompt")), "create")
	if r.Route != RouteRegistrations && r.Route != RouteRegistration && !creates {
		return Decision{}, true
	}
	back := func(d Decision) (Decision, bool) { d.BackLink = true; return d, false }
	if creates && (r.Door != Home || client != ConsoleClient) {
		return back(badRequest("registration_client", sentenceRegisterDoor))
	}
	facts, err := s.d.Network.Facts(ctx)
	if err != nil {
		return back(refuse(http.StatusForbidden, "registration_unknown", sentenceRegisterUnknown))
	}
	if !facts.AdmitsRegistration(r.Peer) {
		return back(refuse(http.StatusForbidden, "registration_source", sentenceRegisterSource))
	}
	full, err := s.d.Waiting.Full(ctx)
	switch {
	case err != nil:
		return back(refuse(http.StatusForbidden, "registration_unknown", sentenceRegisterUnknown))
	case full:
		return back(refuse(http.StatusForbidden, "registration_full", sentenceRegisterFull))
	}
	return Decision{}, true
}

// ---- the fail-closed collaborators, wired until their producers land ------

// NoAppClients holds no app client: until Identity 7.3 registers them, only
// the app door's own clients sign in there.
type NoAppClients struct{}

// AppClient answers that no app client exists.
func (NoAppClients) AppClient(context.Context, string) (AppClient, bool, error) {
	return AppClient{}, false, nil
}

// NoActionsIssued has issued no action: until the launcher issues them, every
// kc_action is refused.
type NoActionsIssued struct{}

// Issued answers false.
func (NoActionsIssued) Issued(context.Context, ActionRequest) (bool, error) { return false, nil }

// ErrRegistrationClosed is RegistrationClosed's answer.
var ErrRegistrationClosed = errors.New("policy: account creation is not wired")

// RegistrationClosed refuses every registration until Identity 4.8 supplies
// the network facts and the waiting count.
type RegistrationClosed struct{}

// Facts refuses.
func (RegistrationClosed) Facts(context.Context) (NetworkFacts, error) {
	return NetworkFacts{}, ErrRegistrationClosed
}

// Full refuses.
func (RegistrationClosed) Full(context.Context) (bool, error) { return false, ErrRegistrationClosed }
