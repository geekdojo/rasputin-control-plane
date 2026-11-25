// Package markers keeps the per-door second-step markers on accounts
// (geekdojo/geekdojo-brain#987, Identity 4.5; identity-authz.md §5.1): the
// admin-only attributes the sign-in flows' conditions read to ask for a
// second step only where the account can answer it.
//
// Writer sets them from each drained credential event (a user-event sink of
// the sign-in history drain) and, for the Jobs that make an account
// privileged (Identity 4.8 and 6.3), from the account's credentials before
// the role takes effect (BeforePrivilege). Identity 4.12's credential
// removals (geekdojo/geekdojo-brain#994) recompute them from what remains
// (AfterRemoval), the one path that clears a marker.
//
// Nothing here logs a user id.
package markers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/events"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
)

// MetricMarkerCorrections is the counter of marker writes that changed a
// marker (Corrections).
const MetricMarkerCorrections = "rasputin_identity_marker_corrections_total"

// ErrNoSecondStep is BeforePrivilege's answer for an account that holds no
// authenticator app, passkey or security key: it must not be made
// privileged.
var ErrNoSecondStep = errors.New("markers: the account holds no second step")

// The credential types (Keycloak 26.8.2's credential type names).
const (
	typeOTP          = "otp"
	typeWebAuthn     = "webauthn"
	typePasswordless = "webauthn-passwordless"
)

// profileFields are the user profile's own fields a user PUT carries.
var profileFields = []string{"username", "email", "firstName", "lastName"}

// The user events that store a credential.
var credentialEvents = []string{"UPDATE_CREDENTIAL", "UPDATE_TOTP"}

// Admin is the Admin API session (*idclient.Session).
type Admin interface {
	Admin(ctx context.Context, method, path string, in, out any) (idclient.Response, error)
}

// Deps are a Writer's collaborators. New refuses a missing one.
type Deps struct {
	Admin Admin
	// Realm is the realm the accounts are in: rasputin.
	Realm string
	// DoorOf is the door a client belongs to; false for a client no door
	// serves.
	DoorOf func(clientID string) (flows.Door, bool)
	// Lock is the one accounts lock. UserEvent holds it across its read and
	// write; BeforePrivilege and AfterRemoval never take it, as their
	// callers hold it (the lock is not re-entrant).
	Lock sync.Locker
	Log  *slog.Logger
}

// Writer writes the markers.
type Writer struct {
	d           Deps
	log         *slog.Logger
	corrections atomic.Uint64

	mu   sync.Mutex
	down bool
}

// New checks d and returns a Writer. It does no I/O.
func New(d Deps) (*Writer, error) {
	switch {
	case d.Admin == nil:
		return nil, errors.New("markers: Deps.Admin is nil")
	case d.Realm == "":
		return nil, errors.New("markers: Deps.Realm is empty")
	case d.DoorOf == nil:
		return nil, errors.New("markers: Deps.DoorOf is nil")
	case d.Lock == nil:
		return nil, errors.New("markers: Deps.Lock is nil")
	case d.Log == nil:
		return nil, errors.New("markers: Deps.Log is nil")
	}
	return &Writer{d: d, log: d.Log.With("component", "identity")}, nil
}

// Corrections counts the writes that changed a marker.
func (w *Writer) Corrections() uint64 { return w.corrections.Load() }

var _ events.UserSink = (*Writer)(nil)

// UserEvent sets the markers a stored credential calls for: a passkey or
// security key sets its door's webauthn and second-step markers; an
// authenticator app sets both doors' second-step markers; either sets
// rasputin_second_step_any. A privileged account's two second-step markers
// follow rasputin_second_step_any. Recovery codes and passwords set nothing.
// The read and the write run under the accounts lock.
func (w *Writer) UserEvent(ctx context.Context, e events.UserEvent) {
	if !slices.Contains(credentialEvents, e.Type) || e.UserID == "" {
		return
	}
	set := map[string]bool{}
	switch e.CredentialType {
	case typeWebAuthn, typePasswordless:
		door, ok := w.d.DoorOf(e.ClientID)
		if e.ClientID == "" || !ok {
			w.log.LogAttrs(ctx, slog.LevelWarn, "A passkey was stored at a client no door serves, so no marker was set.",
				slog.String("event", "identity.markers.no_door"), slog.String("client_id", e.ClientID))
			return
		}
		set[flows.WebAuthnMarker(door)] = true
		set[flows.SecondStepMarker(door)] = true
	case typeOTP:
		set[flows.MarkerSecondStepHome] = true
		set[flows.MarkerSecondStepApp] = true
	default:
		return
	}
	set[flows.MarkerSecondStepAny] = true
	w.outage(ctx, w.locked(ctx, e.UserID, set))
}

// locked is apply, following privilege, under the accounts lock.
func (w *Writer) locked(ctx context.Context, userID string, set map[string]bool) error {
	w.d.Lock.Lock()
	defer w.d.Lock.Unlock()
	return w.apply(ctx, userID, set, true)
}

// BeforePrivilege sets both doors' second-step markers and
// rasputin_second_step_any from the account's credentials, before a Job
// makes it privileged. It returns ErrNoSecondStep, writing nothing, when the
// account holds no authenticator app, passkey or security key. Its caller
// holds the accounts lock.
func (w *Writer) BeforePrivilege(ctx context.Context, userID string) error {
	types, err := w.credentialTypes(ctx, userID)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(types, IsSecondStep) {
		return ErrNoSecondStep
	}
	set := map[string]bool{flows.MarkerSecondStepHome: true, flows.MarkerSecondStepApp: true, flows.MarkerSecondStepAny: true}
	if err := w.apply(ctx, userID, set, false); err != nil {
		return fmt.Errorf("markers: write the account's markers: %w", err)
	}
	return nil
}

// IsSecondStep reports whether a credential of type credType is a second
// step: an authenticator app, a passkey or a security key. It is the one
// test BeforePrivilege and the designation facts (accounts.RoleAccounts)
// share.
func IsSecondStep(credType string) bool {
	return credType == typeOTP || credType == typeWebAuthn || credType == typePasswordless
}

func (w *Writer) userPath(userID string) string {
	return "/admin/realms/" + url.PathEscape(w.d.Realm) + "/users/" + url.PathEscape(userID)
}

// apply reads the account, sets each marker in set to true (and, with
// follow, a privileged account's two second-step markers once it holds
// rasputin_second_step_any), and writes the account back, its other
// attributes as read, only when a marker changed.
func (w *Writer) apply(ctx context.Context, userID string, set map[string]bool, follow bool) error {
	user, attrs, err := w.read(ctx, userID)
	if err != nil {
		return err
	}
	if follow {
		privileged, err := w.privileged(ctx, userID, attrs)
		if err != nil {
			return err
		}
		if privileged {
			set[flows.MarkerSecondStepHome] = true
			set[flows.MarkerSecondStepApp] = true
		}
	}
	return w.write(ctx, userID, user, attrs, set)
}

// read is the account's representation and its attributes.
func (w *Writer) read(ctx context.Context, userID string) (map[string]any, map[string]any, error) {
	var user map[string]any
	if _, err := w.d.Admin.Admin(ctx, http.MethodGet, w.userPath(userID), nil, &user); err != nil {
		return nil, nil, err
	}
	attrs, _ := user["attributes"].(map[string]any)
	if attrs == nil {
		attrs = map[string]any{}
	}
	return user, attrs, nil
}

// write gives each marker in want its value, true as "true" and false as
// no attribute, and writes the account back only when one changed or an
// attribute stored twice was collapsed (CollapseSingleValued).
func (w *Writer) write(ctx context.Context, userID string, user, attrs map[string]any, want map[string]bool) error {
	changed := CollapseSingleValued(attrs)
	for name, on := range want {
		switch held := holds(attrs, name, "true"); {
		case on && !held:
			attrs[name] = []any{"true"}
			changed = true
		case !on && attrs[name] != nil:
			delete(attrs, name)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	// Only the profile's fields go back, as read, with the attributes: a
	// whole representation would also write back the required actions as
	// read, undoing one the account completed meanwhile.
	body := map[string]any{"attributes": attrs}
	for _, k := range profileFields {
		if v, ok := user[k]; ok {
			body[k] = v
		}
	}
	if _, err := w.d.Admin.Admin(ctx, http.MethodPut, w.userPath(userID), body, nil); err != nil {
		return err
	}
	w.corrections.Add(1)
	return nil
}

// AfterRemoval recomputes the five markers from the credentials that
// remain, after a credential was removed (geekdojo/geekdojo-brain#994,
// F-994-05):
//
//   - a door's webauthn marker stays true only while a passkey or security
//     key remains and it is already true; with none left both clear. A
//     credential's door comes only from its registration event, so it is
//     never set here;
//   - a door's second-step marker is true when an authenticator app remains
//     or that door's webauthn marker is true;
//   - rasputin_second_step_any is true while any second step remains;
//   - a privileged account's two second-step markers follow
//     rasputin_second_step_any, as UserEvent does.
//
// It writes only when a marker changes. A failed read writes nothing. Its
// caller holds the accounts lock.
func (w *Writer) AfterRemoval(ctx context.Context, userID string) error {
	types, err := w.credentialTypes(ctx, userID)
	if err != nil {
		return err
	}
	user, attrs, err := w.read(ctx, userID)
	if err != nil {
		return fmt.Errorf("markers: read the account: %w", err)
	}
	otp := slices.Contains(types, typeOTP)
	passkey := slices.Contains(types, typeWebAuthn) || slices.Contains(types, typePasswordless)
	want := map[string]bool{flows.MarkerSecondStepAny: otp || passkey}
	for _, door := range []flows.Door{flows.DoorHome, flows.DoorApp} {
		web := passkey && holds(attrs, flows.WebAuthnMarker(door), "true")
		want[flows.WebAuthnMarker(door)] = web
		want[flows.SecondStepMarker(door)] = otp || web
	}
	privileged, err := w.privileged(ctx, userID, attrs)
	if err != nil {
		return fmt.Errorf("markers: read the account's roles: %w", err)
	}
	if privileged {
		want[flows.MarkerSecondStepHome] = want[flows.MarkerSecondStepAny]
		want[flows.MarkerSecondStepApp] = want[flows.MarkerSecondStepAny]
	}
	if err := w.write(ctx, userID, user, attrs, want); err != nil {
		return fmt.Errorf("markers: write the account's markers: %w", err)
	}
	return nil
}

// credentialTypes is the type of each of the account's credentials.
func (w *Writer) credentialTypes(ctx context.Context, userID string) ([]string, error) {
	var creds []struct {
		Type string `json:"type"`
	}
	if _, err := w.d.Admin.Admin(ctx, http.MethodGet, w.userPath(userID)+"/credentials", nil, &creds); err != nil {
		return nil, fmt.Errorf("markers: read the account's credentials: %w", err)
	}
	out := make([]string, 0, len(creds))
	for _, c := range creds {
		out = append(out, c.Type)
	}
	return out, nil
}

// privileged reports whether the account is privileged, by the one rule
// (authz.HoldsPrivilege, F-994-06) over its console roles, app access and
// network grants.
func (w *Writer) privileged(ctx context.Context, userID string, attrs map[string]any) (bool, error) {
	f := authz.AccountFacts{AppRole: first(attrs, "rasputin_app_role"), Network: values(attrs, "rasputin_network")}
	if authz.HoldsPrivilege(f) {
		return true, nil
	}
	var clients []struct {
		ID string `json:"id"`
	}
	if _, err := w.d.Admin.Admin(ctx, http.MethodGet, "/admin/realms/"+url.PathEscape(w.d.Realm)+"/clients?clientId="+
		url.QueryEscape(flows.ConsoleClient), nil, &clients); err != nil {
		return false, err
	}
	if len(clients) != 1 {
		return false, fmt.Errorf("markers: %d console clients", len(clients))
	}
	var roles []struct {
		Name string `json:"name"`
	}
	if _, err := w.d.Admin.Admin(ctx, http.MethodGet, w.userPath(userID)+"/role-mappings/clients/"+url.PathEscape(clients[0].ID)+"/composite", nil, &roles); err != nil {
		return false, err
	}
	for _, r := range roles {
		f.Roles = append(f.Roles, r.Name)
	}
	return authz.HoldsPrivilege(f), nil
}

// values is the attribute name's string values.
func values(attrs map[string]any, name string) []string {
	vs, _ := attrs[name].([]any)
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// first is the attribute name's first value, "" when it has none.
func first(attrs map[string]any, name string) string {
	if vs := values(attrs, name); len(vs) > 0 {
		return vs[0]
	}
	return ""
}

// CollapseSingleValued keeps only the first value of each admin-only
// attribute the user profile declares single-valued
// (flows.AdminOnlyAttributes) that attrs holds more than once, and reports
// whether it changed attrs. Two overlapping writes of one account can store
// such an attribute twice; the identity service then refuses any write
// that sends it back so, so every whole-account write passes its
// attributes through here first (geekdojo/geekdojo-brain#994). The first
// value is the one every reader here already takes.
func CollapseSingleValued(attrs map[string]any) bool {
	changed := false
	for name, multi := range flows.AdminOnlyAttributes {
		if vs, _ := attrs[name].([]any); !multi && len(vs) > 1 {
			attrs[name] = []any{vs[0]}
			changed = true
		}
	}
	return changed
}

// holds reports whether the attribute name holds value.
func holds(attrs map[string]any, name, value string) bool {
	vs, _ := attrs[name].([]any)
	return slices.ContainsFunc(vs, func(v any) bool { s, _ := v.(string); return s == value })
}

// outage logs an Admin API failure at WARN once per run of failures, with
// no user id, and clears the flag on success.
func (w *Writer) outage(ctx context.Context, err error) {
	w.mu.Lock()
	first := err != nil && !w.down
	w.down = err != nil
	w.mu.Unlock()
	if !first {
		return
	}
	attrs := []slog.Attr{slog.String("event", "identity.markers.write_failed")}
	// An Admin API error's path names the account, so only its status and
	// kind are logged.
	var ie *idclient.Error
	if errors.As(err, &ie) {
		attrs = append(attrs, slog.Int("status", ie.Status), slog.String("err", fmt.Sprint(ie.Kind)))
	} else {
		attrs = append(attrs, slog.String("err", err.Error()))
	}
	w.log.LogAttrs(ctx, slog.LevelWarn, "A sign-in marker could not be written; the next credential event writes it.", attrs...)
}
